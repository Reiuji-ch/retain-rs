use crate::config::Config;
use crate::server::resume_large_file::resume_large_file;
use crate::server::upload_file::upload_file;
use crate::server::upload_large_file::{cancel_large_file, upload_large_file};
use crate::server::{
    cleaner, decrypt_file_name, enqueuer, get_file_list_from_b2, get_nonce_from_name, KnownFiles,
};
use crate::stream::get_nonces_required;
use crate::{format_bytes, retry_forever};
use backblaze_api::api::{b2_authorize_account, b2_list_parts, b2_list_unfinished_large_files};
use backblaze_api::Auth;
use std::collections::VecDeque;
use std::ops::Deref;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::UNIX_EPOCH;
use clap::ArgMatches;
use strmap::StrMapConfig;
use tokio::sync::{Mutex, RwLock, Semaphore};
use tokio::time::MissedTickBehavior;

const ABSOLUTE_MAX_CONCURRENT_UPLOADS: u64 = 16;
const MAXIMUM_ENQUEUED_FILES: usize = 32;

pub async fn supervise(
    api_auth: Arc<RwLock<Option<Auth>>>,
    config: Arc<RwLock<Config>>,
    known_files: KnownFiles,
    args: ArgMatches,
) {
    // Spawn the authorization supervisor
    // This tasks tries to ensure we always have Some(Auth) in our api_auth
    // If we have Some(Auth), it will sleep until it becomes None
    // If it's None, it will keep calling b2_authorize_account with exponential backoff until either:
    // 1. The call succeeds
    // 2. We got an auth from somewhere else, i.e. an Authorize command
    // Note that if the key (from the config file) is empty, we will not attempt to authorize
    // That typically happens on the first run. In that case, the client send an Authorize command
    //
    // We can detect API calls return the codes "bad_auth_token" or "expired_auth_token" and `take()`
    // the Option<Auth>, causing this to re-authenticate
    let auth_copy = api_auth.clone();
    let config_copy = config.clone();
    let encryption_key = { config.read().await.get_encryption_key() };
    tokio::spawn(async move {
        retry_forever!(
            [1, 3, 5, 10, 30, 60, 600, 1800, 3600],
            result,
            {
                let status = { auth_copy.read().await.is_some() };
                match status {
                    true => {
                        tokio::time::sleep(Duration::from_secs(10)).await;
                        continue;
                    }
                    false => {
                        let key = { config_copy.read().await.get_key().to_string() };
                        if !key.is_empty() {
                            b2_authorize_account(&key).await
                        } else {
                            tokio::time::sleep(Duration::from_secs(10)).await;
                            continue;
                        }
                    }
                }
            },
            {
                auth_copy.write().await.replace(result);
            },
            {
                eprintln!("Failed to authorize: {result:?}");
            }
        );
    });

    // Read max bandwidth and determine maximum concurrent uploads
    let mut max_bandwidth = {
        match config.read().await.get_bandwidth() {
            0 => 1_000_000_000,
            n => {
                if n < 10000 {
                    eprintln!("NOTICE: Configured bandwidth limit of {n} lower than minimum (10KB/s), clamping to 10'000");
                    10000
                } else {
                    n
                }
            }
        }
    };
    eprintln!("Total maximum bandwidth: {}/s", format_bytes(max_bandwidth));
    // Minimum 100KiB/s per additional simultaneous upload
    let max_concurrency = (max_bandwidth / 100000)
        .min(ABSOLUTE_MAX_CONCURRENT_UPLOADS)
        .max(1);
    eprintln!("Setting max concurrent uploads to: {max_concurrency}");
    let mut upload_auths = VecDeque::with_capacity((ABSOLUTE_MAX_CONCURRENT_UPLOADS * 2) as usize);
    let concurrent_uploads_semaphore = Arc::new(Semaphore::new(max_concurrency as usize));
    let bandwidth_semaphore = Arc::new(Semaphore::new(0));

    // Wait until we have an authorization before we start any work
    // Determine how big we think a file should be before we use the large file API
    // This is set such that any file that would be expected to take more than 10 minutes to upload is split up.
    // With the absolute minimum 10KB/s, this is 6MB. With the recommended minimum of 100KB/s, this is 60MB.
    let mut large_file_threshold;
    loop {
        {
            if let Some(auth) = api_auth.read().await.deref() {
                large_file_threshold = ((max_bandwidth / max_concurrency) * 600)
                    .max(auth.absolute_minimum_part_size)
                    .min(auth.recommended_part_size);
                break;
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    eprintln!(
        "Files larger than {} bytes will use large file API",
        format_bytes(large_file_threshold)
    );

    // Start the primary upload task spawning loop
    // This loop manages upload auths and the amount of concurrent uploads
    // The Semaphore limits the degree of concurrency, since we only spawn tasks when we get a permit
    // A channel is used to return still-valid upload auths after they finish uploading

    // Upload tasks can send their UploadAuth back so it can be re-used via this channel
    let (auth_return_tx, mut auth_return_rx) =
        tokio::sync::mpsc::channel(ABSOLUTE_MAX_CONCURRENT_UPLOADS as usize);
    // A task sends work via the rx, the upload loops receives those and spawns the upload tasks
    let (upload_queue_tx, mut upload_queue_rx) =
        tokio::sync::mpsc::channel::<PathBuf>(MAXIMUM_ENQUEUED_FILES);

    // Vec of (path, modified_timestamp) for files we know are stored in B2
    eprintln!("Retrieving list of known files");
    {
        let files_from_b2 = get_file_list_from_b2(api_auth.clone(), &encryption_key).await;
        eprintln!(
            "Got file list from B2 -- There are {} files stored",
            files_from_b2.len()
        );
        *known_files.lock().await = files_from_b2;
    }

    // Spawn rebalancer thread
    // This will rebalance the KnownFiles tree every 10 minutes
    let known_files_clone = known_files.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(60 * 10));
        let mut lock = known_files_clone.blocking_lock();
        lock.rebalance(&StrMapConfig::InMemory).unwrap();
    });

    // Keeps track of whiles files are currently uploading, to prevent simultaneous uploads of the same file
    let currently_uploading: Arc<Mutex<Vec<PathBuf>>> = Arc::new(Mutex::new(Vec::new()));

    // Spawn task that queues files to be uploaded
    if args.contains_id("readonly") {
        println!("Read-only mode: disabling 'upload' task");
    } else {
        let cfg_clone = config.clone();
        tokio::spawn(async move {
            enqueuer::enqueue_files(cfg_clone, upload_queue_tx).await;
        });
    }

    // Spawn task that hides files which should no longer be uploaded
    if args.contains_id("readonly") {
        println!("Read-only mode: disabling 'hide unused' task");
    } else {
        let cfg_clone = config.clone();
        let auth_clone = api_auth.clone();
        let known_files_clone = known_files.clone();
        tokio::spawn(async move {
            cleaner::hide_unused(cfg_clone, auth_clone, known_files_clone).await;
        });
    }

    // Task that keeps supplying bandwidth, up to some max buffered amount
    let bandwidth_semaphore_clone = bandwidth_semaphore.clone();
    let config_copy = config.clone();
    tokio::spawn(async move {
        // Every 50ms, add 1/20th of the maximum bandwidth/second
        let mut interval = tokio::time::interval(Duration::from_millis(50));
        let mut max_bandwidth = max_bandwidth;
        interval.set_missed_tick_behavior(MissedTickBehavior::Burst);
        loop {
            // Loop 100 times = 5 seconds...
            for _ in 0..100 {
                let _ = interval.tick().await;
                // Check how much bandwidth is available
                let available = bandwidth_semaphore_clone.available_permits() as u64;
                // Add 1/100th, but only up to the maximum value
                let permits_to_add =
                    (max_bandwidth / 20).max(1).min(max_bandwidth - available) as usize;
                bandwidth_semaphore_clone.add_permits(permits_to_add);
            }
            // ...then check if the bandwidth limit needs to be updated
            let previous_limit = max_bandwidth;
            max_bandwidth = {
                match config_copy.try_read() {
                    Ok(cfg) => {
                        match cfg.get_bandwidth() {
                            0 => 1_000_000_000,
                            // Minimum of 10KB/s
                            n => n.max(10000),
                        }
                    }
                    Err(_) => max_bandwidth,
                }
            };
            // If the limit was adjusted downwards, we need to drop excess permits
            if max_bandwidth < previous_limit {
                bandwidth_semaphore_clone
                    .acquire_many(bandwidth_semaphore_clone.available_permits() as u32)
                    .await
                    .expect("Unexpected semaphore closure")
                    .forget();
            }
        }
    });

    /*
    Handle unfinished large files
    The program may have been restarted or otherwise interrupted with a large file in-progress
    We need to retrieve a list of unfinished large files and resume them before resuming other activities
     */
    eprintln!("Getting list of unfinished large files");
    let unfinished_large_files;
    retry_forever!(
        [1, 3, 5, 10, 30, 60, 600, 1800, 3600],
        result,
        { b2_list_unfinished_large_files(api_auth.clone()).await },
        {
            unfinished_large_files = result.files;
            break;
        },
        {
            eprintln!("Error while getting list of unfinished large files: {result:?}",);
        }
    );
    eprintln!(
        "There are {} unfinished large files",
        unfinished_large_files.len()
    );
    // For each unfinished large file:
    // * Check the 'modified timestamp' hasn't changed since we initially started the upload
    // * Check the filesize hasn't changed since we started
    // If both are the same, start uploading it from where we left off
    for file in unfinished_large_files {
        let name_nonce = match get_nonce_from_name(&file.file_name) {
            Some(nonce) => nonce,
            None => {
                eprintln!("Obtaining name nonce failed -- Cancelling large file");
                continue;
            }
        };
        let path = match decrypt_file_name(&file.file_name, &encryption_key) {
            Some(path) => path,
            None => {
                eprintln!("Decrypting path failed -- Cancelling large file");
                cancel_large_file(api_auth.clone(), file.file_id.clone()).await;
                continue;
            }
        };
        if args.contains_id("readonly") {
            eprintln!("Read-only mode: skipping {path:?}, will retry when not in read-only mode");
            continue;
        } else {
            eprintln!("Resuming upload of {path:?}");
        }
        let metadata = match tokio::fs::metadata(&path).await {
            Ok(meta) => meta,
            Err(err) => {
                eprintln!("Couldn't read metadata for {path:?}: {err:?} -- Cancelling large file");
                cancel_large_file(api_auth.clone(), file.file_id.clone()).await;
                continue;
            }
        };
        let modified_time = match file.file_info.get("src_last_modified_millis") {
            Some(t) => match u128::from_str(t) {
                Ok(n) => n,
                Err(_err) => {
                    eprintln!(
                        "Invalid src_last_modified_millis value: {} -- Cancelling large file",
                        t
                    );
                    cancel_large_file(api_auth.clone(), file.file_id.clone()).await;
                    continue;
                }
            },
            None => {
                eprintln!("No src_last_modified_millis value -- Cancelling large file");
                cancel_large_file(api_auth.clone(), file.file_id.clone()).await;
                continue;
            }
        };
        let current_timestamp = metadata
            .modified()
            .expect("Modified time unsupported!")
            .duration_since(UNIX_EPOCH)
            .map(|dur| dur.as_millis())
            .expect("System time is before Unix epoch???");
        if current_timestamp != modified_time {
            eprintln!("Large file has been modified since we started it -- Cancelling large file");
            cancel_large_file(api_auth.clone(), file.file_id.clone()).await;
            continue;
        }
        let large_file_size = match file.file_info.get("large_file_size") {
            Some(t) => match u64::from_str(t) {
                Ok(n) => n,
                Err(_err) => {
                    eprintln!(
                        "Invalid large_file_size value: {} -- Cancelling large file",
                        t
                    );
                    cancel_large_file(api_auth.clone(), file.file_id.clone()).await;
                    continue;
                }
            },
            None => {
                eprintln!("No large_file_size value -- Cancelling large file");
                cancel_large_file(api_auth.clone(), file.file_id.clone()).await;
                continue;
            }
        };
        if metadata.len() != large_file_size {
            eprintln!(
                "Size of large file has changed since it was started -- Cancelling large file"
            );
            cancel_large_file(api_auth.clone(), file.file_id.clone()).await;
            continue;
        }

        let mut parts_list;
        retry_forever!(
            [1, 3, 5, 10, 30, 60, 600, 1800, 3600],
            result,
            { b2_list_parts(api_auth.clone(), file.file_id.clone(), None).await },
            {
                parts_list = result;
                break;
            },
            {
                eprintln!("Unexpected error while getting parts list: {result:?}");
            }
        );
        // If there are no parts on we might as well cancel it at handle it as normal later on...
        if parts_list.parts.is_empty() {
            eprintln!("Large file has no successful parts -- Cancelling large file");
            cancel_large_file(api_auth.clone(), file.file_id.clone()).await;
            continue;
        }

        // Permit for resuming large file
        let permit = concurrent_uploads_semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("Unexpected AcquireError from upload-concurrency-semaphore");

        eprintln!("Resuming large file at {path:?}");
        let auth_clone = api_auth.clone();
        let known_files_clone = known_files.clone();
        let currently_uploading_clone = currently_uploading.clone();
        let key = encryption_key;
        let bandwidth_semaphore_clone = bandwidth_semaphore.clone();
        let required_nonces = get_nonces_required(metadata.len());
        let start_nonce = match file.file_info.get("large_file_nonce") {
            Some(t) => match u128::from_str(t) {
                Ok(n) => n,
                Err(_err) => {
                    eprintln!(
                        "Invalid large_file_nonce value: {} -- Cancelling large file",
                        t
                    );
                    cancel_large_file(api_auth.clone(), file.file_id.clone()).await;
                    continue;
                }
            },
            None => {
                eprintln!("No large_file_nonce value -- Cancelling large file");
                cancel_large_file(api_auth.clone(), file.file_id.clone()).await;
                continue;
            }
        };
        // Ensure parts are in order
        parts_list.parts.sort_by_key(|elem| elem.part_number);
        let part_hashes: Vec<String> = parts_list
            .parts
            .into_iter()
            .map(|part| part.content_sha1)
            .collect();
        eprintln!(
            "Resuming large file at {path:?} from part {}",
            part_hashes.len() + 1
        );

        {
            currently_uploading.lock().await.push(path.clone());
        }
        tokio::spawn(resume_large_file(
            auth_clone,
            path,
            file.file_id.clone(),
            metadata,
            large_file_threshold,
            current_timestamp,
            known_files_clone,
            currently_uploading_clone,
            key,
            bandwidth_semaphore_clone,
            start_nonce,
            required_nonces,
            part_hashes,
            name_nonce,
            permit,
        ));
    }

    // Sleep until the large files are done
    loop {
        if currently_uploading.lock().await.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    eprintln!("Finished outstanding large files");

    // Upload loop
    loop {
        // Check if bandwidth limit changed
        let new_max_bandwidth = {
            match config.read().await.get_bandwidth() {
                0 => 1_000_000_000,
                n => {
                    if n < 10000 {
                        10000
                    } else {
                        n
                    }
                }
            }
        };
        // If bandwidth limit changed, adjust max concurrency
        if new_max_bandwidth != max_bandwidth {
            eprintln!("Available bandwidth changed, adjusting concurrency limits");
            max_bandwidth = new_max_bandwidth;
            let new_max_concurrency = (max_bandwidth / 100000)
                .min(ABSOLUTE_MAX_CONCURRENT_UPLOADS)
                .max(1);
            // If max concurrency changed, add or forget the difference in permits on the semaphore
            if new_max_concurrency != max_concurrency {
                let diff = (new_max_concurrency as i64) - max_concurrency as i64;
                match diff {
                    diff if diff > 0 => {
                        concurrent_uploads_semaphore
                            .clone()
                            .add_permits(diff as usize);
                    }
                    diff if diff < 0 => {
                        concurrent_uploads_semaphore
                            .clone()
                            .acquire_many_owned(diff.unsigned_abs() as u32)
                            .await
                            .expect("Concurrency semaphore closed")
                            .forget();
                    }
                    _ => (),
                };
            }
            eprintln!("New max concurrency limit: {new_max_concurrency}");

            // Update the large file threshold
            loop {
                {
                    if let Some(auth) = api_auth.read().await.deref() {
                        large_file_threshold = ((max_bandwidth / max_concurrency) * 600)
                            .max(auth.absolute_minimum_part_size)
                            .min(auth.recommended_part_size);
                        eprintln!(
                            "Files larger than {} bytes will use large file API",
                            format_bytes(large_file_threshold)
                        );
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        }

        // Grab the next item to upload
        let work = upload_queue_rx
            .recv()
            .await
            .expect("Unexpected closure of upload queue channel");

        // Get the metadata
        // If this fails for whatever reason, assume it's unchanged, since most failures
        // mean we can't read the file even if we try
        // We strictly need modified time and filesize, so failure to get metadata = skip
        let metadata = match tokio::fs::metadata(&work).await {
            Ok(meta) => meta,
            Err(err) => {
                eprintln!("Couldn't read metadata for {work:?}: {err:?}");
                continue;
            }
        };
        // Get the timestamp
        // This should never fail. If it does, there's probably something wrong with the OS...
        let current_timestamp = metadata
            .modified()
            .expect("Modified time unsupported!")
            .duration_since(UNIX_EPOCH)
            .map(|dur| dur.as_millis())
            .expect("System time is before Unix epoch???");

        // Check if it needs to be uploaded
        let (should_upload, existing_name_nonce) = {
            let f = known_files.lock().await;
            match f.get(&work) {
                Some((stored_timestamp, nonce)) => {
                    if current_timestamp != *stored_timestamp {
                        // Check there isn't an upload in-progress for this file
                        let mut current = currently_uploading.lock().await;
                        if current.contains(&work) {
                            (false, None)
                        } else {
                            current.push(work.clone());
                            (true, Some(*nonce))
                        }
                    } else {
                        (false, None)
                    }
                }
                None => {
                    // If it isn't stored yet, upload it unless we're already uploading it
                    let mut current = currently_uploading.lock().await;
                    if current.contains(&work) {
                        (false, None)
                    } else {
                        current.push(work.clone());
                        (true, None)
                    }
                }
            }
        };
        if !should_upload {
            continue;
        }

        eprintln!("Preparing to upload {work:?}");
        let permit = concurrent_uploads_semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("Unexpected AcquireError from upload-concurrency-semaphore");

        // If the file is "too big", use the large file API to upload in smaller chunks
        // If it's interrupted, this program can resume the progress it had made upon restarting
        if metadata.len() >= large_file_threshold {
            println!(
                "Preparing upload of {} (large file)",
                format_bytes(metadata.len())
            );
            let auth_clone = api_auth.clone();
            let known_files_clone = known_files.clone();
            let currently_uploading_clone = currently_uploading.clone();
            let key = encryption_key;
            let bandwidth_semaphore_clone = bandwidth_semaphore.clone();
            let required_nonces = get_nonces_required(metadata.len());
            let (start_nonce, name_nonce) = {
                let mut cfg = config.write().await;
                (cfg.get_next_nonce(required_nonces), cfg.get_next_nonce(1))
            };
            tokio::spawn(upload_large_file(
                auth_clone,
                work,
                large_file_threshold,
                existing_name_nonce,
                metadata,
                current_timestamp,
                known_files_clone,
                currently_uploading_clone,
                key,
                bandwidth_semaphore_clone,
                start_nonce,
                required_nonces,
                name_nonce,
                permit,
            ));
            continue;
        }

        println!("Preparing upload of {}", format_bytes(metadata.len()));

        // Get all returned auths before trying to get a new one
        while let Ok(auth) = auth_return_rx.try_recv() {
            upload_auths.push_back(auth);
        }

        // Grab an existing auth
        // If there are none, fetch a new one
        let auth = match upload_auths.pop_front() {
            Some(auth) => {
                eprintln!("Re-using old auth");
                auth
            }
            None => {
                eprintln!("Grabbing fresh UploadAuth");
                let upauth;
                retry_forever!(
                    [1, 3, 5, 10, 30, 60, 600, 1800, 3600],
                    result,
                    { backblaze_api::api::b2_get_upload_url(api_auth.clone()).await },
                    {
                        upauth = result;
                        break;
                    },
                    {
                        eprintln!("Unexpected error while getting upload auth: {result:?}");
                    }
                );
                upauth
            }
        };
        let return_tx = auth_return_tx.clone();
        let known_files_clone = known_files.clone();
        let currently_uploading_clone = currently_uploading.clone();
        let required_nonces = get_nonces_required(metadata.len());
        // Get 2 nonces
        // start_nonce is for the file body and uses a stream of blocks
        // name_nonce is for the file name as encrypts the entire name as 1 arbitrarily sized block
        let (start_nonce, name_nonce) = {
            let mut cfg = config.write().await;
            (cfg.get_next_nonce(required_nonces), cfg.get_next_nonce(1))
        };
        let key = encryption_key;
        let bandwidth_semaphore_clone = bandwidth_semaphore.clone();
        tokio::spawn(upload_file(
            work,
            existing_name_nonce,
            metadata,
            current_timestamp,
            known_files_clone,
            currently_uploading_clone,
            key,
            bandwidth_semaphore_clone,
            start_nonce,
            required_nonces,
            name_nonce,
            return_tx,
            permit,
            auth,
        ));
    }
}
