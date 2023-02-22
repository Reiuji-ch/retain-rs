use crate::config::Config;
use crate::retry_limited;
use crate::server::KnownFiles;
use crate::stream::nonce_from_u128;
use backblaze_api::api::b2_hide_file;
use backblaze_api::Auth;
use base64::Engine;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, Semaphore};
use tokio::time::Instant;

/// Worker that hides files stored in B2 if they are no longer included by the rules
pub async fn hide_unused(
    config: Arc<RwLock<Config>>,
    auth: Arc<RwLock<Option<Auth>>>,
    known_files: KnownFiles,
) {
    let mut rules = { config.write().await.get_rules() };

    // last_recheck and recheck_interval are used to periodically poll for changes to the rules
    let mut last_recheck = Instant::now();
    let recheck_interval = Duration::from_secs(5);

    let aead = { XChaCha20Poly1305::new(&config.write().await.get_encryption_key()) };

    // Semaphore for limiting max outstanding hide calls
    let concurrent_calls_semaphore = Arc::new(Semaphore::new(8));

    let mut last_path = PathBuf::from_str("").unwrap();
    loop {
        // Sleep a bit to avoid hammering the filesystem
        tokio::time::sleep(Duration::from_millis(2)).await;
        // Update our rules if it's been too long since we last did it
        if last_recheck.elapsed() > recheck_interval {
            last_recheck = Instant::now();
            let should_refetch = { config.read().await.get_rules_version() > rules.version };
            if should_refetch {
                eprintln!("Reloading rules");
                rules = config.write().await.get_rules();
            }
        }
        let file = {
            let mut lock = known_files.lock().await;
            let (path, &(modified, nonce)) = match lock.next(&last_path) {
                Some(data) => data,
                None => {
                    drop(lock);
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    continue;
                }
            };
            last_path = path.clone();
            let mut should_hide = false;

            if path.exists() {
                if !rules.should_upload(&path) {
                    // File exists but is no longer covered by rules, hide it in B2
                    should_hide = true;
                }
            } else {
                // File doesn't exists on disk anymore, hide it in B2
                should_hide = true;
            }
            match should_hide {
                true => {
                    let _ = lock.delete(&path);
                    Some((path, modified, nonce))
                }
                false => None,
            }
        };
        match file {
            Some(file) => {
                let encrypted_filename = match aead.encrypt(
                    &nonce_from_u128(file.2),
                    file.0.to_string_lossy().replace("\\", "/").as_bytes(),
                ) {
                    Ok(mut ciphertext) => {
                        let mut name = file.2.to_le_bytes().to_vec();
                        name.append(&mut ciphertext);
                        base64::engine::general_purpose::URL_SAFE.encode(name)
                    }
                    Err(err) => {
                        panic!("Encryption failed: {err:?}");
                    }
                };
                eprintln!("Hiding {:?} ({})", file.0, encrypted_filename);
                let permit = concurrent_calls_semaphore
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("Hide semaphore closed");
                let auth = auth.clone();
                let known_files = known_files.clone();
                tokio::task::spawn(async move {
                    retry_limited!(
                        [1, 3, 5, 10, 30, 60, 600],
                        result,
                        { b2_hide_file(auth.clone(), encrypted_filename.clone()).await },
                        {
                            // Ensure we drop the permit after we're done
                            std::mem::drop(permit);
                            return;
                        },
                        {
                            eprintln!("Error while trying to hide file: {result:?}");
                        }
                    );
                    // If we ran out of retries, re-add the file to the list of known files
                    // It will eventually be checked and re-tried once we loop back around to it
                    let mut f = known_files.lock().await;
                    match f.has_key(&file.0) {
                        true => {
                            // This scenario should be impossible to hit
                            // The file can _technically_ be re-added to known files if it was re-uploaded while the hiding was failing
                            // However, since it's re-uploaded it should receive a new encrypted name and thus match the binary search
                            panic!("File exists in known files when it shouldn't")
                        }
                        false => {
                            f.insert(&file.0, (file.1, file.2)).unwrap();
                        }
                    }
                });
            }
            None => (),
        };
    }
}
