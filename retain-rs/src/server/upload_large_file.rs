use crate::server::KnownFiles;
use crate::stream::encrypt::EncryptingStream;
use crate::stream::hash::HashingStream;
use crate::stream::nonce_from_u128;
use crate::stream::throttle::ThrottlingStream;
use crate::{retry_forever, retry_limited};
use backblaze_api::api::{
    b2_cancel_large_file, b2_finish_large_file, b2_start_large_file, b2_upload_part, FileInfo,
    PartInfo, UploadPartAuth,
};
use backblaze_api::{ApiError, Auth};
use base64::Engine;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305};
use futures_util::stream::StreamExt;
use std::fs::Metadata;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};
use tokio::fs::File;
use tokio::sync::{Mutex, OwnedSemaphorePermit, RwLock, Semaphore};
use tokio_util::codec::{BytesCodec, FramedRead};

pub async fn upload_large_file(
    auth: Arc<RwLock<Option<Auth>>>,
    path: PathBuf,
    part_size: u64,
    existing_name_nonce: Option<u128>,
    metadata: Metadata,
    current_timestamp: u128,
    known_files: KnownFiles,
    currently_uploading: Arc<Mutex<Vec<PathBuf>>>,
    key: Key,
    bandwidth_semaphore: Arc<Semaphore>,
    start_nonce: u128,
    allocated_nonces: u128,
    name_nonce: u128,
    permit: OwnedSemaphorePermit,
) {
    // Encrypt the filename
    let aead = XChaCha20Poly1305::new(&key);
    let name_nonce = match existing_name_nonce {
        // We already know the nonce (because a previous version of the file already exists)
        // Re-encrypting the path with the same nonce will give us the same encrypted name, which
        // will let us update/overwrite the old file
        Some(n) => n,
        // The file does not already exist -- Use the new nonce we allocated
        None => name_nonce,
    };
    let encrypted_filename = match aead.encrypt(
        &nonce_from_u128(name_nonce),
        path.to_string_lossy().replace("\\", "/").as_bytes(),
    ) {
        Ok(mut ciphertext) => {
            let mut name = name_nonce.to_le_bytes().to_vec();
            name.append(&mut ciphertext);
            base64::engine::general_purpose::URL_SAFE.encode(name)
        }
        Err(err) => {
            panic!("Encryption failed: {err:?}");
        }
    };

    // * Call b2_start_large_file (bucketid, filename, contenttype, fileinfo) -> fileid
    let file_id = match b2_start_large_file(
        auth.clone(),
        FileInfo {
            file_name: encrypted_filename.clone(),
            modified: current_timestamp,
            size: metadata.len(),
        },
        start_nonce,
    )
    .await
    {
        Ok(file) => file.file_id,
        Err(err) => {
            eprintln!("Failed to start large file: {err:?}");
            currently_uploading
                .lock()
                .await
                .retain(|elem| elem != &path);
            return;
        }
    };

    // * Call b2_get_upload_part_url (fileid) -> upload url, auth token
    let mut upauth = get_upload_part_auth(auth.clone(), file_id.clone()).await;

    // * Call b2_upload_part (Call until done. Call b2_get_upload_part_url if needed)
    // Open file and wrap it in the various stream processors
    let file = match File::open(&path).await {
        Ok(file) => file,
        Err(_err) => {
            eprintln!("Failed to open (large) file {}", path.to_string_lossy());
            currently_uploading
                .lock()
                .await
                .retain(|elem| elem != &path);
            return;
        }
    };
    let stream = FramedRead::new(file, BytesCodec::new());
    let mut stream = EncryptingStream::wrap(stream, &key, start_nonce, allocated_nonces);

    let mut part_hashes = Vec::with_capacity((metadata.len() / part_size) as usize);
    let mut buffer = Vec::with_capacity(part_size as usize);
    let mut part_number = 1;
    loop {
        // Read bytes from the stream until we have enough for a part
        while let Some(bytes) = stream.next().await {
            match bytes {
                Ok(bytes) => {
                    buffer.append(&mut bytes.to_vec());
                }
                Err(err) => {
                    // Fatal error, something went wrong _somewhere_ in the stream
                    eprintln!("Error getting bytes from stream: {err:?}");
                    cancel_large_file(auth.clone(), file_id.clone()).await;
                    currently_uploading
                        .lock()
                        .await
                        .retain(|elem| elem != &path);
                    return;
                }
            }
            // Read at least one full part (+1 byte)
            if buffer.len() > part_size as usize {
                break;
            }
        }
        // Determine the actual part size. This will typically be smaller than part_size for the last part
        let this_part_size = part_size.min(buffer.len() as u64);
        // Upload part
        // Note that we can retry this, since we buffer the whole part in memory
        // This let's us retry without rewinding the whole stream
        let mut successfully_uploaded;
        retry_limited!(
            [1, 3, 5, 10, 30, 60, 600, 1800, 3600],
            result,
            {
                // Check the file's modified time has changed. Cancel file if it has.
                match std::fs::metadata(&path) {
                    Ok(meta) => {
                        let timestamp = meta
                            .modified()
                            .expect("Modified time unsupported!")
                            .duration_since(UNIX_EPOCH)
                            .map(|dur| dur.as_millis())
                            .expect("System time is before Unix epoch???");
                        if timestamp != current_timestamp {
                            eprintln!("Large file {path:?} changed during upload between part {part_number} and the previous part");
                            cancel_large_file(auth.clone(), file_id.clone()).await;
                            currently_uploading
                                .lock()
                                .await
                                .retain(|elem| elem != &path);
                            return;
                        }
                    }
                    Err(err) => {
                        eprintln!("Failed to read file metadata for {path:?} during upload of part {part_number}: {err:?}");
                        cancel_large_file(auth.clone(), file_id.clone()).await;
                        currently_uploading
                            .lock()
                            .await
                            .retain(|elem| elem != &path);
                        return;
                    }
                }
                let part_buffer = buffer[..this_part_size as usize].to_vec();
                let upload_stream = FramedRead::new(Cursor::new(part_buffer), BytesCodec::new());
                let upload_stream = HashingStream::wrap(upload_stream);
                let upload_stream =
                    ThrottlingStream::wrap(upload_stream, bandwidth_semaphore.clone());
                b2_upload_part(
                    &upauth,
                    upload_stream,
                    PartInfo {
                        part_number,
                        part_size: this_part_size + 40, // +40 for hex_digits_at_end
                    },
                )
                .await
            },
            {
                part_hashes.push(result.content_sha1);
                successfully_uploaded = true;
                break;
            },
            {
                eprintln!("Error while uploading part: {result:?}");
                if let ApiError::Unauthorized = result {
                    upauth = get_upload_part_auth(auth.clone(), file_id.clone()).await;
                }
                successfully_uploaded = false;
            }
        );
        if !successfully_uploaded {
            eprintln!("Ran out of retries trying to upload part {part_number} of {path:?}");
            cancel_large_file(auth.clone(), file_id.clone()).await;
            currently_uploading
                .lock()
                .await
                .retain(|elem| elem != &path);
            return;
        }

        // The buffer normally holds _at least_ part_size+1 bytes
        // If it holds part_size or less, it means the stream is done
        if buffer.len() <= part_size as usize {
            break;
        }
        // Remove the data we just uploaded from the buffer
        let _: Vec<_> = buffer.drain(..this_part_size as usize).collect();
        // Next part
        part_number += 1;
    }

    // * Call b2_finish_large_file
    finish_large_file(
        auth.clone(),
        file_id.clone(),
        path.clone(),
        name_nonce,
        part_hashes,
        current_timestamp,
        currently_uploading,
        known_files,
    )
    .await;
    // Ensure we drop the permit _after_ we're done
    std::mem::drop(permit);
}

// Get an upload part auth, backing off with increasing interval on error
pub async fn get_upload_part_auth(
    auth: Arc<RwLock<Option<Auth>>>,
    file_id: String,
) -> UploadPartAuth {
    let upauth;
    retry_forever!(
        [1, 3, 5, 10, 30, 60, 600, 1800, 3600],
        result,
        { backblaze_api::api::b2_get_upload_part_url(auth.clone(), file_id.clone()).await },
        {
            upauth = result;
            break;
        },
        {
            eprintln!("Error while getting part upload auth: {result:?}");
        }
    );

    upauth
}

// Attempts to finish a large file until the call succeeds or we get an error response
pub async fn finish_large_file(
    auth: Arc<RwLock<Option<Auth>>>,
    file_id: String,
    path: PathBuf,
    name_nonce: u128,
    part_hashes: Vec<String>,
    current_timestamp: u128,
    currently_uploading: Arc<Mutex<Vec<PathBuf>>>,
    known_files: KnownFiles,
) {
    retry_limited!(
        [1, 3, 5, 10, 30, 60, 600, 1800, 3600],
        result,
        { b2_finish_large_file(auth.clone(), file_id.clone(), part_hashes.clone()).await },
        {
            let mut f = known_files.lock().await;
            let _ = f.delete(&path);
            let _ = f.insert(&path, (current_timestamp, name_nonce));

            eprintln!("Successfully uploaded large file: {path:?}");
            currently_uploading
                .lock()
                .await
                .retain(|elem| elem != &path);
            return;
        },
        {
            eprintln!("Error while finishing large file: {result:?}");
        }
    );
    eprintln!("Exceeded retry limit while finishing large file: {path:?}");
    cancel_large_file(auth.clone(), file_id.clone()).await;
    currently_uploading
        .lock()
        .await
        .retain(|elem| elem != &path);
}

// Attempts to cancel a large file until the call succeeds or we get an error response
pub async fn cancel_large_file(auth: Arc<RwLock<Option<Auth>>>, file_id: String) {
    retry_forever!(
        [1, 3, 5, 10, 30, 60, 600, 1800, 3600],
        result,
        { b2_cancel_large_file(auth.clone(), file_id.clone()).await },
        {
            return;
        },
        {
            eprintln!("Failed to cancel large file: {result:?}");
        }
    );
}
