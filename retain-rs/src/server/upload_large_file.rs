use crate::server::KnownFiles;
use crate::stream::encrypt::EncryptingStream;
use crate::stream::hash::HashingStream;
use crate::stream::sized::SizedStream;
use crate::stream::throttle::ThrottlingStream;
use crate::stream::{get_encrypted_size, get_nonces_required, nonce_from_u128, BLOCK_SIZE};
use crate::{retry_forever, retry_limited};
use backblaze_api::api::{
    b2_cancel_large_file, b2_finish_large_file, b2_start_large_file, b2_upload_part, FileInfo,
    PartInfo, UploadPartAuth,
};
use backblaze_api::{ApiError, Auth};
use base64::Engine;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305};
use std::fs::Metadata;
use std::io::SeekFrom;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};
use tokio::fs::File;
use tokio::io::AsyncSeekExt;
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
    mut allocated_nonces: u128,
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
    let total_size = metadata.len();
    let file_id = match b2_start_large_file(
        auth.clone(),
        FileInfo {
            file_name: encrypted_filename.clone(),
            modified: current_timestamp,
            size: total_size,
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
    // Align part size to BLOCK_SIZE for predictable encryption
    // Add an extra block to ensure we don't round down below absolute_minimum_part_size
    let part_size = ((part_size / BLOCK_SIZE as u64) + 1) * BLOCK_SIZE as u64;
    let parts_required = match total_size % part_size {
        0 => total_size / part_size,
        _ => (total_size / part_size) + 1,
    };
    let mut part_hashes = Vec::with_capacity(parts_required as usize);
    let mut continue_with_nonce = start_nonce;
    for part_number in 1..(parts_required + 1) {
        // Determine the actual part size. This will typically be smaller than part_size for the last part
        let this_part_size = (total_size - (part_number - 1) * part_size).min(part_size);
        // Upload part
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

                // Open file and wrap it in the various stream processors
                let mut file = match File::open(&path).await {
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

                // Determine size of uploaded part
                // Only count the 16 bytes used for initial nonce on the first part
                // get_encrypted_size includes a padding block, only count it for the LAST part
                // Note that the padding block is an ENCRYPTED block, and thus has +16 bytes MAC
                let actual_part_size = if part_number == 1 {
                    get_encrypted_size(this_part_size) - (BLOCK_SIZE + 16) as u64
                } else if part_number == parts_required {
                    get_encrypted_size(this_part_size) - 16
                } else {
                    get_encrypted_size(this_part_size) - 16 - (BLOCK_SIZE + 16) as u64
                };

                // Reset the stream. Seek to where the part starts
                // This ensures we read from the correct part
                match file
                    .seek(SeekFrom::Start((part_number - 1) * part_size))
                    .await
                {
                    Ok(_) => {}
                    Err(err) => {
                        eprintln!("Error seeking in (large) file {path:?} {err:?}");
                        cancel_large_file(auth.clone(), file_id.clone()).await;
                        currently_uploading
                            .lock()
                            .await
                            .retain(|elem| elem != &path);
                        return;
                    }
                }
                let file_stream = FramedRead::new(file, BytesCodec::new());
                let encrypt_stream = EncryptingStream::wrap(
                    file_stream,
                    &key,
                    continue_with_nonce,
                    allocated_nonces,
                    part_number != 1,
                );
                let limit_stream = SizedStream::wrap(encrypt_stream, actual_part_size as usize);
                let hash_stream = HashingStream::wrap(limit_stream);
                let throttle_stream =
                    ThrottlingStream::wrap(hash_stream, bandwidth_semaphore.clone());

                b2_upload_part(
                    &upauth,
                    throttle_stream,
                    PartInfo {
                        part_number: part_number as u16,
                        part_size: actual_part_size + 40, // +40 for hex_digits_at_end
                    },
                )
                .await
            },
            {
                part_hashes.push(result.content_sha1);
                // Compute required nonces for this part
                // We have already have allocated this many, so we don't update the counter
                // but if we need to retry, we need to track from which nonce to resume
                // Note we subtract one, since get_nonces_required returns the number with padding
                // Since we only pad the last part, the nonce for the pad block is not used here
                continue_with_nonce += get_nonces_required(this_part_size) - 1;
                allocated_nonces -= get_nonces_required(this_part_size) - 1;
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
