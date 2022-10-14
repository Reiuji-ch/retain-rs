use std::io::Cursor;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::UNIX_EPOCH;
use chacha20poly1305::Key;
use tokio::fs::File;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, RwLock};
use tokio_util::codec::{BytesCodec, FramedRead};
use futures_util::stream::StreamExt;
use backblaze_api::api::{b2_upload_part, PartInfo};
use backblaze_api::Auth;
use crate::retry_forever;
use crate::server::KnownFiles;
use crate::server::upload_large_file::{cancel_large_file, finish_large_file, get_upload_part_auth};
use crate::stream::encrypt::EncryptingStream;
use crate::stream::hash::HashingStream;
use crate::stream::throttle::ThrottlingStream;

// Resumes a previously started large file
// This will resume by processing the file again, skipping the first 'offset_bytes' of the stream
pub async fn resume_large_file(
    auth: Arc<RwLock<Option<Auth>>>,
    path: PathBuf,
    file_id: String,
    name_nonce: u128,
    part_size: u64,
    current_timestamp: u128,
    known_files: KnownFiles,
    currently_uploading: Arc<Mutex<Vec<PathBuf>>>,
    key: Key,
    bandwidth_semaphore: Arc<Semaphore>,
    start_nonce: u128,
    allocated_nonces: u128,
    permit: OwnedSemaphorePermit,
    mut part_hashes: Vec<String>,
    offset_bytes: u64,
    next_part: u16,
) {
    // * Call b2_get_upload_part_url (fileid) -> upload url, auth token
    let upauth = get_upload_part_auth(auth.clone(), file_id.clone()).await;

    // * Call b2_upload_part (Call until done. Call b2_get_upload_part_url if needed)
    // Open file and wrap it in the various stream processors
    let file = match File::open(&path).await {
        Ok(file) => file,
        Err(_err) => {
            eprintln!("Failed to open (large) file {}", path.to_string_lossy());
            currently_uploading.lock().await.retain(|elem| elem != &path);
            return;
        }
    };
    let stream = FramedRead::new(file, BytesCodec::new());
    let mut stream = EncryptingStream::wrap(stream, &key, start_nonce, allocated_nonces);

    let mut buffer = Vec::with_capacity(part_size as usize);
    let mut part_number = next_part;
    let mut discarded_bytes = 0;
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
                    currently_uploading.lock().await.retain(|elem| elem != &path);
                    return;
                }
            }
            if discarded_bytes < offset_bytes {
                let amount_to_drain = ((offset_bytes-discarded_bytes) as usize).min(buffer.len());
                let drain = buffer.drain(..amount_to_drain);
                let discarded = drain.len() as u64;
                let _: Vec<_> = drain.collect();
                discarded_bytes += discarded;
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
        // That is, we can just reset _this_ part of the stream
        retry_forever!([1, 3, 5, 10, 30, 60, 600, 1800, 3600], result, {
            // Check the file's modified time has changed. Cancel file if it has.
            match std::fs::metadata(&path) {
                Ok(meta) => {
                    let timestamp = meta.modified()
                        .expect("Modified time unsupported!")
                        .duration_since(UNIX_EPOCH)
                        .map(|dur| dur.as_millis())
                        .expect("System time is before Unix epoch???");
                    if timestamp != current_timestamp {
                        eprintln!("Large file {path:?} changed during upload between part {part_number} and the previous part");
                        cancel_large_file(auth.clone(), file_id.clone()).await;
                        currently_uploading.lock().await.retain(|elem| elem != &path);
                        return;
                    }
                }
                Err(err) => {
                    eprintln!("Failed to read file metadata for {path:?} during upload of part {part_number}: {err:?}");
                    cancel_large_file(auth.clone(), file_id.clone()).await;
                    currently_uploading.lock().await.retain(|elem| elem != &path);
                    return;
                }
            }
            let part_buffer = buffer[..this_part_size as usize].to_vec();
            let upload_stream = FramedRead::new(Cursor::new(part_buffer), BytesCodec::new());
            let upload_stream = HashingStream::wrap(upload_stream);
            let upload_stream = ThrottlingStream::wrap(upload_stream, bandwidth_semaphore.clone());
            b2_upload_part(&upauth, upload_stream, PartInfo {
                part_number,
                part_size: this_part_size + 40 // +40 for hex_digits_at_end
            }).await
        }, {
            part_hashes.push(result.content_sha1);
            break;
        }, {
            eprintln!("Unexpected error while uploading part: {result:?}");
        });
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
    finish_large_file(auth.clone(),
                      file_id.clone(),
                      path.clone(),
                      name_nonce,
                      part_hashes,
                      current_timestamp,
                      currently_uploading,
                      known_files).await;

    // Ensure we drop the permit _after_ we're done
    std::mem::drop(permit);
}

