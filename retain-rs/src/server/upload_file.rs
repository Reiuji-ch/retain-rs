use crate::server::KnownFiles;
use crate::stream::encrypt::EncryptingStream;
use crate::stream::hash::HashingStream;
use crate::stream::throttle::ThrottlingStream;
use crate::stream::{get_encrypted_size, nonce_from_u128};
use backblaze_api::api::{b2_upload_file, FileInfo, UploadAuth};
use base64::Engine;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305};
use std::fs::Metadata;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::File;
use tokio::sync::mpsc::Sender;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio_util::codec::{BytesCodec, FramedRead};

pub async fn upload_file(
    path: PathBuf,
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
    auth_return_tx: Sender<UploadAuth>,
    permit: OwnedSemaphorePermit,
    auth: UploadAuth,
) {
    // Open file and wrap it in the various stream processors
    let file = match File::open(&path).await {
        Ok(file) => file,
        Err(_err) => {
            eprintln!("Failed to open file {}", path.to_string_lossy());
            currently_uploading
                .lock()
                .await
                .retain(|elem| elem != &path);
            return;
        }
    };
    let stream = FramedRead::new(file, BytesCodec::new());
    let stream = EncryptingStream::wrap(stream, &key, start_nonce, allocated_nonces, false);
    let stream = HashingStream::wrap(stream);
    let stream = ThrottlingStream::wrap(stream, bandwidth_semaphore);

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

    let result = b2_upload_file(
        &auth,
        stream,
        FileInfo {
            file_name: encrypted_filename.clone(),
            modified: current_timestamp,
            size: get_encrypted_size(metadata.len()) + 40, // +40 for hex_digits_at_end
        },
    )
    .await;
    // We only return the auth if the upload succeeded
    // We only update 'known_files' on success
    // We always update 'currently_uploading'
    match result {
        Ok(_file) => {
            let mut f = known_files.lock().await;
            let _ = f.delete(&path);
            f.insert(&path, (current_timestamp, name_nonce)).unwrap();

            eprintln!("Successfully uploaded: {_file:?}");
            auth_return_tx.send(auth).await.unwrap();
        }
        Err(_err) => {
            eprintln!("Upload failed: {_err:?}");
        }
    }

    currently_uploading
        .lock()
        .await
        .retain(|elem| elem != &path);
    // For sanity reasons, ensure we drop it _after_ we're done
    std::mem::drop(permit);
}
