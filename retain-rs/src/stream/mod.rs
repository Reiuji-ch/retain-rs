use chacha20poly1305::XNonce;

pub mod decrypt;
pub mod encrypt;
pub mod hash;
pub mod sized;
pub mod throttle;

// Size of each block in the stream
pub const BLOCK_SIZE: usize = 8192;
// Each block gets 16 bytes for the authentication header
pub const ENCRYPTED_BLOCK_SIZE: usize = BLOCK_SIZE + 16;

/// Create a 24-byte nonce from a 16-byte number by left-padding 0's
pub fn nonce_from_u128(number: u128) -> XNonce {
    let mut nonce_arr = vec![0u8; 8];
    nonce_arr.append(&mut number.to_le_bytes().to_vec());
    XNonce::from_slice(nonce_arr.as_slice()).to_owned()
}

// Returns exactly how many nonces are required to encrypt a stream of the given size
pub fn get_nonces_required(length: u64) -> u128 {
    ((length + 3) / (BLOCK_SIZE as u64) + 1) as u128
}

// Compute how many bytes a file will be after it is encrypted
pub fn get_encrypted_size(unencrypted_size: u64) -> u64 {
    let nonces_used = get_nonces_required(unencrypted_size) as u64;
    // Overhead: 16 byte initial nonce + 16 byte MAC per BLOCK_SIZE bytes
    16 + (16 + BLOCK_SIZE as u64) * nonces_used
}
