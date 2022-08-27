use std::pin::Pin;
use std::task::{Context, Poll};
use bytes::BytesMut;
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use chacha20poly1305::aead::{Aead, NewAead};
use futures_core::{ready, Stream};
use pin_project::pin_project;
/// Wraps an inner stream, encrypting the contents of it
///
/// There are 4 stages to this, as seen in `EncReadState`
/// * Nonce: Write the initial nonce as the first bytes of the stream. Remaining nonces can be computed from initial nonce and BLOCK_SIZE
/// * Data: Read inner stream into a BLOCK_SIZE buffer, encrypt, return data. Repeat until inner returns None
/// * Pad: Pads the stream s.t. it's a multiple of BLOCK_SIZE
/// * Done: Once pad is done we go to this state. This state simply returns None.

// Size of each block in the stream
pub const BLOCK_SIZE: usize = 8192;

#[pin_project]
pub struct EncryptingStream<S: Stream>  {
    #[pin]
    inner: S,
    aead: XChaCha20Poly1305,
    state: EncReadState,
    nonce: u128, // Current nonce (counter)
    nonce_final: u128, // The last nonce to use. It _must_ be used and _must_ be the last nonce
    input_buffer: Vec<u8>, // Buffered data read from 'inner', until we have a full block of data
    output_buffer: Vec<u8>, // Buffered output, in case our supplied buffer isn't large enough
}

// Represents the state of the stream. It progresses through them in order
// Nonce: write the initial nonce to the stream
// Data: read and encrypt inner data
// Pad: pad (and encrypt) to the goal length
// Done: once output buffer has been read, return 0
enum EncReadState {
    Nonce,
    Data,
    Pad,
    Done,
}


impl<S: Stream> EncryptingStream<S> {
    pub fn wrap(stream: S, key: &Key, start_nonce: u128, allocated_nonce: u128) -> Self {
        EncryptingStream {
            inner: stream,
            aead: XChaCha20Poly1305::new(key),
            state: EncReadState::Nonce,
            nonce: start_nonce,
            nonce_final: start_nonce + allocated_nonce,
            input_buffer: Vec::with_capacity(BLOCK_SIZE),
            output_buffer: Vec::with_capacity(BLOCK_SIZE),
        }
    }
}

impl<S: Stream<Item = Result<bytes::BytesMut, tokio::io::Error>>> Stream for EncryptingStream<S> {
    type Item = Result<bytes::BytesMut, tokio::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        match this.state {
            EncReadState::Nonce => {
                *this.state = EncReadState::Data;
                Poll::Ready(Some(Ok(BytesMut::from(this.nonce.to_le_bytes().as_ref()))))
            }
            EncReadState::Data => {
                let res: Option<Result<bytes::BytesMut, tokio::io::Error>> = ready!(this.inner.poll_next(cx));
                match res {
                    Some(Ok(ref bytes)) => {
                        this.input_buffer.append(&mut bytes.to_vec());
                        this.output_buffer.clear();
                        while this.input_buffer.len() >= BLOCK_SIZE {
                            match this.aead.encrypt(&nonce_from_u128(*this.nonce), &this.input_buffer[0..BLOCK_SIZE]) {
                                Ok(mut ciphertext) => {
                                    *this.nonce += 1;
                                    this.output_buffer.append(&mut ciphertext);
                                }
                                Err(err) => {
                                    panic!("Encryption failed: {err:?}");
                                }
                            }
                            *this.input_buffer = this.input_buffer.split_off(BLOCK_SIZE);
                        }
                        Poll::Ready(Some(Ok(BytesMut::from(&this.output_buffer[..]))))
                    },
                    Some(Err(_)) => {
                        Poll::Ready(res)
                    },
                    None => {
                        *this.state = EncReadState::Pad;
                        Poll::Ready(Some(Ok(BytesMut::new())))
                    }
                }
            }
            EncReadState::Pad => {
                let buffered = this.input_buffer.len();
                assert!((BLOCK_SIZE - buffered) < (u32::MAX as usize));
                let mut needed_for_block: u32 = (BLOCK_SIZE - buffered) as u32;
                if needed_for_block < 4 {
                    needed_for_block += BLOCK_SIZE as u32;
                }
                this.input_buffer.append(&mut vec![0u8; (needed_for_block - 4) as usize]);
                this.input_buffer.append(&mut needed_for_block.to_le_bytes().to_vec());
                this.output_buffer.clear();
                while this.input_buffer.len() >= BLOCK_SIZE {
                    match this.aead.encrypt(&nonce_from_u128(*this.nonce), &this.input_buffer[0..BLOCK_SIZE]) {
                        Ok(mut ciphertext) => {
                            *this.nonce += 1;
                            this.output_buffer.append(&mut ciphertext);
                        }
                        Err(err) => {
                            panic!("Encryption failed: {err:?}");
                        }
                    }
                    *this.input_buffer = this.input_buffer.split_off(BLOCK_SIZE);
                }
                assert!(this.input_buffer.is_empty());
                *this.state = EncReadState::Done;
                Poll::Ready(Some(Ok(BytesMut::from(&this.output_buffer[..]))))
            }
            EncReadState::Done => {
                assert_eq!(*this.nonce, *this.nonce_final);
                Poll::Ready(None)
            }
        }
    }
}

/// Create a 24-byte nonce from a 16-byte number by left-padding 0's
pub fn nonce_from_u128(number: u128) -> XNonce {
    let mut nonce_arr = vec![0u8; 8];
    nonce_arr.append(&mut number.to_le_bytes().to_vec());
    XNonce::from_slice(nonce_arr.as_slice()).to_owned()
}

// Returns exactly how many nonces are required to encrypt a stream of the given size
pub fn get_nonces_required(length: u64) -> u128 {
    ((length+3)/(BLOCK_SIZE as u64)+1) as u128
}

// Compute how many bytes a file will be after it is encrypted
pub fn get_encrypted_size(unencrypted_size: u64) -> u64 {
    let nonces_used = get_nonces_required(unencrypted_size) as u64;
    // Overhead: 16 byte initial nonce + 16 byte MAC per BLOCK_SIZE bytes
    16 + (16+BLOCK_SIZE as u64) * nonces_used
}