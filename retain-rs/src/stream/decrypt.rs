use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::io::ErrorKind;
use std::pin::Pin;
use std::task::{Context, Poll};
use bytes::BytesMut;
use chacha20poly1305::{Key, XChaCha20Poly1305};
use chacha20poly1305::aead::{Aead, NewAead};
use futures_core::{ready, Stream};
use pin_project::pin_project;
use backblaze_api::ReqwestError;
use crate::stream::{ENCRYPTED_BLOCK_SIZE, nonce_from_u128};

/// Wraps an inner stream, decrypting the contents of it
///
/// There are 4 stages to this, as seen in `DecReadState`
/// * Nonce: Read the nonce at the start of the stream
/// * Data: Read inner stream into chunks of ENCRYPTED_BLOCK_SIZE bytes, decrypt, return data. Repeat until inner returns None
/// * Pad: Determine pad, decrypt rest of stream, discarding the padding
/// * Done: Returns None forever, indicating end of stream

#[pin_project]
pub struct DecryptingStream<S: Stream>  {
    #[pin]
    inner: S,
    aead: XChaCha20Poly1305,
    state: DecReadState,
    nonce: u128, // Current nonce (counter)
    input_buffer: Vec<u8>, // Buffered data read from 'inner'
    output_buffer: Vec<u8>, // Buffered output
}

// Represents the state of the stream. It progresses through them in order
// Nonce: read the initial nonce to use
// Data: read and decrypt inner data
// Pad: decrypt last bit and remove padding
// Done: once output buffer has been read, return None
enum DecReadState {
    Nonce,
    Data,
    Pad,
    Done,
}

#[derive(Debug)]
struct DecryptError {
    message: &'static str,
}

impl Display for DecryptError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("Decrypt error: {}", self.message))
    }
}

impl Error for DecryptError {}


impl<S: Stream<Item = Result<bytes::Bytes, ReqwestError>>> DecryptingStream<S> {
    pub fn wrap(stream: S, key: &Key) -> Self {
        DecryptingStream {
            inner: stream,
            aead: XChaCha20Poly1305::new(key),
            state: DecReadState::Nonce,
            nonce: 0,
            // 3 * ENCRYPTED_BLOCK_SIZE, since we need to detect padding, which may take up 2 blocks
            input_buffer: Vec::with_capacity(ENCRYPTED_BLOCK_SIZE * 3),
            output_buffer: Vec::with_capacity(ENCRYPTED_BLOCK_SIZE),
        }
    }
}

impl<S: Stream<Item = Result<bytes::Bytes, ReqwestError>>> Stream for DecryptingStream<S> {
    type Item = Result<bytes::BytesMut, tokio::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        match this.state {
            DecReadState::Nonce => {
                let res: Option<Result<bytes::Bytes, ReqwestError>> = ready!(this.inner.poll_next(cx));
                match res {
                    Some(Ok(ref bytes)) => {
                        this.input_buffer.append(&mut bytes.to_vec());
                    }
                    Some(Err(err)) => {
                        return Poll::Ready(Some(Err(tokio::io::Error::new(
                            ErrorKind::Other,
                            err,
                        ))));
                    },
                    None => {
                        // Fail since we the inner stream is done before we got the nonce
                        return Poll::Ready(Some(Err(tokio::io::Error::new(
                            ErrorKind::Other,
                            DecryptError {
                                message: "Inner stream too short"
                            }
                            ))));
                    }
                }
                if this.input_buffer.len() >= 16 {
                    *this.nonce = u128::from_le_bytes(match this.input_buffer[0..16].try_into() {
                        Ok(bytes) => bytes,
                        Err(_err) => {
                            eprintln!("Failed to get nonce, stream too short");
                            return Poll::Ready(Some(Err(tokio::io::Error::new(
                                ErrorKind::Other,
                                DecryptError {
                                    message: "Failed to construct nonce"
                                }
                            ))));
                        }
                    });
                    *this.input_buffer = this.input_buffer.split_off(16);
                    *this.state = DecReadState::Data;
                }
                Poll::Ready(Some(Ok(BytesMut::new())))
            }
            DecReadState::Data => {
                let res: Option<Result<bytes::Bytes, ReqwestError>> = ready!(this.inner.poll_next(cx));
                match res {
                    Some(Ok(ref bytes)) => {
                        this.input_buffer.append(&mut bytes.to_vec());
                        this.output_buffer.clear();
                        while this.input_buffer.len() >= 3*ENCRYPTED_BLOCK_SIZE {
                            match this.aead.decrypt(&nonce_from_u128(*this.nonce), &this.input_buffer[0..ENCRYPTED_BLOCK_SIZE]) {
                                Ok(mut ciphertext) => {
                                    *this.nonce += 1;
                                    this.output_buffer.append(&mut ciphertext);
                                }
                                Err(err) => {
                                    panic!("Decryption failed: {err:?}");
                                }
                            }
                            *this.input_buffer = this.input_buffer.split_off(ENCRYPTED_BLOCK_SIZE);
                        }
                        Poll::Ready(Some(Ok(BytesMut::from(&this.output_buffer[..]))))
                    },
                    Some(Err(err)) => {
                        return Poll::Ready(Some(Err(tokio::io::Error::new(
                            ErrorKind::Other,
                            err,
                        ))));
                    },
                    None => {
                        *this.state = DecReadState::Pad;
                        Poll::Ready(Some(Ok(BytesMut::new())))
                    }
                }
            }
            DecReadState::Pad => {
                let buffered = this.input_buffer.len();
                // There should always be 1, 2 or 3 blocks left.
                // 1 data-pad hybrid (for tiny files that fit wholly in 1 block) OR
                // 1 data + 1 data-pad hybrid OR
                // 1 data + 1 data-pad hybrid + 1 full pad
                assert!(buffered == ENCRYPTED_BLOCK_SIZE || buffered == ENCRYPTED_BLOCK_SIZE * 2 || buffered == ENCRYPTED_BLOCK_SIZE * 3);
                this.output_buffer.clear();
                while this.input_buffer.len() >= ENCRYPTED_BLOCK_SIZE {
                    match this.aead.decrypt(&nonce_from_u128(*this.nonce), &this.input_buffer[0..ENCRYPTED_BLOCK_SIZE]) {
                        Ok(mut ciphertext) => {
                            *this.nonce += 1;
                            this.output_buffer.append(&mut ciphertext);
                        }
                        Err(err) => {
                            panic!("Decryption failed: {err:?}");
                        }
                    }
                    *this.input_buffer = this.input_buffer.split_off(ENCRYPTED_BLOCK_SIZE);
                }
                // Determine how much of the remaining buffer is padding
                let pad_amount = u32::from_le_bytes(match this.output_buffer[this.output_buffer.len()-4..].try_into() {
                    Ok(n) => n,
                    Err(_err) => {
                        eprintln!("Failed to determine padding amount");
                        return Poll::Ready(Some(Err(tokio::io::Error::new(
                            ErrorKind::Other,
                            DecryptError {
                                message: "Failed to determine padding amount"
                            }
                        ))));
                    }
                });
                // There should always be at least 4 bytes padding
                assert!(pad_amount >= 4);
                assert!(this.input_buffer.is_empty());
                *this.state = DecReadState::Done;
                Poll::Ready(Some(Ok(BytesMut::from(&this.output_buffer[..(this.output_buffer.len() - pad_amount as usize)]))))
            }
            DecReadState::Done => {
                Poll::Ready(None)
            }
        }
    }
}