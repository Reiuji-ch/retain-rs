use bytes::Bytes;
use futures_core::{ready, Stream};
use pin_project::pin_project;
use sha1::Digest;
use std::borrow::BorrowMut;
use std::pin::Pin;
use std::task::{Context, Poll};

#[pin_project]
pub struct HashingStream<S: Stream> {
    #[pin]
    inner: S,
    hasher: sha1::Sha1,
    done: bool,
}

impl<S: Stream> HashingStream<S> {
    pub fn wrap(stream: S) -> Self {
        HashingStream {
            inner: stream,
            hasher: sha1::Sha1::new(),
            done: false,
        }
    }
}

impl<S: Stream<Item = Result<bytes::BytesMut, tokio::io::Error>>> Stream for HashingStream<S> {
    type Item = Result<bytes::BytesMut, tokio::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        let res: Option<Result<bytes::BytesMut, tokio::io::Error>> =
            ready!(this.inner.poll_next(cx));

        match res {
            Some(Ok(ref bytes)) => {
                this.hasher.borrow_mut().update(bytes);
                Poll::Ready(res)
            }
            Some(Err(_)) => Poll::Ready(res),
            None => {
                match this.done {
                    false => {
                        // Finalize the hash, convert it into a hex digest and return the bytes
                        let digest = this.hasher.finalize_reset();
                        let hash_bytes = Bytes::copy_from_slice(digest.as_slice());
                        let hash_hex = format!("{:02X}", hash_bytes);
                        *this.done = true;
                        Poll::Ready(Some(Ok(bytes::BytesMut::from(hash_hex.as_bytes()))))
                    }
                    true => {
                        // If the inner stream finished and we already sent the hash, return None
                        Poll::Ready(None)
                    }
                }
            }
        }
    }
}
