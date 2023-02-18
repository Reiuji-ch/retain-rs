use futures_core::{ready, Stream};
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};

/// SizedStream will return at most 'limit' bytes
#[pin_project]
pub struct SizedStream<S: Stream> {
    #[pin]
    inner: S,
    limit: usize,
    read: usize,
}

impl<S: Stream> SizedStream<S> {
    pub fn wrap(stream: S, limit: usize) -> Self {
        SizedStream {
            inner: stream,
            limit,
            read: 0,
        }
    }
}

impl<S: Stream<Item = Result<bytes::BytesMut, tokio::io::Error>>> Stream for SizedStream<S> {
    type Item = Result<bytes::BytesMut, tokio::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        let mut res: Option<Result<bytes::BytesMut, tokio::io::Error>> =
            ready!(this.inner.poll_next(cx));

        match res {
            Some(Ok(ref mut bytes)) => {
                // Avoid reading more than the limit
                if this.read == this.limit {
                    Poll::Ready(None)
                } else if bytes.len() + *this.read > *this.limit {
                    let _ = bytes.split_off(*this.limit - *this.read);
                    *this.read = *this.limit;
                    Poll::Ready(res)
                } else {
                    *this.read += bytes.len();
                    Poll::Ready(res)
                }
            }
            Some(Err(_)) => Poll::Ready(res),
            None => Poll::Ready(None),
        }
    }
}
