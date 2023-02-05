use bytes::BytesMut;
use futures_core::{ready, Stream};
use pin_project::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::{AcquireError, OwnedSemaphorePermit, Semaphore};

// How big each chunk will be
// Think of it as how many bytes we send at a time
// Using a high chunk size with a low bandwidth will lead to a very long delay between packets
const CHUNK_SIZE: usize = 1024;

#[pin_project]
pub struct ThrottlingStream<S: Stream> {
    #[pin]
    inner: S,
    buffer: Vec<u8>,
    done: bool,
    semaphore: Arc<Semaphore>,
    #[pin]
    bandwidth_future:
        Pin<Box<dyn Future<Output = Result<OwnedSemaphorePermit, AcquireError>> + Send + Sync>>,
    chunk: Vec<u8>,
}

impl<S: Stream> ThrottlingStream<S> {
    pub fn wrap(stream: S, semaphore: Arc<Semaphore>) -> Self {
        ThrottlingStream {
            inner: stream,
            buffer: Vec::with_capacity(8192),
            done: false,
            semaphore: semaphore.clone(),
            bandwidth_future: Box::pin(semaphore.acquire_many_owned(CHUNK_SIZE as u32)),
            chunk: Vec::new(),
        }
    }
}

impl<S: Stream<Item = Result<bytes::BytesMut, tokio::io::Error>>> Stream for ThrottlingStream<S> {
    type Item = Result<bytes::BytesMut, tokio::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        if !this.chunk.is_empty() {
            return match this.bandwidth_future.poll(cx) {
                Poll::Ready(res) => {
                    res.expect("Bandwidth semaphore closed").forget();
                    let bytes = bytes::BytesMut::from(this.chunk.as_slice());
                    this.chunk.clear();
                    Poll::Ready(Some(Ok(bytes)))
                }
                Poll::Pending => Poll::Pending,
            };
        }

        if this.buffer.len() >= CHUNK_SIZE {
            let chunk: Vec<u8> = this.buffer.drain(..CHUNK_SIZE).collect();
            *this.chunk = chunk;
            *this.bandwidth_future =
                Box::pin(this.semaphore.clone().acquire_many_owned(CHUNK_SIZE as u32));
            return Poll::Ready(Some(Ok(bytes::BytesMut::new())));
        }
        let res: Option<Result<bytes::BytesMut, tokio::io::Error>> =
            ready!(this.inner.poll_next(cx));

        match res {
            Some(Ok(bytes)) => {
                this.buffer.append(&mut bytes.to_vec());
                if this.buffer.len() >= CHUNK_SIZE {
                    let chunk: Vec<u8> = this.buffer.drain(..CHUNK_SIZE).collect();
                    *this.chunk = chunk;
                    *this.bandwidth_future =
                        Box::pin(this.semaphore.clone().acquire_many_owned(CHUNK_SIZE as u32));
                    Poll::Ready(Some(Ok(bytes::BytesMut::new())))
                } else {
                    Poll::Ready(Some(Ok(BytesMut::new())))
                }
            }
            Some(Err(_)) => Poll::Ready(res),
            None => {
                match this.done {
                    false => {
                        // First time: Output the remaining buffer
                        // This should be somewhere between 0 to CHUNK_SIZE-1 bytes
                        *this.done = true;
                        this.chunk.append(this.buffer);
                        *this.bandwidth_future = Box::pin(
                            this.semaphore
                                .clone()
                                .acquire_many_owned(this.buffer.len() as u32),
                        );
                        Poll::Ready(Some(Ok(bytes::BytesMut::new())))
                    }
                    true => {
                        // If the inner stream finished and we emptied our buffer, return None
                        Poll::Ready(None)
                    }
                }
            }
        }
    }
}
