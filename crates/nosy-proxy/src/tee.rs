//! A body wrapper that streams frames through untouched while copying data
//! into a capture buffer (up to a limit). Adds no latency: nothing is buffered
//! on the forwarding path.

use std::{
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::{Bytes, BytesMut};
use http_body::{Body, Frame, SizeHint};

pub struct Captured {
    pub body: Bytes,
    /// Total data bytes that passed through (may exceed `body.len()`).
    pub size: u64,
    pub truncated: bool,
    /// `None` if the stream ended cleanly.
    pub error: Option<String>,
}

type OnDone = Box<dyn FnOnce(Captured) + Send + 'static>;

struct State {
    buf: BytesMut,
    limit: usize,
    size: u64,
    truncated: bool,
    on_done: OnDone,
}

pub struct TeeBody<B> {
    inner: B,
    state: Option<State>,
}

impl<B: Body + Unpin> TeeBody<B> {
    pub fn new(inner: B, limit: usize, on_done: impl FnOnce(Captured) + Send + 'static) -> Self {
        let hint = inner.size_hint();
        let cap = hint
            .exact()
            .or(hint.upper())
            .unwrap_or(hint.lower())
            .min(limit as u64) as usize;
        Self {
            inner,
            state: Some(State {
                buf: BytesMut::with_capacity(cap.min(1 << 20)),
                limit,
                size: 0,
                truncated: false,
                on_done: Box::new(on_done),
            }),
        }
    }

    fn finish(&mut self, error: Option<String>) {
        if let Some(s) = self.state.take() {
            (s.on_done)(Captured {
                body: s.buf.freeze(),
                size: s.size,
                truncated: s.truncated,
                error,
            });
        }
    }
}

impl<B> Body for TeeBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = &mut *self;
        match ready!(Pin::new(&mut this.inner).poll_frame(cx)) {
            Some(Ok(frame)) => {
                if let (Some(data), Some(s)) = (frame.data_ref(), this.state.as_mut()) {
                    s.size += data.len() as u64;
                    let room = s.limit.saturating_sub(s.buf.len());
                    if data.len() > room {
                        s.truncated = true;
                    }
                    s.buf.extend_from_slice(&data[..data.len().min(room)]);
                }
                if this.inner.is_end_stream() {
                    this.finish(None);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Some(Err(e)) => {
                this.finish(Some(e.to_string()));
                Poll::Ready(Some(Err(e)))
            }
            None => {
                this.finish(None);
                Poll::Ready(None)
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl<B> Drop for TeeBody<B> {
    fn drop(&mut self) {
        if let Some(s) = self.state.take() {
            // Bodies that are empty from the start are often never polled; that
            // is a clean end, not an abort. Without access to `B: Body` here we
            // treat "nothing seen" as clean.
            let error = (s.size > 0 || !s.buf.is_empty()).then(|| "body stream aborted".to_owned());
            (s.on_done)(Captured {
                body: s.buf.freeze(),
                size: s.size,
                truncated: s.truncated,
                error,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Full, StreamBody};
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn captures_and_truncates() {
        let chunks: Vec<Result<Frame<Bytes>, std::convert::Infallible>> = vec![
            Ok(Frame::data(Bytes::from_static(b"hello "))),
            Ok(Frame::data(Bytes::from_static(b"world"))),
        ];
        let out = Arc::new(Mutex::new(None));
        let o = out.clone();
        let body = TeeBody::new(
            StreamBody::new(futures_util::stream::iter(chunks)),
            8,
            move |c| {
                *o.lock().unwrap() = Some(c);
            },
        );
        let all = body.collect().await.unwrap().to_bytes();
        assert_eq!(&all[..], b"hello world");
        let c = out.lock().unwrap().take().unwrap();
        assert_eq!(&c.body[..], b"hello wo");
        assert_eq!(c.size, 11);
        assert!(c.truncated);
        assert!(c.error.is_none());
    }

    #[tokio::test]
    async fn unpolled_empty_body_is_clean() {
        let out = Arc::new(Mutex::new(None));
        let o = out.clone();
        let body = TeeBody::new(Full::new(Bytes::new()), 8, move |c| {
            *o.lock().unwrap() = Some(c)
        });
        drop(body);
        assert!(out.lock().unwrap().take().unwrap().error.is_none());
    }
}
