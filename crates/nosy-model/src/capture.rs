//! Events emitted by the proxy engine and consumed by the store.

use bytes::Bytes;

use crate::FlowId;

#[derive(Debug, Clone)]
pub struct RequestRecord {
    pub id: FlowId,
    pub ts_start: i64,
    pub scheme: &'static str,
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: String,
    pub http_version: &'static str,
    /// Encoded with [`crate::headers::encode`].
    pub headers: Vec<u8>,
    /// Captured body (possibly truncated).
    pub body: Bytes,
    /// Total body size seen on the wire.
    pub body_size: i64,
    pub truncated: bool,
}

#[derive(Debug, Clone)]
pub struct ResponseRecord {
    pub id: FlowId,
    pub ts_end: i64,
    pub duration_us: i64,
    pub status: u16,
    pub http_version: &'static str,
    pub headers: Vec<u8>,
    pub content_type: Option<String>,
    pub body: Bytes,
    pub body_size: i64,
    pub truncated: bool,
    /// Set when the body stream ended abnormally.
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub enum FlowEvent {
    Request(Box<RequestRecord>),
    Response(Box<ResponseRecord>),
    Error {
        id: FlowId,
        ts_end: i64,
        duration_us: i64,
        message: String,
    },
}

/// Destination for captured traffic. Must never block the caller.
pub trait FlowSink: Send + Sync + 'static {
    /// Allocate a fresh, unique flow id.
    fn next_id(&self) -> FlowId;
    /// Submit an event. Implementations drop events rather than block.
    fn submit(&self, event: FlowEvent);
}

pub fn http_version_str(v: http::Version) -> &'static str {
    match v {
        http::Version::HTTP_09 => "HTTP/0.9",
        http::Version::HTTP_10 => "HTTP/1.0",
        http::Version::HTTP_11 => "HTTP/1.1",
        http::Version::HTTP_2 => "HTTP/2",
        http::Version::HTTP_3 => "HTTP/3",
        _ => "HTTP/?",
    }
}
