//! Repeater engine: send a hand-edited request and capture the raw response.
//!
//! * HTTP/1.x is sent **byte-for-byte** over a fresh TCP/TLS connection, so
//!   malformed or ambiguous requests (smuggling tests etc.) go out unmodified.
//! * HTTP/2 requests are parsed from the same text format and sent with hyper.

pub mod h1;
pub mod raw;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method, Request, StatusCode, Version};
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::{TokioExecutor, TokioIo};
use nosy_model::{SendRequest, Target};
use rustls::{ClientConfig, crypto::CryptoProvider, pki_types::ServerName};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub struct Outcome {
    /// Bytes actually sent (normalized request).
    pub sent: Vec<u8>,
    pub response: Option<Vec<u8>>,
    pub status: Option<u16>,
    pub http_version: Option<String>,
    pub ttfb_us: Option<i64>,
    pub duration_us: Option<i64>,
    pub error: Option<String>,
}

#[derive(Clone)]
pub struct Repeater {
    h1: TlsConnector,
    h2: TlsConnector,
}

impl Repeater {
    pub fn new(provider: Arc<CryptoProvider>) -> Self {
        let base: ClientConfig = nosy_proxy::upstream::tls_config(provider, false);
        let mut h1 = base.clone();
        h1.alpn_protocols = vec![b"http/1.1".to_vec()];
        let mut h2 = base;
        h2.alpn_protocols = vec![b"h2".to_vec()];
        Self {
            h1: TlsConnector::from(Arc::new(h1)),
            h2: TlsConnector::from(Arc::new(h2)),
        }
    }

    pub async fn send(&self, req: &SendRequest) -> Outcome {
        let sent = raw::normalize(&req.raw_request, req.update_content_length);
        let timeout = req
            .timeout_ms
            .map_or(DEFAULT_TIMEOUT, Duration::from_millis);
        let started = Instant::now();
        let mut out = Outcome {
            sent,
            ..Default::default()
        };

        let result = tokio::time::timeout(timeout, async {
            if req.target.http2 {
                self.send_h2(&req.target, &out.sent).await
            } else {
                self.send_h1(&req.target, &out.sent).await
            }
        })
        .await
        .unwrap_or_else(|_| Err(format!("timed out after {} ms", timeout.as_millis())));

        out.duration_us = Some(started.elapsed().as_micros() as i64);
        match result {
            Ok(r) => {
                out.ttfb_us = r
                    .first_byte
                    .map(|t| t.duration_since(started).as_micros() as i64);
                out.status = r.status;
                out.http_version = r.version.map(str::to_owned);
                out.response = Some(r.raw);
            }
            Err(e) => out.error = Some(e),
        }
        out
    }

    async fn connect(&self, t: &Target) -> Result<TcpStream, String> {
        let tcp = TcpStream::connect((t.host.as_str(), t.port))
            .await
            .map_err(|e| format!("connect to {}:{} failed: {e}", t.host, t.port))?;
        let _ = tcp.set_nodelay(true);
        Ok(tcp)
    }

    async fn tls(
        &self,
        connector: &TlsConnector,
        t: &Target,
        tcp: TcpStream,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
        let name = ServerName::try_from(
            t.host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_owned(),
        )
        .map_err(|e| format!("invalid server name {:?}: {e}", t.host))?;
        connector
            .connect(name, tcp)
            .await
            .map_err(|e| format!("TLS handshake failed: {e}"))
    }

    async fn send_h1(&self, t: &Target, bytes: &[u8]) -> Result<h1::H1Response, String> {
        let tcp = self.connect(t).await?;
        let head = raw::method(bytes).eq_ignore_ascii_case(b"HEAD");
        if t.tls {
            let mut s = self.tls(&self.h1, t, tcp).await?;
            exchange_h1(&mut s, bytes, head).await
        } else {
            let mut s = tcp;
            exchange_h1(&mut s, bytes, head).await
        }
    }

    async fn send_h2(&self, t: &Target, bytes: &[u8]) -> Result<h1::H1Response, String> {
        let req = build_h2_request(t, bytes)?;
        let tcp = self.connect(t).await?;
        if t.tls {
            let s = self.tls(&self.h2, t, tcp).await?;
            if s.get_ref().1.alpn_protocol() != Some(b"h2") {
                return Err(
                    "server did not negotiate HTTP/2 (ALPN); disable HTTP/2 for this target".into(),
                );
            }
            exchange_h2(s, req).await
        } else {
            exchange_h2(tcp, req).await // h2c with prior knowledge
        }
    }
}

async fn exchange_h1<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    bytes: &[u8],
    head: bool,
) -> Result<h1::H1Response, String> {
    s.write_all(bytes)
        .await
        .map_err(|e| format!("write failed: {e}"))?;
    s.flush().await.map_err(|e| format!("write failed: {e}"))?;
    let r = h1::read_response(s, head, MAX_RESPONSE)
        .await
        .map_err(|e| format!("read failed: {e}"))?;
    if r.raw.is_empty() {
        return Err("connection closed without a response".into());
    }
    Ok(r)
}

const H2_FORBIDDEN: &[&str] = &[
    "host",
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
];

fn build_h2_request(t: &Target, bytes: &[u8]) -> Result<Request<Full<Bytes>>, String> {
    // Parsed by hand: the request line may say `HTTP/2`, which HTTP/1 parsers reject.
    let (head, body) = raw::split_message(bytes);
    let mut lines = head
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let request_line = std::str::from_utf8(lines.next().unwrap_or_default())
        .map_err(|_| "request line is not valid UTF-8".to_owned())?;
    let mut parts = request_line.split_ascii_whitespace();
    let method = Method::from_bytes(parts.next().unwrap_or("GET").as_bytes())
        .map_err(|e| format!("invalid method: {e}"))?;
    let path = parts.next().unwrap_or("/");
    let headers: Vec<(&[u8], &[u8])> = lines.filter_map(raw::split_header).collect();

    let authority = headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(b"host"))
        .and_then(|(_, v)| std::str::from_utf8(v).ok())
        .map(str::to_owned)
        .unwrap_or_else(|| {
            let default = if t.tls { 443 } else { 80 };
            if t.port == default {
                t.host.clone()
            } else {
                format!("{}:{}", t.host, t.port)
            }
        });
    let uri = if path.starts_with("http://") || path.starts_with("https://") {
        path.to_owned()
    } else {
        format!(
            "{}://{authority}{path}",
            if t.tls { "https" } else { "http" }
        )
    };

    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .version(Version::HTTP_2);
    for (name, value) in headers {
        let lname = name.to_ascii_lowercase();
        if H2_FORBIDDEN
            .iter()
            .any(|f| f.as_bytes() == lname.as_slice())
            || (lname == b"te" && value != b"trailers")
        {
            continue;
        }
        let shown = String::from_utf8_lossy(name);
        let name = HeaderName::from_bytes(&lname).map_err(|e| format!("header {shown:?}: {e}"))?;
        let value = HeaderValue::from_bytes(value).map_err(|e| format!("header {shown:?}: {e}"))?;
        builder = builder.header(name, value);
    }
    builder
        .body(Full::new(Bytes::copy_from_slice(body)))
        .map_err(|e| e.to_string())
}

async fn exchange_h2<S>(io: S, req: Request<Full<Bytes>>) -> Result<h1::H1Response, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(io))
            .await
            .map_err(|e| format!("HTTP/2 handshake failed: {e}"))?;
    let conn_task = tokio::spawn(conn);
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| format!("HTTP/2 request failed: {e}"))?;
    let first_byte = Some(Instant::now());
    let (parts, body) = resp.into_parts();
    let body = Limited::new(body, MAX_RESPONSE)
        .collect()
        .await
        .map_err(|e| format!("reading HTTP/2 body failed: {e}"))?
        .to_bytes();
    conn_task.abort();

    let mut raw = Vec::with_capacity(body.len() + 512);
    raw.extend_from_slice(format!("HTTP/2 {}", parts.status.as_u16()).as_bytes());
    if let Some(reason) = StatusCode::canonical_reason(&parts.status) {
        raw.push(b' ');
        raw.extend_from_slice(reason.as_bytes());
    }
    raw.extend_from_slice(b"\r\n");
    for (name, value) in &parts.headers {
        raw.extend_from_slice(name.as_str().as_bytes());
        raw.extend_from_slice(b": ");
        raw.extend_from_slice(value.as_bytes());
        raw.extend_from_slice(b"\r\n");
    }
    raw.extend_from_slice(b"\r\n");
    raw.extend_from_slice(&body);
    Ok(h1::H1Response {
        raw,
        status: Some(parts.status.as_u16()),
        version: Some("HTTP/2"),
        first_byte,
    })
}
