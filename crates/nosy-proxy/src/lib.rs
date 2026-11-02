//! MITM HTTP/HTTPS proxy engine.
//!
//! ```text
//! client ──TCP──► http1 server ──┬─ absolute-form request ─► forward()
//!                                └─ CONNECT ─► tunnel ─┬─ TLS (0x16) ─► rustls (SNI cert) ─► h1|h2 server ─► forward()
//!                                                      └─ plaintext  ─► h1 server ─► forward()
//! ```
//! Bodies stream through [`tee::TeeBody`], which copies data for capture without
//! adding latency. Captured data is handed to a [`FlowSink`].

mod landing;
mod rewind;
pub mod tee;
pub mod upstream;

use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

use bytes::{Bytes, BytesMut};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri, Version, header};
use http_body_util::{Either, Full};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    client::legacy::Client,
    rt::{TokioExecutor, TokioIo, TokioTimer},
};
use nosy_ca::CertificateAuthority;
use nosy_model::{
    capture::{FlowEvent, FlowSink, RequestRecord, ResponseRecord, http_version_str},
    headers, now_ms,
};
use tokio::{io::AsyncReadExt, net::TcpListener};
use tokio_util::sync::CancellationToken;

use crate::{rewind::Rewind, tee::TeeBody, upstream::Connector};

pub type RespBody = Either<TeeBody<Incoming>, Full<Bytes>>;
type ReqBody = TeeBody<Incoming>;

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Max bytes captured per body (traffic beyond that still flows).
    pub max_capture: usize,
    /// Verify upstream TLS certificates.
    pub verify_upstream: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            max_capture: 16 * 1024 * 1024,
            verify_upstream: false,
        }
    }
}

#[derive(Clone)]
pub struct Proxy {
    inner: Arc<Inner>,
}

struct Inner {
    ca: Arc<CertificateAuthority>,
    sink: Arc<dyn FlowSink>,
    /// Pooled client negotiating h2/h1 via ALPN.
    client: Client<Connector, ReqBody>,
    /// HTTP/1.1-only client for protocol upgrades (WebSocket).
    client_h1: Client<Connector, ReqBody>,
    cfg: ProxyConfig,
    local_addr: OnceLock<SocketAddr>,
}

/// Where requests on a connection are going (known from CONNECT or the request URI).
#[derive(Clone)]
struct Origin {
    scheme: &'static str,
    host: Arc<str>,
    port: u16,
}

impl Proxy {
    pub fn new(ca: Arc<CertificateAuthority>, sink: Arc<dyn FlowSink>, cfg: ProxyConfig) -> Self {
        let tls = upstream::tls_config(ca.crypto_provider().clone(), cfg.verify_upstream);
        Self {
            inner: Arc::new(Inner {
                client: upstream::build_client(tls.clone(), true),
                client_h1: upstream::build_client(tls, false),
                ca,
                sink,
                cfg,
                local_addr: OnceLock::new(),
            }),
        }
    }

    /// Accept connections until `shutdown` is cancelled.
    pub async fn serve(
        self,
        listener: TcpListener,
        shutdown: CancellationToken,
    ) -> std::io::Result<()> {
        let local = listener.local_addr()?;
        let _ = self.inner.local_addr.set(local);
        tracing::info!(addr = %local, "proxy listening");
        loop {
            let (stream, peer) = tokio::select! {
                r = listener.accept() => match r {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                },
                () = shutdown.cancelled() => break,
            };
            let _ = stream.set_nodelay(true);
            let inner = self.inner.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req| {
                    let inner = inner.clone();
                    async move { Ok::<_, std::convert::Infallible>(handle(inner, req).await) }
                });
                let conn = hyper::server::conn::http1::Builder::new()
                    .preserve_header_case(true)
                    .timer(TokioTimer::new())
                    .header_read_timeout(Duration::from_secs(30))
                    .serve_connection(TokioIo::new(stream), svc)
                    .with_upgrades();
                tokio::pin!(conn);
                let res = tokio::select! {
                    r = conn.as_mut() => r,
                    () = shutdown.cancelled() => {
                        conn.as_mut().graceful_shutdown();
                        conn.await
                    }
                };
                if let Err(e) = res {
                    tracing::debug!(%peer, error = %e, "client connection error");
                }
            });
        }
        Ok(())
    }
}

/// Entry point for requests arriving on the proxy port itself.
async fn handle(inner: Arc<Inner>, req: Request<Incoming>) -> Response<RespBody> {
    if req.method() == Method::CONNECT {
        return connect(inner, req);
    }
    let uri = req.uri();
    match (uri.scheme_str(), uri.host()) {
        (Some(scheme @ ("http" | "https")), Some(host)) => {
            let scheme = if scheme == "https" { "https" } else { "http" };
            let port = uri
                .port_u16()
                .unwrap_or(if scheme == "https" { 443 } else { 80 });
            let origin = Origin {
                scheme,
                host: host.into(),
                port,
            };
            forward(inner, req, &origin).await
        }
        // Origin-form request: someone is talking to the proxy directly.
        _ => landing::respond(&inner.ca, req.uri().path()),
    }
}

fn connect(inner: Arc<Inner>, req: Request<Incoming>) -> Response<RespBody> {
    let Some(authority) = req.uri().authority().cloned() else {
        return text(StatusCode::BAD_REQUEST, "CONNECT requires host:port");
    };
    let host: Arc<str> = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .into();
    let port = authority.port_u16().unwrap_or(443);
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                if let Err(e) = tunnel(inner, TokioIo::new(upgraded), host.clone(), port).await {
                    tracing::debug!(%host, port, error = %e, "tunnel closed with error");
                }
            }
            Err(e) => tracing::debug!(error = %e, "CONNECT upgrade failed"),
        }
    });
    Response::new(Either::Right(Full::new(Bytes::new())))
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

async fn tunnel<IO>(
    inner: Arc<Inner>,
    mut io: IO,
    host: Arc<str>,
    port: u16,
) -> Result<(), BoxError>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut buf = BytesMut::with_capacity(4096);
    if io.read_buf(&mut buf).await? == 0 {
        return Ok(());
    }
    let is_tls = buf[0] == 0x16;
    let io = Rewind::new(io, buf.freeze());

    if !is_tls {
        let origin = Origin {
            scheme: "http",
            host,
            port,
        };
        return serve_inner_h1(inner, io, origin).await;
    }

    let start =
        tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), io).await?;
    let sni: Arc<str> = start.client_hello().server_name().map_or(host, Into::into);
    let ca = inner.ca.clone();
    let name = sni.clone();
    // Signing is fast (~tens of µs) but keep it off the reactor in case of bursts.
    let cfg = tokio::task::spawn_blocking(move || ca.server_config(&name)).await??;
    let tls = start.into_stream(cfg).await?;
    let h2 = tls.get_ref().1.alpn_protocol() == Some(nosy_ca::ALPN_H2);
    let origin = Origin {
        scheme: "https",
        host: sni,
        port,
    };

    if h2 {
        let svc = service_fn(move |req| {
            let (inner, origin) = (inner.clone(), origin.clone());
            async move { Ok::<_, std::convert::Infallible>(forward(inner, req, &origin).await) }
        });
        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .timer(TokioTimer::new())
            .adaptive_window(true)
            .max_concurrent_streams(256)
            .serve_connection(TokioIo::new(tls), svc)
            .await?;
        Ok(())
    } else {
        serve_inner_h1(inner, tls, origin).await
    }
}

async fn serve_inner_h1<IO>(inner: Arc<Inner>, io: IO, origin: Origin) -> Result<(), BoxError>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let svc = service_fn(move |req| {
        let (inner, origin) = (inner.clone(), origin.clone());
        async move { Ok::<_, std::convert::Infallible>(forward(inner, req, &origin).await) }
    });
    hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(30))
        .serve_connection(TokioIo::new(io), svc)
        .with_upgrades()
        .await?;
    Ok(())
}

impl Inner {
    fn is_self(&self, host: &str, port: u16) -> bool {
        if host.eq_ignore_ascii_case(landing::MAGIC_HOST) {
            return true;
        }
        let Some(local) = self.local_addr.get() else {
            return false;
        };
        if port != local.port() {
            return false;
        }
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified() || ip == local.ip())
    }
}

async fn forward(
    inner: Arc<Inner>,
    mut req: Request<Incoming>,
    origin: &Origin,
) -> Response<RespBody> {
    if inner.is_self(&origin.host, origin.port) {
        return landing::respond(&inner.ca, req.uri().path());
    }

    let id = inner.sink.next_id();
    let ts_start = now_ms();
    let started = Instant::now();
    let client_version = req.version();
    let upgrade = is_upgrade(req.headers());
    let client_upgrade = upgrade.then(|| hyper::upgrade::on(&mut req));

    let (mut parts, body) = req.into_parts();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map_or("/", |p| p.as_str())
        .to_owned();
    let default_port = if origin.scheme == "https" { 443 } else { 80 };
    let host_fmt = if origin.host.contains(':') {
        format!("[{}]", origin.host)
    } else {
        origin.host.to_string()
    };
    let authority = if origin.port == default_port {
        host_fmt
    } else {
        format!("{host_fmt}:{}", origin.port)
    };

    let mut request_headers = parts.headers.clone();
    if !request_headers.contains_key(header::HOST) {
        // HTTP/2 carries it in :authority; record it so the request reads naturally.
        if let Ok(v) = HeaderValue::from_str(&authority) {
            request_headers.insert(header::HOST, v);
        }
    }
    let record = RequestRecord {
        id,
        ts_start,
        scheme: origin.scheme,
        host: origin.host.to_string(),
        port: origin.port,
        method: parts.method.to_string(),
        path: path_and_query.clone(),
        http_version: http_version_str(client_version),
        headers: headers::encode(&request_headers),
        body: Bytes::new(),
        body_size: 0,
        truncated: false,
    };

    parts.uri = match Uri::builder()
        .scheme(origin.scheme)
        .authority(authority.as_str())
        .path_and_query(path_and_query.as_str())
        .build()
    {
        Ok(u) => u,
        Err(e) => {
            return text(
                StatusCode::BAD_REQUEST,
                &format!("invalid request target: {e}"),
            );
        }
    };
    // The pooled client picks h1/h2 per connection; HTTP_2 here would forbid h1 upstreams.
    parts.version = Version::HTTP_11;
    strip_hop_by_hop(&mut parts.headers, upgrade);

    let sink = inner.sink.clone();
    let body = TeeBody::new(body, inner.cfg.max_capture, move |c| {
        let mut record = record;
        record.body = c.body;
        record.body_size = c.size as i64;
        record.truncated = c.truncated;
        sink.submit(FlowEvent::Request(Box::new(record)));
    });

    let client = if upgrade {
        &inner.client_h1
    } else {
        &inner.client
    };
    let mut resp = match client.request(Request::from_parts(parts, body)).await {
        Ok(r) => r,
        Err(e) => {
            let message = error_chain(&e);
            tracing::debug!(id, error = %message, "upstream request failed");
            inner.sink.submit(FlowEvent::Error {
                id,
                ts_end: now_ms(),
                duration_us: started.elapsed().as_micros() as i64,
                message: message.clone(),
            });
            return text(
                StatusCode::BAD_GATEWAY,
                &format!("Nosy: upstream error: {message}\n"),
            );
        }
    };

    let status = resp.status();
    if status == StatusCode::SWITCHING_PROTOCOLS
        && let Some(client_upgrade) = client_upgrade
    {
        let server_upgrade = hyper::upgrade::on(&mut resp);
        tokio::spawn(async move {
            match tokio::try_join!(client_upgrade, server_upgrade) {
                Ok((c, s)) => {
                    let (mut c, mut s) = (TokioIo::new(c), TokioIo::new(s));
                    let _ = tokio::io::copy_bidirectional(&mut c, &mut s).await;
                }
                Err(e) => tracing::debug!(error = %e, "upgrade failed"),
            }
        });
    }

    let (mut rparts, rbody) = resp.into_parts();
    let content_type = rparts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let response_headers = headers::encode(&rparts.headers);
    let upstream_version = http_version_str(rparts.version);
    strip_hop_by_hop(
        &mut rparts.headers,
        status == StatusCode::SWITCHING_PROTOCOLS,
    );
    rparts.version = client_version;

    let sink = inner.sink.clone();
    let rbody = TeeBody::new(rbody, inner.cfg.max_capture, move |c| {
        sink.submit(FlowEvent::Response(Box::new(ResponseRecord {
            id,
            ts_end: now_ms(),
            duration_us: started.elapsed().as_micros() as i64,
            status: status.as_u16(),
            http_version: upstream_version,
            headers: response_headers,
            content_type,
            body: c.body,
            body_size: c.size as i64,
            truncated: c.truncated,
            error: c.error,
        })));
    });
    Response::from_parts(rparts, Either::Left(rbody))
}

fn is_upgrade(h: &HeaderMap) -> bool {
    h.contains_key(header::UPGRADE)
        && h.get_all(header::CONNECTION).iter().any(|v| {
            v.to_str().is_ok_and(|s| {
                s.split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
            })
        })
}

/// Remove connection-scoped headers (RFC 9110 §7.6.1). Keeps `Upgrade`/`Connection`
/// when proxying a protocol upgrade, and `TE: trailers` (needed by gRPC).
fn strip_hop_by_hop(h: &mut HeaderMap, keep_upgrade: bool) {
    let listed: Vec<String> = h
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty() && !(keep_upgrade && t == "upgrade"))
        .collect();
    for name in listed {
        h.remove(name.as_str());
    }
    if !keep_upgrade {
        h.remove(header::CONNECTION);
        h.remove(header::UPGRADE);
    }
    for name in [
        "proxy-connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "trailer",
    ] {
        h.remove(name);
    }
    h.remove(header::TRANSFER_ENCODING);
    let te_trailers = h
        .get(header::TE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("trailers"))
        });
    h.remove(header::TE);
    if te_trailers {
        h.insert(header::TE, HeaderValue::from_static("trailers"));
    }
}

fn error_chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut src = e.source();
    while let Some(inner) = src {
        let msg = inner.to_string();
        if !s.contains(&msg) {
            s.push_str(": ");
            s.push_str(&msg);
        }
        src = inner.source();
    }
    s
}

pub(crate) fn text(status: StatusCode, body: &str) -> Response<RespBody> {
    let mut r = Response::new(Either::Right(Full::new(Bytes::copy_from_slice(
        body.as_bytes(),
    ))));
    *r.status_mut() = status;
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_by_hop_stripping() {
        let mut h = HeaderMap::new();
        h.insert(
            "connection",
            HeaderValue::from_static("keep-alive, x-secret"),
        );
        h.insert("x-secret", HeaderValue::from_static("1"));
        h.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        h.insert("te", HeaderValue::from_static("trailers, deflate"));
        h.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        h.insert("x-keep", HeaderValue::from_static("1"));
        strip_hop_by_hop(&mut h, false);
        let names: Vec<_> = h.keys().map(|k| k.as_str()).collect();
        assert_eq!(names.len(), 2, "{names:?}");
        assert_eq!(h["te"], "trailers");
        assert!(h.contains_key("x-keep"));
    }

    #[test]
    fn upgrade_detection() {
        let mut h = HeaderMap::new();
        h.insert(
            "connection",
            HeaderValue::from_static("keep-alive, Upgrade"),
        );
        h.insert("upgrade", HeaderValue::from_static("websocket"));
        assert!(is_upgrade(&h));
        strip_hop_by_hop(&mut h, true);
        assert!(h.contains_key("upgrade") && h.contains_key("connection"));
    }
}
