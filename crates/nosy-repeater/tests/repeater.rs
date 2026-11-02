use std::{net::SocketAddr, sync::Arc};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use nosy_model::{SendRequest, Target};
use nosy_repeater::Repeater;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn acceptor(alpn: &[&[u8]]) -> tokio_rustls::TlsAcceptor {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key)
        .unwrap();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    tokio_rustls::TlsAcceptor::from(Arc::new(cfg))
}

/// Replies with the exact bytes it received (head + Content-Length body).
async fn raw_echo(tls: bool) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let acc = tls.then(|| acceptor(&[b"http/1.1"]));
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let acc = acc.clone();
            tokio::spawn(async move {
                match acc {
                    Some(a) => handle(a.accept(s).await.unwrap()).await,
                    None => handle(s).await,
                }
            });
        }
    });
    addr
}

async fn handle<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(mut s: S) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = s.read(&mut tmp).await.unwrap();
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..i]).to_lowercase();
            let cl: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .map_or(0, |v| v.trim().parse().unwrap());
            if buf.len() >= i + 4 + cl {
                break;
            }
        }
    }
    let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", buf.len());
    s.write_all(resp.as_bytes()).await.unwrap();
    s.write_all(&buf).await.unwrap();
    s.flush().await.unwrap();
}

async fn h2_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let acc = acceptor(&[b"h2"]);
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let acc = acc.clone();
            tokio::spawn(async move {
                let tls = acc.accept(s).await.unwrap();
                let svc = service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                    let line = format!(
                        "{} {} {:?}",
                        req.method(),
                        req.uri(),
                        req.headers().get("x-a")
                    );
                    let body = req.into_body().collect().await?.to_bytes();
                    Ok::<_, hyper::Error>(hyper::Response::new(Full::new(Bytes::from(format!(
                        "{line} {}",
                        String::from_utf8_lossy(&body)
                    )))))
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    addr
}

fn send_req(addr: SocketAddr, tls: bool, http2: bool, raw: &str) -> SendRequest {
    SendRequest {
        target: Target {
            host: "localhost".into(),
            port: addr.port(),
            tls,
            http2,
        },
        raw_request: raw.into(),
        update_content_length: true,
        timeout_ms: Some(5000),
    }
}

#[tokio::test]
async fn h1_is_byte_exact_plain_and_tls() {
    let rep = Repeater::new(provider());
    for tls in [false, true] {
        let addr = raw_echo(tls).await;
        // Odd casing, duplicate headers and a space before the colon must survive.
        let raw =
            "POST /a?b HTTP/1.1\nHost: x\nX-weird-CASE: 1\nX-Dup: a\nX-Dup: b\nBad : v\n\nbody";
        let out = rep.send(&send_req(addr, tls, false, raw)).await;
        assert_eq!(out.error, None);
        assert_eq!(out.status, Some(200));
        let resp = out.response.unwrap();
        let echoed = &resp[resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4..];
        assert_eq!(echoed, out.sent.as_slice());
        assert_eq!(
            String::from_utf8(out.sent).unwrap(),
            "POST /a?b HTTP/1.1\r\nHost: x\r\nX-weird-CASE: 1\r\nX-Dup: a\r\nX-Dup: b\r\nBad : v\r\nContent-Length: 4\r\n\r\nbody"
        );
        assert!(out.ttfb_us.unwrap() <= out.duration_us.unwrap());
    }
}

#[tokio::test]
async fn h2_request() {
    let rep = Repeater::new(provider());
    let addr = h2_server().await;
    let raw = format!(
        "PATCH /x HTTP/2\nHost: localhost:{}\nX-A: 1\nConnection: close\n\nhi",
        addr.port()
    );
    let out = rep.send(&send_req(addr, true, true, &raw)).await;
    assert_eq!(out.error, None);
    assert_eq!(out.http_version.as_deref(), Some("HTTP/2"));
    let resp = String::from_utf8(out.response.unwrap()).unwrap();
    assert!(resp.starts_with("HTTP/2 200 OK\r\n"), "{resp}");
    assert!(
        resp.ends_with(&format!(
            "PATCH https://localhost:{}/x Some(\"1\") hi",
            addr.port()
        )),
        "{resp}"
    );
}

#[tokio::test]
async fn connection_refused_is_reported() {
    let rep = Repeater::new(provider());
    let port = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let out = rep
        .send(&send_req(
            SocketAddr::from(([127, 0, 0, 1], port)),
            false,
            false,
            "GET / HTTP/1.1\n\n",
        ))
        .await;
    assert!(out.error.unwrap().contains("connect"));
    assert!(out.response.is_none());
}
