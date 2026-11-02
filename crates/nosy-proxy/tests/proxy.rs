//! End-to-end: real upstream servers (HTTP, HTTPS h1+h2) ← proxy ← reqwest.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, body::Incoming, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use nosy_ca::CertificateAuthority;
use nosy_model::{FlowFilter, FlowSummary};
use nosy_proxy::{Proxy, ProxyConfig};
use nosy_store::Store;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

async fn echo(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let line = format!("{:?} {} {}", req.version(), req.method(), req.uri());
    let host = req
        .headers()
        .get("host")
        .map(|h| h.to_str().unwrap().to_owned());
    let body = req.into_body().collect().await?.to_bytes();
    let text = format!(
        "{line} host={host:?} body={}",
        String::from_utf8_lossy(&body)
    );
    Ok(Response::builder()
        .header("content-type", "text/plain")
        .header("x-upstream", "1")
        .body(Full::new(Bytes::from(text)))
        .unwrap())
}

async fn spawn_upstream(tls: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = tls.then(|| {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
        let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key)
        .unwrap();
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        tokio_rustls::TlsAcceptor::from(Arc::new(cfg))
    });
    tokio::spawn(async move {
        loop {
            let (s, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                let svc = service_fn(echo);
                let _ = match acceptor {
                    Some(a) => {
                        let Ok(tls) = a.accept(s).await else { return };
                        builder.serve_connection(TokioIo::new(tls), svc).await
                    }
                    None => builder.serve_connection(TokioIo::new(s), svc).await,
                };
            });
        }
    });
    addr
}

struct Env {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    ca_pem: String,
    proxy: SocketAddr,
    _shutdown: tokio_util::sync::DropGuard,
}

async fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let ca = Arc::new(CertificateAuthority::load_or_create(dir.path()).unwrap());
    let store = Store::open(&dir.path().join("p.db")).unwrap();
    let proxy = Proxy::new(ca.clone(), store.clone(), ProxyConfig::default());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let token = CancellationToken::new();
    tokio::spawn(proxy.serve(listener, token.clone()));
    Env {
        ca_pem: ca.ca_pem().to_owned(),
        _dir: dir,
        store,
        proxy: addr,
        _shutdown: token.drop_guard(),
    }
}

impl Env {
    fn client(&self, http2: bool) -> reqwest::Client {
        let mut b = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(format!("http://{}", self.proxy)).unwrap())
            .add_root_certificate(reqwest::Certificate::from_pem(self.ca_pem.as_bytes()).unwrap());
        if !http2 {
            b = b.http1_only();
        }
        b.build().unwrap()
    }

    /// Wait until the flow has a recorded response.
    async fn last_flow(&self) -> FlowSummary {
        for _ in 0..100 {
            self.store.flush();
            if let Some(f) = self
                .store
                .list_flows(&FlowFilter::default())
                .unwrap()
                .into_iter()
                .next()
                && f.status.is_some()
                && !f.method.is_empty()
            {
                return f;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("flow not captured");
    }
}

#[tokio::test]
async fn plain_http_is_proxied_and_captured() {
    let env = env().await;
    let up = spawn_upstream(false).await;
    let resp = env
        .client(false)
        .post(format!("http://localhost:{}/hello?x=1", up.port()))
        .body("ping")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.headers()["x-upstream"], "1");
    let text = resp.text().await.unwrap();
    assert!(text.starts_with("HTTP/1.1 POST /hello?x=1"), "{text}");
    assert!(text.contains("body=ping"), "{text}");

    let f = env.last_flow().await;
    assert_eq!(
        (f.scheme.as_str(), f.method.as_str(), f.path.as_str()),
        ("http", "POST", "/hello?x=1")
    );
    assert_eq!(f.status, Some(200));
    let req = env.store.request_message(f.id).unwrap();
    assert_eq!(req.body, b"ping");
    let resp = env.store.response_message(f.id).unwrap();
    assert_eq!(resp.body, text.as_bytes());
}

#[tokio::test]
async fn https_mitm_http1() {
    let env = env().await;
    let up = spawn_upstream(true).await;
    let text = env
        .client(false)
        .get(format!("https://localhost:{}/secure", up.port()))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(text.contains("GET") && text.contains("/secure"), "{text}");
    let f = env.last_flow().await;
    assert_eq!(
        (f.scheme.as_str(), f.http_version.as_str()),
        ("https", "HTTP/1.1")
    );
    assert_eq!(f.host, "localhost");
}

#[tokio::test]
async fn https_mitm_http2_end_to_end() {
    let env = env().await;
    let up = spawn_upstream(true).await;
    let resp = env
        .client(true)
        .put(format!("https://localhost:{}/h2", up.port()))
        .body("data")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.version(),
        reqwest::Version::HTTP_2,
        "client <-> proxy is h2"
    );
    let text = resp.text().await.unwrap();
    assert!(
        text.starts_with("HTTP/2.0 PUT"),
        "proxy <-> upstream is h2: {text}"
    );
    assert!(text.contains("body=data"));
    let f = env.last_flow().await;
    assert_eq!(f.http_version, "HTTP/2");
    let detail = env.store.flow_detail(f.id).unwrap();
    assert!(
        detail.request_headers.iter().any(|h| h.name == "host"),
        "host synthesized from :authority"
    );
}

#[tokio::test]
async fn upstream_failure_is_recorded() {
    let env = env().await;
    // Bind and drop to get a closed port.
    let port = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let resp = env
        .client(false)
        .get(format!("http://127.0.0.1:{port}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 502);
    for _ in 0..100 {
        env.store.flush();
        if let Some(f) = env
            .store
            .list_flows(&FlowFilter::default())
            .unwrap()
            .into_iter()
            .next()
            && f.error.is_some()
            && !f.method.is_empty()
        {
            assert!(f.status.is_none());
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("error flow not recorded");
}

#[tokio::test]
async fn landing_serves_ca() {
    let env = env().await;
    let pem = env
        .client(false)
        .get("http://nosy/ca.crt")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(pem, env.ca_pem);
    env.store.flush();
    assert!(
        env.store
            .list_flows(&FlowFilter::default())
            .unwrap()
            .is_empty(),
        "landing is not captured"
    );
}
