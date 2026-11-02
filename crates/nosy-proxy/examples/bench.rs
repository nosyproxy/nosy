//! Throughput/latency: direct vs. through the proxy (with full capture into SQLite).
//! `cargo run --release -p nosy-proxy --example bench`

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use nosy_ca::CertificateAuthority;
use nosy_proxy::{Proxy, ProxyConfig};
use nosy_store::Store;
use tokio::net::TcpListener;

const CONCURRENCY: usize = 64;
const DURATION: Duration = Duration::from_secs(5);

async fn upstream() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let body = Bytes::from(vec![b'x'; 1024]);
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let body = body.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |_req| {
                    let b = body.clone();
                    async move { Ok::<_, hyper::Error>(Response::new(Full::new(b))) }
                });
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(s), svc)
                    .await;
            });
        }
    });
    port
}

async fn run(label: &str, client: reqwest::Client, url: String) {
    let deadline = Instant::now() + DURATION;
    let mut tasks = Vec::new();
    for _ in 0..CONCURRENCY {
        let (c, u) = (client.clone(), url.clone());
        tasks.push(tokio::spawn(async move {
            let mut lat = Vec::new();
            while Instant::now() < deadline {
                let t = Instant::now();
                let r = c.get(&u).send().await.unwrap();
                r.bytes().await.unwrap();
                lat.push(t.elapsed());
            }
            lat
        }));
    }
    let mut all: Vec<Duration> = Vec::new();
    for t in tasks {
        all.extend(t.await.unwrap());
    }
    all.sort();
    let p = |q: f64| all[((all.len() as f64 * q) as usize).min(all.len() - 1)];
    println!(
        "{label:<28} {:>8.0} req/s   p50 {:>7.2?}   p99 {:>7.2?}",
        all.len() as f64 / DURATION.as_secs_f64(),
        p(0.50),
        p(0.99)
    );
}

#[tokio::main]
async fn main() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Arc::new(CertificateAuthority::load_or_create(dir.path()).unwrap());
    let store = Store::open(&dir.path().join("bench.db")).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let token = tokio_util::sync::CancellationToken::new();
    tokio::spawn(
        Proxy::new(ca, store.clone(), ProxyConfig::default()).serve(listener, token.clone()),
    );

    let port = upstream().await;
    let url = format!("http://127.0.0.1:{port}/bench");
    println!(
        "concurrency {CONCURRENCY}, {}s each, 1 KiB responses\n",
        DURATION.as_secs()
    );
    run(
        "direct",
        reqwest::Client::builder().no_proxy().build().unwrap(),
        url.clone(),
    )
    .await;
    let via = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_addr}")).unwrap())
        .build()
        .unwrap();
    run("via Nosy (+capture)", via, url).await;

    let t = Instant::now();
    store.flush();
    let n = store.list_flows(&Default::default()).unwrap().len();
    println!(
        "\nstore backlog flushed in {:?}; dropped events: {}; sample rows: {n}",
        t.elapsed(),
        store.dropped_events()
    );
    token.cancel();
}
