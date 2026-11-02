use std::time::Duration;

use nosy_model::{FlowDetail, FlowSummary, RepeaterEntry, RepeaterTab, SendRequest};
use nosy_server::{App, Cli};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_util::sync::CancellationToken;

/// Minimal HTTP/1.1 upstream answering every request with a fixed body.
async fn upstream() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                let mut acc = Vec::new();
                while !acc.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = s.read(&mut buf).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    acc.extend_from_slice(&buf[..n]);
                }
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
                    .await;
            });
        }
    });
    port
}

struct Env {
    api: String,
    proxy: String,
    http: reqwest::Client,
    _dir: tempfile::TempDir,
    _guard: tokio_util::sync::DropGuard,
}

async fn start() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let cli = Cli {
        proxy: "127.0.0.1:0".parse().unwrap(),
        ui: "127.0.0.1:0".parse().unwrap(),
        project: None,
        data_dir: Some(dir.path().to_path_buf()),
        verify_upstream: false,
        max_capture_mb: 16,
        open: false,
    };
    let app = App::new(&cli).await.unwrap();
    let api = format!("http://{}/api", app.state.info.ui_addr);
    let proxy = format!("http://{}", app.state.info.proxy_addr);
    let token = CancellationToken::new();
    tokio::spawn(app.run(token.clone()));
    Env {
        api,
        proxy,
        http: reqwest::Client::builder().no_proxy().build().unwrap(),
        _dir: dir,
        _guard: token.drop_guard(),
    }
}

#[tokio::test]
async fn capture_then_repeat() {
    let env = start().await;
    let port = upstream().await;

    let via_proxy = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(&env.proxy).unwrap())
        .build()
        .unwrap();
    let body = via_proxy
        .get(format!("http://localhost:{port}/item?id=7"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(body, "hello");

    let mut flows: Vec<FlowSummary> = Vec::new();
    for _ in 0..100 {
        flows = env
            .http
            .get(format!("{}/flows", env.api))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if flows
            .first()
            .is_some_and(|f| f.status.is_some() && !f.method.is_empty())
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let flow = &flows[0];
    assert_eq!((flow.path.as_str(), flow.status), ("/item?id=7", Some(200)));

    let detail: FlowDetail = env
        .http
        .get(format!("{}/flows/{}", env.api, flow.id))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(detail.request_headers.iter().any(|h| h.name == "host"));

    let raw = env
        .http
        .get(format!("{}/flows/{}/response", env.api, flow.id))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        raw.starts_with("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"),
        "{raw}"
    );
    assert!(raw.ends_with("\r\n\r\nhello"));

    let tab: RepeaterTab = env
        .http
        .post(format!("{}/flows/{}/repeater", env.api, flow.id))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        tab.raw_request.starts_with("GET /item?id=7 HTTP/1.1\r\n"),
        "{}",
        tab.raw_request
    );
    assert!(
        tab.raw_request.contains("\r\nHost: localhost:"),
        "{}",
        tab.raw_request
    );
    assert_eq!(tab.target.port, port);

    let entry: RepeaterEntry = env
        .http
        .post(format!("{}/repeater/tabs/{}/send", env.api, tab.id))
        .json(&SendRequest {
            target: tab.target.clone(),
            raw_request: tab.raw_request.replace("id=7", "id=8"),
            update_content_length: true,
            timeout_ms: Some(5000),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(entry.status, Some(200), "{entry:?}");
    let resp = env
        .http
        .get(format!(
            "{}/repeater/history/{}/response",
            env.api, entry.id
        ))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(resp.ends_with("hello"));

    let tabs: Vec<RepeaterTab> = env
        .http
        .get(format!("{}/repeater/tabs", env.api))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        tabs[0].raw_request.contains("id=8"),
        "sent request persisted into the tab"
    );
}

#[tokio::test]
async fn rejects_cross_origin_and_foreign_host() {
    let env = start().await;
    let r = env
        .http
        .delete(format!("{}/flows", env.api))
        .header("origin", "http://evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let r = env
        .http
        .get(format!("{}/info", env.api))
        .header("host", "evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let r = env
        .http
        .get(format!("{}/info", env.api))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}
