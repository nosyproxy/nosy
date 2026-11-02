//! Nosy application: wires the proxy, store, repeater and web UI together.

mod api;
mod assets;
pub mod codec;
mod error;
mod search;
mod security;
mod state;
mod ws;

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::Context;
use axum::{Router, middleware};
use clap::Parser;
use nosy_ca::CertificateAuthority;
use nosy_model::AppInfo;
use nosy_proxy::{Proxy, ProxyConfig};
use nosy_repeater::Repeater;
use nosy_store::Store;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

pub use state::AppState;

#[derive(Debug, Clone, Parser)]
#[command(
    name = "nosy",
    version,
    about = "HTTP/HTTPS intercepting proxy with a web UI"
)]
pub struct Cli {
    /// Proxy listen address.
    #[arg(long, default_value = "127.0.0.1:8080", env = "NOSY_PROXY")]
    pub proxy: SocketAddr,
    /// Web UI / API listen address.
    #[arg(long, default_value = "127.0.0.1:1337", env = "NOSY_UI")]
    pub ui: SocketAddr,
    /// Project database file (created if missing). Defaults to <data-dir>/default.db.
    #[arg(long, env = "NOSY_PROJECT")]
    pub project: Option<PathBuf>,
    /// Directory for the CA certificate and default project.
    #[arg(long, env = "NOSY_DATA_DIR")]
    pub data_dir: Option<PathBuf>,
    /// Verify upstream TLS certificates (off by default, like most pentest proxies).
    #[arg(long)]
    pub verify_upstream: bool,
    /// Max captured bytes per message body, in MiB (traffic beyond that still flows).
    #[arg(long, default_value_t = 16)]
    pub max_capture_mb: u64,
    /// Open the UI in the default browser.
    #[arg(long)]
    pub open: bool,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .nest("/api", api::routes())
        .fallback(assets::serve)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security::guard,
        ))
        .with_state(state)
}

pub struct App {
    pub state: AppState,
    pub proxy_listener: TcpListener,
    pub ui_listener: TcpListener,
    proxy: Proxy,
}

impl App {
    pub async fn new(cli: &Cli) -> anyhow::Result<Self> {
        let data_dir = match &cli.data_dir {
            Some(d) => d.clone(),
            None => directories::ProjectDirs::from("", "", "nosy")
                .context("cannot determine data directory; pass --data-dir")?
                .data_dir()
                .to_path_buf(),
        };
        std::fs::create_dir_all(&data_dir)
            .with_context(|| format!("create {}", data_dir.display()))?;
        let project = cli
            .project
            .clone()
            .unwrap_or_else(|| data_dir.join("default.db"));

        let ca = Arc::new(CertificateAuthority::load_or_create(&data_dir).context("load CA")?);
        let store =
            Store::open(&project).with_context(|| format!("open project {}", project.display()))?;

        let proxy_listener = TcpListener::bind(cli.proxy)
            .await
            .with_context(|| format!("bind proxy on {}", cli.proxy))?;
        let ui_listener = TcpListener::bind(cli.ui)
            .await
            .with_context(|| format!("bind UI on {}", cli.ui))?;
        let proxy_addr = proxy_listener.local_addr()?;
        let ui_addr = ui_listener.local_addr()?;

        let cfg = ProxyConfig {
            max_capture: (cli.max_capture_mb * 1024 * 1024) as usize,
            verify_upstream: cli.verify_upstream,
        };
        let info = AppInfo {
            version: env!("CARGO_PKG_VERSION").into(),
            proxy_addr: proxy_addr.to_string(),
            ui_addr: ui_addr.to_string(),
            project_path: project.display().to_string(),
            ca_path: data_dir.join("ca.crt").display().to_string(),
            verify_upstream: cfg.verify_upstream,
            max_capture_bytes: cfg.max_capture as u64,
        };
        let proxy = Proxy::new(ca.clone(), store.clone(), cfg);
        let state = AppState {
            repeater: Repeater::new(ca.crypto_provider().clone()),
            store,
            ca,
            info: Arc::new(info),
            allowed_hosts: Arc::new(security::allowed_hosts(ui_addr)),
        };
        Ok(Self {
            state,
            proxy_listener,
            ui_listener,
            proxy,
        })
    }

    pub async fn run(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        let proxy = tokio::spawn(self.proxy.serve(self.proxy_listener, shutdown.clone()));
        let app = router(self.state.clone());
        let s = shutdown.clone();
        axum::serve(self.ui_listener, app)
            .with_graceful_shutdown(async move { s.cancelled().await })
            .await?;
        shutdown.cancel();
        let _ = proxy.await;
        let store = self.state.store.clone();
        tokio::task::spawn_blocking(move || store.flush()).await?;
        Ok(())
    }
}
