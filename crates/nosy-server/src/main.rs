use clap::Parser;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = nosy_server::Cli::parse();
    let default_filter = "info,hyper=warn,hyper_util=warn,rustls=warn";
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter)),
        )
        .init();

    let app = nosy_server::App::new(&cli).await?;
    let info = app.state.info.clone();
    let ui_url = format!("http://{}", info.ui_addr);

    println!();
    println!("  Nosy v{}", info.version);
    println!("  ├─ proxy    http://{}", info.proxy_addr);
    println!("  ├─ web UI   {ui_url}");
    println!("  ├─ project  {}", info.project_path);
    println!(
        "  └─ CA cert  {}  (also at http://nosy/ via the proxy)",
        info.ca_path
    );
    println!();

    if cli.open {
        open_browser(&ui_url);
    }

    let shutdown = CancellationToken::new();
    let s = shutdown.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutting down");
        s.cancel();
    });
    app.run(shutdown).await
}

fn open_browser(url: &str) {
    let cmd = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(windows) {
        "explorer"
    } else {
        "xdg-open"
    };
    if let Err(e) = std::process::Command::new(cmd).arg(url).spawn() {
        tracing::warn!(error = %e, "could not open browser");
    }
}
