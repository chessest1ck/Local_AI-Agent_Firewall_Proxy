mod config;
mod dns;
mod policy;
mod prompt;
mod proxy;
mod sandbox;
mod shim;
mod tls;

use anyhow::Result;
use clap::{Parser, Subcommand};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, warn};


use policy::PolicyEngine;
use prompt::PromptCoordinator;
use proxy::ProxyHandler;
use tls::MitmCa;

/// Local AI-Agent Firewall Proxy — monitor, filter, and secure AI agents.
#[derive(Parser)]
#[command(name = "ai-firewall", version, about)]
struct Cli {
    /// Path to the configuration file.
    #[arg(short, long, default_value = "firewall_config.toml")]
    config: String,

    /// Override the listen port.
    #[arg(short, long)]
    port: Option<u16>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a command inside the OS sandbox (macOS only).
    Sandbox {
        /// Workspace directory to allow writes to.
        workspace: String,
        /// Command and arguments to run.
        #[arg(trailing_var_arg = true, required = true)]
        cmd: Vec<String>,
    },
    /// Run the command interceptor shim.
    Shim {
        /// Arguments to pass to the real shell.
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    // Handle subcommands first
    match cli.command {
        Some(Commands::Sandbox { workspace, cmd }) => {
            // Load config for sandbox settings (optional — use defaults if missing)
            let sandbox_config = config::load_config(&cli.config)
                .ok()
                .map(|c| c.sandbox);
            if let Err(e) = sandbox::run_sandbox(&workspace, &cmd, sandbox_config.as_ref()) {
                error!("Sandbox error: {:?}", e);
                std::process::exit(1);
            }
            return Ok(());
        }
        Some(Commands::Shim { args }) => {
            return shim::run_shim(args).await;
        }
        None => {}
    }

    // Also handle legacy symlink invocation (sh/bash)
    if let Some(exe_name) = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        && (exe_name == "sh" || exe_name == "bash") {
            let args: Vec<String> = std::env::args().collect();
            return shim::run_shim(args).await;
        }

    // ── Load Configuration ──────────────────────────────────────

    let config_path = config::resolve_config_path(Some(&cli.config))?;
    let firewall_config = config::load_config(&config_path)?;

    let listen_port = cli.port.unwrap_or(firewall_config.proxy.listen_port);
    let listen_addr: SocketAddr = format!("{}:{}", firewall_config.proxy.listen_addr, listen_port)
        .parse()
        .expect("Invalid listen address");

    // ── Initialize Components ───────────────────────────────────

    // 1. Policy Engine
    let policy_engine = Arc::new(PolicyEngine::new(&firewall_config.policy)?);

    // 2. Threat Feed (background refresh)
    if firewall_config.policy.threat_feed.enabled {
        spawn_threat_feed_task(
            policy_engine.threat_feed_handle(),
            firewall_config.policy.threat_feed.url.clone(),
            firewall_config.policy.threat_feed.refresh_interval_hours,
            firewall_config.policy.threat_feed.cache_path.clone(),
        );
    }

    // 3. MITM CA
    let mitm_ca = Arc::new(MitmCa::new()?);

    // 4. Prompt Coordinator
    let has_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
    let prompt_coordinator = Arc::new(PromptCoordinator::new(has_tty));

    // 5. Proxy Handler
    let proxy_handler = Arc::new(ProxyHandler::new(
        policy_engine,
        mitm_ca,
        prompt_coordinator,
        &firewall_config.policy,
    )?);

    // ── Start Listening ─────────────────────────────────────────

    let listener = TcpListener::bind(listen_addr).await?;
    info!("Local AI-Agent Firewall Proxy listening on http://{}", listen_addr);
    info!("Ensure your agent trusts the generated Root CA to avoid TLS errors.");

    // ── Accept Loop with Graceful Shutdown ───────────────────────

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, peer_addr)) => {
                        let io = TokioIo::new(stream);
                        let handler = proxy_handler.clone();

                        tokio::task::spawn(async move {
                            let service = service_fn(move |req| {
                                let handler = handler.clone();
                                async move { handler.handle_request(req).await }
                            });

                            if let Err(err) = http1::Builder::new()
                                .preserve_header_case(true)
                                .title_case_headers(true)
                                .serve_connection(io, service)
                                .with_upgrades()
                                .await
                            {
                                // Filter out common benign errors
                                let err_str = format!("{:?}", err);
                                if !err_str.contains("connection closed")
                                    && !err_str.contains("reset by peer")
                                {
                                    error!("Failed to serve connection from {}: {:?}", peer_addr, err);
                                }
                            }
                        });
                    }
                    Err(e) => {
                        // Log and continue — don't crash the proxy on accept errors
                        error!("Failed to accept connection: {}. Continuing...", e);
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Received SIGINT — shutting down gracefully.");
                break;
            }
        }
    }

    info!("Proxy stopped.");
    Ok(())
}

/// Spawns a background task that periodically refreshes the threat feed.
fn spawn_threat_feed_task(
    threat_feed: Arc<std::sync::RwLock<HashSet<String>>>,
    url: String,
    interval_hours: u64,
    cache_path: String,
) {
    tokio::spawn(async move {
        // Initial load: try download, fall back to cache
        load_or_refresh_threat_feed(&threat_feed, &url, &cache_path).await;

        // Periodic refresh
        let mut interval = tokio::time::interval(
            std::time::Duration::from_secs(interval_hours * 3600),
        );
        interval.tick().await; // skip the first immediate tick

        loop {
            interval.tick().await;
            info!("Refreshing threat feed...");
            load_or_refresh_threat_feed(&threat_feed, &url, &cache_path).await;
        }
    });
}

/// Attempts to download the threat feed. Falls back to cached data.
async fn load_or_refresh_threat_feed(
    threat_feed: &Arc<std::sync::RwLock<HashSet<String>>>,
    url: &str,
    cache_path: &str,
) {
    // Try downloading
    match download_threat_feed(url).await {
        Ok(raw_data) => {
            match policy::parse_threat_feed(&raw_data) {
                Ok(domains) => {
                    let count = domains.len();
                    if let Ok(mut feed) = threat_feed.write() {
                        *feed = domains;
                    }
                    // Save as last-known-good
                    policy::save_threat_feed_cache(cache_path, &raw_data);
                    info!("Threat feed loaded: {} domains from {}", count, url);
                }
                Err(e) => {
                    warn!("Downloaded threat feed is invalid: {}. Trying cache...", e);
                    load_from_cache(threat_feed, cache_path);
                }
            }
        }
        Err(e) => {
            warn!("Failed to download threat feed: {}. Trying cache...", e);
            load_from_cache(threat_feed, cache_path);
        }
    }
}

fn load_from_cache(
    threat_feed: &Arc<std::sync::RwLock<HashSet<String>>>,
    cache_path: &str,
) {
    if let Some(cached_domains) = policy::load_threat_feed_cache(cache_path) {
        let count = cached_domains.len();
        if let Ok(mut feed) = threat_feed.write() {
            *feed = cached_domains;
        }
        info!("Threat feed loaded from cache: {} domains", count);
    } else {
        warn!(
            "No threat feed available (download failed and no cache). \
             Threat feed tier is inactive — unknown hosts will rely on \
             allowlist + prompt only."
        );
    }
}

async fn download_threat_feed(url: &str) -> Result<String> {
    // Use a simple reqwest-less approach: shell out to curl or use hyper
    // For simplicity and to avoid adding reqwest, we use a basic hyper GET
    let uri: hyper::Uri = url.parse()?;
    let host = uri.host().unwrap_or("").to_string();
    let port = uri.port_u16().unwrap_or(if uri.scheme_str() == Some("https") { 443 } else { 80 });
    let addr = format!("{}:{}", host, port);

    let tcp = tokio::net::TcpStream::connect(&addr).await?;

    if uri.scheme_str() == Some("https") {
        // For HTTPS, we need a TLS connection
        let mut root_store = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().expect("load native certs") {
            root_store.add(cert).ok();
        }
        let tls_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        );
        let connector = tokio_rustls::TlsConnector::from(tls_config);
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())?;
        let tls_stream = connector.connect(server_name, tcp).await?;
        let io = TokioIo::new(tls_stream);

        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(async move { let _ = conn.await; });

        let req = hyper::Request::builder()
            .uri(uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/"))
            .header("host", &host)
            .header("user-agent", "Local-AI-Firewall/0.2")
            .body(http_body_util::Empty::<bytes::Bytes>::new())?;

        let res = sender.send_request(req).await?;
        let body = http_body_util::BodyExt::collect(res.into_body()).await?;
        Ok(String::from_utf8_lossy(&body.to_bytes()).to_string())
    } else {
        let io = TokioIo::new(tcp);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(async move { let _ = conn.await; });

        let req = hyper::Request::builder()
            .uri(uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/"))
            .header("host", &host)
            .header("user-agent", "Local-AI-Firewall/0.2")
            .body(http_body_util::Empty::<bytes::Bytes>::new())?;

        let res = sender.send_request(req).await?;
        let body = http_body_util::BodyExt::collect(res.into_body()).await?;
        Ok(String::from_utf8_lossy(&body.to_bytes()).to_string())
    }
}
