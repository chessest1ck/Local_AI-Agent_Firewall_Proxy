mod policy;
mod proxy;
mod shim;
mod sandbox;
mod tls;

use anyhow::Result;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::env;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info};

use policy::PolicyEngine;
use proxy::ProxyHandler;
use tls::MitmCa;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = env::args().collect();
    if !args.is_empty() {
        let exe_name = Path::new(&args[0]).file_name().unwrap_or_default().to_string_lossy();
        
        // Handle sandbox command
        if args.get(1).map(|s| s.as_str()) == Some("sandbox") {
            if args.len() < 4 {
                error!("Usage: Local_AI-Agent_Firewall_Proxy sandbox <workspace_dir> <command...>");
                std::process::exit(1);
            }
            let workspace = &args[2];
            let cmd_args = &args[3..];
            if let Err(e) = sandbox::run_sandbox(workspace, cmd_args) {
                error!("Sandbox error: {:?}", e);
                std::process::exit(1);
            }
            return Ok(());
        }

        // If invoked via symlink (sh, bash) or explicitly passed "shim"
        if exe_name == "sh" || exe_name == "bash" || args.get(1).map(|s| s.as_str()) == Some("shim") {
            // Remove the "shim" argument if passed explicitly via `cargo run -- shim`
            let shim_args = if args.get(1).map(|s| s.as_str()) == Some("shim") {
                args[2..].to_vec()
            } else {
                args
            };
            return shim::run_shim(shim_args).await;
        }
    }

    // 1. Initialize our Root CA for MITM
    let mitm_ca = Arc::new(MitmCa::new()?);

    // 2. Initialize our Policy Engine (DLP, Allow/Deny lists)
    let policy_engine = Arc::new(PolicyEngine::new());

    // 3. Initialize Proxy Handler
    let proxy_handler = Arc::new(ProxyHandler::new(policy_engine, mitm_ca));

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    let listener = TcpListener::bind(addr).await?;
    info!("Local AI-Agent Firewall Proxy listening on http://{}", addr);
    info!("Ensure your agent trusts the generated Root CA to avoid TLS errors.");

    loop {
        let (stream, _) = listener.accept().await?;
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
                error!("Failed to serve connection: {:?}", err);
            }
        });
    }
}
