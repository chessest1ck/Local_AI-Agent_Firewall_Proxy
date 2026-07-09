use anyhow::Result;
use hyper::{Method, Request, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::process;
use tracing::error;
use http_body_util::Full;
use bytes::Bytes;

pub async fn run_shim(args: Vec<String>) -> Result<()> {
    // 1. Send the command to the firewall proxy for approval
    let payload = serde_json::json!({
        "command": args,
    });
    let body = Full::new(Bytes::from(payload.to_string()));

    let req = Request::builder()
        .method(Method::POST)
        .uri("http://127.0.0.1:8080/api/firewall/command")
        .header("Content-Type", "application/json")
        .body(body)?;

    let client = Client::builder(TokioExecutor::new()).build_http();

    match client.request(req).await {
        Ok(res) => {
            if !res.status().is_success() {
                error!("Command blocked by Local AI-Agent Firewall.");
                process::exit(1);
            }
        }
        Err(e) => {
            error!("Failed to reach Local AI-Agent Firewall: {}. Ensure proxy is running.", e);
            process::exit(1);
        }
    }

    // 2. If approved, execute the real command
    // We assume the real binary is in standard path, e.g., /bin/sh or /bin/bash
    // We can extract the exe name and find the absolute path.
    let exe_name = std::path::Path::new(&args[0])
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();

    let real_exe = format!("/bin/{}", exe_name);

    let mut cmd = std::process::Command::new(real_exe);
    cmd.args(&args[1..]);

    // Forward stdin/out/err
    cmd.stdin(std::process::Stdio::inherit());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            error!("Failed to spawn real command: {}", e);
            process::exit(1);
        }
    };

    let status = child.wait()?;
    process::exit(status.code().unwrap_or(1));
}
