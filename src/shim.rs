use anyhow::Result;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Request};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::process;
use tracing::{error, info};

pub async fn run_shim(args: Vec<String>) -> Result<()> {
    if args.is_empty() {
        anyhow::bail!("Shim invoked with empty arguments — nothing to execute.");
    }

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
            error!(
                "Failed to reach Local AI-Agent Firewall: {}. Ensure proxy is running.",
                e
            );
            process::exit(1);
        }
    }

    // 2. If approved, find the real binary via PATH resolution
    let exe_name = std::path::Path::new(&args[0])
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let real_exe = find_real_executable(&exe_name);
    info!("Shim: resolved '{}' to '{}'", exe_name, real_exe);

    let mut cmd = std::process::Command::new(&real_exe);
    cmd.args(&args[1..]);

    // Forward stdin/out/err
    cmd.stdin(std::process::Stdio::inherit());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            error!("Failed to spawn real command '{}': {}", real_exe, e);
            process::exit(1);
        }
    };

    let status = child.wait()?;
    process::exit(status.code().unwrap_or(1));
}

/// Finds the real executable by walking $PATH, skipping directories
/// that contain the shim. Falls back to /bin/ and /usr/bin/.
fn find_real_executable(exe_name: &str) -> String {
    // Get the shim directory to skip
    let shim_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));

    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(':') {
            // Skip the shim directory
            if let Some(ref sd) = shim_dir
                && let Ok(canonical_dir) = std::fs::canonicalize(dir)
                    && let Ok(canonical_shim) = std::fs::canonicalize(sd)
                        && canonical_dir == canonical_shim {
                            continue;
                        }

            let candidate = std::path::Path::new(dir).join(exe_name);
            if candidate.exists() && candidate.is_file() {
                return candidate.to_string_lossy().to_string();
            }
        }
    }

    // Fallback chain
    for prefix in &["/bin", "/usr/bin"] {
        let candidate = format!("{}/{}", prefix, exe_name);
        if std::path::Path::new(&candidate).exists() {
            return candidate;
        }
    }

    // Last resort — hope the system finds it
    format!("/bin/{}", exe_name)
}
