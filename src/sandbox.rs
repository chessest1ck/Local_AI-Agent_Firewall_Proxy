use crate::config::SandboxConfig;
use anyhow::{Context, Result};
use std::process;
use tracing::info;

pub fn run_sandbox(workspace: &str, command: &[String], config: Option<&SandboxConfig>) -> Result<()> {
    // macOS sandbox profiles evaluate real absolute paths
    let abs_workspace =
        std::fs::canonicalize(workspace).context("Failed to canonicalize workspace path. Ensure it exists.")?;

    let workspace_path_str = abs_workspace.to_string_lossy();

    // Build individual /dev write rules from config (not blanket subpath)
    let dev_rules = if let Some(cfg) = config {
        cfg.allowed_write_paths
            .iter()
            .map(|p| format!("(allow file-write* (literal \"{}\"))", p))
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        // Fallback: restrictive defaults
        ["/dev/null", "/dev/tty", "/dev/urandom", "/dev/random"]
            .iter()
            .map(|p| format!("(allow file-write* (literal \"{}\"))", p))
            .collect::<Vec<_>>()
            .join("\n")
    };

    let profile_content = format!(
        r#"
(version 1)
(allow default)
(deny file-write*)
(allow file-write* (subpath "{}"))
{}
"#,
        workspace_path_str, dev_rules
    );

    // Use tempfile to avoid TOCTOU race condition
    let temp_profile = tempfile::Builder::new()
        .prefix("agent_sandbox_")
        .suffix(".sb")
        .tempfile()
        .context("Failed to create temporary sandbox profile")?;

    std::fs::write(temp_profile.path(), profile_content)
        .context("Failed to write sandbox profile")?;

    info!("Launching sandbox for workspace: {}", workspace_path_str);

    if command.is_empty() {
        return Err(anyhow::anyhow!("No command provided to run in sandbox"));
    }

    let mut cmd = process::Command::new("sandbox-exec");
    cmd.arg("-f")
        .arg(temp_profile.path())
        .args(command);

    cmd.stdin(process::Stdio::inherit());
    cmd.stdout(process::Stdio::inherit());
    cmd.stderr(process::Stdio::inherit());

    let mut child = cmd.spawn().context("Failed to spawn sandbox-exec")?;
    let status = child.wait()?;

    // temp_profile is dropped here, cleaning up the temporary file
    process::exit(status.code().unwrap_or(1));
}
