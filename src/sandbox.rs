use anyhow::{Context, Result};
use std::fs;
use std::process;
use tracing::info;

pub fn run_sandbox(workspace: &str, command: &[String]) -> Result<()> {
    // macOS sandbox profiles evaluate real absolute paths
    let abs_workspace = fs::canonicalize(workspace)
        .context("Failed to canonicalize workspace path. Ensure it exists.")?;
    
    let workspace_path_str = abs_workspace.to_string_lossy();

    let profile_content = format!(r#"
(version 1)
(allow default)
(deny file-write*)
(allow file-write* (subpath "{}"))
(allow file-write* (subpath "/dev"))
"#, workspace_path_str);

    let temp_profile = "/tmp/agent_sandbox.sb";
    fs::write(temp_profile, profile_content).context("Failed to write sandbox profile")?;

    info!("Launching sandbox for workspace: {}", workspace_path_str);

    if command.is_empty() {
        return Err(anyhow::anyhow!("No command provided to run in sandbox"));
    }

    let mut cmd = process::Command::new("sandbox-exec");
    cmd.arg("-f")
       .arg(temp_profile)
       .args(command);

    cmd.stdin(process::Stdio::inherit());
    cmd.stdout(process::Stdio::inherit());
    cmd.stderr(process::Stdio::inherit());

    let mut child = cmd.spawn().context("Failed to spawn sandbox-exec")?;
    let status = child.wait()?;

    process::exit(status.code().unwrap_or(1));
}
