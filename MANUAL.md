# Local AI-Agent Firewall Proxy - User Manual

Welcome to the Local AI-Agent Firewall Proxy! This manual provides step-by-step instructions for installing, configuring, and using the tool to secure your local AI agents.

---

## 1. Requirements & Supported Environment
- **Operating System:** macOS (Required for the `sandbox` command. The network proxy and `shim` commands work on Linux/macOS).
- **Dependencies:** Rust and Cargo (Install via [rustup.rs](https://rustup.rs/)).
- **Target Applications:** Any AI Agent, script, or CLI tool that supports `HTTP_PROXY` environment variables and relies on system `$PATH` for command execution.

---

## 2. Installation Instructions

1. **Clone the repository:**
   ```bash
   git clone https://github.com/chessest1ck/Local_AI-Agent_Firewall_Proxy.git
   cd Local_AI-Agent_Firewall_Proxy
   ```

2. **Build the binary:**
   ```bash
   cargo build
   ```

3. **Generate the Command Shim:**
   The shim allows the firewall to intercept commands like `sh` and `bash`.
   ```bash
   mkdir -p shim
   ln -sf ../target/debug/Local_AI-Agent_Firewall_Proxy shim/sh
   ln -sf ../target/debug/Local_AI-Agent_Firewall_Proxy shim/bash
   ```

---

## 3. Explanation of Commands and Modes

The tool operates using a single binary that handles three distinct modes based on how it is invoked:

- **Mode 1: The Proxy Server (`cargo run`)**
  Starts the MITM HTTP/HTTPS proxy on `127.0.0.1:8080`. It loads rules from `firewall_config.toml`, performs Deep Packet Inspection (DPI), enforces a 3-tier host filter (Allowlist, Threat Feed, User Prompt), prevents DNS rebinding, and listens for internal API requests from the command shim.

- **Mode 2: The Command Shim (Invoked via symlink like `sh`)**
  When the binary is executed via a symlink named `sh` or `bash`, it operates as a shim. It reads the command arguments, forwards them to the running Proxy Server for user approval, and only executes the real `/bin/sh` if approved.

- **Mode 3: The OS Sandbox (`Local_AI-Agent_Firewall_Proxy sandbox <workspace> <command>`)**
  Dynamically generates a macOS Seatbelt (`.sb`) profile safely via `tempfile` and launches the `<command>` inside a kernel-level sandbox that explicitly denies write access anywhere outside the `<workspace>`.

---

## 4. Configuration (`firewall_config.toml`)

The proxy uses `firewall_config.toml` in the project root to control its behavior.
Key settings:
- **`[policy]`**: Controls the `unknown_host_action` ("prompt" or "block"), and features like `block_private_ips` (DNS rebinding defense).
- **`[policy.allowlist]`**: List of auto-approved domains (e.g., `"api.openai.com"`). Supports automatic subdomain matching.
- **`[policy.threat_feed]`**: Toggles the URLhaus malicious host blocklist and sets its auto-refresh interval.
- **`[policy.dlp]`**: Configures Data Loss Prevention rules. You can define maximum payload sizes (`max_inspect_bytes`), whether to decompress payloads, and custom regex `[[policy.dlp.rules]]` to block sensitive data leakage (e.g. Prompt Injections, AWS Keys).

*A sample configuration file can be found in `examples/firewall_config_sample.toml`.*

---

## 5. Step-by-Step Usage Guide (Worked Example)

Here is a complete end-to-end example of securing a hypothetical agent called `claude`.

### Step A: Start the Proxy
In **Terminal Window 1**, start the firewall:
```bash
cargo run
```
**Expected Output:**
```text
[INFO] Loaded config from firewall_config.toml
[INFO] Generating new temporary Root CA for MITM...
===================================================
NEW ROOT CA GENERATED.
If you want to avoid TLS errors in your agent, trust this certificate:
Save this to 'ca.crt' and set NODE_EXTRA_CA_CERTS='ca.crt' for Node.js
-----BEGIN CERTIFICATE-----
MIIB6TCCAZCgAwIBAgIUedI8... (certificate omitted) ...
-----END CERTIFICATE-----
===================================================
[INFO] Local AI-Agent Firewall Proxy listening on http://127.0.0.1:8080
```

### Step B: Configure the Agent Environment
In **Terminal Window 2**, save the certificate output from Step A into a file named `ca.crt`. 
Then, configure your environment variables to route traffic through the proxy and enable the shim:
```bash
export HTTP_PROXY="http://127.0.0.1:8080"
export HTTPS_PROXY="http://127.0.0.1:8080"
export NODE_EXTRA_CA_CERTS="$(pwd)/ca.crt"
export PATH="$(pwd)/shim:$PATH"
```

### Step C: Launch the Agent in the Sandbox
Still in **Terminal Window 2**, launch your agent inside the sandbox. We will give it write access *only* to a folder named `~/my_project`.
```bash
./target/debug/Local_AI-Agent_Firewall_Proxy sandbox ~/my_project claude
```
*(The agent is now running with better security. All network traffic is monitored, all shell commands require approval, and all file writes outside `~/my_project` are blocked by the OS).*

### Step D: Intercepting Malicious Activity
If the agent attempts to run a dangerous command (e.g., `sh -c "rm -rf ~/.ssh"`), it will pause.
Check **Terminal Window 1** (the proxy server). You will see:
```text
[WARNING] Agent wants to run command:
> sh -c rm -rf ~/.ssh
Approve? [y/N]: 
```
Type `n` and press Enter. The proxy will output `[INFO] Command denied by user.` and the agent's command will instantly fail.

---

## 6. Output Fields (Logs)
The Proxy Server generates highly readable logs:
- **`[WARN] DLP blocked request...`**: The Deep Packet Inspection detected a prompt injection or secret leakage and blocked the HTTP request.
- **`[WARN] Host blocked: 1.1.1.1...`**: The proxy blocked a direct IP connection or a malicious domain.
- **`[WARN] NEW ROOT CA GENERATED`**: Prints the dynamic certificate needed to decrypt TLS traffic.
- **`[INFO] Command approved/denied`**: The result of your interactive `y/N` terminal prompt.

---

## 7. Troubleshooting

**Error: "Certificate verify failed" or "TLS Error" in Agent**
- *Cause:* The agent does not trust the Proxy's temporary Root CA.
- *Fix:* Ensure you saved the *exact* certificate printed by the proxy to `ca.crt`, and that your agent supports the environment variable you set (e.g., `NODE_EXTRA_CA_CERTS` for Node.js, `REQUESTS_CA_BUNDLE` for Python). Note: The certificate changes every time you restart the proxy!

**Error: "Failed to canonicalize workspace path"**
- *Cause:* The workspace path provided to the `sandbox` command does not exist.
- *Fix:* Ensure the directory exists (e.g., `mkdir ~/my_project`) before launching the sandbox.

**Error: "No TTY — blocking unknown host (fail-closed)"**
- *Cause:* An unknown host was encountered, but the proxy is running in the background without a terminal to prompt the user.
- *Fix:* Run the proxy in a foreground terminal, or add the domain to `firewall_config.toml` allowlist.

**Agent bypasses the interactive `y/N` prompt**
- *Cause:* The agent is executing commands using absolute paths (e.g., calling `/bin/sh` directly instead of `sh`).
- *Fix:* The shim relies on `$PATH`. If the agent hardcodes `/bin/sh`, the shim is bypassed. However, the OS Sandbox (Phase 3) still applies and will block malicious file writes regardless.
