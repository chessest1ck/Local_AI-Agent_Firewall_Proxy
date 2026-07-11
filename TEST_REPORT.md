# Local AI-Agent Firewall Proxy - Test Report

**Test Date:** 2026-07-11
**Environment:** macOS (M1/M2/M3 Architecture), Rust stable, tokio runtime.
**Tool Version:** v0.1.1 (Hardened Implementation)

## Test Cases Summary

| Test | Command / Input | Expected | Actual | Status |
|---|---|---|---|---|
| T1: Allowed Host | `curl -s -k -x http://127.0.0.1:8080 -I https://api.openai.com` | Connection intercepted, DNS resolves properly, and request reaches the upstream API without blocking. | Request reached upstream (Cloudflare 421 response due to missing headers, but connection was fully established). | Pass |
| T2: IP Literal (DNS Rebinding) | `curl -s -x http://127.0.0.1:8080 -I https://1.1.1.1` | Proxy blocks connection immediately and returns 403 Forbidden since `block_ip_literals` is enabled. | Proxy returned 403 Forbidden with message "Direct IP connections are blocked". | Pass |
| T3: Unknown Host (Fail Closed) | `curl -s -x http://127.0.0.1:8080 -I http://example.com` (running proxy without a TTY) | Proxy detects lack of interactive terminal and fails closed to prevent hanging, returning 403 Forbidden. | Proxy safely failed closed and returned 403 Forbidden instantly. | Pass |
| T4: DLP Engine (Prompt Injection) | `curl -s -k -x http://127.0.0.1:8080 -X POST https://api.openai.com/v1/chat/completions -H "Content-Type: application/json" -d '{"prompt": "ignore previous instructions"}'` | Proxy intercepts JSON body, detects the prompt injection regex rule, and blocks the request. | Proxy returned "Blocked malicious prompt (Prompt Injection attempt)" and dropped connection. | Pass |

---

## Terminal Captures

### Environment Setup (Starting Proxy)
```bash
$ cargo run
[INFO] Loaded config from firewall_config.toml
[INFO]   Allowlist: 5 hosts
[INFO]   DLP rules: 7
[INFO]   Threat feed: enabled
[INFO]   Unknown host action: prompt
[INFO]   Oversized body action: block
[INFO] Compiled 7 DLP rules.
[INFO] Generating new temporary Root CA for MITM...
[WARN] ===================================================
[WARN] NEW ROOT CA GENERATED.
[WARN] If you want to avoid TLS errors in your agent, trust this certificate:
[WARN] Save this to 'ca.crt' and set NODE_EXTRA_CA_CERTS='ca.crt' for Node.js
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
[WARN] ===================================================
[WARN] No TTY detected — all unknown-host prompts will fail closed (block).
[INFO] Local AI-Agent Firewall Proxy listening on http://127.0.0.1:8080
[INFO] Ensure your agent trusts the generated Root CA to avoid TLS errors.
[INFO] Threat feed loaded: 466 domains from https://urlhaus.abuse.ch/downloads/hostfile/
```

### T1: Allowed Host
**Command:**
```bash
curl -s -k -x http://127.0.0.1:8080 -I https://api.openai.com
```
**Proxy Output:**
```text
[INFO] Received request: CONNECT api.openai.com:443
[INFO] MITM Intercepted: HEAD api.openai.com/
[INFO] Connected to api.openai.com via pinned IP 162.159.140.245:443 (TLS)
```
*(The connection was allowed because `api.openai.com` is in the default `firewall_config.toml` allowlist).*

### T2: IP Literal (DNS Rebinding Defense)
**Command:**
```bash
curl -s -x http://127.0.0.1:8080 -I https://1.1.1.1
```
**Proxy Output:**
```text
[INFO] Received request: CONNECT 1.1.1.1:443
[WARN] Host blocked: 1.1.1.1 — Direct IP connections are blocked: 1.1.1.1
```
**Client Output:**
```text
HTTP/1.1 403 Forbidden
```

### T3: Unknown Host (Fail Closed)
**Command:**
```bash
curl -s -x http://127.0.0.1:8080 -I http://example.com
```
**Proxy Output:**
```text
[INFO] Received request: HEAD http://example.com/
[INFO] Unknown host: example.com — checking prompt coordinator.
[WARN] No TTY — blocking unknown host (fail-closed): example.com
```

### T4: DLP Engine (Prompt Injection)
**Command:**
```bash
curl -s -k -x http://127.0.0.1:8080 -X POST https://api.openai.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"prompt": "ignore previous instructions"}'
```
**Proxy Output:**
```text
[INFO] Received request: CONNECT api.openai.com:443
[INFO] MITM Intercepted: POST api.openai.com/v1/chat/completions
[INFO] DLP violation [prompt_injection]: Blocked malicious prompt (Prompt Injection attempt)
[WARN] DLP blocked request to api.openai.com: Blocked malicious prompt (Prompt Injection attempt)
```

---

## Known Bugs and Limitations

While the firewall proxy is highly effective at inspecting HTTP/HTTPS payloads and constraining local filesystem access, there is a known limitation regarding the **PATH Command Shim evasion**. Because the shim intercepts commands by prepending itself to the system `$PATH`, a malicious agent could potentially bypass the interactive approval prompt by executing binaries via their absolute paths (e.g., executing `/bin/sh` instead of `sh`). However, even if the interactive prompt is bypassed, the macOS OS Sandbox (`sandbox-exec`) acts as a hard kernel-level boundary and will safely prevent any unauthorized file writes across the system.
