# Local AI-Agent Firewall Proxy - Examples

This directory contains safe sample configurations and payloads to test the functionality of the Local AI-Agent Firewall Proxy.

## Included Files

- `firewall_config_sample.toml`: A heavily commented sample configuration file that demonstrates how to set up the allowlist, configure the threat feed, and write custom Data Loss Prevention (DLP) rules using regular expressions.
- `agent_payload_sample.json`: A benign sample JSON payload that represents a malicious prompt injection attempt. You can use this to verify that the firewall's DPI engine successfully catches and blocks the payload.

## How to Test

To test the Deep Packet Inspection (DPI) against the sample payload:

1. Copy the sample config to your project root if you haven't already:
   ```bash
   cp examples/firewall_config_sample.toml firewall_config.toml
   ```
2. Start the proxy in the background:
   ```bash
   cargo run &
   ```
3. Use curl to send the sample payload through the proxy. We will simulate an agent sending a malicious prompt to `api.openai.com`:
   ```bash
   curl -s -k -x http://127.0.0.1:8080 -X POST https://api.openai.com/v1/chat/completions \
     -H "Content-Type: application/json" \
     -d @examples/agent_payload_sample.json
   ```
4. Check the proxy terminal output. You should see a log message similar to:
   ```text
   [WARN] DLP blocked request to api.openai.com: Blocked malicious prompt (Prompt Injection attempt)
   ```
