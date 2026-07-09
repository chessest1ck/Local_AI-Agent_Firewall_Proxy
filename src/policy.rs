use tracing::info;

pub struct PolicyEngine;

impl PolicyEngine {
    pub fn new() -> Self {
        Self
    }

    /// Checks if a domain is allowed to be accessed via HTTP CONNECT
    pub fn is_host_allowed(&self, host: &str) -> bool {
        if host.contains("evil.com") {
            info!("Policy Engine: Blocking host {}", host);
            return false;
        }
        true
    }

    /// Inspects the JSON payload (DLP) for sensitive information
    pub fn inspect_json_payload(&self, json_bytes: &[u8]) -> bool {
        // Parse the body as JSON if possible
        if let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(json_bytes) {
            // Check for specific forbidden patterns in the JSON tree
            let json_str = json_val.to_string().to_lowercase();
            if json_str.contains("ignore previous instructions") {
                info!("Policy Engine (DLP): Blocked malicious prompt (Prompt Injection attempt)");
                return false;
            }
            if json_str.contains("BEGIN RSA PRIVATE KEY") || json_str.contains("sk-") {
                info!("Policy Engine (DLP): Blocked potential secret leakage");
                return false;
            }
        }
        true
    }
}
