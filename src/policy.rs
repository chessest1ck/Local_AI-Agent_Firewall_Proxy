use crate::config::{compile_dlp_rules, CompiledDlpRule, DlpConfig, PolicyConfig};
use dashmap::DashMap;
use std::collections::HashSet;
use std::io::Read;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use tracing::{debug, info, warn};

/// The verdict for a host check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostVerdict {
    /// Host is in the allowlist — auto-allow.
    Allowed,
    /// Host is blocked (with reason string).
    Blocked(String),
    /// Host is not in allowlist or threat feed — needs interactive prompt or fail-closed.
    Unknown,
}

/// A DLP violation found during body inspection.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DlpViolation {
    pub rule_name: String,
    pub severity: String,
    pub message: String,
}

/// The policy engine: host filtering (3-tier), DLP inspection, threat feed.
pub struct PolicyEngine {
    /// Normalized allowlist from config (lowercase, no trailing dots).
    allowlist: Vec<String>,
    /// Runtime allowlist — hosts the user approved with "always".
    runtime_allowlist: DashMap<String, ()>,
    /// Threat feed domains.
    threat_feed: Arc<RwLock<HashSet<String>>>,
    /// Compiled DLP regex rules.
    dlp_rules: Vec<CompiledDlpRule>,
    /// DLP configuration.
    dlp_config: DlpConfig,
    /// Whether to block IP literals.
    block_ip_literals: bool,
    /// Whether to block private IPs (DNS rebinding defense).
    pub block_private_ips: bool,
    /// Threat feed cache path for last-known-good persistence.
    #[allow(dead_code)]
    threat_feed_cache_path: String,
}

impl PolicyEngine {
    pub fn new(config: &PolicyConfig) -> anyhow::Result<Self> {
        let allowlist: Vec<String> = config
            .allowlist
            .hosts
            .iter()
            .map(|h| normalize_host(h).unwrap_or_else(|_| h.to_lowercase()))
            .collect();

        if allowlist.is_empty() {
            warn!("Allowlist is empty — ALL non-local hosts will trigger prompts or be blocked.");
        }

        let dlp_rules = compile_dlp_rules(&config.dlp.rules)?;
        info!("Compiled {} DLP rules.", dlp_rules.len());

        let threat_feed = Arc::new(RwLock::new(HashSet::new()));

        Ok(Self {
            allowlist,
            runtime_allowlist: DashMap::new(),
            threat_feed,
            dlp_rules,
            dlp_config: DlpConfig {
                max_inspect_bytes: config.dlp.max_inspect_bytes,
                oversized_action: config.dlp.oversized_action.clone(),
                decompress: config.dlp.decompress,
                skip_binary: config.dlp.skip_binary,
                rules: config.dlp.rules.clone(),
            },
            block_ip_literals: config.block_ip_literals,
            block_private_ips: config.block_private_ips,
            threat_feed_cache_path: config.threat_feed.cache_path.clone(),
        })
    }

    // ── Host Filtering ──────────────────────────────────────────

    /// Checks a raw host string through the 3-tier system.
    /// The host should already be normalized via `normalize_host()`.
    pub fn check_host(&self, normalized_host: &str) -> HostVerdict {
        // Tier 0: Check if it's an IP literal
        if self.block_ip_literals && normalized_host.parse::<IpAddr>().is_ok() {
            return HostVerdict::Blocked(format!(
                "Direct IP connections are blocked: {}",
                normalized_host
            ));
        }

        // Tier 1: Allowlist (config + runtime)
        if self.is_in_allowlist(normalized_host) {
            return HostVerdict::Allowed;
        }

        // Tier 2: Threat feed
        if self.is_in_threat_feed(normalized_host) {
            return HostVerdict::Blocked(format!(
                "Host {} found in threat feed (URLhaus)",
                normalized_host
            ));
        }

        // Tier 3: Unknown
        HostVerdict::Unknown
    }

    /// Checks if a host matches any entry in the config or runtime allowlist.
    /// Uses proper domain suffix matching at dot boundaries.
    fn is_in_allowlist(&self, host: &str) -> bool {
        // Check runtime allowlist first (fast path for "always" approvals)
        if self.runtime_allowlist.contains_key(host) {
            return true;
        }

        // Check config allowlist with suffix matching
        for entry in &self.allowlist {
            if domain_matches(host, entry) {
                return true;
            }
        }

        false
    }

    /// Adds a host to the runtime allowlist (user chose "always").
    pub fn add_runtime_allowlist(&self, host: &str) {
        info!("Adding to runtime allowlist: {}", host);
        self.runtime_allowlist.insert(host.to_string(), ());
    }

    /// Checks if a host is in the threat feed.
    fn is_in_threat_feed(&self, host: &str) -> bool {
        if let Ok(feed) = self.threat_feed.read() {
            if feed.contains(host) {
                info!("Threat feed match: {}", host);
                return true;
            }
            // Also check parent domains (e.g., sub.evil.com should match evil.com in feed)
            let parts: Vec<&str> = host.split('.').collect();
            for i in 1..parts.len().saturating_sub(1) {
                let parent = parts[i..].join(".");
                if feed.contains(&parent) {
                    info!("Threat feed match (parent domain): {} via {}", host, parent);
                    return true;
                }
            }
        }
        false
    }

    /// Returns a clone of the threat feed Arc for background refresh tasks.
    pub fn threat_feed_handle(&self) -> Arc<RwLock<HashSet<String>>> {
        self.threat_feed.clone()
    }

    /// Returns the threat feed cache path.
    pub fn threat_feed_cache_path(&self) -> &str {
        &self.threat_feed_cache_path
    }

    // ── DLP Inspection ──────────────────────────────────────────

    /// Inspects a request body for DLP violations.
    ///
    /// Returns `Ok(vec![])` if no violations, `Ok(vec![...])` with violations,
    /// or `Err` if the body should be blocked due to policy (e.g. oversized).
    pub fn inspect_body(
        &self,
        body_bytes: &[u8],
        content_type: Option<&str>,
        content_encoding: Option<&str>,
    ) -> Result<Vec<DlpViolation>, DlpAction> {
        // Check if binary content should be skipped
        if self.dlp_config.skip_binary && is_binary_content_type(content_type) {
            debug!("DLP: Skipping binary content type: {:?}", content_type);
            return Ok(vec![]);
        }

        // Size check on raw body
        if body_bytes.len() > self.dlp_config.max_inspect_bytes {
            return match self.dlp_config.oversized_action.as_str() {
                "block" => Err(DlpAction::BlockOversized),
                _ => {
                    warn!(
                        "DLP: Body size {} exceeds limit {} — passing uninspected.",
                        body_bytes.len(),
                        self.dlp_config.max_inspect_bytes
                    );
                    Ok(vec![])
                }
            };
        }

        // Decompress if needed
        let inspectable = if self.dlp_config.decompress {
            match decompress_body(body_bytes, content_encoding, self.dlp_config.max_inspect_bytes) {
                Ok(decompressed) => decompressed,
                Err(e) => {
                    warn!("DLP: Decompression failed ({}), inspecting raw bytes.", e);
                    body_bytes.to_vec()
                }
            }
        } else {
            body_bytes.to_vec()
        };

        // Post-decompression size check (decompression bomb defense)
        if inspectable.len() > self.dlp_config.max_inspect_bytes {
            return match self.dlp_config.oversized_action.as_str() {
                "block" => Err(DlpAction::BlockOversized),
                _ => {
                    warn!(
                        "DLP: Decompressed size {} exceeds limit {} — passing uninspected.",
                        inspectable.len(),
                        self.dlp_config.max_inspect_bytes
                    );
                    Ok(vec![])
                }
            };
        }

        let mut violations = Vec::new();

        // Try JSON traversal first
        let is_json = content_type
            .map(|ct| ct.contains("json"))
            .unwrap_or(false);

        if is_json
            && let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(&inspectable) {
                self.scan_json_value(&json_val, &mut violations);
                return Ok(violations);
            }

        // Fallback: scan raw text
        if let Ok(text) = std::str::from_utf8(&inspectable) {
            self.scan_text(text, &mut violations);
        }

        Ok(violations)
    }

    /// Recursively walks a JSON value, scanning all string fields.
    fn scan_json_value(&self, value: &serde_json::Value, violations: &mut Vec<DlpViolation>) {
        match value {
            serde_json::Value::String(s) => {
                self.scan_text(s, violations);
            }
            serde_json::Value::Array(arr) => {
                for item in arr {
                    self.scan_json_value(item, violations);
                }
            }
            serde_json::Value::Object(map) => {
                for (_key, val) in map {
                    self.scan_json_value(val, violations);
                }
            }
            _ => {} // numbers, bools, null — skip
        }
    }

    /// Scans a text string against all compiled DLP rules.
    fn scan_text(&self, text: &str, violations: &mut Vec<DlpViolation>) {
        for rule in &self.dlp_rules {
            if rule.regex.is_match(text) {
                info!("DLP violation [{}]: {}", rule.name, rule.message);
                violations.push(DlpViolation {
                    rule_name: rule.name.clone(),
                    severity: rule.severity.clone(),
                    message: rule.message.clone(),
                });
            }
        }
    }
}

/// Action to take when DLP can't inspect (e.g. oversized body).
#[derive(Debug)]
pub enum DlpAction {
    BlockOversized,
}

// ── Host Utilities ──────────────────────────────────────────────

/// Normalizes a hostname: lowercase, strip trailing dots, reject invalid chars.
pub fn normalize_host(host: &str) -> anyhow::Result<String> {
    // Reject null bytes and control characters
    if host.bytes().any(|b| b == 0 || (b < 32 && b != b'\t')) {
        anyhow::bail!("Invalid hostname: contains null bytes or control characters");
    }

    if host.is_empty() {
        anyhow::bail!("Invalid hostname: empty string");
    }

    let mut normalized = host.to_lowercase();
    // Strip trailing dots (DNS FQDN notation)
    while normalized.ends_with('.') {
        normalized.pop();
    }

    if normalized.is_empty() {
        anyhow::bail!("Invalid hostname: only dots");
    }

    Ok(normalized)
}

/// Parses a raw authority string into (host, optional port).
/// Handles: "host:port", "[::1]:port", "host", "[::1]"
pub fn parse_authority(authority: &str) -> anyhow::Result<(String, Option<u16>)> {
    if authority.is_empty() {
        anyhow::bail!("Empty authority string");
    }

    // Bracketed IPv6: [::1]:port or [::1]
    if authority.starts_with('[') {
        let close = authority
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("Malformed IPv6 authority: missing ']': {}", authority))?;
        let host = &authority[1..close];
        let rest = &authority[close + 1..];
        let port = if let Some(port_str) = rest.strip_prefix(':') {
            Some(
                port_str
                    .parse::<u16>()
                    .map_err(|_| anyhow::anyhow!("Invalid port in authority: {}", authority))?,
            )
        } else if rest.is_empty() {
            None
        } else {
            anyhow::bail!("Unexpected characters after IPv6 bracket: {}", authority);
        };
        return Ok((host.to_string(), port));
    }

    // Regular host:port or bare host
    // Count colons — if more than one, it's a bare IPv6 without brackets
    let colon_count = authority.chars().filter(|&c| c == ':').count();
    if colon_count > 1 {
        // Bare IPv6 address (no port)
        return Ok((authority.to_string(), None));
    }

    if let Some(colon_pos) = authority.rfind(':') {
        let host = &authority[..colon_pos];
        let port_str = &authority[colon_pos + 1..];
        if let Ok(port) = port_str.parse::<u16>() {
            return Ok((host.to_string(), Some(port)));
        }
        // Colon but no valid port — treat entire string as host
        return Ok((authority.to_string(), None));
    }

    // No colon — bare hostname
    Ok((authority.to_string(), None))
}

/// Checks if `host` matches an allowlist `entry` using proper domain
/// suffix matching at dot boundaries.
///
/// - `api.openai.com` matches `api.openai.com` ✅ (exact)
/// - `sub.api.openai.com` matches `api.openai.com` ✅ (subdomain)
/// - `evilapi.openai.com` does NOT match `api.openai.com` ❌ (not at dot boundary)
fn domain_matches(host: &str, entry: &str) -> bool {
    if host == entry {
        return true;
    }
    // host must end with ".{entry}" for subdomain match
    if host.len() > entry.len() {
        let suffix = &host[host.len() - entry.len()..];
        let preceding_char = host.as_bytes()[host.len() - entry.len() - 1];
        return suffix == entry && preceding_char == b'.';
    }
    false
}

/// Checks if a Content-Type header indicates binary content.
fn is_binary_content_type(content_type: Option<&str>) -> bool {
    let ct = match content_type {
        Some(ct) => ct.to_lowercase(),
        None => return false, // Unknown — inspect to be safe
    };
    ct.starts_with("image/")
        || ct.starts_with("audio/")
        || ct.starts_with("video/")
        || ct.contains("octet-stream")
        || ct.contains("zip")
        || ct.contains("tar")
        || ct.contains("gzip")
        || ct.contains("pdf")
        || ct.contains("protobuf")
}

/// Decompresses a body based on Content-Encoding, with a size cap.
fn decompress_body(
    data: &[u8],
    encoding: Option<&str>,
    max_bytes: usize,
) -> anyhow::Result<Vec<u8>> {
    let enc = match encoding {
        Some(e) => e.to_lowercase(),
        None => return Ok(data.to_vec()), // No encoding — return as-is
    };

    match enc.as_str() {
        "gzip" => {
            let decoder = flate2::read::GzDecoder::new(data);
            let mut buf = Vec::with_capacity(data.len() * 2);
            // Read with size limit
            decoder.take(max_bytes as u64 + 1).read_to_end(&mut buf)?;
            Ok(buf)
        }
        "deflate" => {
            let decoder = flate2::read::DeflateDecoder::new(data);
            let mut buf = Vec::with_capacity(data.len() * 2);
            decoder.take(max_bytes as u64 + 1).read_to_end(&mut buf)?;
            Ok(buf)
        }
        "br" => {
            let decoder = brotli::Decompressor::new(data, 4096);
            let mut buf = Vec::with_capacity(data.len() * 2);
            decoder.take(max_bytes as u64 + 1).read_to_end(&mut buf)?;
            Ok(buf)
        }
        "identity" => Ok(data.to_vec()),
        other => {
            warn!("DLP: Unknown Content-Encoding '{}', inspecting raw.", other);
            Ok(data.to_vec())
        }
    }
}

// ── Threat Feed ──────────────────────────────────────────────

/// Parses a URLhaus-style hostfile into a set of domain names.
/// Validates the data format — rejects HTML, binary, and files with
/// too few valid hostfile lines.
pub fn parse_threat_feed(data: &str) -> anyhow::Result<HashSet<String>> {
    let mut domains = HashSet::new();
    let mut valid_lines = 0;

    for line in data.lines() {
        let trimmed = line.trim();
        // Skip comments and empty lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Expect lines like "127.0.0.1 malware.example.com" or "0.0.0.0 malware.example.com"
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 2 && (parts[0] == "127.0.0.1" || parts[0] == "0.0.0.0") {
            let domain = parts[1].to_lowercase();
            // Basic domain format validation
            if domain.contains('.')
                && !domain.contains('<')
                && !domain.contains('>')
                && !domain.contains('/')
            {
                domains.insert(domain);
                valid_lines += 1;
            }
        }
    }

    // Sanity check: a real hostfile should have many entries
    if valid_lines < 10 {
        anyhow::bail!(
            "Threat feed data doesn't look like a valid hostfile (only {} valid entries, expected ≥10)",
            valid_lines
        );
    }

    Ok(domains)
}

/// Loads the threat feed from cache (last-known-good).
pub fn load_threat_feed_cache(cache_path: &str) -> Option<HashSet<String>> {
    match std::fs::read_to_string(cache_path) {
        Ok(data) => match parse_threat_feed(&data) {
            Ok(domains) => {
                info!("Loaded {} domains from threat feed cache: {}", domains.len(), cache_path);
                Some(domains)
            }
            Err(e) => {
                warn!("Threat feed cache is invalid ({}): {}", cache_path, e);
                None
            }
        },
        Err(_) => {
            debug!("No threat feed cache file found at: {}", cache_path);
            None
        }
    }
}

/// Saves threat feed data to the cache file.
pub fn save_threat_feed_cache(cache_path: &str, raw_data: &str) {
    if let Err(e) = std::fs::write(cache_path, raw_data) {
        warn!("Failed to save threat feed cache to {}: {}", cache_path, e);
    } else {
        debug!("Saved threat feed cache to: {}", cache_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_host() {
        assert_eq!(normalize_host("API.OpenAI.COM").unwrap(), "api.openai.com");
        assert_eq!(normalize_host("api.openai.com.").unwrap(), "api.openai.com");
        assert_eq!(normalize_host("api.openai.com...").unwrap(), "api.openai.com");
        assert!(normalize_host("").is_err());
        assert!(normalize_host(".").is_err());
        assert!(normalize_host("host\0name").is_err());
    }

    #[test]
    fn test_parse_authority() {
        let (h, p) = parse_authority("api.openai.com:443").unwrap();
        assert_eq!(h, "api.openai.com");
        assert_eq!(p, Some(443));

        let (h, p) = parse_authority("[::1]:8080").unwrap();
        assert_eq!(h, "::1");
        assert_eq!(p, Some(8080));

        let (h, p) = parse_authority("example.com").unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, None);

        let (h, p) = parse_authority("[::1]").unwrap();
        assert_eq!(h, "::1");
        assert_eq!(p, None);

        assert!(parse_authority("").is_err());
        assert!(parse_authority("[::1").is_err());
    }

    #[test]
    fn test_domain_matches() {
        // Exact match
        assert!(domain_matches("api.openai.com", "api.openai.com"));
        // Subdomain match
        assert!(domain_matches("sub.api.openai.com", "api.openai.com"));
        // NOT a subdomain (no dot boundary)
        assert!(!domain_matches("evilapi.openai.com", "api.openai.com"));
        // Shorter host than entry
        assert!(!domain_matches("openai.com", "api.openai.com"));
    }

    #[test]
    fn test_parse_threat_feed_valid() {
        let data = (0..20)
            .map(|i| format!("127.0.0.1 malware{}.example.com", i))
            .collect::<Vec<_>>()
            .join("\n");
        let result = parse_threat_feed(&data).unwrap();
        assert_eq!(result.len(), 20);
        assert!(result.contains("malware0.example.com"));
    }

    #[test]
    fn test_parse_threat_feed_rejects_html() {
        let data = "<html><body>Error 503</body></html>";
        assert!(parse_threat_feed(data).is_err());
    }

    #[test]
    fn test_parse_threat_feed_rejects_too_few() {
        let data = "127.0.0.1 evil.com\n127.0.0.1 bad.com";
        assert!(parse_threat_feed(data).is_err());
    }

    #[test]
    fn test_is_binary_content_type() {
        assert!(is_binary_content_type(Some("image/png")));
        assert!(is_binary_content_type(Some("application/octet-stream")));
        assert!(is_binary_content_type(Some("application/zip")));
        assert!(!is_binary_content_type(Some("application/json")));
        assert!(!is_binary_content_type(Some("text/plain")));
        assert!(!is_binary_content_type(None));
    }
}
