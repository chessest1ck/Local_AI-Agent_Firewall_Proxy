use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use std::path::Path;
use tracing::info;

/// Top-level configuration for the firewall proxy.
#[derive(Debug, Deserialize)]
pub struct FirewallConfig {
    pub proxy: ProxyConfig,
    pub policy: PolicyConfig,
    pub sandbox: SandboxConfig,
}

#[derive(Debug, Deserialize)]
pub struct ProxyConfig {
    pub listen_addr: String,
    pub listen_port: u16,
}

#[derive(Debug, Deserialize)]
pub struct PolicyConfig {
    /// "prompt" or "block" — action for unknown hosts when TTY is available.
    pub unknown_host_action: String,
    /// Seconds to wait for user prompt before auto-denying.
    pub prompt_timeout_secs: u64,
    /// Block direct IP-address connections.
    pub block_ip_literals: bool,
    /// Block connections resolving to private/reserved IPs (DNS rebinding defense).
    pub block_private_ips: bool,
    pub allowlist: AllowlistConfig,
    pub threat_feed: ThreatFeedConfig,
    pub dlp: DlpConfig,
}

#[derive(Debug, Deserialize)]
pub struct AllowlistConfig {
    pub hosts: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ThreatFeedConfig {
    pub enabled: bool,
    pub url: String,
    pub refresh_interval_hours: u64,
    pub cache_path: String,
}

#[derive(Debug, Deserialize)]
pub struct DlpConfig {
    /// Maximum body size in bytes to buffer for inspection.
    pub max_inspect_bytes: usize,
    /// "block" or "pass" when body exceeds max_inspect_bytes.
    pub oversized_action: String,
    /// Whether to decompress gzip/deflate/br before inspection.
    pub decompress: bool,
    /// Skip DLP for non-text content types.
    pub skip_binary: bool,
    pub rules: Vec<DlpRuleConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DlpRuleConfig {
    pub name: String,
    pub pattern: String,
    pub severity: String,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct SandboxConfig {
    pub allowed_write_paths: Vec<String>,
}

/// A compiled DLP rule ready for use at runtime.
#[derive(Debug)]
pub struct CompiledDlpRule {
    pub name: String,
    pub regex: Regex,
    pub severity: String,
    pub message: String,
}

/// Loads and validates the firewall configuration from a TOML file.
pub fn load_config(path: &str) -> Result<FirewallConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path))?;
    let config: FirewallConfig = toml::from_str(&content)
        .with_context(|| format!("Failed to parse config file: {}", path))?;

    // Validate
    if config.policy.prompt_timeout_secs == 0 {
        anyhow::bail!("prompt_timeout_secs must be > 0");
    }
    if config.policy.dlp.max_inspect_bytes == 0 {
        anyhow::bail!("max_inspect_bytes must be > 0");
    }
    match config.policy.dlp.oversized_action.as_str() {
        "block" | "pass" => {}
        other => anyhow::bail!("Invalid oversized_action '{}': must be 'block' or 'pass'", other),
    }
    match config.policy.unknown_host_action.as_str() {
        "prompt" | "block" => {}
        other => anyhow::bail!("Invalid unknown_host_action '{}': must be 'prompt' or 'block'", other),
    }

    info!("Loaded config from {}", path);
    info!("  Allowlist: {} hosts", config.policy.allowlist.hosts.len());
    info!("  DLP rules: {}", config.policy.dlp.rules.len());
    info!("  Threat feed: {}", if config.policy.threat_feed.enabled { "enabled" } else { "disabled" });
    info!("  Unknown host action: {}", config.policy.unknown_host_action);
    info!("  Oversized body action: {}", config.policy.dlp.oversized_action);

    Ok(config)
}

/// Pre-compiles DLP regex patterns. Fails fast on invalid patterns.
pub fn compile_dlp_rules(rules: &[DlpRuleConfig]) -> Result<Vec<CompiledDlpRule>> {
    rules
        .iter()
        .map(|r| {
            let regex = Regex::new(&r.pattern)
                .with_context(|| format!("Invalid regex in DLP rule '{}': {}", r.name, r.pattern))?;
            Ok(CompiledDlpRule {
                name: r.name.clone(),
                regex,
                severity: r.severity.clone(),
                message: r.message.clone(),
            })
        })
        .collect()
}

/// Finds the config file, checking a CLI-specified path first,
/// then falling back to `./firewall_config.toml`.
pub fn resolve_config_path(cli_path: Option<&str>) -> Result<String> {
    if let Some(p) = cli_path {
        if Path::new(p).exists() {
            return Ok(p.to_string());
        }
        anyhow::bail!("Specified config file not found: {}", p);
    }
    let default = "firewall_config.toml";
    if Path::new(default).exists() {
        return Ok(default.to_string());
    }
    anyhow::bail!(
        "No config file found. Create '{}' or specify one with --config <path>",
        default
    );
}
