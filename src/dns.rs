use anyhow::{Context, Result};
use rustls::pki_types::ServerName;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, info};

/// Resolves a hostname and validates that none of the resolved IPs are
/// in private/reserved ranges. Returns the first valid public SocketAddr.
pub async fn resolve_and_validate(host: &str, port: u16) -> Result<SocketAddr> {
    let lookup = format!("{}:{}", host, port);
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&lookup)
        .await
        .with_context(|| format!("DNS resolution failed for {}", host))?
        .collect();

    if addrs.is_empty() {
        anyhow::bail!("DNS resolution returned no addresses for {}", host);
    }

    // Check ALL resolved IPs — if any is private, block the whole thing
    for addr in &addrs {
        if is_private_ip(&addr.ip()) {
            anyhow::bail!(
                "DNS rebinding defense: {} resolved to private/reserved IP {}",
                host,
                addr.ip()
            );
        }
    }

    let chosen = addrs[0];
    debug!("DNS resolved {} → {} (validated as public)", host, chosen);
    Ok(chosen)
}

/// Checks if an IP address belongs to a private, reserved, or loopback range.
///
/// Blocked ranges:
/// - 127.0.0.0/8        — Loopback
/// - 10.0.0.0/8         — RFC 1918 private
/// - 172.16.0.0/12      — RFC 1918 private
/// - 192.168.0.0/16     — RFC 1918 private
/// - 169.254.0.0/16     — Link-local
/// - 0.0.0.0/8          — "This" network
/// - 100.64.0.0/10      — Shared address (CGNAT)
/// - 192.0.0.0/24       — IETF Protocol Assignments
/// - 192.0.2.0/24       — TEST-NET-1
/// - 198.51.100.0/24    — TEST-NET-2
/// - 203.0.113.0/24     — TEST-NET-3
/// - 198.18.0.0/15      — Benchmarking
/// - 224.0.0.0/4        — Multicast
/// - 240.0.0.0/4        — Reserved
/// - 255.255.255.255/32 — Broadcast
/// - ::1/128            — IPv6 loopback
/// - fc00::/7           — IPv6 unique local
/// - fe80::/10          — IPv6 link-local
/// - ::ffff:0:0/96      — IPv4-mapped IPv6 (checked recursively)
pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_ipv4(v4),
        IpAddr::V6(v6) => is_private_ipv6(v6),
    }
}

fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 0.0.0.0/8
    if octets[0] == 0 {
        return true;
    }
    // 10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }
    // 100.64.0.0/10 (CGNAT)
    if octets[0] == 100 && (octets[1] & 0xC0) == 64 {
        return true;
    }
    // 127.0.0.0/8
    if octets[0] == 127 {
        return true;
    }
    // 169.254.0.0/16
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }
    // 172.16.0.0/12
    if octets[0] == 172 && (octets[1] & 0xF0) == 16 {
        return true;
    }
    // 192.0.0.0/24
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return true;
    }
    // 192.0.2.0/24 (TEST-NET-1)
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
        return true;
    }
    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }
    // 198.18.0.0/15 (Benchmarking)
    if octets[0] == 198 && (octets[1] & 0xFE) == 18 {
        return true;
    }
    // 198.51.100.0/24 (TEST-NET-2)
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return true;
    }
    // 203.0.113.0/24 (TEST-NET-3)
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return true;
    }
    // 224.0.0.0/4 (Multicast)
    if (octets[0] & 0xF0) == 224 {
        return true;
    }
    // 240.0.0.0/4 (Reserved) + 255.255.255.255
    if (octets[0] & 0xF0) == 240 {
        return true;
    }
    false
}

fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
    // ::1 loopback
    if ip.is_loopback() {
        return true;
    }
    let segments = ip.segments();
    // fc00::/7 — unique local
    if (segments[0] & 0xFE00) == 0xFC00 {
        return true;
    }
    // fe80::/10 — link-local
    if (segments[0] & 0xFFC0) == 0xFE80 {
        return true;
    }
    // ::ffff:0:0/96 — IPv4-mapped, check the embedded v4 address
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_private_ipv4(&v4);
    }
    false
}

/// A connector that connects to a pre-resolved, validated IP address
/// while preserving the original hostname for TLS SNI and certificate
/// validation. This eliminates the TOCTOU gap between DNS validation
/// and actual connection.
pub struct PinnedConnector {
    tls_config: std::sync::Arc<rustls::ClientConfig>,
}

impl PinnedConnector {
    pub fn new() -> Result<Self> {
        let mut root_store = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().expect("Failed to load native root certificates") {
            root_store.add(cert).ok();
        }

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(Self {
            tls_config: std::sync::Arc::new(config),
        })
    }

    /// Connect to the pre-resolved `addr` with TLS, using `hostname`
    /// for SNI and certificate validation.
    pub async fn connect_tls(
        &self,
        addr: SocketAddr,
        hostname: &str,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let tcp = TcpStream::connect(addr)
            .await
            .with_context(|| format!("TCP connect to {} (for {}) failed", addr, hostname))?;

        let server_name = ServerName::try_from(hostname.to_string())
            .with_context(|| format!("Invalid server name: {}", hostname))?;

        let connector = TlsConnector::from(self.tls_config.clone());
        let tls = connector
            .connect(server_name, tcp)
            .await
            .with_context(|| format!("TLS handshake with {} (via {}) failed", hostname, addr))?;

        info!("Connected to {} via pinned IP {} (TLS)", hostname, addr);
        Ok(tls)
    }

    /// Connect to the pre-resolved `addr` with plain TCP (no TLS).
    pub async fn connect_tcp(
        &self,
        addr: SocketAddr,
        hostname: &str,
    ) -> Result<TcpStream> {
        let tcp = TcpStream::connect(addr)
            .await
            .with_context(|| format!("TCP connect to {} (for {}) failed", addr, hostname))?;

        info!("Connected to {} via pinned IP {} (plain TCP)", hostname, addr);
        Ok(tcp)
    }
}
