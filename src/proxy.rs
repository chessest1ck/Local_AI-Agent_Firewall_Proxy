use crate::config::PolicyConfig;
use crate::dns::{self, PinnedConnector};
use crate::policy::{self, DlpAction, HostVerdict, PolicyEngine};
use crate::prompt::{PromptCoordinator, PromptDecision};
use crate::tls::MitmCa;
use anyhow::Result;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

pub struct ProxyHandler {
    policy_engine: Arc<PolicyEngine>,
    mitm_ca: Arc<MitmCa>,
    prompt_coordinator: Arc<PromptCoordinator>,
    pinned_connector: Arc<PinnedConnector>,
    prompt_timeout: Duration,
    block_private_ips: bool,
    /// "prompt" or "block" — controls unknown-host behavior.
    unknown_host_action: String,
}

impl ProxyHandler {
    pub fn new(
        policy_engine: Arc<PolicyEngine>,
        mitm_ca: Arc<MitmCa>,
        prompt_coordinator: Arc<PromptCoordinator>,
        policy_config: &PolicyConfig,
    ) -> Result<Self> {
        let pinned_connector = Arc::new(PinnedConnector::new()?);

        Ok(Self {
            policy_engine,
            mitm_ca,
            prompt_coordinator,
            pinned_connector,
            prompt_timeout: Duration::from_secs(policy_config.prompt_timeout_secs),
            block_private_ips: policy_config.block_private_ips,
            unknown_host_action: policy_config.unknown_host_action.clone(),
        })
    }

    pub async fn handle_request(
        &self,
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        info!("Received request: {} {}", req.method(), req.uri());

        if Method::CONNECT == req.method() {
            self.handle_connect(req).await
        } else {
            self.handle_http(req).await
        }
    }

    // ── CONNECT (HTTPS tunnel) ──────────────────────────────────

    async fn handle_connect(
        &self,
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        let raw_authority = match req.uri().authority() {
            Some(a) => a.to_string(),
            None => {
                return Ok(build_response(StatusCode::BAD_REQUEST, full_body("Missing authority in CONNECT request")));
            }
        };

        // Parse authority
        let (raw_host, port) = match policy::parse_authority(&raw_authority) {
            Ok(hp) => hp,
            Err(e) => {
                warn!("Malformed authority '{}': {}", raw_authority, e);
                return Ok(build_response(StatusCode::BAD_REQUEST, full_body("Malformed authority")));
            }
        };
        let port = port.unwrap_or(443);

        // Normalize host
        let host = match policy::normalize_host(&raw_host) {
            Ok(h) => h,
            Err(e) => {
                warn!("Invalid hostname '{}': {}", raw_host, e);
                return Ok(forbidden_response(&format!("Invalid hostname: {}", e)));
            }
        };

        // Check host through 3-tier policy
        match self.check_host_with_prompt(&host).await {
            Ok(true) => {} // allowed
            Ok(false) => return Ok(forbidden_response("Host blocked by policy")),
            Err(reason) => return Ok(forbidden_response(&reason)),
        }

        // DNS rebinding check — resolve and validate before connecting
        if self.block_private_ips
            && let Err(e) = dns::resolve_and_validate(&host, port).await {
                warn!("DNS validation failed for {}: {}", host, e);
                return Ok(forbidden_response(&format!("{}", e)));
            }

        let mitm_ca = self.mitm_ca.clone();
        let policy = self.policy_engine.clone();
        let pinned_connector = self.pinned_connector.clone();
        let host_clone = host.clone();
        let block_private_ips = self.block_private_ips;

        tokio::task::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    let io = TokioIo::new(upgraded);
                    // Start MITM
                    if let Ok(acceptor) = mitm_ca.get_acceptor(&host_clone) {
                        match acceptor.accept(io).await {
                            Ok(tls_stream) => {
                                let tls_io = TokioIo::new(tls_stream);
                                let host_for_inner = host_clone.clone();

                                let service = service_fn(move |inner_req| {
                                    let policy = policy.clone();
                                    let h = host_for_inner.clone();
                                    let connector = pinned_connector.clone();
                                    async move {
                                        handle_decrypted_request(
                                            inner_req,
                                            h,
                                            policy,
                                            connector,
                                            block_private_ips,
                                        )
                                        .await
                                    }
                                });

                                if let Err(e) = http1::Builder::new()
                                    .preserve_header_case(true)
                                    .title_case_headers(true)
                                    .serve_connection(tls_io, service)
                                    .await
                                {
                                    error!("Failed to serve MITM connection: {:?}", e);
                                }
                            }
                            Err(e) => error!("TLS accept error for {}: {}", host_clone, e),
                        }
                    }
                }
                Err(e) => error!("Upgrade error: {}", e),
            }
        });

        Ok(Response::new(empty()))
    }

    // ── Plain HTTP ──────────────────────────────────────────────

    async fn handle_http(
        &self,
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        // Handle firewall command API (from shim)
        if req.uri().path() == "/api/firewall/command" && req.method() == Method::POST {
            return self.handle_firewall_command(req).await;
        }

        let raw_host = req.uri().host().unwrap_or("unknown");
        let port = req.uri().port_u16().unwrap_or(80);

        let host = match policy::normalize_host(raw_host) {
            Ok(h) => h,
            Err(e) => {
                warn!("Invalid hostname '{}': {}", raw_host, e);
                return Ok(forbidden_response(&format!("Invalid hostname: {}", e)));
            }
        };

        // 3-tier host check
        match self.check_host_with_prompt(&host).await {
            Ok(true) => {}
            Ok(false) => return Ok(forbidden_response("Host blocked by policy")),
            Err(reason) => return Ok(forbidden_response(&reason)),
        }

        // DNS rebinding check
        if self.block_private_ips
            && let Err(e) = dns::resolve_and_validate(&host, port).await {
                warn!("DNS validation failed for {}: {}", host, e);
                return Ok(forbidden_response(&format!("{}", e)));
            }

        // Forward plain HTTP via pinned connection
        let addr = match dns::resolve_and_validate(&host, port).await {
            Ok(a) => a,
            Err(e) => {
                error!("DNS resolution failed for {}: {}", host, e);
                return Ok(build_response(StatusCode::BAD_GATEWAY, full_body(&format!("DNS resolution failed: {}", e))));
            }
        };

        let tcp = match self.pinned_connector.connect_tcp(addr, &host).await {
            Ok(t) => t,
            Err(e) => {
                error!("TCP connect failed for {}: {}", host, e);
                return Ok(build_response(StatusCode::BAD_GATEWAY, empty()));
            }
        };

        let io = TokioIo::new(tcp);
        let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
            Ok(sc) => sc,
            Err(e) => {
                error!("HTTP handshake failed for {}: {}", host, e);
                return Ok(build_response(StatusCode::BAD_GATEWAY, empty()));
            }
        };

        tokio::task::spawn(async move {
            if let Err(e) = conn.await {
                error!("HTTP connection error: {}", e);
            }
        });

        let req = req.map(|b| b.boxed());
        match sender.send_request(req).await {
            Ok(res) => Ok(res.map(|b| b.boxed())),
            Err(e) => {
                error!("HTTP request failed for {}: {}", host, e);
                Ok(build_response(StatusCode::BAD_GATEWAY, empty()))
            }
        }
    }

    // ── Firewall command endpoint (shim) ────────────────────────

    async fn handle_firewall_command(
        &self,
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        let body_bytes = match req.into_body().collect().await {
            Ok(b) => b.to_bytes(),
            Err(e) => {
                error!("Failed to read firewall command body: {}", e);
                return Ok(build_response(StatusCode::BAD_REQUEST, empty()));
            }
        };

        let payload: serde_json::Value = match serde_json::from_slice(&body_bytes) {
            Ok(v) => v,
            Err(_) => {
                return Ok(build_response(StatusCode::BAD_REQUEST, empty()));
            }
        };

        let command_args = payload
            .get("command")
            .and_then(|c| c.as_array())
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>()
            .join(" ");

        // Use the prompt coordinator for command approval too
        let approved = if !self.prompt_coordinator.has_tty() {
            warn!("No TTY — blocking command execution (fail-closed): {}", command_args);
            false
        } else {
            // For commands, use a spawn_blocking with direct stdin since
            // the prompt coordinator is designed for host prompts.
            // Command prompts have a different format.
            tokio::task::spawn_blocking(move || {
                use std::io::Write;
                eprintln!(
                    "\n\x1b[33m[WARNING] Agent wants to run command:\x1b[0m\n> \x1b[1m{}\x1b[0m",
                    command_args
                );
                eprint!("Approve? [\x1b[32my\x1b[0m/\x1b[31mN\x1b[0m]: ");
                let _ = std::io::stderr().flush();
                let mut input = String::new();
                if std::io::stdin().read_line(&mut input).is_ok() {
                    input.trim().eq_ignore_ascii_case("y")
                } else {
                    false
                }
            })
            .await
            .unwrap_or(false)
        };

        if approved {
            info!("Command approved by user.");
            Ok(Response::new(empty()))
        } else {
            info!("Command denied by user.");
            Ok(build_response(StatusCode::FORBIDDEN, empty()))
        }
    }

    // ── Host check with interactive prompt ──────────────────────

    /// Checks a normalized host through the 3-tier system.
    /// Returns Ok(true) to allow, Ok(false) to silently block,
    /// Err(reason) with a specific block reason.
    async fn check_host_with_prompt(&self, host: &str) -> Result<bool, String> {
        match self.policy_engine.check_host(host) {
            HostVerdict::Allowed => {
                debug!("Host allowed (allowlist): {}", host);
                Ok(true)
            }
            HostVerdict::Blocked(reason) => {
                warn!("Host blocked: {} — {}", host, reason);
                Err(reason)
            }
            HostVerdict::Unknown => {
                info!("Unknown host: {} — checking prompt coordinator.", host);

                // If policy is set to "block", skip prompting entirely
                if self.unknown_host_action == "block" {
                    warn!("Unknown host blocked by policy (unknown_host_action=block): {}", host);
                    return Err(format!(
                        "Unknown host blocked by policy: {}",
                        host
                    ));
                }

                if !self.prompt_coordinator.has_tty() {
                    warn!("No TTY — blocking unknown host (fail-closed): {}", host);
                    return Err(format!(
                        "No TTY available — unknown host blocked (fail-closed): {}",
                        host
                    ));
                }

                // Send prompt request via channel
                let response_rx = match self
                    .prompt_coordinator
                    .request_prompt_async(host.to_string())
                    .await
                {
                    Some(rx) => rx,
                    None => {
                        warn!("Prompt coordinator unavailable — fail closed: {}", host);
                        return Err("Prompt coordinator unavailable".to_string());
                    }
                };

                // Await with timeout
                match tokio::time::timeout(self.prompt_timeout, response_rx).await {
                    Ok(Ok(PromptDecision::AllowOnce)) => {
                        info!("User allowed (once): {}", host);
                        Ok(true)
                    }
                    Ok(Ok(PromptDecision::AllowAlways)) => {
                        info!("User allowed (always): {}", host);
                        self.policy_engine.add_runtime_allowlist(host);
                        Ok(true)
                    }
                    Ok(Ok(PromptDecision::Deny)) => {
                        info!("User denied: {}", host);
                        Ok(false)
                    }
                    Ok(Err(_)) => {
                        // oneshot sender dropped — coordinator thread issue
                        warn!("Prompt channel closed for {} — denying.", host);
                        Ok(false)
                    }
                    Err(_) => {
                        // Timeout — the oneshot receiver is dropped here,
                        // coordinator will see the send fail and discard.
                        warn!(
                            "Prompt timed out after {}s — blocking: {}",
                            self.prompt_timeout.as_secs(),
                            host
                        );
                        Err(format!(
                            "Prompt timed out after {}s — host blocked",
                            self.prompt_timeout.as_secs()
                        ))
                    }
                }
            }
        }
    }
}

// ── Decrypted (MITM) request handler ────────────────────────────

async fn handle_decrypted_request(
    req: Request<hyper::body::Incoming>,
    host: String,
    policy: Arc<PolicyEngine>,
    pinned_connector: Arc<PinnedConnector>,
    _block_private_ips: bool,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    info!("MITM Intercepted: {} {}{}", req.method(), host, req.uri());

    // Extract headers we need before consuming the body
    let content_type = req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let content_encoding = req
        .headers()
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Read the body
    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            error!("Failed to read body: {}", e);
            return Ok(build_response(StatusCode::BAD_REQUEST, empty()));
        }
    };

    // DLP Check
    match policy.inspect_body(
        &body_bytes,
        content_type.as_deref(),
        content_encoding.as_deref(),
    ) {
        Ok(violations) if !violations.is_empty() => {
            let reasons: Vec<String> = violations.iter().map(|v| v.message.clone()).collect();
            let reason = reasons.join("; ");
            warn!("DLP blocked request to {}: {}", host, reason);
            return Ok(build_response(StatusCode::FORBIDDEN, full_body(&format!("Blocked by Local AI Firewall (DLP): {}", reason))));
        }
        Err(DlpAction::BlockOversized) => {
            warn!("DLP blocked oversized request to {}", host);
            return Ok(build_response(StatusCode::PAYLOAD_TOO_LARGE, full_body("Request body too large for DLP inspection")));
        }
        _ => {} // No violations or pass-through
    }

    // DNS resolve + validate + connect to pinned IP
    let port = 443;
    let addr = match dns::resolve_and_validate(&host, port).await {
        Ok(a) => a,
        Err(e) => {
            error!("DNS validation failed for {}: {}", host, e);
            return Ok(build_response(StatusCode::BAD_GATEWAY, full_body(&format!("{}", e))));
        }
    };

    // Connect via pinned connector (TLS with SNI = hostname)
    let tls_stream = match pinned_connector.connect_tls(addr, &host).await {
        Ok(s) => s,
        Err(e) => {
            error!("Upstream TLS connect failed for {}: {}", host, e);
            return Ok(build_response(StatusCode::BAD_GATEWAY, empty()));
        }
    };

    let io = TokioIo::new(tls_stream);
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(sc) => sc,
        Err(e) => {
            error!("HTTP handshake over TLS failed for {}: {}", host, e);
            return Ok(build_response(StatusCode::BAD_GATEWAY, empty()));
        }
    };

    tokio::task::spawn(async move {
        if let Err(e) = conn.await {
            error!("HTTPS connection error: {}", e);
        }
    });

    // Reconstruct request
    let mut builder = Request::builder()
        .method(parts.method)
        .uri(parts.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/"));

    for (k, v) in parts.headers.iter() {
        builder = builder.header(k, v);
    }
    // Ensure Host header is set
    if !parts.headers.contains_key("host") {
        builder = builder.header("host", &host);
    }

    let body_to_send = Full::new(body_bytes)
        .map_err(|never| match never {})
        .boxed();
    let reconstructed_req = match builder.body(body_to_send) {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to build upstream request: {}", e);
            return Ok(build_response(StatusCode::INTERNAL_SERVER_ERROR, full_body("Failed to construct upstream request")));
        }
    };

    match sender.send_request(reconstructed_req).await {
        Ok(res) => Ok(res.map(|b| b.boxed())),
        Err(e) => {
            error!("Upstream HTTPS request failed for {}: {}", host, e);
            Ok(build_response(StatusCode::BAD_GATEWAY, empty()))
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full_body(msg: &str) -> BoxBody<Bytes, hyper::Error> {
    Full::new(Bytes::from(msg.to_string()))
        .map_err(|never| match never {})
        .boxed()
}

fn forbidden_response(reason: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    build_response(StatusCode::FORBIDDEN, full_body(reason))
}

/// Safe response builder that never panics. Falls back to a minimal
/// 500 response if the builder somehow fails (which should not happen
/// with valid StatusCode + body, but we avoid expect() on principle).
fn build_response(
    status: StatusCode,
    body: BoxBody<Bytes, hyper::Error>,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(status)
        .body(body)
        .unwrap_or_else(|_| {
            Response::new(full_body("Internal proxy error"))
        })
}
