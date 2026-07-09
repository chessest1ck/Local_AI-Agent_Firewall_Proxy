use crate::policy::PolicyEngine;
use crate::tls::MitmCa;
use anyhow::Result;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::Arc;
use tracing::{error, info};

pub struct ProxyHandler {
    policy_engine: Arc<PolicyEngine>,
    mitm_ca: Arc<MitmCa>,
}

impl ProxyHandler {
    pub fn new(policy_engine: Arc<PolicyEngine>, mitm_ca: Arc<MitmCa>) -> Self {
        Self {
            policy_engine,
            mitm_ca,
        }
    }

    pub async fn handle_request(
        &self,
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        info!("Received request: {} {}", req.method(), req.uri());

        if Method::CONNECT == req.method() {
            self.handle_connect(req).await
        } else {
            self.handle_http(req, None).await
        }
    }

    async fn handle_connect(
        &self,
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        if let Some(addr) = req.uri().authority().map(|a| a.to_string()) {
            let host = addr.split(':').next().unwrap_or(&addr).to_string();

            if !self.policy_engine.is_host_allowed(&host) {
                return Ok(Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(empty())
                    .unwrap());
            }

            let mitm_ca = self.mitm_ca.clone();
            let policy = self.policy_engine.clone();
            let host_clone = host.clone();

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
                                    
                                    // Start a nested HTTP server for the decrypted traffic
                                    let service = service_fn(move |inner_req| {
                                        let policy = policy.clone();
                                        let h = host_for_inner.clone();
                                        async move {
                                            handle_decrypted_request(inner_req, h, policy).await
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
        } else {
            Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(empty())
                .unwrap())
        }
    }

    async fn handle_http(
        &self,
        req: Request<hyper::body::Incoming>,
        _override_host: Option<String>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        if req.uri().path() == "/api/firewall/command" && req.method() == Method::POST {
            return self.handle_firewall_command(req).await;
        }

        let host = req.uri().host().unwrap_or("unknown");
        if !self.policy_engine.is_host_allowed(host) {
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(empty())
                .unwrap());
        }

        // Just a basic forward for unencrypted HTTP
        let client = Client::builder(TokioExecutor::new()).build_http();
        let req = req.map(|b| b.boxed());
        
        match client.request(req).await {
            Ok(res) => Ok(res.map(|b| b.boxed())),
            Err(e) => {
                error!("Client request error: {}", e);
                Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(empty())
                    .unwrap())
            }
        }
    }

    async fn handle_firewall_command(
        &self,
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        let body_bytes = match req.into_body().collect().await {
            Ok(b) => b.to_bytes(),
            Err(e) => {
                error!("Failed to read firewall command body: {}", e);
                return Ok(Response::builder().status(StatusCode::BAD_REQUEST).body(empty()).unwrap());
            }
        };

        let payload: serde_json::Value = match serde_json::from_slice(&body_bytes) {
            Ok(v) => v,
            Err(_) => return Ok(Response::builder().status(StatusCode::BAD_REQUEST).body(empty()).unwrap())
        };

        let command_args = payload
            .get("command")
            .and_then(|c| c.as_array())
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        
        let approved = tokio::task::spawn_blocking(move || {
            use std::io::Write;
            println!("\n\x1b[33m⚠️  Agent wants to run command:\x1b[0m\n> \x1b[1m{}\x1b[0m", command_args);
            print!("Approve? [y/N]: ");
            let _ = std::io::stdout().flush();
            let mut input = String::new();
            if std::io::stdin().read_line(&mut input).is_ok() {
                input.trim().eq_ignore_ascii_case("y")
            } else {
                false
            }
        }).await.unwrap_or(false);

        if approved {
            info!("Command approved by user.");
            Ok(Response::new(empty()))
        } else {
            info!("Command denied by user.");
            Ok(Response::builder().status(StatusCode::FORBIDDEN).body(empty()).unwrap())
        }
    }
}

async fn handle_decrypted_request(
    mut req: Request<hyper::body::Incoming>,
    host: String,
    policy: Arc<PolicyEngine>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    info!("MITM Intercepted: {} {}{}", req.method(), host, req.uri());

    // Read the body
    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            error!("Failed to read body: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(empty())
                .unwrap());
        }
    };

    // DLP Check
    if !policy.inspect_json_payload(&body_bytes) {
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Full::new(Bytes::from("Blocked by Local AI Firewall (DLP)")).map_err(|e| match e {}).boxed())
            .unwrap());
    }

    // Reconstruct URI to point to the real HTTPS server
    let mut uri_builder = Uri::builder().scheme("https").authority(host.as_str());
    if let Some(path_and_query) = parts.uri.path_and_query() {
        uri_builder = uri_builder.path_and_query(path_and_query.clone());
    }
    let new_uri = uri_builder.build().unwrap_or_else(|_| parts.uri.clone());

    let mut new_req = Request::builder()
        .method(parts.method)
        .uri(new_uri)
        .version(parts.version);
    
    for (k, v) in parts.headers.iter() {
        new_req = new_req.header(k, v);
    }

    let body_to_send = Full::new(body_bytes).map_err(|never| match never {}).boxed();
    let reconstructed_req = new_req.body(body_to_send).unwrap();

    // Send to upstream HTTPS server
    // Build an HTTPS client
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .expect("no native roots found")
        .https_only()
        .enable_http1()
        .build();
    let client: Client<hyper_rustls::HttpsConnector<HttpConnector>, BoxBody<Bytes, hyper::Error>> = Client::builder(TokioExecutor::new()).build(https);

    match client.request(reconstructed_req).await {
        Ok(res) => Ok(res.map(|b| b.boxed())),
        Err(e) => {
            error!("Upstream HTTPS request failed: {}", e);
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(empty())
                .unwrap())
        }
    }
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}
