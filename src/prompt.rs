use std::io::{self, BufRead, Write};
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

/// The decision a user makes at a prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptDecision {
    AllowOnce,
    AllowAlways,
    Deny,
}

/// A request sent to the prompt coordinator.
pub struct PromptRequest {
    pub host: String,
    pub response_tx: oneshot::Sender<PromptDecision>,
}

/// Handle used by request handlers to send prompt requests.
#[derive(Clone)]
pub struct PromptCoordinator {
    /// `None` when no TTY is available (fail-closed mode).
    sender: Option<mpsc::Sender<PromptRequest>>,
}

impl PromptCoordinator {
    /// Creates a new coordinator. If a TTY is available, spawns the
    /// background stdin-reader thread. Otherwise returns a coordinator
    /// that always reports no-TTY.
    pub fn new(has_tty: bool) -> Self {
        if !has_tty {
            warn!("No TTY detected — all unknown-host prompts will fail closed (block).");
            return Self { sender: None };
        }

        // Bounded channel: backpressure if too many prompts queue up
        let (tx, rx) = mpsc::channel::<PromptRequest>(64);

        // Spawn a blocking thread that owns stdin for the proxy's lifetime
        match std::thread::Builder::new()
            .name("prompt-coordinator".into())
            .spawn(move || {
                run_stdin_reader(rx);
            }) {
            Ok(_) => {
                info!("Prompt coordinator started (interactive mode).");
                Self { sender: Some(tx) }
            }
            Err(e) => {
                warn!("Failed to spawn prompt coordinator thread: {} — falling back to fail-closed.", e);
                Self { sender: None }
            }
        }
    }

    /// Returns true if a TTY is available and prompts can be shown.
    pub fn has_tty(&self) -> bool {
        self.sender.is_some()
    }

    /// Sends a prompt request and returns a receiver for the decision.
    /// Returns `None` if no TTY is available (caller should fail closed).
    #[allow(dead_code)]
    pub fn request_prompt(&self, host: String) -> Option<oneshot::Receiver<PromptDecision>> {
        let sender = self.sender.as_ref()?;
        let (response_tx, response_rx) = oneshot::channel();
        let req = PromptRequest { host, response_tx };

        // If the coordinator thread has died, treat as no-TTY
        if sender.blocking_send(req).is_err() {
            warn!("Prompt coordinator channel closed — failing closed.");
            return None;
        }

        Some(response_rx)
    }

    /// Async version for use inside async request handlers.
    pub async fn request_prompt_async(&self, host: String) -> Option<oneshot::Receiver<PromptDecision>> {
        let sender = self.sender.as_ref()?;
        let (response_tx, response_rx) = oneshot::channel();
        let req = PromptRequest { host, response_tx };

        if sender.send(req).await.is_err() {
            warn!("Prompt coordinator channel closed — failing closed.");
            return None;
        }

        Some(response_rx)
    }
}

/// The blocking stdin reader loop — runs in a dedicated OS thread.
/// Processes prompt requests one at a time (inherent serialization).
fn run_stdin_reader(mut rx: mpsc::Receiver<PromptRequest>) {
    let stdin = io::stdin();
    let mut reader = stdin.lock();

    // Use blocking_recv to wait for prompt requests
    while let Some(req) = rx.blocking_recv() {
        // Display the prompt
        let prompt_text = format!(
            "\n\x1b[33m[WARNING] Agent is trying to connect to: \x1b[1m{}\x1b[0m\n\
             \x1b[33m   This host is NOT in your allowlist.\x1b[0m\n\
             Allow? [\x1b[32my\x1b[0m/\x1b[31mN\x1b[0m/\x1b[36malways\x1b[0m]: ",
            req.host
        );
        // Print to stderr so it doesn't mix with piped stdout
        eprint!("{}", prompt_text);
        let _ = io::stderr().flush();

        // Read one line
        let mut input = String::new();
        let decision = match reader.read_line(&mut input) {
            Ok(0) => {
                // EOF — treat as deny
                warn!("stdin EOF during prompt for {} — denying.", req.host);
                PromptDecision::Deny
            }
            Ok(_) => {
                let trimmed = input.trim().to_lowercase();
                match trimmed.as_str() {
                    "y" | "yes" => {
                        info!("User allowed (once): {}", req.host);
                        PromptDecision::AllowOnce
                    }
                    "always" | "a" => {
                        info!("User allowed (always): {}", req.host);
                        PromptDecision::AllowAlways
                    }
                    _ => {
                        info!("User denied: {}", req.host);
                        PromptDecision::Deny
                    }
                }
            }
            Err(e) => {
                warn!("stdin read error during prompt for {}: {} — denying.", req.host, e);
                PromptDecision::Deny
            }
        };

        // Send the response. If the receiver was dropped (caller timed out),
        // we silently discard the result and move on to the next prompt.
        if req.response_tx.send(decision).is_err() {
            info!("Prompt response for {} discarded (caller timed out).", req.host);
        }
    }

    info!("Prompt coordinator shutting down.");
}
