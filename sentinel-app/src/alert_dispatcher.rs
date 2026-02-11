use crate::components::{SecurityStack, UnifiedAlert};
use std::sync::Arc;
use std::path::PathBuf;
use tokio::sync::broadcast;
use tracing::{info, warn, error};

/// Central alert dispatcher that collects alerts from all security components
/// and routes them to configured outputs (file, webhook, broadcast channel).
pub struct AlertDispatcher {
    stack: Arc<SecurityStack>,
    log_path: Option<PathBuf>,
    webhook_url: Option<String>,
    broadcast_tx: broadcast::Sender<UnifiedAlert>,
    poll_interval_secs: u64,
}

impl AlertDispatcher {
    pub fn new(stack: Arc<SecurityStack>) -> Self {
        let (tx, _) = broadcast::channel(1024);
        Self {
            stack,
            log_path: None,
            webhook_url: None,
            broadcast_tx: tx,
            poll_interval_secs: 5,
        }
    }

    pub fn with_log_file(mut self, path: &str) -> Self {
        self.log_path = Some(PathBuf::from(path));
        self
    }

    pub fn with_webhook(mut self, url: &str) -> Self {
        if !url.is_empty() {
            self.webhook_url = Some(url.into());
        }
        self
    }

    pub fn with_interval(mut self, secs: u64) -> Self {
        self.poll_interval_secs = secs;
        self
    }

    pub fn subscribe(&self) -> broadcast::Receiver<UnifiedAlert> {
        self.broadcast_tx.subscribe()
    }

    /// Start the background alert collection and dispatch loop.
    pub fn start(self) -> AlertDispatchHandle {
        let handle = AlertDispatchHandle {
            tx: self.broadcast_tx.clone(),
        };

        tokio::spawn(async move {
            let mut seen_count: usize = 0;
            let mut ticker = tokio::time::interval(
                std::time::Duration::from_secs(self.poll_interval_secs),
            );

            // Ensure log directory exists
            if let Some(ref path) = self.log_path {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
            }

            loop {
                ticker.tick().await;

                let alerts = self.stack.collect_alerts();
                if alerts.len() <= seen_count {
                    continue;
                }

                // New alerts since last poll
                let new_alerts = &alerts[..alerts.len().saturating_sub(seen_count)];
                seen_count = alerts.len();

                for alert in new_alerts {
                    // Broadcast to subscribers (dashboard SSE, etc.)
                    let _ = self.broadcast_tx.send(alert.clone());

                    // Write to log file
                    if let Some(ref path) = self.log_path {
                        if let Ok(line) = serde_json::to_string(alert) {
                            use std::io::Write;
                            if let Ok(mut f) = std::fs::OpenOptions::new()
                                .create(true).append(true).open(path)
                            {
                                let _ = writeln!(f, "{}", line);
                            }
                        }
                    }

                    // Send webhook (fire-and-forget)
                    if let Some(ref url) = self.webhook_url {
                        let url = url.clone();
                        let payload = alert.clone();
                        tokio::spawn(async move {
                            let client = reqwest::Client::new();
                            match client.post(&url)
                                .json(&payload)
                                .timeout(std::time::Duration::from_secs(5))
                                .send().await
                            {
                                Ok(resp) if resp.status().is_success() => {},
                                Ok(resp) => warn!(status = %resp.status(), "Webhook response not OK"),
                                Err(e) => warn!(error = %e, "Webhook delivery failed"),
                            }
                        });
                    }
                }

                if !new_alerts.is_empty() {
                    info!(new = new_alerts.len(), total = seen_count, "Alerts dispatched");
                }
            }
        });

        handle
    }
}

pub struct AlertDispatchHandle {
    pub tx: broadcast::Sender<UnifiedAlert>,
}
