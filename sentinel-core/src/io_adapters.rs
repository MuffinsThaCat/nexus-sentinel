//! # I/O Adapters — Network listeners, file watchers, webhook receivers
//!
//! Provides the input layer that feeds real-world events into the security pipeline.
//! Each adapter converts raw I/O into SecurityEvents on the EventBus.

use crate::event_bus::{EventBus, EventCategory, EventSeverity, SecurityEvent};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{error, info, warn};

// ── File Watcher Adapter ─────────────────────────────────────────────────

/// Watches filesystem paths for changes and emits Detection events.
pub struct FileWatcherAdapter {
    watch_paths: Vec<PathBuf>,
    running: Arc<AtomicBool>,
    events_emitted: AtomicU64,
}

impl FileWatcherAdapter {
    pub fn new(paths: Vec<PathBuf>) -> Self {
        Self {
            watch_paths: paths,
            running: Arc::new(AtomicBool::new(false)),
            events_emitted: AtomicU64::new(0),
        }
    }

    /// Start watching in a background task. Requires tokio runtime.
    pub fn start(&self, bus: Arc<EventBus>) -> Result<(), String> {
        if self.watch_paths.is_empty() {
            info!("FileWatcher: no paths configured, skipping");
            return Ok(());
        }
        self.running.store(true, Ordering::Relaxed);
        let paths = self.watch_paths.clone();
        let running = self.running.clone();

        info!(paths = ?paths, "FileWatcher started");

        tokio::spawn(async move {
            // Use notify crate for real file watching
            use notify::{Watcher, RecursiveMode, Event, EventKind};

            let (tx, mut rx) = tokio::sync::mpsc::channel::<Event>(1000);

            let mut watcher = match notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    let _ = tx.blocking_send(event);
                }
            }) {
                Ok(w) => w,
                Err(e) => {
                    error!(error = %e, "Failed to create file watcher");
                    return;
                }
            };

            for path in &paths {
                if let Err(e) = watcher.watch(path.as_ref(), RecursiveMode::Recursive) {
                    warn!(path = %path.display(), error = %e, "Failed to watch path");
                }
            }

            while running.load(Ordering::Relaxed) {
                match tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv()).await {
                    Ok(Some(event)) => {
                        let (severity, title) = match event.kind {
                            EventKind::Create(_) => (EventSeverity::Medium, "File created"),
                            EventKind::Modify(_) => (EventSeverity::Low, "File modified"),
                            EventKind::Remove(_) => (EventSeverity::High, "File deleted"),
                            _ => continue,
                        };

                        let paths_str: Vec<String> = event.paths.iter()
                            .map(|p| p.display().to_string())
                            .collect();

                        let mut details = HashMap::new();
                        details.insert("paths".into(), paths_str.join(", "));
                        details.insert("kind".into(), format!("{:?}", event.kind));

                        bus.emit_detection(
                            "file_watcher", "sentinel-core",
                            severity, title,
                            details,
                            vec!["filesystem".into(), "integrity".into()],
                        );
                    }
                    Ok(None) => break,
                    Err(_) => continue, // timeout, check running flag
                }
            }
            info!("FileWatcher stopped");
        });

        Ok(())
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    pub fn events_emitted(&self) -> u64 { self.events_emitted.load(Ordering::Relaxed) }
}

// ── Webhook Receiver Adapter ─────────────────────────────────────────────

/// HTTP webhook receiver that accepts JSON payloads and emits events.
pub struct WebhookAdapter {
    bind_addr: SocketAddr,
    running: Arc<AtomicBool>,
    events_received: Arc<AtomicU64>,
}

impl WebhookAdapter {
    pub fn new(bind: SocketAddr) -> Self {
        Self {
            bind_addr: bind,
            running: Arc::new(AtomicBool::new(false)),
            events_received: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Start the webhook HTTP server in a background task.
    pub fn start(&self, bus: Arc<EventBus>) -> Result<(), String> {
        self.running.store(true, Ordering::Relaxed);
        let addr = self.bind_addr;
        let counter = self.events_received.clone();
        let running = self.running.clone();

        info!(bind = %addr, "Webhook receiver starting");

        tokio::spawn(async move {
            use axum::{Router, Json, routing::post, extract::State};

            #[derive(serde::Deserialize)]
            struct WebhookPayload {
                source: String,
                #[serde(default = "default_severity")]
                severity: String,
                title: String,
                #[serde(default)]
                details: HashMap<String, String>,
                #[serde(default)]
                tags: Vec<String>,
            }

            fn default_severity() -> String { "medium".into() }

            #[derive(Clone)]
            struct AppState {
                bus: Arc<EventBus>,
                counter: Arc<AtomicU64>,
            }

            async fn handle_webhook(
                State(state): State<AppState>,
                Json(payload): Json<WebhookPayload>,
            ) -> &'static str {
                let severity = match payload.severity.to_lowercase().as_str() {
                    "critical" => EventSeverity::Critical,
                    "high" => EventSeverity::High,
                    "medium" => EventSeverity::Medium,
                    "low" => EventSeverity::Low,
                    _ => EventSeverity::Info,
                };

                state.bus.emit_detection(
                    &payload.source, "webhook",
                    severity, &payload.title,
                    payload.details, payload.tags,
                );
                state.counter.fetch_add(1, Ordering::Relaxed);
                "OK"
            }

            let state = AppState { bus, counter };
            let app = Router::new()
                .route("/webhook", post(handle_webhook))
                .with_state(state);

            let listener = match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(e) => {
                    error!(error = %e, "Failed to bind webhook listener");
                    return;
                }
            };

            info!(bind = %addr, "Webhook receiver listening");
            if let Err(e) = axum::serve(listener, app).await {
                error!(error = %e, "Webhook server error");
            }
        });

        Ok(())
    }

    pub fn stop(&self) { self.running.store(false, Ordering::Relaxed); }
    pub fn events_received(&self) -> u64 { self.events_received.load(Ordering::Relaxed) }
}

// ── Syslog Receiver Adapter ──────────────────────────────────────────────

/// UDP syslog receiver that parses syslog messages and emits events.
pub struct SyslogAdapter {
    bind_addr: SocketAddr,
    running: Arc<AtomicBool>,
    messages_received: Arc<AtomicU64>,
}

impl SyslogAdapter {
    pub fn new(bind: SocketAddr) -> Self {
        Self {
            bind_addr: bind,
            running: Arc::new(AtomicBool::new(false)),
            messages_received: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Start the syslog UDP listener in a background task.
    pub fn start(&self, bus: Arc<EventBus>) -> Result<(), String> {
        self.running.store(true, Ordering::Relaxed);
        let addr = self.bind_addr;
        let counter = self.messages_received.clone();
        let running = self.running.clone();

        info!(bind = %addr, "Syslog receiver starting");

        tokio::spawn(async move {
            let socket = match tokio::net::UdpSocket::bind(addr).await {
                Ok(s) => s,
                Err(e) => {
                    error!(error = %e, "Failed to bind syslog socket");
                    return;
                }
            };

            let mut buf = vec![0u8; 8192];
            info!(bind = %addr, "Syslog receiver listening");

            while running.load(Ordering::Relaxed) {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    socket.recv_from(&mut buf),
                ).await {
                    Ok(Ok((len, src))) => {
                        counter.fetch_add(1, Ordering::Relaxed);
                        let msg = String::from_utf8_lossy(&buf[..len]);

                        // Simple syslog severity extraction
                        let severity = if msg.contains("CRIT") || msg.contains("EMERG") {
                            EventSeverity::Critical
                        } else if msg.contains("ERR") || msg.contains("ALERT") {
                            EventSeverity::High
                        } else if msg.contains("WARN") {
                            EventSeverity::Medium
                        } else {
                            EventSeverity::Low
                        };

                        let mut details = HashMap::new();
                        details.insert("source_ip".into(), src.to_string());
                        details.insert("raw_message".into(), msg.to_string());

                        bus.emit_detection(
                            "syslog_receiver", "sentinel-core",
                            severity, "Syslog message",
                            details,
                            vec!["syslog".into(), "log".into()],
                        );
                    }
                    Ok(Err(e)) => {
                        warn!(error = %e, "Syslog recv error");
                    }
                    Err(_) => continue, // timeout
                }
            }
            info!("Syslog receiver stopped");
        });

        Ok(())
    }

    pub fn stop(&self) { self.running.store(false, Ordering::Relaxed); }
    pub fn messages_received(&self) -> u64 { self.messages_received.load(Ordering::Relaxed) }
}

// ── Periodic Scanner Adapter ─────────────────────────────────────────────

/// Runs periodic security checks (health, integrity, rotation) on a timer.
pub struct PeriodicScanner {
    interval_secs: u64,
    running: Arc<AtomicBool>,
    scans_completed: Arc<AtomicU64>,
}

impl PeriodicScanner {
    pub fn new(interval_secs: u64) -> Self {
        Self {
            interval_secs: interval_secs.max(10),
            running: Arc::new(AtomicBool::new(false)),
            scans_completed: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Start periodic scanning. The callback runs each scan cycle.
    pub fn start<F>(&self, bus: Arc<EventBus>, scan_fn: F) -> Result<(), String>
    where
        F: Fn(&EventBus) + Send + Sync + 'static,
    {
        self.running.store(true, Ordering::Relaxed);
        let interval = self.interval_secs;
        let running = self.running.clone();
        let counter = self.scans_completed.clone();

        info!(interval_secs = interval, "Periodic scanner started");

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval));
            while running.load(Ordering::Relaxed) {
                ticker.tick().await;
                scan_fn(&bus);
                counter.fetch_add(1, Ordering::Relaxed);
            }
            info!("Periodic scanner stopped");
        });

        Ok(())
    }

    pub fn stop(&self) { self.running.store(false, Ordering::Relaxed); }
    pub fn scans_completed(&self) -> u64 { self.scans_completed.load(Ordering::Relaxed) }
}
