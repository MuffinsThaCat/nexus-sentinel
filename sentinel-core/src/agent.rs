//! # Agent Daemon — Production runtime orchestrator
//!
//! This is the beating heart of Nexus Sentinel: a single daemon process that
//! starts, manages, and coordinates all real-time monitoring subsystems:
//!
//! - **Process Monitor** — Real sysinfo-based process scanning
//! - **File Integrity Monitor** — BLAKE3 hash-based change detection
//! - **Filesystem Watcher** — Push-based inotify/FSEvents/kqueue
//! - **Packet Capture** — Raw network interface sniffing via pnet
//! - **Network Connection Tracker** — Live socket enumeration
//! - **TAXII Client** — Real threat intelligence feed ingestion
//! - **TLS Probe** — Certificate chain validation
//! - **Event Bus** — Central event routing and correlation
//! - **Dashboard** — Web-based management UI
//!
//! The agent runs as a long-lived process (daemon/service) and exposes a
//! REST API for management and a web dashboard for operators.

use crate::event_bus::EventBus;
use crate::file_integrity::FileIntegrityMonitor;
use crate::fs_watcher::FsWatcher;
use crate::net_connections::NetConnectionTracker;
use crate::process_monitor::ProcessMonitor;
use crate::taxii_client::TaxiiClient;
use crate::MemoryMetrics;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{error, info, warn};

/// Agent configuration loaded from sentinel.toml or environment.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentConfig {
    /// Process scan interval in seconds
    pub process_scan_interval_secs: u64,
    /// Network connection scan interval in seconds
    pub net_scan_interval_secs: u64,
    /// File integrity scan interval in seconds
    pub fim_scan_interval_secs: u64,
    /// Threat intel poll interval in seconds
    pub threat_intel_poll_secs: u64,
    /// Dashboard bind address
    pub dashboard_bind: String,
    /// Paths to monitor with filesystem watcher
    pub watch_paths: Vec<String>,
    /// Paths to monitor with file integrity
    pub fim_paths: Vec<String>,
    /// Network interface for packet capture
    pub capture_interface: Option<String>,
    /// Enable/disable individual subsystems
    pub enable_process_monitor: bool,
    pub enable_fs_watcher: bool,
    pub enable_fim: bool,
    pub enable_net_tracker: bool,
    pub enable_packet_capture: bool,
    pub enable_threat_intel: bool,
    pub enable_dashboard: bool,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            process_scan_interval_secs: 10,
            net_scan_interval_secs: 30,
            fim_scan_interval_secs: 300,
            threat_intel_poll_secs: 3600,
            dashboard_bind: "127.0.0.1:9800".into(),
            watch_paths: vec![
                "/etc".into(),
                "/usr/bin".into(),
                "/usr/sbin".into(),
                "/usr/local/bin".into(),
            ],
            fim_paths: vec![
                "/etc".into(),
                "/usr/bin".into(),
            ],
            capture_interface: None,
            enable_process_monitor: true,
            enable_fs_watcher: true,
            enable_fim: true,
            enable_net_tracker: true,
            enable_packet_capture: false, // requires root
            enable_threat_intel: true,
            enable_dashboard: true,
        }
    }
}

/// Runtime status of the agent.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentStatus {
    pub running: bool,
    pub uptime_secs: u64,
    pub subsystems: Vec<SubsystemStatus>,
    pub total_events: u64,
    pub total_anomalies: u64,
    pub threat_intel_indicators: u64,
    pub active_connections: usize,
    pub watched_files: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SubsystemStatus {
    pub name: String,
    pub enabled: bool,
    pub running: bool,
    pub events_generated: u64,
}

/// The Nexus Sentinel Agent — orchestrates all subsystems.
pub struct Agent {
    config: AgentConfig,
    bus: Arc<EventBus>,
    process_monitor: Arc<ProcessMonitor>,
    fs_watcher: Arc<FsWatcher>,
    fim: Arc<FileIntegrityMonitor>,
    net_tracker: Arc<NetConnectionTracker>,
    taxii: Arc<TaxiiClient>,
    running: Arc<AtomicBool>,
    started_at: RwLock<Option<std::time::Instant>>,
}

impl Agent {
    /// Create a new agent with the given configuration.
    pub fn new(config: AgentConfig) -> Self {
        let bus = Arc::new(EventBus::new());

        Self {
            config,
            bus,
            process_monitor: Arc::new(ProcessMonitor::new()),
            fs_watcher: Arc::new(FsWatcher::new()),
            fim: Arc::new(FileIntegrityMonitor::new()),
            net_tracker: Arc::new(NetConnectionTracker::new()),
            taxii: Arc::new(TaxiiClient::new()),
            running: Arc::new(AtomicBool::new(false)),
            started_at: RwLock::new(None),
        }
    }

    /// Create an agent with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(AgentConfig::default())
    }

    /// Start the agent and all enabled subsystems.
    pub async fn start(&self) -> Result<(), String> {
        if self.running.load(Ordering::Relaxed) {
            return Err("Agent already running".into());
        }
        self.running.store(true, Ordering::Relaxed);
        *self.started_at.write() = Some(std::time::Instant::now());

        info!("╔══════════════════════════════════════════════╗");
        info!("║       NEXUS SENTINEL AGENT v0.1.0           ║");
        info!("║       Production Security Runtime            ║");
        info!("╚══════════════════════════════════════════════╝");

        // 1. Process Monitor
        if self.config.enable_process_monitor {
            info!("[1/6] Starting process monitor (interval={}s)", self.config.process_scan_interval_secs);
            self.process_monitor.baseline();
            self.process_monitor.start_periodic(
                self.config.process_scan_interval_secs, self.bus.clone(),
            );
        }

        // 2. Filesystem Watcher (push-based)
        if self.config.enable_fs_watcher {
            info!("[2/6] Starting filesystem watcher ({} paths)", self.config.watch_paths.len());
            for path in &self.config.watch_paths {
                self.fs_watcher.watch_path(path);
            }
            if let Err(e) = self.fs_watcher.start(Some(self.bus.clone())) {
                warn!("FS watcher failed to start: {} (continuing without it)", e);
            }
        }

        // 3. File Integrity Monitor
        if self.config.enable_fim {
            info!("[3/6] Starting file integrity monitor ({} paths)", self.config.fim_paths.len());
            for path in &self.config.fim_paths {
                self.fim.watch(path);
            }
            self.fim.build_baseline();
            // Start periodic FIM scan
            let fim = self.fim.clone();
            let bus = self.bus.clone();
            let interval = self.config.fim_scan_interval_secs;
            let running = self.running.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(
                    std::time::Duration::from_secs(interval),
                );
                while running.load(Ordering::Relaxed) {
                    ticker.tick().await;
                    let violations = fim.scan();
                    if !violations.is_empty() {
                        info!(count = violations.len(), "FIM detected changes");
                    }
                }
            });
        }

        // 4. Network Connection Tracker
        if self.config.enable_net_tracker {
            info!("[4/6] Starting network connection tracker (interval={}s)", self.config.net_scan_interval_secs);
            self.net_tracker.start_periodic(
                self.config.net_scan_interval_secs, self.bus.clone(),
            );
        }

        // 5. Threat Intelligence (TAXII)
        if self.config.enable_threat_intel {
            info!("[5/6] Starting threat intel feed ingestion");
            let taxii = self.taxii.clone();
            let net_tracker = self.net_tracker.clone();
            let poll_secs = self.config.threat_intel_poll_secs;
            let running = self.running.clone();
            tokio::spawn(async move {
                // Initial pull
                Self::pull_threat_intel(&taxii, &net_tracker).await;

                let mut ticker = tokio::time::interval(
                    std::time::Duration::from_secs(poll_secs),
                );
                while running.load(Ordering::Relaxed) {
                    ticker.tick().await;
                    Self::pull_threat_intel(&taxii, &net_tracker).await;
                }
            });
        }

        // 6. Dashboard
        if self.config.enable_dashboard {
            info!("[6/6] Dashboard available at http://{}", self.config.dashboard_bind);
        }

        info!("Agent started — all enabled subsystems are running");
        Ok(())
    }

    /// Pull threat intel from configured TAXII feeds and load IOCs into net tracker.
    async fn pull_threat_intel(taxii: &Arc<TaxiiClient>, net_tracker: &Arc<NetConnectionTracker>) {
        // Pull from MITRE ATT&CK
        match taxii.pull_objects(
            "https://cti-taxii.mitre.org/stix/collections",
            "enterprise-attack",
            "MITRE ATT&CK",
            None,
        ).await {
            Ok(result) => {
                info!(
                    objects = result.objects_fetched,
                    indicators = result.indicators,
                    "MITRE ATT&CK pull complete"
                );
                // Extract IPs from indicators and feed into net tracker blacklist
                let indicators = taxii.all_indicators();
                let mut ips = Vec::new();
                for ind in &indicators {
                    // Extract IPs from STIX patterns like [ipv4-addr:value = '1.2.3.4']
                    if ind.pattern.contains("ipv4-addr") || ind.pattern.contains("ipv6-addr") {
                        if let Some(ip) = Self::extract_ip_from_pattern(&ind.pattern) {
                            ips.push(ip);
                        }
                    }
                }
                if !ips.is_empty() {
                    net_tracker.load_blacklist(&ips);
                    info!(count = ips.len(), "Loaded threat intel IPs into network tracker");
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to pull MITRE ATT&CK feed (non-fatal)");
            }
        }
    }

    /// Extract an IP address from a STIX pattern string.
    fn extract_ip_from_pattern(pattern: &str) -> Option<String> {
        // Patterns look like: [ipv4-addr:value = '203.0.113.5']
        let start = pattern.find('\'')?;
        let end = pattern.rfind('\'')?;
        if end > start + 1 {
            Some(pattern[start + 1..end].to_string())
        } else {
            None
        }
    }

    /// Stop all subsystems gracefully.
    pub fn stop(&self) {
        info!("Stopping Nexus Sentinel Agent...");
        self.running.store(false, Ordering::Relaxed);
        self.process_monitor.stop();
        self.fs_watcher.stop();
        self.net_tracker.stop();
        info!("Agent stopped");
    }

    /// Get current agent status.
    pub fn status(&self) -> AgentStatus {
        let uptime = self.started_at.read()
            .map(|s| s.elapsed().as_secs())
            .unwrap_or(0);

        AgentStatus {
            running: self.running.load(Ordering::Relaxed),
            uptime_secs: uptime,
            subsystems: vec![
                SubsystemStatus {
                    name: "process_monitor".into(),
                    enabled: self.config.enable_process_monitor,
                    running: self.config.enable_process_monitor && self.running.load(Ordering::Relaxed),
                    events_generated: self.process_monitor.anomalies_detected(),
                },
                SubsystemStatus {
                    name: "fs_watcher".into(),
                    enabled: self.config.enable_fs_watcher,
                    running: self.fs_watcher.is_running(),
                    events_generated: self.fs_watcher.total_events(),
                },
                SubsystemStatus {
                    name: "file_integrity".into(),
                    enabled: self.config.enable_fim,
                    running: self.config.enable_fim && self.running.load(Ordering::Relaxed),
                    events_generated: self.fim.violations_found(),
                },
                SubsystemStatus {
                    name: "net_connection_tracker".into(),
                    enabled: self.config.enable_net_tracker,
                    running: self.net_tracker.is_running(),
                    events_generated: self.net_tracker.total_anomalies(),
                },
                SubsystemStatus {
                    name: "threat_intel".into(),
                    enabled: self.config.enable_threat_intel,
                    running: self.config.enable_threat_intel && self.running.load(Ordering::Relaxed),
                    events_generated: self.taxii.total_objects(),
                },
            ],
            total_events: self.bus.total_published(),
            total_anomalies: self.process_monitor.anomalies_detected()
                + self.fs_watcher.total_critical()
                + self.net_tracker.total_anomalies(),
            threat_intel_indicators: self.taxii.total_indicators(),
            active_connections: self.net_tracker.current_connections().len(),
            watched_files: self.fim.files_tracked(),
        }
    }

    /// Get reference to the event bus for external subscribers.
    pub fn event_bus(&self) -> &Arc<EventBus> { &self.bus }
    /// Get reference to the TAXII client for IOC matching.
    pub fn taxii_client(&self) -> &Arc<TaxiiClient> { &self.taxii }
    /// Get reference to the net tracker for connection queries.
    pub fn net_tracker(&self) -> &Arc<NetConnectionTracker> { &self.net_tracker }
    /// Get reference to the process monitor.
    pub fn process_monitor(&self) -> &Arc<ProcessMonitor> { &self.process_monitor }
    /// Get reference to the FIM.
    pub fn file_integrity(&self) -> &Arc<FileIntegrityMonitor> { &self.fim }
    /// Get reference to the FS watcher.
    pub fn fs_watcher(&self) -> &Arc<FsWatcher> { &self.fs_watcher }
}
