mod components;
mod alert_dispatcher;
mod dashboard_ui;

use anyhow::Result;
use clap::Parser;
use std::sync::Arc;
use tracing::{info, warn, error, Level};
use tracing_subscriber::FmtSubscriber;

use sentinel_core::config_loader::SentinelConfig;

/// Expand ~ to the user's home directory
fn expand_tilde(path: &str) -> String {
    if path.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            return format!("{}/{}", home.to_string_lossy(), &path[2..]);
        }
    }
    path.to_string()
}
use sentinel_core::event_bus::EventBus;
use sentinel_core::file_integrity::FileIntegrityMonitor;
use sentinel_core::fs_watcher::FsWatcher;
use sentinel_core::io_adapters::{FileWatcherAdapter, WebhookAdapter, SyslogAdapter, PeriodicScanner};
use sentinel_core::net_connections::NetConnectionTracker;
use sentinel_core::persistence::PersistenceManager;
use sentinel_core::process_monitor::ProcessMonitor;
use sentinel_core::taxii_client::TaxiiClient;
use sentinel_core::threat_intel::ThreatIntelFeed;
use sentinel_core::MemoryMetrics;

#[derive(Parser, Debug)]
#[command(name = "nexus-sentinel", version, about = "Nexus Sentinel — Comprehensive Local Security Suite")]
struct Cli {
    /// Configuration file path
    #[arg(short, long, default_value = "sentinel.toml")]
    config: String,

    /// Memory budget in MB (overrides config file)
    #[arg(short, long)]
    memory_mb: Option<usize>,

    /// Log level (overrides config file)
    #[arg(short, long)]
    log_level: Option<String>,

    /// Generate a default config file and exit
    #[arg(long)]
    generate_config: bool,

    /// Dry-run: load config, validate, print report, exit
    #[arg(long)]
    dry_run: bool,

    /// Dashboard bind address
    #[arg(long, default_value = "127.0.0.1:9090")]
    dashboard_bind: String,

    /// Disable dashboard
    #[arg(long)]
    no_dashboard: bool,

    /// Alert log file path
    #[arg(long, default_value = "~/.beaver-warrior/alerts.jsonl")]
    alert_log: String,

    /// Webhook URL for alert delivery (empty = disabled)
    #[arg(long, default_value = "")]
    alert_webhook: String,

    /// Enable file integrity monitoring
    #[arg(long)]
    file_integrity: bool,

    /// Enable process monitoring
    #[arg(long)]
    process_monitor: bool,

    /// Enable threat intel feed fetching
    #[arg(long)]
    threat_intel: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // ── Generate Config ──────────────────────────────────────────────
    if cli.generate_config {
        let config = SentinelConfig::default();
        config.save(&cli.config).map_err(|e| anyhow::anyhow!(e))?;
        println!("Default configuration written to {}", cli.config);
        return Ok(());
    }

    // ── Load Config ──────────────────────────────────────────────────
    let config = SentinelConfig::load(&cli.config).unwrap_or_else(|e| {
        eprintln!("Warning: {}, using defaults", e);
        SentinelConfig::default()
    });

    let memory_mb = cli.memory_mb.unwrap_or(config.general.memory_budget_mb);
    let log_level = cli.log_level.as_deref().unwrap_or(&config.general.log_level);

    // ── Tracing ──────────────────────────────────────────────────────
    let level = match log_level {
        "trace" => Level::TRACE, "debug" => Level::DEBUG,
        "warn" => Level::WARN, "error" => Level::ERROR, _ => Level::INFO,
    };
    let subscriber = FmtSubscriber::builder().with_max_level(level).finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Nexus Sentinel v{}", env!("CARGO_PKG_VERSION"));
    info!("Memory budget: {} MB", memory_mb);
    info!("Security layers enabled: {}/38", config.enabled_layer_count());

    // ── Core Infrastructure ──────────────────────────────────────────
    let budget = memory_mb * 1024 * 1024;
    let metrics = MemoryMetrics::new(budget);
    let event_bus = Arc::new(EventBus::new());
    info!("Event bus initialized");

    // Ensure data directory exists
    let data_dir = expand_tilde("~/.beaver-warrior");
    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        warn!(error = %e, "Could not create data directory");
    }

    let snapshot_dir = expand_tilde(&config.general.snapshot_dir);
    let persistence = Arc::new(PersistenceManager::new(&snapshot_dir));
    if let Err(e) = persistence.init() {
        warn!(error = %e, "Persistence init failed (snapshots disabled)");
    }

    // ══════════════════════════════════════════════════════════════════
    //  BOOTSTRAP ALL 38 SECURITY DOMAINS
    // ══════════════════════════════════════════════════════════════════

    let stack = Arc::new(components::bootstrap(&config, metrics.clone()));

    // ── Alert Dispatcher ─────────────────────────────────────────────
    let alert_log = expand_tilde(&cli.alert_log);
    let _alert_handle = alert_dispatcher::AlertDispatcher::new(stack.clone())
        .with_log_file(&alert_log)
        .with_webhook(&cli.alert_webhook)
        .with_interval(5)
        .start();
    info!(log = %cli.alert_log, "Alert dispatcher started");

    // ── I/O Adapters ─────────────────────────────────────────────────
    if !config.io.watch_paths.is_empty() {
        let paths: Vec<std::path::PathBuf> = config.io.watch_paths.iter()
            .map(|p| std::path::PathBuf::from(p)).collect();
        let watcher = FileWatcherAdapter::new(paths);
        if let Err(e) = watcher.start(event_bus.clone()) {
            warn!(error = %e, "File watcher failed to start");
        }
    }
    if config.io.webhook_enabled {
        if let Ok(addr) = config.io.webhook_bind.parse() {
            let webhook = WebhookAdapter::new(addr);
            if let Err(e) = webhook.start(event_bus.clone()) {
                warn!(error = %e, "Webhook receiver failed to start");
            }
        }
    }
    if config.io.syslog_enabled {
        if let Ok(addr) = config.io.syslog_bind.parse() {
            let syslog = SyslogAdapter::new(addr);
            if let Err(e) = syslog.start(event_bus.clone()) {
                warn!(error = %e, "Syslog receiver failed to start");
            }
        }
    }

    // Periodic health scanner
    let health_interval = config.mgmt.settings.get("health_check_interval_secs")
        .and_then(|v| v.as_integer()).unwrap_or(60) as u64;
    if health_interval > 0 {
        let scanner = PeriodicScanner::new(health_interval);
        let m = metrics.clone();
        let _ = scanner.start(event_bus.clone(), move |bus| {
            let report = m.report();
            if report.utilization_percent > 90.0 {
                let mut details = std::collections::HashMap::new();
                details.insert("utilization".into(), format!("{:.1}%", report.utilization_percent));
                details.insert("used_bytes".into(), report.total_used.to_string());
                bus.emit_detection(
                    "health_scanner", "sentinel-core",
                    sentinel_core::event_bus::EventSeverity::High,
                    "Memory utilization critical",
                    details, vec!["health".into(), "memory".into()],
                );
            }
        });
    }

    // ── Periodic Snapshots ───────────────────────────────────────────
    if config.general.snapshot_interval_secs > 0 {
        let snap_persistence = persistence.clone();
        let interval = config.general.snapshot_interval_secs;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval));
            loop {
                ticker.tick().await;
                let results = snap_persistence.snapshot_all();
                let fail = results.iter().filter(|r| r.is_err()).count();
                if fail > 0 { warn!(failed = fail, "Snapshot cycle errors"); }
            }
        });
    }

    // ── Dry Run ──────────────────────────────────────────────────────
    if cli.dry_run {
        let report = metrics.report();
        info!(budget = report.total_budget, used = report.total_used,
            util = format!("{:.1}%", report.utilization_percent),
            components = report.components.len(), "Memory report");
        info!("Dry-run complete. Configuration valid.");
        return Ok(());
    }

    // ── Process Monitor ──────────────────────────────────────────────
    let process_mon = if cli.process_monitor {
        let pm = Arc::new(ProcessMonitor::new());
        pm.baseline();
        pm.start_periodic(15, event_bus.clone());
        metrics.register_component("process_monitor", 16 * 1024 * 1024);
        info!("Process monitor started (15s interval)");
        Some(pm)
    } else { None };

    // ── File Integrity Monitor ───────────────────────────────────────
    let fim = if cli.file_integrity {
        let f = Arc::new(FileIntegrityMonitor::new());
        f.watch_system_paths();
        f.build_baseline();
        f.start_periodic(300, event_bus.clone());
        metrics.register_component("file_integrity", 32 * 1024 * 1024);
        info!("File integrity monitor started (5min interval)");
        Some(f)
    } else { None };

    // ── Threat Intelligence ──────────────────────────────────────────
    let threat_intel = if cli.threat_intel {
        let ti = Arc::new(ThreatIntelFeed::new());
        info!("Fetching initial threat intel feeds...");
        match ti.fetch_all().await {
            Ok(count) => info!(indicators = count, "Threat intel loaded"),
            Err(e) => warn!(error = %e, "Initial threat intel fetch failed"),
        }
        ti.start_periodic(3600, event_bus.clone());
        metrics.register_component("threat_intel", 64 * 1024 * 1024);
        Some(ti)
    } else { None };

    // ── Filesystem Watcher (push-based real-time) ────────────────────
    let fs_watcher = {
        let fw = Arc::new(FsWatcher::new());
        fw.watch_path("/etc");
        fw.watch_path("/usr/bin");
        fw.watch_path("/usr/local/bin");
        if let Err(e) = fw.start(Some(event_bus.clone())) {
            warn!(error = %e, "FS watcher failed to start");
        } else {
            info!("Filesystem watcher started (3 paths)");
        }
        metrics.register_component("fs_watcher", 4 * 1024 * 1024);
        Some(fw)
    };

    // ── Network Connection Tracker ─────────────────────────────────
    let net_tracker = {
        let nt = Arc::new(NetConnectionTracker::new());
        nt.start_periodic(30, event_bus.clone());
        metrics.register_component("net_connection_tracker", 8 * 1024 * 1024);
        info!("Network connection tracker started (30s interval)");
        Some(nt)
    };

    // ── TAXII Threat Intel Client ──────────────────────────────────
    let taxii = {
        use sentinel_core::taxii_client::TaxiiServerConfig;
        let tc = Arc::new(TaxiiClient::new());
        tc.add_server(TaxiiServerConfig {
            name: "MITRE ATT&CK".into(),
            discovery_url: "https://cti-taxii.mitre.org/taxii2".into(),
            api_root: Some("https://cti-taxii.mitre.org/stix/collections".into()),
            collection_id: None,
            poll_interval_secs: 3600,
            enabled: true,
        });
        metrics.register_component("taxii_client", 32 * 1024 * 1024);
        info!("TAXII 2.1 client initialized (MITRE ATT&CK feed)");
        Some(tc)
    };

    // ── Web Dashboard ────────────────────────────────────────────────
    if !cli.no_dashboard {
        let dash_stack = stack.clone();
        let bind = cli.dashboard_bind.clone();
        tokio::spawn(async move {
            if let Err(e) = dashboard_ui::start_dashboard(dash_stack, &bind).await {
                error!(error = %e, "Dashboard failed");
            }
        });
        info!(addr = %cli.dashboard_bind, "Dashboard available at http://{}", cli.dashboard_bind);
    }

    // ── Ready ────────────────────────────────────────────────────────
    let report = metrics.report();
    info!(
        budget_mb = memory_mb,
        used = report.total_used,
        utilization = format!("{:.1}%", report.utilization_percent),
        registered_components = report.components.len(),
        event_bus_subscribers = event_bus.subscriber_count(),
        "Nexus Sentinel fully initialized — all security domains active"
    );

    info!("Nexus Sentinel running. Press Ctrl+C to stop.");
    tokio::signal::ctrl_c().await?;
    info!("Shutting down Nexus Sentinel...");

    // ── Graceful Shutdown ────────────────────────────────────────────
    if let Some(ref pm) = process_mon {
        pm.stop();
        info!(scans = pm.scans_completed(), anomalies = pm.anomalies_detected(), "Process monitor stopped");
    }
    if let Some(ref f) = fim {
        f.stop();
        info!(scans = f.scans_completed(), violations = f.violations_found(), "File integrity stopped");
    }
    if let Some(ref ti) = threat_intel {
        ti.stop();
        info!(indicators = ti.total_indicators(), "Threat intel stopped");
    }
    if let Some(ref fw) = fs_watcher {
        fw.stop();
        info!(events = fw.total_events(), critical = fw.total_critical(), "FS watcher stopped");
    }
    if let Some(ref nt) = net_tracker {
        nt.stop();
        info!(scans = nt.scans_completed(), "Net tracker stopped");
    }
    if let Some(ref tc) = taxii {
        info!(servers = tc.server_count(), indicators = tc.total_indicators(), "TAXII client stopped");
    }

    info!("Saving final snapshots...");
    let results = persistence.snapshot_all();
    let ok = results.iter().filter(|r| r.is_ok()).count();

    info!(
        events_published = event_bus.total_published(),
        events_delivered = event_bus.total_delivered(),
        snapshots = ok,
        "Shutdown complete"
    );

    Ok(())
}
