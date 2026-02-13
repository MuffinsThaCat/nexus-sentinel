//! # Download Guard — Real-time download folder malware scanner (Pro)
//!
//! Watches ~/Downloads (and configurable additional paths) using the `notify`
//! crate for new file creations. Every new file is automatically scanned by
//! `MalwareScanner` and alerts are emitted for suspicious/malicious verdicts.
//!
//! Integration points:
//! - Registered with `reg!()` in sentinel.rs so alerts appear in the dashboard
//! - Uses `MalwareScanner::scan_file()` for all 22 analysis engines
//! - Debounces rapid file writes (waits for file to stabilize before scanning)

use crate::malware_scanner::{MalwareScanner, ScanResult, ScanVerdict};
use crate::types::{EndpointAlert, Severity};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::RwLock;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

// ── Constants ────────────────────────────────────────────────────────────────

const MAX_FILE_SIZE: u64 = 256 * 1024 * 1024; // 256 MB scan limit
const DEBOUNCE_MS: u64 = 1500; // Wait for file write to complete
const MAX_ALERTS: usize = 500;
const MAX_RESULTS: usize = 2000;

// ── DownloadGuard ────────────────────────────────────────────────────────────

pub struct DownloadGuard {
    scanner: Arc<MalwareScanner>,
    alerts: Arc<RwLock<Vec<EndpointAlert>>>,
    results: Arc<RwLock<Vec<ScanResult>>>,
    watch_paths: Vec<PathBuf>,
    running: Arc<std::sync::atomic::AtomicBool>,
    total_scanned: Arc<AtomicU64>,
    total_threats: Arc<AtomicU64>,
    total_suspicious: Arc<AtomicU64>,
    total_errors: Arc<AtomicU64>,
    recently_scanned: Arc<RwLock<HashSet<String>>>,
    _watcher: RwLock<Option<RecommendedWatcher>>,
}

impl DownloadGuard {
    pub fn new() -> Self {
        let mut watch_paths = Vec::new();

        // Always watch ~/Downloads
        if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
            let downloads = home.join("Downloads");
            if downloads.exists() {
                watch_paths.push(downloads);
            }
            // macOS also has ~/Desktop as a common drop target
            let desktop = home.join("Desktop");
            if desktop.exists() {
                watch_paths.push(desktop);
            }
        }

        let guard = Self {
            scanner: Arc::new(MalwareScanner::new()),
            alerts: Arc::new(RwLock::new(Vec::new())),
            results: Arc::new(RwLock::new(Vec::new())),
            watch_paths,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            total_scanned: Arc::new(AtomicU64::new(0)),
            total_threats: Arc::new(AtomicU64::new(0)),
            total_suspicious: Arc::new(AtomicU64::new(0)),
            total_errors: Arc::new(AtomicU64::new(0)),
            recently_scanned: Arc::new(RwLock::new(HashSet::new())),
            _watcher: RwLock::new(None),
        };

        // Auto-start the watcher
        guard.start();
        guard
    }

    /// Start watching download directories for new files.
    fn start(&self) {
        if self.watch_paths.is_empty() {
            warn!("DownloadGuard: no watch paths found, skipping");
            return;
        }
        if self.running.load(Ordering::Relaxed) {
            return;
        }
        self.running.store(true, Ordering::Relaxed);

        let (tx, rx) = std::sync::mpsc::channel::<Event>();

        let watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    let _ = tx.send(event);
                }
            },
            Config::default(),
        );

        let mut watcher = match watcher {
            Ok(w) => w,
            Err(e) => {
                error!("DownloadGuard: failed to create watcher: {}", e);
                return;
            }
        };

        for path in &self.watch_paths {
            if let Err(e) = watcher.watch(path, RecursiveMode::NonRecursive) {
                warn!(path = %path.display(), error = %e, "DownloadGuard: failed to watch");
            } else {
                info!(path = %path.display(), "DownloadGuard: watching");
            }
        }

        *self._watcher.write() = Some(watcher);

        // Spawn background thread to process file events
        let scanner = self.scanner.clone();
        let alerts = self.alerts.clone();
        let results = self.results.clone();
        let running = self.running.clone();
        let total_scanned = self.total_scanned.clone();
        let total_threats = self.total_threats.clone();
        let total_suspicious = self.total_suspicious.clone();
        let total_errors = self.total_errors.clone();
        let recently_scanned = self.recently_scanned.clone();

        std::thread::Builder::new()
            .name("download-guard".into())
            .spawn(move || {
                while running.load(Ordering::Relaxed) {
                    match rx.recv_timeout(std::time::Duration::from_millis(500)) {
                        Ok(event) => {
                            // Only care about file creations and modifications
                            let dominated = matches!(
                                event.kind,
                                EventKind::Create(_) | EventKind::Modify(notify::event::ModifyKind::Data(_))
                            );
                            if !dominated { continue; }

                            for path in &event.paths {
                                Self::handle_new_file(
                                    path, &scanner, &alerts, &results,
                                    &total_scanned, &total_threats,
                                    &total_suspicious, &total_errors,
                                    &recently_scanned,
                                );
                            }
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
                info!("DownloadGuard: watcher thread exiting");
            })
            .ok();

        let path_list: Vec<String> = self.watch_paths.iter()
            .map(|p| p.display().to_string()).collect();
        info!(paths = ?path_list, "DownloadGuard: active");
    }

    /// Handle a newly created/modified file.
    fn handle_new_file(
        path: &Path,
        scanner: &Arc<MalwareScanner>,
        alerts: &Arc<RwLock<Vec<EndpointAlert>>>,
        results: &Arc<RwLock<Vec<ScanResult>>>,
        total_scanned: &Arc<AtomicU64>,
        total_threats: &Arc<AtomicU64>,
        total_suspicious: &Arc<AtomicU64>,
        total_errors: &Arc<AtomicU64>,
        recently_scanned: &Arc<RwLock<HashSet<String>>>,
    ) {
        let path_str = path.display().to_string();

        // Skip directories, temporary files, hidden files, .part/.crdownload
        if path.is_dir() { return; }
        if let Some(fname) = path.file_name().and_then(|f| f.to_str()) {
            if fname.starts_with('.') { return; }
            // Chrome/Firefox partial downloads
            let lower = fname.to_lowercase();
            if lower.ends_with(".crdownload") || lower.ends_with(".part")
                || lower.ends_with(".tmp") || lower.ends_with(".download")
            {
                return;
            }
        }

        // Dedup: skip if we scanned this path in the last few seconds
        {
            let scanned = recently_scanned.read();
            if scanned.contains(&path_str) { return; }
        }

        // Debounce: wait for the file to finish writing
        std::thread::sleep(std::time::Duration::from_millis(DEBOUNCE_MS));

        // Verify file still exists and is readable
        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return, // File vanished (temp file)
        };

        if !metadata.is_file() { return; }
        if metadata.len() == 0 { return; }
        if metadata.len() > MAX_FILE_SIZE { return; }

        // Mark as recently scanned
        {
            let mut scanned = recently_scanned.write();
            scanned.insert(path_str.clone());
            // Prune old entries periodically
            if scanned.len() > 5000 { scanned.clear(); }
        }

        // Read the file
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                debug!(path = %path_str, error = %e, "DownloadGuard: can't read file");
                total_errors.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };

        // Compute hash and scan
        let hash = MalwareScanner::sha256_hex(&data);
        let result = scanner.scan_file(&path_str, &data, &hash);
        total_scanned.fetch_add(1, Ordering::Relaxed);

        let verdict_str = match &result.verdict {
            ScanVerdict::Clean => "Clean".to_string(),
            ScanVerdict::Suspicious { score, .. } => format!("Suspicious({:.0}%)", score * 100.0),
            ScanVerdict::Malicious { rule_name, .. } => format!("Malicious({})", rule_name),
            ScanVerdict::HashMatch { family, .. } => format!("HashMatch({})", family),
            ScanVerdict::Error { message } => format!("Error({})", message),
        };
        info!(path = %path_str, size = data.len(), verdict = %verdict_str, "DownloadGuard: scanned");

        // Emit alert for non-clean verdicts
        match &result.verdict {
            ScanVerdict::Malicious { rule_name, details } => {
                total_threats.fetch_add(1, Ordering::Relaxed);
                Self::push_alert(alerts, Severity::High,
                    &format!("Malicious file detected: {}", path.file_name().unwrap_or_default().to_string_lossy()),
                    &format!("Rule: {} | {} | SHA-256: {} | Size: {} bytes", rule_name, details, hash, data.len()),
                );
            }
            ScanVerdict::HashMatch { family, .. } => {
                total_threats.fetch_add(1, Ordering::Relaxed);
                Self::push_alert(alerts, Severity::Critical,
                    &format!("Known malware downloaded: {}", family),
                    &format!("File: {} | Family: {} | SHA-256: {} | Size: {} bytes",
                        path.file_name().unwrap_or_default().to_string_lossy(), family, hash, data.len()),
                );
            }
            ScanVerdict::Suspicious { score, reasons } => {
                total_suspicious.fetch_add(1, Ordering::Relaxed);
                if *score >= 0.5 {
                    Self::push_alert(alerts, Severity::Medium,
                        &format!("Suspicious download: {} (score {:.0}%)",
                            path.file_name().unwrap_or_default().to_string_lossy(), score * 100.0),
                        &format!("{} | SHA-256: {} | Size: {} bytes", reasons.join("; "), hash, data.len()),
                    );
                }
            }
            ScanVerdict::Clean => {}
            ScanVerdict::Error { message } => {
                total_errors.fetch_add(1, Ordering::Relaxed);
                debug!(path = %path_str, error = %message, "DownloadGuard: scan error");
            }
        }

        // Store result
        {
            let mut r = results.write();
            if r.len() >= MAX_RESULTS { let drain = r.len() - MAX_RESULTS + 1; r.drain(..drain); }
            r.push(result);
        }
    }

    fn push_alert(alerts: &Arc<RwLock<Vec<EndpointAlert>>>, severity: Severity, title: &str, details: &str) {
        let alert = EndpointAlert {
            timestamp: chrono::Utc::now().timestamp(),
            severity,
            component: "download_guard".to_string(),
            title: title.to_string(),
            details: details.to_string(),
            remediation: None,
            process: None,
            file: None,
        };
        let mut a = alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(alert);
    }

    // ── Public API ───────────────────────────────────────────────────────────

    pub fn alerts(&self) -> Vec<EndpointAlert> { self.alerts.read().clone() }

    pub fn recent_results(&self, limit: usize) -> Vec<ScanResult> {
        let r = self.results.read();
        r.iter().rev().take(limit).cloned().collect()
    }

    pub fn total_scanned(&self) -> u64 { self.total_scanned.load(Ordering::Relaxed) }
    pub fn total_threats(&self) -> u64 { self.total_threats.load(Ordering::Relaxed) }
    pub fn total_suspicious(&self) -> u64 { self.total_suspicious.load(Ordering::Relaxed) }
    pub fn is_running(&self) -> bool { self.running.load(Ordering::Relaxed) }

    pub fn watched_paths(&self) -> Vec<String> {
        self.watch_paths.iter().map(|p| p.display().to_string()).collect()
    }

    /// Manual scan: scan a file on demand and return the result.
    pub fn scan_file(&self, path: &str) -> Result<ScanResult, String> {
        let p = Path::new(path);
        if !p.exists() { return Err("File not found".into()); }
        let meta = std::fs::metadata(p).map_err(|e| format!("Cannot read metadata: {}", e))?;
        if meta.len() > MAX_FILE_SIZE { return Err("File too large (>256 MB)".into()); }
        let data = std::fs::read(p).map_err(|e| format!("Cannot read file: {}", e))?;
        let hash = MalwareScanner::sha256_hex(&data);
        Ok(self.scanner.scan_file(path, &data, &hash))
    }

    /// Get a reference to the inner MalwareScanner (for hash DB stats, etc.)
    pub fn scanner(&self) -> &MalwareScanner { &self.scanner }
}
