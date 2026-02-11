//! # Filesystem Event Watcher — Real-time push-based file monitoring
//!
//! Uses the `notify` crate (inotify on Linux, FSEvents on macOS, ReadDirectoryChanges on Windows)
//! to get instant notification of file creates, modifies, deletes, and renames.
//! This is the production-grade replacement for polling-based integrity checks.

use crate::event_bus::{EventBus, EventSeverity};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{error, info, warn};

/// Categorized filesystem event for security analysis.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum FsEventType {
    Created,
    Modified,
    Deleted,
    Renamed { from: String },
    PermissionChanged,
    MetadataChanged,
}

/// A processed filesystem event with security context.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FsSecurityEvent {
    pub path: String,
    pub event_type: FsEventType,
    pub timestamp: i64,
    pub severity: FsEventSeverity,
    pub context: String,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum FsEventSeverity {
    Info,
    Warning,
    Critical,
}

/// Paths that are security-sensitive and warrant higher severity.
const CRITICAL_PATHS: &[&str] = &[
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh",
    "/etc/pam.d", "/etc/crontab", "/var/spool/cron",
    "/usr/bin", "/usr/sbin", "/usr/local/bin",
    "/boot", "/System/Library", "/Library/LaunchDaemons",
    "/Library/LaunchAgents",
    "~/.ssh/authorized_keys", "~/.bashrc", "~/.bash_profile",
    "~/.zshrc", "~/.profile",
];

/// Extensions that indicate executable/script content.
const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "exe", "dll", "so", "dylib", "sh", "bash", "py", "rb", "pl",
    "ps1", "bat", "cmd", "vbs", "js", "msi", "deb", "rpm",
    "elf", "bin", "app", "command",
];

/// Real-time filesystem watcher.
pub struct FsWatcher {
    watched_paths: RwLock<Vec<PathBuf>>,
    events_log: Arc<RwLock<Vec<FsSecurityEvent>>>,
    running: Arc<AtomicBool>,
    events_received: Arc<AtomicU64>,
    critical_events: Arc<AtomicU64>,
    max_events: usize,
    watcher_handle: RwLock<Option<RecommendedWatcher>>,
}

impl FsWatcher {
    pub fn new() -> Self {
        Self {
            watched_paths: RwLock::new(Vec::new()),
            events_log: Arc::new(RwLock::new(Vec::new())),
            running: Arc::new(AtomicBool::new(false)),
            events_received: Arc::new(AtomicU64::new(0)),
            critical_events: Arc::new(AtomicU64::new(0)),
            max_events: 100_000,
            watcher_handle: RwLock::new(None),
        }
    }

    /// Add a path to watch (directory = recursive).
    pub fn watch_path(&self, path: &str) {
        let pb = PathBuf::from(path);
        self.watched_paths.write().push(pb.clone());

        // If watcher is already running, add the path dynamically
        if let Some(ref mut w) = *self.watcher_handle.write() {
            let mode = if pb.is_dir() { RecursiveMode::Recursive } else { RecursiveMode::NonRecursive };
            if let Err(e) = w.watch(&pb, mode) {
                warn!(path = %path, error = %e, "Failed to add watch path");
            } else {
                info!(path = %path, "Added watch path dynamically");
            }
        }
    }

    /// Classify severity based on path and event type.
    fn classify_severity(path: &str, event_type: &FsEventType) -> FsEventSeverity {
        let path_lower = path.to_lowercase();

        // Critical path modifications
        for cp in CRITICAL_PATHS {
            if path_lower.contains(cp) {
                return FsEventSeverity::Critical;
            }
        }

        // Executable file changes
        if let Some(ext) = Path::new(path).extension().and_then(|e| e.to_str()) {
            if EXECUTABLE_EXTENSIONS.contains(&ext.to_lowercase().as_str()) {
                return match event_type {
                    FsEventType::Created | FsEventType::Modified => FsEventSeverity::Warning,
                    FsEventType::Deleted => FsEventSeverity::Warning,
                    _ => FsEventSeverity::Info,
                };
            }
        }

        // Hidden files (dotfiles) in sensitive locations
        if let Some(fname) = Path::new(path).file_name().and_then(|f| f.to_str()) {
            if fname.starts_with('.') && matches!(event_type, FsEventType::Created) {
                return FsEventSeverity::Warning;
            }
        }

        FsEventSeverity::Info
    }

    /// Build security context string for an event.
    fn build_context(path: &str, event_type: &FsEventType) -> String {
        let mut ctx = Vec::new();

        if let Some(ext) = Path::new(path).extension().and_then(|e| e.to_str()) {
            if EXECUTABLE_EXTENSIONS.contains(&ext.to_lowercase().as_str()) {
                ctx.push("executable_content".to_string());
            }
        }

        for cp in CRITICAL_PATHS {
            if path.contains(cp) {
                ctx.push(format!("critical_path:{}", cp));
                break;
            }
        }

        match event_type {
            FsEventType::Created => ctx.push("new_file".into()),
            FsEventType::Modified => ctx.push("content_changed".into()),
            FsEventType::Deleted => ctx.push("file_removed".into()),
            FsEventType::Renamed { from } => ctx.push(format!("renamed_from:{}", from)),
            FsEventType::PermissionChanged => ctx.push("perms_changed".into()),
            FsEventType::MetadataChanged => ctx.push("metadata_changed".into()),
        }

        if ctx.is_empty() { "none".into() } else { ctx.join(", ") }
    }

    /// Process a raw notify event into a security event.
    fn process_event(
        event: &Event,
        events_log: &Arc<RwLock<Vec<FsSecurityEvent>>>,
        events_received: &Arc<AtomicU64>,
        critical_events: &Arc<AtomicU64>,
        max_events: usize,
        bus: &Option<Arc<EventBus>>,
    ) {
        let event_type = match event.kind {
            EventKind::Create(_) => FsEventType::Created,
            EventKind::Modify(notify::event::ModifyKind::Data(_)) => FsEventType::Modified,
            EventKind::Modify(notify::event::ModifyKind::Metadata(_)) => FsEventType::MetadataChanged,
            EventKind::Remove(_) => FsEventType::Deleted,
            EventKind::Modify(notify::event::ModifyKind::Name(_)) => {
                // For renames we get two events; simplify
                FsEventType::Renamed { from: "unknown".into() }
            }
            _ => return, // Ignore Access, Other, Any
        };

        for path in &event.paths {
            let path_str = path.display().to_string();
            let severity = Self::classify_severity(&path_str, &event_type);
            let context = Self::build_context(&path_str, &event_type);
            let now = chrono::Utc::now().timestamp();

            events_received.fetch_add(1, Ordering::Relaxed);
            if matches!(severity, FsEventSeverity::Critical) {
                critical_events.fetch_add(1, Ordering::Relaxed);
            }

            let sec_event = FsSecurityEvent {
                path: path_str.clone(),
                event_type: event_type.clone(),
                timestamp: now,
                severity,
                context: context.clone(),
            };

            // Store in ring buffer
            {
                let mut log = events_log.write();
                if log.len() >= max_events {
                    let drain = max_events / 4;
                    log.drain(..drain);
                }
                log.push(sec_event);
            }

            // Emit to event bus if available
            if let Some(ref bus) = bus {
                let bus_severity = match severity {
                    FsEventSeverity::Critical => EventSeverity::Critical,
                    FsEventSeverity::Warning => EventSeverity::Medium,
                    FsEventSeverity::Info => EventSeverity::Low,
                };
                let mut details = HashMap::new();
                details.insert("path".into(), path_str);
                details.insert("event".into(), format!("{:?}", event_type));
                details.insert("context".into(), context);
                bus.emit_detection(
                    "fs_watcher", "sentinel-core",
                    bus_severity,
                    &format!("FS event: {:?}", event_type),
                    details,
                    vec!["filesystem".into(), "integrity".into()],
                );
            }
        }
    }

    /// Start the watcher. Spawns a background thread for the notify event loop.
    pub fn start(&self, bus: Option<Arc<EventBus>>) -> Result<(), String> {
        if self.running.load(Ordering::Relaxed) {
            return Err("Watcher already running".into());
        }
        self.running.store(true, Ordering::Relaxed);

        let events_log = self.events_log.clone();
        let events_received = self.events_received.clone();
        let critical_events = self.critical_events.clone();
        let max_events = self.max_events;
        let running = self.running.clone();

        let (tx, rx) = std::sync::mpsc::channel();

        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    let _ = tx.send(event);
                }
            },
            Config::default(),
        ).map_err(|e| format!("Failed to create watcher: {}", e))?;

        // Add all watched paths
        let paths = self.watched_paths.read().clone();
        for path in &paths {
            let mode = if path.is_dir() { RecursiveMode::Recursive } else { RecursiveMode::NonRecursive };
            watcher.watch(path, mode)
                .map_err(|e| format!("Failed to watch {}: {}", path.display(), e))?;
            info!(path = %path.display(), "Watching path");
        }

        *self.watcher_handle.write() = Some(watcher);

        // Spawn receiver thread
        std::thread::Builder::new()
            .name("fs-watcher-recv".into())
            .spawn(move || {
                while running.load(Ordering::Relaxed) {
                    match rx.recv_timeout(std::time::Duration::from_millis(500)) {
                        Ok(event) => {
                            Self::process_event(
                                &event, &events_log, &events_received,
                                &critical_events, max_events, &bus,
                            );
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
                info!("FS watcher receiver thread exiting");
            })
            .map_err(|e| format!("Failed to spawn watcher thread: {}", e))?;

        let path_count = paths.len();
        info!(paths = path_count, "Filesystem watcher started");
        Ok(())
    }

    /// Stop the watcher.
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        *self.watcher_handle.write() = None;
        info!("Filesystem watcher stopped");
    }

    /// Get recent events (last N).
    pub fn recent_events(&self, count: usize) -> Vec<FsSecurityEvent> {
        let log = self.events_log.read();
        let start = log.len().saturating_sub(count);
        log[start..].to_vec()
    }

    /// Get only critical events.
    pub fn critical_events_log(&self) -> Vec<FsSecurityEvent> {
        self.events_log.read().iter()
            .filter(|e| matches!(e.severity, FsEventSeverity::Critical))
            .cloned()
            .collect()
    }

    pub fn is_running(&self) -> bool { self.running.load(Ordering::Relaxed) }
    pub fn total_events(&self) -> u64 { self.events_received.load(Ordering::Relaxed) }
    pub fn total_critical(&self) -> u64 { self.critical_events.load(Ordering::Relaxed) }
    pub fn watched_path_count(&self) -> usize { self.watched_paths.read().len() }
}
