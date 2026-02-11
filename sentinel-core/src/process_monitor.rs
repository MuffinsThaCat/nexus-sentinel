//! # Process Monitor — Real OS process scanning with anomaly detection
//!
//! Uses sysinfo to enumerate running processes, detect anomalies (high CPU,
//! suspicious names, unsigned binaries), and emit events to the bus.

use crate::event_bus::{EventBus, EventSeverity};
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use sysinfo::System;
use tracing::{info, warn};

/// A snapshot of a running process.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub exe_path: String,
    pub cmd: Vec<String>,
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    pub status: String,
    pub parent_pid: Option<u32>,
    pub start_time: u64,
}

/// Process anomaly types.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ProcessAnomaly {
    HighCpu { pid: u32, name: String, cpu: f32 },
    HighMemory { pid: u32, name: String, bytes: u64 },
    SuspiciousName { pid: u32, name: String, reason: String },
    NewProcess { pid: u32, name: String, exe: String },
    HiddenProcess { pid: u32, name: String },
}

/// Real process monitor using sysinfo.
pub struct ProcessMonitor {
    system: RwLock<System>,
    known_pids: RwLock<HashSet<u32>>,
    baseline_names: RwLock<HashSet<String>>,
    running: Arc<AtomicBool>,
    scans_completed: Arc<AtomicU64>,
    anomalies_detected: Arc<AtomicU64>,
    cpu_threshold: f32,
    memory_threshold_bytes: u64,
    suspicious_patterns: Vec<String>,
}

impl ProcessMonitor {
    pub fn new() -> Self {
        Self {
            system: RwLock::new(System::new_all()),
            known_pids: RwLock::new(HashSet::new()),
            baseline_names: RwLock::new(HashSet::new()),
            running: Arc::new(AtomicBool::new(false)),
            scans_completed: Arc::new(AtomicU64::new(0)),
            anomalies_detected: Arc::new(AtomicU64::new(0)),
            cpu_threshold: 90.0,
            memory_threshold_bytes: 2 * 1024 * 1024 * 1024, // 2GB
            suspicious_patterns: vec![
                "mimikatz".into(), "lazagne".into(), "pwdump".into(),
                "procdump".into(), "keylog".into(), "reverse_shell".into(),
                "netcat".into(), "ncat".into(), "socat".into(),
                "cryptominer".into(), "xmrig".into(), "cgminer".into(),
                "coinhive".into(), "minergate".into(),
                "metasploit".into(), "msfconsole".into(), "meterpreter".into(),
                "cobalt".into(), "beacon".into(),
            ],
        }
    }

    /// Take a baseline snapshot of currently running processes.
    pub fn baseline(&self) {
        let mut sys = self.system.write();
        sys.refresh_all();
        let mut known = self.known_pids.write();
        let mut names = self.baseline_names.write();
        known.clear();
        names.clear();
        for (pid, proc_info) in sys.processes() {
            known.insert(pid.as_u32());
            names.insert(proc_info.name().to_lowercase());
        }
        info!(processes = known.len(), "Process baseline captured");
    }

    /// Perform a single scan and return anomalies.
    pub fn scan(&self) -> Vec<ProcessAnomaly> {
        let mut sys = self.system.write();
        sys.refresh_all();
        self.scans_completed.fetch_add(1, Ordering::Relaxed);

        let mut anomalies = Vec::new();
        let known = self.known_pids.read();

        for (pid, proc_info) in sys.processes() {
            let pid_u32 = pid.as_u32();
            let name = proc_info.name().to_string();
            let exe = proc_info.exe().map(|p| p.display().to_string()).unwrap_or_default();
            let cpu = proc_info.cpu_usage();
            let mem = proc_info.memory();

            // New process detection
            if !known.contains(&pid_u32) {
                anomalies.push(ProcessAnomaly::NewProcess {
                    pid: pid_u32, name: name.clone(), exe: exe.clone(),
                });
            }

            // High CPU
            if cpu > self.cpu_threshold {
                anomalies.push(ProcessAnomaly::HighCpu {
                    pid: pid_u32, name: name.clone(), cpu,
                });
            }

            // High memory
            if mem > self.memory_threshold_bytes {
                anomalies.push(ProcessAnomaly::HighMemory {
                    pid: pid_u32, name: name.clone(), bytes: mem,
                });
            }

            // Suspicious name patterns
            let name_lower = name.to_lowercase();
            for pattern in &self.suspicious_patterns {
                if name_lower.contains(pattern) {
                    anomalies.push(ProcessAnomaly::SuspiciousName {
                        pid: pid_u32, name: name.clone(),
                        reason: format!("Matches suspicious pattern: {}", pattern),
                    });
                    break;
                }
            }
        }

        // Update known PIDs
        drop(known);
        let mut known = self.known_pids.write();
        known.clear();
        for pid in sys.processes().keys() {
            known.insert(pid.as_u32());
        }

        self.anomalies_detected.fetch_add(anomalies.len() as u64, Ordering::Relaxed);
        anomalies
    }

    /// Get a snapshot of all running processes.
    pub fn snapshot(&self) -> Vec<ProcessInfo> {
        let mut sys = self.system.write();
        sys.refresh_all();
        sys.processes().iter().map(|(pid, p)| ProcessInfo {
            pid: pid.as_u32(),
            name: p.name().to_string(),
            exe_path: p.exe().map(|e| e.display().to_string()).unwrap_or_default(),
            cmd: p.cmd().to_vec(),
            cpu_percent: p.cpu_usage(),
            memory_bytes: p.memory(),
            status: format!("{:?}", p.status()),
            parent_pid: p.parent().map(|p| p.as_u32()),
            start_time: p.start_time(),
        }).collect()
    }

    /// Start periodic scanning in a background task.
    pub fn start_periodic(&self, interval_secs: u64, bus: Arc<EventBus>) {
        self.running.store(true, Ordering::Relaxed);
        let running = self.running.clone();
        let scans = self.scans_completed.clone();
        let anomaly_count = self.anomalies_detected.clone();
        let cpu_thresh = self.cpu_threshold;
        let mem_thresh = self.memory_threshold_bytes;
        let patterns = self.suspicious_patterns.clone();

        info!(interval_secs, "Process monitor started");

        tokio::spawn(async move {
            let mut sys = System::new_all();
            let mut known_pids: HashSet<u32> = HashSet::new();

            // Initial baseline
            sys.refresh_all();
            for pid in sys.processes().keys() {
                known_pids.insert(pid.as_u32());
            }

            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            while running.load(Ordering::Relaxed) {
                ticker.tick().await;
                sys.refresh_all();
                scans.fetch_add(1, Ordering::Relaxed);

                for (pid, proc_info) in sys.processes() {
                    let pid_u32 = pid.as_u32();
                    let name = proc_info.name().to_string();
                    let exe = proc_info.exe().map(|p| p.display().to_string()).unwrap_or_default();
                    let cpu = proc_info.cpu_usage();
                    let mem = proc_info.memory();

                    // New process
                    if !known_pids.contains(&pid_u32) {
                        let mut details = HashMap::new();
                        details.insert("pid".into(), pid_u32.to_string());
                        details.insert("name".into(), name.clone());
                        details.insert("exe".into(), exe.clone());
                        bus.emit_detection(
                            "process_monitor", "sentinel-endpoint",
                            EventSeverity::Low, "New process detected",
                            details, vec!["endpoint".into(), "process".into()],
                        );
                    }

                    // High CPU
                    if cpu > cpu_thresh {
                        let mut details = HashMap::new();
                        details.insert("pid".into(), pid_u32.to_string());
                        details.insert("name".into(), name.clone());
                        details.insert("cpu_percent".into(), format!("{:.1}", cpu));
                        bus.emit_detection(
                            "process_monitor", "sentinel-endpoint",
                            EventSeverity::Medium, "High CPU usage",
                            details, vec!["endpoint".into(), "resource".into()],
                        );
                        anomaly_count.fetch_add(1, Ordering::Relaxed);
                    }

                    // Suspicious name
                    let name_lower = name.to_lowercase();
                    for pattern in &patterns {
                        if name_lower.contains(pattern.as_str()) {
                            let mut details = HashMap::new();
                            details.insert("pid".into(), pid_u32.to_string());
                            details.insert("name".into(), name.clone());
                            details.insert("pattern".into(), pattern.clone());
                            bus.emit_detection(
                                "process_monitor", "sentinel-endpoint",
                                EventSeverity::Critical, "Suspicious process detected",
                                details, vec!["endpoint".into(), "malware".into()],
                            );
                            anomaly_count.fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                    }
                }

                // Update known PIDs
                known_pids.clear();
                for pid in sys.processes().keys() {
                    known_pids.insert(pid.as_u32());
                }
            }
        });
    }

    pub fn stop(&self) { self.running.store(false, Ordering::Relaxed); }
    pub fn scans_completed(&self) -> u64 { self.scans_completed.load(Ordering::Relaxed) }
    pub fn anomalies_detected(&self) -> u64 { self.anomalies_detected.load(Ordering::Relaxed) }
}

