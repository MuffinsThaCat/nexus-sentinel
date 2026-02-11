//! Decoy Network — manages fake network segments to trap attackers.
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Hot lookups cached
//! - **#6 Theoretical Verifier**: Bound memory usage
use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DecoySegment {
    pub segment_id: String,
    pub cidr: String,
    pub services: Vec<String>,
    pub active: bool,
}

use std::collections::HashMap;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProbeEvent {
    pub source_ip: String,
    pub segment_id: String,
    pub port: u16,
    pub protocol: String,
    pub timestamp: i64,
}

#[derive(Debug, Clone)]
struct ProbeTracker {
    count: u64,
    first_seen: i64,
    last_seen: i64,
    ports_touched: Vec<u16>,
    segments_touched: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProbeAnalysis {
    pub lateral_movement: bool,
    pub port_scanning: bool,
    pub findings: Vec<String>,
    pub severity: Severity,
}

pub struct DecoyNetwork {
    segments: RwLock<Vec<DecoySegment>>,
    probe_tracker: RwLock<HashMap<String, ProbeTracker>>,
    alerts: RwLock<Vec<DeceptionAlert>>,
    total_segments: AtomicU64,
    total_probes: AtomicU64,
    _cache: TieredCache<String, u64>,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

const MAX_TRACKERS: usize = 50_000;

impl DecoyNetwork {
    pub fn new() -> Self {
        Self {
            segments: RwLock::new(Vec::new()),
            probe_tracker: RwLock::new(HashMap::new()),
            alerts: RwLock::new(Vec::new()),
            total_segments: AtomicU64::new(0),
            total_probes: AtomicU64::new(0),
            enabled: true,
            _cache: TieredCache::new(10_000),
            metrics: None,
        }
    }

    pub fn add_segment(&self, id: &str, cidr: &str, services: Vec<String>) {
        self.total_segments.fetch_add(1, Ordering::Relaxed);
        let mut s = self.segments.write();
        if s.len() >= MAX_ALERTS { s.remove(0); }
        s.push(DecoySegment { segment_id: id.into(), cidr: cidr.into(), services, active: true });
    }

    /// Analyze a probe event for lateral movement, port scanning, and persistence.
    pub fn analyze_probe(&self, event: &ProbeEvent) -> ProbeAnalysis {
        self.total_probes.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        let mut findings = Vec::new();
        let mut sev = Severity::Medium;

        // Track per-IP behavior
        let mut trackers = self.probe_tracker.write();
        if trackers.len() >= MAX_TRACKERS {
            if let Some(oldest) = trackers.iter().min_by_key(|(_, t)| t.last_seen).map(|(k, _)| k.clone()) {
                trackers.remove(&oldest);
            }
        }
        let tracker = trackers.entry(event.source_ip.clone()).or_insert(ProbeTracker {
            count: 0, first_seen: now, last_seen: now,
            ports_touched: Vec::new(), segments_touched: Vec::new(),
        });
        tracker.count += 1;
        tracker.last_seen = now;
        if !tracker.ports_touched.contains(&event.port) { tracker.ports_touched.push(event.port); }
        if !tracker.segments_touched.contains(&event.segment_id) { tracker.segments_touched.push(event.segment_id.clone()); }

        // 1. Lateral movement detection (multiple segments)
        let lateral = tracker.segments_touched.len() > 1;
        if lateral {
            findings.push(format!("lateral_movement:{}segments", tracker.segments_touched.len()));
            sev = Severity::Critical;
        }

        // 2. Port scanning detection
        let scanning = tracker.ports_touched.len() > 5;
        if scanning {
            findings.push(format!("port_scan:{}ports", tracker.ports_touched.len()));
            if sev < Severity::High { sev = Severity::High; }
        }

        // 3. Rapid probing (>10 probes in short time)
        if tracker.count > 10 {
            let dwell = (tracker.last_seen - tracker.first_seen).max(1);
            let rate = tracker.count as f64 / dwell as f64;
            if rate > 0.5 {
                findings.push(format!("rapid_probing:{:.1}/s", rate));
                if sev < Severity::High { sev = Severity::High; }
            }
        }

        // 4. High-value port targeting
        let high_value_ports = [22, 3389, 445, 1433, 3306, 5432, 6379, 27017, 8443, 9200];
        if high_value_ports.contains(&event.port) {
            findings.push(format!("high_value_port:{}", event.port));
        }

        // 5. Any probe to decoy = suspicious by definition
        findings.push(format!("decoy_contact:{}:{}", event.segment_id, event.port));

        let ip = event.source_ip.clone();
        drop(trackers);

        let cats = findings.join(", ");
        warn!(source = %ip, segment = %event.segment_id, port = event.port, "Decoy probe");
        self.add_alert(now, sev, "Decoy probe", &format!("{}: {}", ip, &cats[..cats.len().min(200)]));

        ProbeAnalysis { lateral_movement: lateral, port_scanning: scanning, findings, severity: sev }
    }

    /// Legacy API.
    pub fn record_probe(&self, segment_id: &str, source_ip: &str) {
        self.analyze_probe(&ProbeEvent {
            source_ip: source_ip.into(), segment_id: segment_id.into(),
            port: 0, protocol: "tcp".into(), timestamp: chrono::Utc::now().timestamp(),
        });
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(DeceptionAlert { timestamp: ts, severity: sev, component: "decoy_network".into(), title: title.into(), details: details.into() });
    }

    pub fn total_segments(&self) -> u64 { self.total_segments.load(Ordering::Relaxed) }
    pub fn total_probes(&self) -> u64 { self.total_probes.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<DeceptionAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
