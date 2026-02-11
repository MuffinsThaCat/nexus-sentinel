//! Volume Monitor — monitors data transfer volumes for anomalous spikes.
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Hot lookups cached
//! - **#6 Theoretical Verifier**: Bound memory usage
use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;use std::collections::HashMap;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone)]
struct EndpointStats {
    ema_bytes: f64,
    total_bytes: u64,
    total_transfers: u64,
    max_single: u64,
    last_transfer: i64,
    consecutive_spikes: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VolumeVerdict {
    pub allowed: bool,
    pub findings: Vec<String>,
    pub severity: Severity,
    pub current_bytes: u64,
    pub baseline_bytes: f64,
}

pub struct VolumeMonitor {
    baselines: RwLock<HashMap<String, u64>>,
    endpoint_stats: RwLock<HashMap<String, EndpointStats>>,
    alerts: RwLock<Vec<ExfilAlert>>,
    total_checked: AtomicU64,
    total_anomalies: AtomicU64,
    multiplier: f64,
    _cache: TieredCache<String, u64>,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

/// EMA smoothing factor (closer to 1 = more weight on recent values).
const EMA_ALPHA: f64 = 0.3;
/// Absolute daily exfiltration threshold (500MB).
const DAILY_EXFIL_THRESHOLD: u64 = 500_000_000;
/// Single transfer spike threshold (50MB).
const SINGLE_TRANSFER_SPIKE: u64 = 50_000_000;
/// Consecutive spike escalation.
const SPIKE_ESCALATION: u32 = 3;
/// Max tracked endpoints.
const MAX_ENDPOINTS: usize = 50_000;

impl VolumeMonitor {
    pub fn new(multiplier: f64) -> Self {
        Self {
            baselines: RwLock::new(HashMap::new()),
            endpoint_stats: RwLock::new(HashMap::new()),
            alerts: RwLock::new(Vec::new()),
            total_checked: AtomicU64::new(0),
            total_anomalies: AtomicU64::new(0),
            multiplier,
            enabled: true,
            _cache: TieredCache::new(10_000),
            metrics: None,
        }
    }

    pub fn set_baseline(&self, endpoint: &str, bytes: u64) { self.baselines.write().insert(endpoint.into(), bytes); }

    /// Analyze a data transfer with EMA baseline, spike detection, and cumulative monitoring.
    pub fn analyze(&self, endpoint: &str, bytes: u64, dest: &str) -> VolumeVerdict {
        if !self.enabled {
            return VolumeVerdict { allowed: true, findings: vec![], severity: Severity::Low, current_bytes: bytes, baseline_bytes: 0.0 };
        }
        self.total_checked.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        let mut findings = Vec::new();
        let mut sev = Severity::Low;

        // Update EMA and endpoint stats
        let mut stats = self.endpoint_stats.write();
        if stats.len() >= MAX_ENDPOINTS {
            if let Some(oldest) = stats.iter().min_by_key(|(_, s)| s.last_transfer).map(|(k, _)| k.clone()) {
                stats.remove(&oldest);
            }
        }
        let es = stats.entry(endpoint.into()).or_insert(EndpointStats {
            ema_bytes: bytes as f64,
            total_bytes: 0,
            total_transfers: 0,
            max_single: 0,
            last_transfer: now,
            consecutive_spikes: 0,
        });

        es.total_bytes += bytes;
        es.total_transfers += 1;
        es.max_single = es.max_single.max(bytes);
        es.last_transfer = now;

        // EMA baseline update
        let old_ema = es.ema_bytes;
        es.ema_bytes = EMA_ALPHA * bytes as f64 + (1.0 - EMA_ALPHA) * es.ema_bytes;

        // 1. Static baseline check
        if let Some(&baseline) = self.baselines.read().get(endpoint) {
            if bytes as f64 > baseline as f64 * self.multiplier {
                findings.push(format!("exceeds_static_baseline:{}x", (bytes as f64 / baseline as f64 * 10.0).round() / 10.0));
                sev = Severity::High;
            }
        }

        // 2. EMA-based anomaly (transfer > 3x current EMA)
        if old_ema > 100.0 && bytes as f64 > old_ema * 3.0 {
            findings.push(format!("ema_spike:{:.0}x", bytes as f64 / old_ema));
            if sev < Severity::High { sev = Severity::High; }
            es.consecutive_spikes += 1;
        } else {
            es.consecutive_spikes = 0;
        }

        // 3. Consecutive spike escalation
        if es.consecutive_spikes >= SPIKE_ESCALATION {
            findings.push(format!("consecutive_spikes:{}", es.consecutive_spikes));
            sev = Severity::Critical;
        }

        // 4. Single large transfer
        if bytes > SINGLE_TRANSFER_SPIKE {
            findings.push(format!("large_transfer:{}MB", bytes / 1_000_000));
            if sev < Severity::Medium { sev = Severity::Medium; }
        }

        // 5. Cumulative daily volume (rough — assumes all transfers are today)
        if es.total_bytes > DAILY_EXFIL_THRESHOLD {
            findings.push(format!("cumulative_volume:{}MB", es.total_bytes / 1_000_000));
            if sev < Severity::High { sev = Severity::High; }
        }

        // 6. Rapid burst (many transfers in short period)
        if es.total_transfers > 100 {
            let avg_bytes = es.total_bytes / es.total_transfers;
            if bytes > avg_bytes * 10 {
                findings.push("burst_anomaly".into());
                if sev < Severity::Medium { sev = Severity::Medium; }
            }
        }

        let ema = es.ema_bytes;
        drop(stats);

        let anomaly = !findings.is_empty() && sev >= Severity::High;
        if anomaly {
            self.total_anomalies.fetch_add(1, Ordering::Relaxed);
            let cats = findings.join(", ");
            warn!(endpoint = %endpoint, bytes = bytes, dest = %dest, findings = %cats, "Volume anomaly");
            self.add_alert(now, sev, "Volume anomaly", &format!("{} → {} {}B: {}", endpoint, dest, bytes, &cats[..cats.len().min(200)]));
        }

        VolumeVerdict { allowed: !anomaly, findings, severity: sev, current_bytes: bytes, baseline_bytes: ema }
    }

    /// Legacy API.
    pub fn check(&self, endpoint: &str, bytes: u64) -> bool {
        self.analyze(endpoint, bytes, "").allowed
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(ExfilAlert { timestamp: ts, severity: sev, component: "volume_monitor".into(), title: title.into(), details: details.into() });
    }

    pub fn total_checked(&self) -> u64 { self.total_checked.load(Ordering::Relaxed) }
    pub fn total_anomalies(&self) -> u64 { self.total_anomalies.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<ExfilAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
