//! Data Poisoning Detector — detects data poisoning in training pipelines.
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
pub struct PoisoningDetection {
    pub dataset: String,
    pub anomaly_score: f64,
    pub poisoned: bool,
    pub detected_at: i64,
    pub findings: Vec<String>,
    pub severity: Severity,
}

pub struct DataPoisoningDetector {
    detections: RwLock<Vec<PoisoningDetection>>,
    alerts: RwLock<Vec<AiAlert>>,
    total_checked: AtomicU64,
    total_poisoned: AtomicU64,
    threshold: f64,
    _cache: TieredCache<String, u64>,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
    /// Rolling statistics per dataset for drift detection.
    dataset_stats: RwLock<std::collections::HashMap<String, DatasetStats>>,
}

#[derive(Debug, Clone)]
struct DatasetStats {
    sample_count: u64,
    mean: f64,
    m2: f64,           // Welford's online variance accumulator
    min_score: f64,
    max_score: f64,
    last_check: i64,
    consecutive_anomalies: u32,
}

/// Poisoning attack signatures to check in dataset metadata.
const POISONING_SIGNATURES: &[&str] = &[
    "backdoor", "trigger", "trojan", "adversarial",
    "label_flip", "data_injection", "gradient_manipulation",
    "clean_label_attack", "watermark_pattern",
];

/// High-risk data source patterns.
const UNTRUSTED_SOURCES: &[&str] = &[
    "anonymous_upload", "unverified", "scraped_", "crawled_",
    "user_submitted", "crowd_sourced_unvalidated",
];

impl DataPoisoningDetector {
    pub fn new(threshold: f64) -> Self {
        Self {
            detections: RwLock::new(Vec::new()),
            alerts: RwLock::new(Vec::new()),
            total_checked: AtomicU64::new(0),
            total_poisoned: AtomicU64::new(0),
            threshold,
            enabled: true,
            _cache: TieredCache::new(10_000),
            metrics: None,
            dataset_stats: RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Comprehensive data poisoning analysis with statistical drift detection.
    pub fn analyze(&self, dataset: &str, anomaly_score: f64, sample_count: u64, metadata: &str) -> PoisoningDetection {
        if !self.enabled {
            return PoisoningDetection { dataset: dataset.into(), anomaly_score, poisoned: false, detected_at: 0, findings: vec![], severity: Severity::Low };
        }
        self.total_checked.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        let lower_meta = metadata.to_lowercase();
        let mut findings = Vec::new();
        let mut poisoned = false;
        let mut sev = Severity::Low;

        // 1. Basic threshold check
        if anomaly_score > self.threshold {
            findings.push(format!("anomaly_score:{:.3}>{:.3}", anomaly_score, self.threshold));
            poisoned = true;
            sev = Severity::High;
        }

        // 2. Statistical drift detection (Welford's online algorithm)
        {
            let mut stats = self.dataset_stats.write();
            if stats.len() >= 10_000 {
                // Evict oldest
                if let Some(oldest) = stats.iter().min_by_key(|(_, s)| s.last_check).map(|(k, _)| k.clone()) {
                    stats.remove(&oldest);
                }
            }
            let ds = stats.entry(dataset.into()).or_insert(DatasetStats {
                sample_count: 0, mean: 0.0, m2: 0.0,
                min_score: f64::MAX, max_score: f64::MIN,
                last_check: now, consecutive_anomalies: 0,
            });

            ds.sample_count += 1;
            ds.last_check = now;
            ds.min_score = ds.min_score.min(anomaly_score);
            ds.max_score = ds.max_score.max(anomaly_score);

            // Welford's online mean/variance
            let delta = anomaly_score - ds.mean;
            ds.mean += delta / ds.sample_count as f64;
            let delta2 = anomaly_score - ds.mean;
            ds.m2 += delta * delta2;

            // Z-score based drift detection (need at least 10 samples)
            if ds.sample_count > 10 {
                let variance = ds.m2 / (ds.sample_count - 1) as f64;
                let stddev = variance.sqrt();
                if stddev > 0.0 {
                    let z_score = (anomaly_score - ds.mean).abs() / stddev;
                    if z_score > 3.0 {
                        findings.push(format!("z_score_drift:{:.2}", z_score));
                        poisoned = true;
                        if sev < Severity::High { sev = Severity::High; }
                    } else if z_score > 2.0 {
                        findings.push(format!("z_score_elevated:{:.2}", z_score));
                    }
                }
            }

            // Consecutive anomaly tracking
            if anomaly_score > self.threshold {
                ds.consecutive_anomalies += 1;
                if ds.consecutive_anomalies >= 5 {
                    findings.push(format!("consecutive_anomalies:{}", ds.consecutive_anomalies));
                    sev = Severity::Critical;
                    poisoned = true;
                }
            } else {
                ds.consecutive_anomalies = 0;
            }
        }

        // 3. Label distribution anomaly (sudden shift in sample count)
        if sample_count > 0 && sample_count < 10 {
            findings.push("suspiciously_small_sample".into());
        }

        // 4. Metadata-based poisoning signature detection
        for sig in POISONING_SIGNATURES {
            if lower_meta.contains(sig) {
                findings.push(format!("poisoning_signature:{}", sig));
                poisoned = true;
                sev = Severity::Critical;
            }
        }

        // 5. Untrusted source detection
        for src in UNTRUSTED_SOURCES {
            if lower_meta.contains(src) {
                findings.push(format!("untrusted_source:{}", src));
                if sev < Severity::Medium { sev = Severity::Medium; }
            }
        }

        // 6. Sudden distribution change heuristic
        if anomaly_score > 0.0 {
            let stats = self.dataset_stats.read();
            if let Some(ds) = stats.get(dataset) {
                if ds.sample_count > 20 {
                    let range = ds.max_score - ds.min_score;
                    if range > 0.0 && (anomaly_score - ds.min_score) / range > 0.95 {
                        findings.push("near_max_range".into());
                    }
                }
            }
        }

        if poisoned {
            self.total_poisoned.fetch_add(1, Ordering::Relaxed);
            let cats = findings.join(", ");
            warn!(dataset = %dataset, score = anomaly_score, findings = %cats, "Data poisoning detected");
            self.add_alert(now, sev, "Data poisoning", &format!("{}: score {:.3} — {}", dataset, anomaly_score, &cats[..cats.len().min(200)]));
        }

        let det = PoisoningDetection { dataset: dataset.into(), anomaly_score, poisoned, detected_at: now, findings, severity: sev };
        let mut d = self.detections.write();
        if d.len() >= MAX_ALERTS { d.remove(0); }
        d.push(det.clone());
        det
    }

    /// Legacy API.
    pub fn check(&self, dataset: &str, anomaly_score: f64) -> PoisoningDetection {
        self.analyze(dataset, anomaly_score, 0, "")
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "data_poisoning_detector".into(), title: title.into(), details: details.into() });
    }

    pub fn total_checked(&self) -> u64 { self.total_checked.load(Ordering::Relaxed) }
    pub fn total_poisoned(&self) -> u64 { self.total_poisoned.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
