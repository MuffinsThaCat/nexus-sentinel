//! Data Poisoning Detector — detects data poisoning in training pipelines.
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Hot lookups cached
//! - **#6 Theoretical Verifier**: Bound memory usage
use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::differential::DifferentialStore;
use sentinel_core::pruning::PruningMap;
use sentinel_core::hierarchical::HierarchicalState;
use sentinel_core::sparse::SparseMatrix;
use sentinel_core::dedup::DedupStore;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

/// A single data sample for content-based poisoning analysis.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DataSample {
    pub label: String,
    pub features: Vec<f64>,
    pub text_content: String,
}

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
    /// Breakthrough #461: Dataset baseline evolution tracking
    dataset_diffs: DifferentialStore<String, String>,
    /// Breakthrough #569: φ-weighted alert pruning
    pruned_alerts: PruningMap<String, AiAlert>,
    /// Breakthrough #1: O(log n) poisoning trend history
    poison_state: RwLock<HierarchicalState<f64>>,
    /// Breakthrough #627: Sparse dataset×technique matrix
    poison_matrix: RwLock<SparseMatrix<String, String, u64>>,
    /// Breakthrough #592: Content-addressed dedup for sample fingerprints
    sample_dedup: DedupStore<String, String>,
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
            dataset_diffs: DifferentialStore::new(),
            pruned_alerts: PruningMap::new(5_000),
            poison_state: RwLock::new(HierarchicalState::new(8, 64)),
            poison_matrix: RwLock::new(SparseMatrix::new(0)),
            sample_dedup: DedupStore::new(),
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

    /// Content-based poisoning analysis — inspects actual data samples.
    /// This addresses the weakness where the detector relied only on external anomaly_score.
    pub fn analyze_content(&self, dataset: &str, samples: &[DataSample], metadata: &str) -> PoisoningDetection {
        if !self.enabled || samples.is_empty() {
            return PoisoningDetection { dataset: dataset.into(), anomaly_score: 0.0, poisoned: false, detected_at: 0, findings: vec![], severity: Severity::Low };
        }
        self.total_checked.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        let mut findings = Vec::new();
        let mut max_score = 0.0f64;
        let mut sev = Severity::Low;

        // 1. Label distribution analysis (detect label flipping attacks)
        {
            let mut label_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
            for s in samples { *label_counts.entry(&s.label).or_insert(0) += 1; }
            if label_counts.len() >= 2 {
                let counts: Vec<usize> = label_counts.values().copied().collect();
                let max_count = *counts.iter().max().unwrap_or(&1);
                let min_count = *counts.iter().min().unwrap_or(&1);
                let imbalance = max_count as f64 / (min_count.max(1) as f64);
                if imbalance > 20.0 {
                    findings.push(format!("label_imbalance:{:.1}x (possible label-flip attack)", imbalance));
                    max_score = max_score.max(0.75);
                    sev = Severity::High;
                } else if imbalance > 10.0 {
                    findings.push(format!("label_skew:{:.1}x", imbalance));
                    max_score = max_score.max(0.50);
                }
            }
        }

        // 2. Feature outlier detection (z-score on feature values)
        {
            let n = samples.len() as f64;
            if n > 10.0 {
                let feature_len = samples[0].features.len();
                for f_idx in 0..feature_len.min(64) {
                    let vals: Vec<f64> = samples.iter().filter_map(|s| s.features.get(f_idx)).copied().collect();
                    let mean = vals.iter().sum::<f64>() / n;
                    let var = vals.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n - 1.0);
                    let std = var.sqrt();
                    if std > 0.0 {
                        let outliers = vals.iter().filter(|v| ((**v - mean) / std).abs() > 4.0).count();
                        let outlier_rate = outliers as f64 / n;
                        if outlier_rate > 0.05 {
                            findings.push(format!("feature_{}_outlier_rate:{:.1}%", f_idx, outlier_rate * 100.0));
                            max_score = max_score.max(0.65 + outlier_rate * 2.0);
                            if sev < Severity::High { sev = Severity::High; }
                        }
                    }
                }
            }
        }

        // 3. Duplicate injection detection (many near-identical samples = data injection)
        {
            let mut fingerprints: std::collections::HashMap<u64, u32> = std::collections::HashMap::new();
            for s in samples {
                let fp = Self::sample_fingerprint(s);
                *fingerprints.entry(fp).or_insert(0) += 1;
            }
            let max_dupes = fingerprints.values().copied().max().unwrap_or(0);
            let dupe_rate = max_dupes as f64 / samples.len().max(1) as f64;
            if dupe_rate > 0.10 && max_dupes > 5 {
                findings.push(format!("duplicate_injection:{}x copies ({:.1}%)", max_dupes, dupe_rate * 100.0));
                max_score = max_score.max(0.70);
                if sev < Severity::High { sev = Severity::High; }
            }
        }

        // 4. Backdoor trigger pattern detection (suspicious fixed feature patches)
        {
            let n = samples.len();
            let feature_len = samples.get(0).map(|s| s.features.len()).unwrap_or(0);
            for f_idx in 0..feature_len.min(64) {
                let vals: Vec<f64> = samples.iter().filter_map(|s| s.features.get(f_idx)).copied().collect();
                // Check for suspiciously common exact values (backdoor trigger patches)
                let mut val_counts: std::collections::HashMap<u64, u32> = std::collections::HashMap::new();
                for &v in &vals { *val_counts.entry(v.to_bits()).or_insert(0) += 1; }
                for (&_val_bits, &count) in &val_counts {
                    let ratio = count as f64 / n as f64;
                    if ratio > 0.08 && ratio < 0.50 && count > 3 {
                        // A specific value appearing in 8-50% of samples in one feature = suspicious trigger
                        findings.push(format!("potential_backdoor_trigger:feature_{} ({:.1}% samples share exact value)", f_idx, ratio * 100.0));
                        max_score = max_score.max(0.80);
                        sev = Severity::Critical;
                        break; // one finding per feature is enough
                    }
                }
            }
        }

        // 5. Text content injection detection (for text-based datasets)
        {
            let injection_markers = [
                "ignore previous", "system prompt", "you are now", "bypass",
                "override instructions", "<script", "javascript:", "eval(",
                "\\x00", "\\u0000",
            ];
            for s in samples {
                let lower = s.text_content.to_lowercase();
                for marker in &injection_markers {
                    if lower.contains(marker) {
                        findings.push(format!("text_injection:'{}' in sample label={}", marker, s.label));
                        max_score = max_score.max(0.85);
                        sev = Severity::Critical;
                    }
                }
            }
        }

        // 6. Entropy anomaly (very low or very high entropy features = suspicious)
        {
            let feature_len = samples.get(0).map(|s| s.features.len()).unwrap_or(0);
            for f_idx in 0..feature_len.min(32) {
                let vals: Vec<f64> = samples.iter().filter_map(|s| s.features.get(f_idx)).copied().collect();
                if vals.len() > 20 {
                    let entropy = Self::feature_entropy(&vals);
                    if entropy < 0.1 {
                        findings.push(format!("low_entropy_feature_{}:{:.3} (possible constant injection)", f_idx, entropy));
                        max_score = max_score.max(0.55);
                    }
                }
            }
        }

        // Also run existing metadata + threshold checks
        let lower_meta = metadata.to_lowercase();
        for sig in POISONING_SIGNATURES {
            if lower_meta.contains(sig) {
                findings.push(format!("poisoning_signature:{}", sig));
                max_score = max_score.max(0.90);
                sev = Severity::Critical;
            }
        }
        for src in UNTRUSTED_SOURCES {
            if lower_meta.contains(src) {
                findings.push(format!("untrusted_source:{}", src));
                if sev < Severity::Medium { sev = Severity::Medium; }
            }
        }

        let poisoned = max_score >= self.threshold;
        if poisoned {
            self.total_poisoned.fetch_add(1, Ordering::Relaxed);
            let cats = findings.join(", ");
            warn!(dataset=%dataset, score=max_score, findings=%cats, "Content-based data poisoning detected");
            self.add_alert(now, sev, "Data poisoning (content analysis)",
                &format!("{}: score {:.3} — {}", dataset, max_score, &cats[..cats.len().min(300)]));
        }

        let det = PoisoningDetection { dataset: dataset.into(), anomaly_score: max_score, poisoned, detected_at: now, findings, severity: sev };
        let mut d = self.detections.write();
        if d.len() >= MAX_ALERTS { d.remove(0); }
        d.push(det.clone());
        det
    }

    fn sample_fingerprint(s: &DataSample) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        s.label.hash(&mut h);
        for &f in &s.features { f.to_bits().hash(&mut h); }
        h.finish()
    }

    fn feature_entropy(vals: &[f64]) -> f64 {
        let n = vals.len();
        if n == 0 { return 0.0; }
        let mut counts: std::collections::HashMap<u64, u32> = std::collections::HashMap::new();
        for &v in vals { *counts.entry(v.to_bits()).or_insert(0) += 1; }
        let mut e = 0.0f64;
        for &c in counts.values() {
            let p = c as f64 / n as f64;
            if p > 0.0 { e -= p * p.log2(); }
        }
        e
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
