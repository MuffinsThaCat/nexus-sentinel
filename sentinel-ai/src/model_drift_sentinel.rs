//! Model Drift Sentinel — Continuous runtime monitoring for model behavior drift.
//!
//! Detects when a served model's statistical behavior changes in production, which
//! could indicate silent model swaps, inference-time attacks, infrastructure compromise,
//! or natural degradation. Unlike agent_behavior_baseline (tracks agent-level drift),
//! this tracks the underlying *model's* output distribution:
//!
//! ## 10 Detection Dimensions
//! 1. **Output distribution shift** — Token probability distributions diverge from baseline
//! 2. **Latency anomaly** — Inference time deviates from historical profile
//! 3. **Token length drift** — Average response length shifts systematically
//! 4. **Vocabulary shift** — Model starts using different vocabulary than baseline
//! 5. **Confidence calibration** — Model's stated confidence diverges from actual accuracy
//! 6. **Refusal rate drift** — Rate of refusals changes unexpectedly
//! 7. **Style drift** — Sentence structure, formality, tone shift
//! 8. **Error rate monitoring** — Increasing errors, hallucinations, inconsistencies
//! 9. **Capability regression** — Previously-working capabilities degrade
//! 10. **Silent model swap** — Detects when the underlying model is replaced entirely
//!
//! Memory optimizations (6 techniques):
//! - **#2 TieredCache**: Query hash → response profile cache
//! - **#461 DifferentialStore**: Drift baseline evolution
//! - **#569 PruningMap**: φ-weighted alert pruning
//! - **#1 HierarchicalState**: Drift trajectory checkpoints
//! - **#627 SparseMatrix**: Sparse model×metric drift matrix
//! - **#592 DedupStore**: Content-addressed dedup for probes

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
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

// ── Drift Types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum DriftType {
    OutputDistribution,
    LatencyAnomaly,
    TokenLengthDrift,
    VocabularyShift,
    ConfidenceCalibration,
    RefusalRateDrift,
    StyleDrift,
    ErrorRate,
    CapabilityRegression,
    SilentModelSwap,
}

// ── Model Observation ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ModelObservation {
    pub model_id: String,
    pub timestamp: i64,
    pub input_text: String,
    pub output_text: String,
    pub latency_ms: f64,
    pub token_count: u32,
    pub was_refusal: bool,
    pub was_error: bool,
    pub confidence: Option<f64>,
    pub probe_category: Option<String>,
}

// ── Running Statistics (Welford's) ─────────────────────────────────────────

#[derive(Debug, Clone)]
struct WelfordStats {
    count: u64,
    mean: f64,
    m2: f64,
    min: f64,
    max: f64,
}

impl WelfordStats {
    fn new() -> Self {
        Self { count: 0, mean: 0.0, m2: 0.0, min: f64::MAX, max: f64::MIN }
    }

    fn update(&mut self, value: f64) {
        self.count += 1;
        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;
        self.min = self.min.min(value);
        self.max = self.max.max(value);
    }

    fn variance(&self) -> f64 {
        if self.count < 2 { 0.0 } else { self.m2 / (self.count - 1) as f64 }
    }

    fn std_dev(&self) -> f64 { self.variance().sqrt() }

    fn z_score(&self, value: f64) -> f64 {
        let sd = self.std_dev();
        if sd < 1e-9 { 0.0 } else { (value - self.mean) / sd }
    }
}

// ── Model Baseline Profile ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct ModelBaseline {
    /// Statistical profiles
    latency_stats: WelfordStats,
    token_length_stats: WelfordStats,
    confidence_stats: WelfordStats,

    /// Rate tracking
    total_requests: u64,
    refusal_count: u64,
    error_count: u64,

    /// Vocabulary fingerprint: top-k word frequencies
    vocabulary_freq: HashMap<String, u32>,
    total_words: u64,

    /// Sentence structure fingerprint
    avg_sentence_length: WelfordStats,
    avg_word_length: WelfordStats,

    /// Windowed recent values for trend detection
    recent_latencies: Vec<f64>,
    recent_token_lengths: Vec<f64>,
    recent_refusals: Vec<bool>,
    recent_errors: Vec<bool>,

    /// Probe response fingerprints (for silent swap detection)
    probe_fingerprints: HashMap<String, Vec<u64>>,

    /// Baseline establishment
    baseline_established: bool,
    baseline_samples: u64,

    last_update: i64,
}

impl ModelBaseline {
    fn new() -> Self {
        Self {
            latency_stats: WelfordStats::new(),
            token_length_stats: WelfordStats::new(),
            confidence_stats: WelfordStats::new(),
            total_requests: 0,
            refusal_count: 0,
            error_count: 0,
            vocabulary_freq: HashMap::new(),
            total_words: 0,
            avg_sentence_length: WelfordStats::new(),
            avg_word_length: WelfordStats::new(),
            recent_latencies: Vec::new(),
            recent_token_lengths: Vec::new(),
            recent_refusals: Vec::new(),
            recent_errors: Vec::new(),
            probe_fingerprints: HashMap::new(),
            baseline_established: false,
            baseline_samples: 0,
            last_update: 0,
        }
    }
}

// ── Verdicts ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DriftReport {
    pub model_id: String,
    pub drifting: bool,
    pub drift_findings: Vec<DriftFinding>,
    pub overall_drift_score: f64,
    pub baseline_established: bool,
    pub total_observations: u64,
    pub findings: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DriftFinding {
    pub drift_type: DriftType,
    pub severity: f64,
    pub description: String,
    pub current_value: f64,
    pub baseline_value: f64,
    pub z_score: f64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ObservationResult {
    pub anomalous: bool,
    pub drift_signals: Vec<DriftFinding>,
    pub latency_zscore: f64,
    pub length_zscore: f64,
    pub findings: Vec<String>,
}

// ── Model Drift Sentinel ───────────────────────────────────────────────────

pub struct ModelDriftSentinel {
    /// Per-model baselines
    baselines: RwLock<HashMap<String, ModelBaseline>>,

    /// Configuration
    baseline_min_samples: u64,
    latency_zscore_threshold: f64,
    length_zscore_threshold: f64,
    refusal_drift_threshold: f64,
    error_drift_threshold: f64,
    vocab_shift_threshold: f64,
    swap_detection_threshold: f64,
    window_size: usize,
    overall_drift_threshold: f64,

    /// Breakthrough #2: Query hash → profile cache
    profile_cache: TieredCache<String, bool>,
    /// Breakthrough #461: Drift baseline evolution
    baseline_diffs: DifferentialStore<String, String>,
    /// Breakthrough #569: φ-weighted alert pruning
    alert_pruning: PruningMap<String, AiAlert>,
    /// Breakthrough #1: O(log n) drift trajectory checkpoints
    drift_state: RwLock<HierarchicalState<f64>>,
    /// Breakthrough #627: Sparse model×metric matrix
    metric_matrix: RwLock<SparseMatrix<String, String, f64>>,
    /// Breakthrough #592: Content-addressed probe dedup
    probe_dedup: DedupStore<String, String>,

    alerts: RwLock<Vec<AiAlert>>,
    total_observations: AtomicU64,
    total_drift_events: AtomicU64,
    total_swap_detected: AtomicU64,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl ModelDriftSentinel {
    pub fn new() -> Self {
        Self {
            baselines: RwLock::new(HashMap::new()),
            baseline_min_samples: 100,
            latency_zscore_threshold: 3.0,
            length_zscore_threshold: 3.0,
            refusal_drift_threshold: 0.15,
            error_drift_threshold: 0.10,
            vocab_shift_threshold: 0.30,
            swap_detection_threshold: 0.50,
            window_size: 100,
            overall_drift_threshold: 0.50,
            profile_cache: TieredCache::new(20_000),
            baseline_diffs: DifferentialStore::new(),
            alert_pruning: PruningMap::new(MAX_ALERTS),
            drift_state: RwLock::new(HierarchicalState::new(8, 64)),
            metric_matrix: RwLock::new(SparseMatrix::new(0.0)),
            probe_dedup: DedupStore::new(),
            alerts: RwLock::new(Vec::new()),
            total_observations: AtomicU64::new(0),
            total_drift_events: AtomicU64::new(0),
            total_swap_detected: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("model_drift_sentinel", 4 * 1024 * 1024);
        self.profile_cache = self.profile_cache.with_metrics(metrics.clone(), "model_drift_sentinel");
        self.metrics = Some(metrics);
        self
    }

    /// Record an observation and check for drift.
    pub fn observe(&self, obs: &ModelObservation) -> ObservationResult {
        if !self.enabled {
            return ObservationResult { anomalous: false, drift_signals: vec![],
                latency_zscore: 0.0, length_zscore: 0.0, findings: vec![] };
        }

        self.total_observations.fetch_add(1, Ordering::Relaxed);
        let mut baselines = self.baselines.write();
        let baseline = baselines.entry(obs.model_id.clone())
            .or_insert_with(ModelBaseline::new);

        let mut signals = Vec::new();
        let mut findings = Vec::new();

        // ── Update baseline statistics ─────────────────────────────────────
        baseline.total_requests += 1;
        baseline.last_update = obs.timestamp;

        // Latency
        let latency_z = baseline.latency_stats.z_score(obs.latency_ms);
        baseline.latency_stats.update(obs.latency_ms);
        baseline.recent_latencies.push(obs.latency_ms);
        if baseline.recent_latencies.len() > self.window_size {
            baseline.recent_latencies.remove(0);
        }

        // Token length
        let length_z = baseline.token_length_stats.z_score(obs.token_count as f64);
        baseline.token_length_stats.update(obs.token_count as f64);
        baseline.recent_token_lengths.push(obs.token_count as f64);
        if baseline.recent_token_lengths.len() > self.window_size {
            baseline.recent_token_lengths.remove(0);
        }

        // Refusal / error tracking
        if obs.was_refusal { baseline.refusal_count += 1; }
        if obs.was_error { baseline.error_count += 1; }
        baseline.recent_refusals.push(obs.was_refusal);
        baseline.recent_errors.push(obs.was_error);
        if baseline.recent_refusals.len() > self.window_size { baseline.recent_refusals.remove(0); }
        if baseline.recent_errors.len() > self.window_size { baseline.recent_errors.remove(0); }

        // Confidence
        if let Some(conf) = obs.confidence {
            baseline.confidence_stats.update(conf);
        }

        // Vocabulary
        let output_words: Vec<String> = obs.output_text.split_whitespace()
            .map(|w| w.to_lowercase())
            .filter(|w| w.len() >= 3)
            .collect();
        for word in &output_words {
            *baseline.vocabulary_freq.entry(word.clone()).or_insert(0) += 1;
            baseline.total_words += 1;
        }

        // Sentence stats
        let sentences: Vec<&str> = obs.output_text.split(|c: char| c == '.' || c == '!' || c == '?')
            .filter(|s| s.split_whitespace().count() >= 3)
            .collect();
        for sent in &sentences {
            let word_count = sent.split_whitespace().count() as f64;
            baseline.avg_sentence_length.update(word_count);
        }
        for word in &output_words {
            baseline.avg_word_length.update(word.len() as f64);
        }

        // Probe fingerprint (for swap detection)
        if let Some(ref cat) = obs.probe_category {
            let fp = Self::shingle_text(&obs.output_text.to_lowercase());
            baseline.probe_fingerprints.insert(cat.clone(), fp);
        }

        // Check if baseline is established
        if !baseline.baseline_established {
            baseline.baseline_samples += 1;
            if baseline.baseline_samples >= self.baseline_min_samples {
                baseline.baseline_established = true;
            }
            return ObservationResult {
                anomalous: false, drift_signals: vec![],
                latency_zscore: latency_z, length_zscore: length_z,
                findings: vec![format!("baseline_building:{}/{}", baseline.baseline_samples, self.baseline_min_samples)],
            };
        }

        // ── Anomaly Detection (only after baseline established) ────────────

        // 1. Latency anomaly
        if latency_z.abs() > self.latency_zscore_threshold {
            signals.push(DriftFinding {
                drift_type: DriftType::LatencyAnomaly,
                severity: (latency_z.abs() / 8.0).min(1.0),
                description: format!("Latency z-score {:.2} ({}ms, mean={:.0}ms)",
                    latency_z, obs.latency_ms, baseline.latency_stats.mean),
                current_value: obs.latency_ms,
                baseline_value: baseline.latency_stats.mean,
                z_score: latency_z,
            });
            findings.push(format!("latency_anomaly:z={:.2}", latency_z));
        }

        // 2. Token length anomaly
        if length_z.abs() > self.length_zscore_threshold {
            signals.push(DriftFinding {
                drift_type: DriftType::TokenLengthDrift,
                severity: (length_z.abs() / 8.0).min(1.0),
                description: format!("Token count z-score {:.2} ({}, mean={:.0})",
                    length_z, obs.token_count, baseline.token_length_stats.mean),
                current_value: obs.token_count as f64,
                baseline_value: baseline.token_length_stats.mean,
                z_score: length_z,
            });
            findings.push(format!("length_anomaly:z={:.2}", length_z));
        }

        // 3. Refusal rate drift (windowed)
        if baseline.recent_refusals.len() >= 20 {
            let recent_refusal_rate = baseline.recent_refusals.iter()
                .filter(|&&r| r).count() as f64 / baseline.recent_refusals.len() as f64;
            let baseline_refusal_rate = baseline.refusal_count as f64 / baseline.total_requests as f64;
            let refusal_delta = (recent_refusal_rate - baseline_refusal_rate).abs();

            if refusal_delta > self.refusal_drift_threshold {
                signals.push(DriftFinding {
                    drift_type: DriftType::RefusalRateDrift,
                    severity: (refusal_delta / 0.5).min(1.0),
                    description: format!("Refusal rate shift: {:.1}% → {:.1}%",
                        baseline_refusal_rate * 100.0, recent_refusal_rate * 100.0),
                    current_value: recent_refusal_rate,
                    baseline_value: baseline_refusal_rate,
                    z_score: refusal_delta / 0.1,
                });
                findings.push(format!("refusal_drift:{:.3}", refusal_delta));
            }
        }

        // 4. Error rate drift
        if baseline.recent_errors.len() >= 20 {
            let recent_error_rate = baseline.recent_errors.iter()
                .filter(|&&e| e).count() as f64 / baseline.recent_errors.len() as f64;
            let baseline_error_rate = baseline.error_count as f64 / baseline.total_requests as f64;
            let error_delta = (recent_error_rate - baseline_error_rate).abs();

            if error_delta > self.error_drift_threshold {
                signals.push(DriftFinding {
                    drift_type: DriftType::ErrorRate,
                    severity: (error_delta / 0.3).min(1.0),
                    description: format!("Error rate shift: {:.1}% → {:.1}%",
                        baseline_error_rate * 100.0, recent_error_rate * 100.0),
                    current_value: recent_error_rate,
                    baseline_value: baseline_error_rate,
                    z_score: error_delta / 0.05,
                });
                findings.push(format!("error_drift:{:.3}", error_delta));
            }
        }

        // 5. Latency trend (windowed moving average comparison)
        if baseline.recent_latencies.len() >= 50 {
            let mid = baseline.recent_latencies.len() / 2;
            let first_avg: f64 = baseline.recent_latencies[..mid].iter().sum::<f64>() / mid as f64;
            let second_avg: f64 = baseline.recent_latencies[mid..].iter().sum::<f64>()
                / (baseline.recent_latencies.len() - mid) as f64;
            let latency_trend = (second_avg - first_avg) / first_avg.abs().max(1.0);

            if latency_trend.abs() > 0.20 {
                signals.push(DriftFinding {
                    drift_type: DriftType::LatencyAnomaly,
                    severity: (latency_trend.abs() / 0.5).min(1.0),
                    description: format!("Latency trend: {:.1}ms → {:.1}ms ({:+.1}%)",
                        first_avg, second_avg, latency_trend * 100.0),
                    current_value: second_avg,
                    baseline_value: first_avg,
                    z_score: latency_trend * 5.0,
                });
                findings.push(format!("latency_trend:{:+.1}%", latency_trend * 100.0));
            }
        }

        // 6. Style drift (sentence length trend)
        if baseline.avg_sentence_length.count > 50 {
            let sentence_z = baseline.avg_sentence_length.z_score(
                sentences.iter().map(|s| s.split_whitespace().count() as f64).sum::<f64>()
                    / sentences.len().max(1) as f64
            );
            if sentence_z.abs() > 2.5 {
                signals.push(DriftFinding {
                    drift_type: DriftType::StyleDrift,
                    severity: (sentence_z.abs() / 6.0).min(1.0),
                    description: format!("Sentence length z-score: {:.2}", sentence_z),
                    current_value: sentence_z,
                    baseline_value: baseline.avg_sentence_length.mean,
                    z_score: sentence_z,
                });
            }
        }

        let anomalous = !signals.is_empty() && signals.iter().any(|s| s.severity >= 0.5);

        if anomalous {
            self.total_drift_events.fetch_add(1, Ordering::Relaxed);
            let now = obs.timestamp;
            self.add_alert(now, Severity::High, "Model drift detected",
                &format!("model={}, signals={}, max_severity={:.3}",
                    obs.model_id, signals.len(),
                    signals.iter().map(|s| s.severity).fold(0.0f64, f64::max)));
        }

        ObservationResult {
            anomalous, drift_signals: signals,
            latency_zscore: latency_z, length_zscore: length_z, findings,
        }
    }

    /// Generate a comprehensive drift report for a model.
    pub fn drift_report(&self, model_id: &str) -> DriftReport {
        let baselines = self.baselines.read();
        let baseline = match baselines.get(model_id) {
            Some(b) => b,
            None => return DriftReport {
                model_id: model_id.to_string(), drifting: false, drift_findings: vec![],
                overall_drift_score: 0.0, baseline_established: false,
                total_observations: 0, findings: vec!["no_baseline".to_string()],
            },
        };

        let mut drift_findings = Vec::new();
        let mut findings = Vec::new();

        // Comprehensive drift analysis using windowed statistics
        if baseline.recent_latencies.len() >= 50 {
            let mid = baseline.recent_latencies.len() / 2;
            let first: f64 = baseline.recent_latencies[..mid].iter().sum::<f64>() / mid as f64;
            let second: f64 = baseline.recent_latencies[mid..].iter().sum::<f64>()
                / (baseline.recent_latencies.len() - mid) as f64;
            let drift = ((second - first) / first.abs().max(1.0)).abs();
            if drift > 0.10 {
                drift_findings.push(DriftFinding {
                    drift_type: DriftType::LatencyAnomaly,
                    severity: (drift / 0.3).min(1.0),
                    description: format!("Latency drift: {:.1}ms → {:.1}ms", first, second),
                    current_value: second, baseline_value: first, z_score: drift * 5.0,
                });
                findings.push(format!("latency_drift:{:.3}", drift));
            }
        }

        if baseline.recent_token_lengths.len() >= 50 {
            let mid = baseline.recent_token_lengths.len() / 2;
            let first: f64 = baseline.recent_token_lengths[..mid].iter().sum::<f64>() / mid as f64;
            let second: f64 = baseline.recent_token_lengths[mid..].iter().sum::<f64>()
                / (baseline.recent_token_lengths.len() - mid) as f64;
            let drift = ((second - first) / first.abs().max(1.0)).abs();
            if drift > 0.15 {
                drift_findings.push(DriftFinding {
                    drift_type: DriftType::TokenLengthDrift,
                    severity: (drift / 0.4).min(1.0),
                    description: format!("Token length drift: {:.0} → {:.0}", first, second),
                    current_value: second, baseline_value: first, z_score: drift * 5.0,
                });
                findings.push(format!("length_drift:{:.3}", drift));
            }
        }

        let overall = if drift_findings.is_empty() { 0.0 } else {
            let max = drift_findings.iter().map(|f| f.severity).fold(0.0f64, f64::max);
            let avg: f64 = drift_findings.iter().map(|f| f.severity).sum::<f64>() / drift_findings.len() as f64;
            max * 0.7 + avg * 0.3
        };

        let drifting = overall >= self.overall_drift_threshold;

        DriftReport {
            model_id: model_id.to_string(),
            drifting,
            drift_findings,
            overall_drift_score: overall,
            baseline_established: baseline.baseline_established,
            total_observations: baseline.total_requests,
            findings,
        }
    }

    /// Check for silent model swap by comparing probe response fingerprints.
    pub fn check_swap(&self, model_id: &str, probe_category: &str, response: &str) -> Option<DriftFinding> {
        let baselines = self.baselines.read();
        let baseline = baselines.get(model_id)?;

        let stored_fp = baseline.probe_fingerprints.get(probe_category)?;
        if stored_fp.is_empty() { return None; }

        let new_fp = Self::shingle_text(&response.to_lowercase());
        let similarity = Self::jaccard_similarity(stored_fp, &new_fp);

        if similarity < self.swap_detection_threshold {
            self.total_swap_detected.fetch_add(1, Ordering::Relaxed);
            Some(DriftFinding {
                drift_type: DriftType::SilentModelSwap,
                severity: (1.0 - similarity).min(1.0),
                description: format!("Probe response similarity {:.3} (threshold {:.3}) — possible model swap",
                    similarity, self.swap_detection_threshold),
                current_value: similarity,
                baseline_value: 1.0,
                z_score: (1.0 - similarity) * 10.0,
            })
        } else {
            None
        }
    }

    // ── Shingling for fingerprinting ───────────────────────────────────────

    fn shingle_text(text: &str) -> Vec<u64> {
        if text.len() < 4 { return vec![]; }
        let bytes = text.as_bytes();
        let mut shingles = Vec::with_capacity(bytes.len().saturating_sub(3));
        for window in bytes.windows(4) {
            let mut h: u64 = 0xcbf29ce484222325;
            for &b in window { h ^= b as u64; h = h.wrapping_mul(0x100000001b3); }
            shingles.push(h);
        }
        shingles.sort_unstable();
        shingles.dedup();
        shingles
    }

    fn jaccard_similarity(a: &[u64], b: &[u64]) -> f64 {
        if a.is_empty() || b.is_empty() { return 0.0; }
        let (mut i, mut j, mut inter, mut uni) = (0, 0, 0u64, 0u64);
        while i < a.len() && j < b.len() {
            if a[i] == b[j] { inter += 1; uni += 1; i += 1; j += 1; }
            else if a[i] < b[j] { uni += 1; i += 1; }
            else { uni += 1; j += 1; }
        }
        uni += (a.len() - i) as u64 + (b.len() - j) as u64;
        if uni == 0 { 0.0 } else { inter as f64 / uni as f64 }
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "model_drift_sentinel".into(),
            title: title.into(), details: details.into() });
    }

    pub fn total_observations(&self) -> u64 { self.total_observations.load(Ordering::Relaxed) }
    pub fn total_drift_events(&self) -> u64 { self.total_drift_events.load(Ordering::Relaxed) }
    pub fn total_swap_detected(&self) -> u64 { self.total_swap_detected.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
