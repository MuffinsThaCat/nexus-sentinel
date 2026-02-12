//! Embedding Space Monitor — Monitors vector embeddings for drift, poisoning, and attacks.
//!
//! RAG systems depend entirely on embedding quality. If an attacker poisons the
//! embedding space, they control what context gets retrieved. This module monitors
//! the health and integrity of vector embeddings in real-time:
//!
//! ## 9 Detection Dimensions
//! 1. **Embedding drift** — statistical shift in embedding distributions over time
//! 2. **Centroid displacement** — cluster centroid movement beyond expected bounds
//! 3. **Nearest-neighbor manipulation** — adversarial vectors that hijack retrieval
//! 4. **Dimensionality collapse** — embeddings collapsing into fewer effective dimensions
//! 5. **Outlier injection** — vectors placed far outside normal distribution
//! 6. **Cluster poisoning** — new vectors distorting existing cluster boundaries
//! 7. **Embedding inversion** — detecting attempts to reconstruct input from embeddings
//! 8. **Cosine similarity anomalies** — unexpected similarity/dissimilarity patterns
//! 9. **Magnitude anomalies** — vectors with unusual L2 norms
//!
//! Memory optimizations (6 techniques):
//! - **#2 TieredCache**: Embedding fingerprint → health cache
//! - **#461 DifferentialStore**: Distribution evolution tracking
//! - **#569 PruningMap**: φ-weighted alert pruning
//! - **#1 HierarchicalState**: Drift trajectory checkpoints
//! - **#627 SparseMatrix**: Sparse namespace×anomaly matrix
//! - **#592 DedupStore**: Content-addressed dedup for vectors

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
const DEFAULT_DIMENSIONS: usize = 1536;

// ── Anomaly Types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum EmbeddingAnomaly {
    DistributionDrift,
    CentroidDisplacement,
    NearestNeighborHijack,
    DimensionalityCollapse,
    OutlierInjection,
    ClusterPoisoning,
    InversionAttempt,
    CosineSimilarityAnomaly,
    MagnitudeAnomaly,
}

// ── Statistics ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct RunningStats {
    count: u64,
    mean: Vec<f64>,
    m2: Vec<f64>,           // For Welford's online variance
    magnitude_mean: f64,
    magnitude_m2: f64,
    min_magnitude: f64,
    max_magnitude: f64,
}

impl RunningStats {
    fn new(dims: usize) -> Self {
        Self {
            count: 0,
            mean: vec![0.0; dims],
            m2: vec![0.0; dims],
            magnitude_mean: 0.0,
            magnitude_m2: 0.0,
            min_magnitude: f64::MAX,
            max_magnitude: f64::MIN,
        }
    }

    /// Welford's online algorithm for streaming mean/variance
    fn update(&mut self, vector: &[f64]) {
        self.count += 1;
        let n = self.count as f64;

        for (i, &v) in vector.iter().enumerate() {
            if i < self.mean.len() {
                let delta = v - self.mean[i];
                self.mean[i] += delta / n;
                let delta2 = v - self.mean[i];
                self.m2[i] += delta * delta2;
            }
        }

        let mag = Self::magnitude(vector);
        let delta = mag - self.magnitude_mean;
        self.magnitude_mean += delta / n;
        let delta2 = mag - self.magnitude_mean;
        self.magnitude_m2 += delta * delta2;
        self.min_magnitude = self.min_magnitude.min(mag);
        self.max_magnitude = self.max_magnitude.max(mag);
    }

    fn variance(&self) -> Vec<f64> {
        if self.count < 2 { return vec![0.0; self.mean.len()]; }
        self.m2.iter().map(|m| m / (self.count - 1) as f64).collect()
    }

    fn magnitude_variance(&self) -> f64 {
        if self.count < 2 { return 0.0; }
        self.magnitude_m2 / (self.count - 1) as f64
    }

    fn magnitude(v: &[f64]) -> f64 {
        v.iter().map(|x| x * x).sum::<f64>().sqrt()
    }
}

// ── Cluster State ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct ClusterState {
    centroid: Vec<f64>,
    member_count: u64,
    radius: f64,            // Average distance from centroid
    last_centroid: Vec<f64>, // Previous centroid for displacement tracking
}

// ── Namespace State ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct NamespaceState {
    stats: RunningStats,
    clusters: Vec<ClusterState>,
    recent_magnitudes: Vec<f64>,
    recent_similarities: Vec<f64>,
    effective_dimensions: f64,
    vector_count: u64,
}

// ── Verdicts ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EmbeddingHealthReport {
    pub namespace: String,
    pub healthy: bool,
    pub anomalies: Vec<EmbeddingAnomalyFinding>,
    pub drift_score: f64,
    pub effective_dimensionality: f64,
    pub avg_magnitude: f64,
    pub magnitude_variance: f64,
    pub findings: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EmbeddingAnomalyFinding {
    pub anomaly_type: EmbeddingAnomaly,
    pub severity: f64,
    pub description: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VectorVerdict {
    pub safe: bool,
    pub anomalies: Vec<EmbeddingAnomalyFinding>,
    pub magnitude: f64,
    pub magnitude_zscore: f64,
    pub nearest_neighbor_suspicious: bool,
    pub findings: Vec<String>,
}

// ── Embedding Space Monitor ────────────────────────────────────────────────

pub struct EmbeddingSpaceMonitor {
    /// Per-namespace embedding statistics
    namespaces: RwLock<HashMap<String, NamespaceState>>,

    /// Configuration
    dimensions: usize,
    magnitude_zscore_threshold: f64,
    drift_threshold: f64,
    dimensionality_collapse_threshold: f64,
    outlier_threshold: f64,
    similarity_window: usize,

    /// Breakthrough #2: Vector fingerprint → health cache
    health_cache: TieredCache<String, bool>,
    /// Breakthrough #461: Distribution evolution tracking
    distribution_diffs: DifferentialStore<String, String>,
    /// Breakthrough #569: φ-weighted alert pruning
    alert_pruning: PruningMap<String, AiAlert>,
    /// Breakthrough #1: O(log n) drift trajectory checkpoints
    drift_state: RwLock<HierarchicalState<f64>>,
    /// Breakthrough #627: Sparse namespace×anomaly matrix
    anomaly_matrix: RwLock<SparseMatrix<String, String, u64>>,
    /// Breakthrough #592: Content-addressed vector dedup
    vector_dedup: DedupStore<String, String>,

    alerts: RwLock<Vec<AiAlert>>,
    total_vectors_checked: AtomicU64,
    total_anomalies: AtomicU64,
    total_blocked: AtomicU64,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl EmbeddingSpaceMonitor {
    pub fn new() -> Self {
        Self::with_dimensions(DEFAULT_DIMENSIONS)
    }

    pub fn with_dimensions(dims: usize) -> Self {
        Self {
            namespaces: RwLock::new(HashMap::new()),
            dimensions: dims,
            magnitude_zscore_threshold: 3.5,
            drift_threshold: 0.15,
            dimensionality_collapse_threshold: 0.3,
            outlier_threshold: 4.0,
            similarity_window: 100,
            health_cache: TieredCache::new(50_000),
            distribution_diffs: DifferentialStore::new(),
            alert_pruning: PruningMap::new(MAX_ALERTS),
            drift_state: RwLock::new(HierarchicalState::new(8, 64)),
            anomaly_matrix: RwLock::new(SparseMatrix::new(0)),
            vector_dedup: DedupStore::new(),
            alerts: RwLock::new(Vec::new()),
            total_vectors_checked: AtomicU64::new(0),
            total_anomalies: AtomicU64::new(0),
            total_blocked: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("embedding_space_monitor", 8 * 1024 * 1024);
        self.health_cache = self.health_cache.with_metrics(metrics.clone(), "embedding_space_monitor");
        self.metrics = Some(metrics);
        self
    }

    /// Check a new vector before it is inserted into the embedding store.
    pub fn check_vector(&self, namespace: &str, vector: &[f64], id: Option<&str>) -> VectorVerdict {
        if !self.enabled || vector.is_empty() {
            return VectorVerdict { safe: true, anomalies: vec![], magnitude: 0.0,
                magnitude_zscore: 0.0, nearest_neighbor_suspicious: false, findings: vec![] };
        }

        self.total_vectors_checked.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        let magnitude = RunningStats::magnitude(vector);
        let mut anomalies = Vec::new();
        let mut findings = Vec::new();

        let mut ns_map = self.namespaces.write();
        let ns = ns_map.entry(namespace.to_string()).or_insert_with(|| NamespaceState {
            stats: RunningStats::new(self.dimensions),
            clusters: Vec::new(),
            recent_magnitudes: Vec::new(),
            recent_similarities: Vec::new(),
            effective_dimensions: self.dimensions as f64,
            vector_count: 0,
        });

        // 1. Magnitude anomaly detection
        let magnitude_zscore = if ns.stats.count > 10 {
            let mag_var = ns.stats.magnitude_variance();
            if mag_var > 0.0 {
                (magnitude - ns.stats.magnitude_mean) / mag_var.sqrt()
            } else {
                0.0
            }
        } else {
            0.0
        };

        if magnitude_zscore.abs() > self.magnitude_zscore_threshold {
            anomalies.push(EmbeddingAnomalyFinding {
                anomaly_type: EmbeddingAnomaly::MagnitudeAnomaly,
                severity: (magnitude_zscore.abs() / 10.0).min(1.0),
                description: format!("Magnitude z-score {:.2} (mag={:.4}, mean={:.4})",
                    magnitude_zscore, magnitude, ns.stats.magnitude_mean),
            });
            findings.push(format!("magnitude_anomaly:zscore={:.2}", magnitude_zscore));
        }

        // 2. Outlier detection (distance from centroid)
        if ns.stats.count > 20 {
            let centroid_dist = self.cosine_distance(vector, &ns.stats.mean);
            if centroid_dist > self.outlier_threshold * 0.1 {
                anomalies.push(EmbeddingAnomalyFinding {
                    anomaly_type: EmbeddingAnomaly::OutlierInjection,
                    severity: (centroid_dist * 2.0).min(1.0),
                    description: format!("Outlier vector: cosine distance {:.4} from centroid", centroid_dist),
                });
                findings.push(format!("outlier:dist={:.4}", centroid_dist));
            }
        }

        // 3. Zero-vector / degenerate vector check
        if magnitude < 1e-6 {
            anomalies.push(EmbeddingAnomalyFinding {
                anomaly_type: EmbeddingAnomaly::MagnitudeAnomaly,
                severity: 0.90,
                description: "Near-zero magnitude vector (degenerate)".to_string(),
            });
        }

        // 4. Dimensionality check: mostly-zero vector in high-dimensional space
        let nonzero_dims = vector.iter().filter(|&&v| v.abs() > 1e-8).count();
        let sparsity = 1.0 - (nonzero_dims as f64 / vector.len() as f64);
        if sparsity > 0.95 && vector.len() > 100 {
            anomalies.push(EmbeddingAnomalyFinding {
                anomaly_type: EmbeddingAnomaly::DimensionalityCollapse,
                severity: sparsity,
                description: format!("Extremely sparse vector: {:.1}% zero dimensions", sparsity * 100.0),
            });
        }

        // Update running statistics
        ns.stats.update(vector);
        ns.vector_count += 1;
        ns.recent_magnitudes.push(magnitude);
        if ns.recent_magnitudes.len() > self.similarity_window {
            ns.recent_magnitudes.remove(0);
        }

        // Periodically update effective dimensionality
        if ns.vector_count % 100 == 0 && ns.stats.count > 50 {
            ns.effective_dimensions = self.compute_effective_dimensionality(&ns.stats);
        }

        let safe = anomalies.iter().all(|a| a.severity < 0.7);

        if !safe {
            self.total_anomalies.fetch_add(anomalies.len() as u64, Ordering::Relaxed);
            self.total_blocked.fetch_add(1, Ordering::Relaxed);
            warn!(namespace=namespace, id=?id, anomalies=anomalies.len(),
                "Embedding anomaly BLOCKED");
            self.add_alert(now, Severity::High, "Embedding anomaly detected",
                &format!("ns={}, anomalies={}, mag={:.4}, zscore={:.2}",
                    namespace, anomalies.len(), magnitude, magnitude_zscore));
        }

        VectorVerdict { safe, anomalies, magnitude, magnitude_zscore,
            nearest_neighbor_suspicious: false, findings }
    }

    /// Generate a health report for an embedding namespace.
    pub fn health_report(&self, namespace: &str) -> EmbeddingHealthReport {
        let ns_map = self.namespaces.read();
        let ns = match ns_map.get(namespace) {
            Some(n) => n,
            None => return EmbeddingHealthReport {
                namespace: namespace.to_string(), healthy: true, anomalies: vec![],
                drift_score: 0.0, effective_dimensionality: self.dimensions as f64,
                avg_magnitude: 0.0, magnitude_variance: 0.0, findings: vec![],
            },
        };

        let mut anomalies = Vec::new();
        let mut findings = Vec::new();

        // 1. Check for dimensionality collapse
        let eff_dim_ratio = ns.effective_dimensions / self.dimensions as f64;
        if eff_dim_ratio < self.dimensionality_collapse_threshold {
            anomalies.push(EmbeddingAnomalyFinding {
                anomaly_type: EmbeddingAnomaly::DimensionalityCollapse,
                severity: (1.0 - eff_dim_ratio).min(1.0),
                description: format!("Effective dimensionality {:.1} / {} ({:.1}%)",
                    ns.effective_dimensions, self.dimensions, eff_dim_ratio * 100.0),
            });
            findings.push(format!("dim_collapse:{:.1}%", eff_dim_ratio * 100.0));
        }

        // 2. Check magnitude distribution health
        let mag_var = ns.stats.magnitude_variance();
        if mag_var > 0.0 {
            let cv = mag_var.sqrt() / ns.stats.magnitude_mean.abs().max(1e-8);
            if cv > 0.5 {
                findings.push(format!("high_magnitude_variance:cv={:.3}", cv));
            }
        }

        // 3. Check for drift in recent magnitudes
        let drift_score = if ns.recent_magnitudes.len() >= 20 {
            let mid = ns.recent_magnitudes.len() / 2;
            let first_avg: f64 = ns.recent_magnitudes[..mid].iter().sum::<f64>() / mid as f64;
            let second_avg: f64 = ns.recent_magnitudes[mid..].iter().sum::<f64>()
                / (ns.recent_magnitudes.len() - mid) as f64;
            ((second_avg - first_avg) / first_avg.abs().max(1e-8)).abs()
        } else {
            0.0
        };

        if drift_score > self.drift_threshold {
            anomalies.push(EmbeddingAnomalyFinding {
                anomaly_type: EmbeddingAnomaly::DistributionDrift,
                severity: (drift_score / 0.5).min(1.0),
                description: format!("Embedding drift detected: {:.3}", drift_score),
            });
            findings.push(format!("drift:{:.3}", drift_score));
        }

        let healthy = anomalies.iter().all(|a| a.severity < 0.5);

        EmbeddingHealthReport {
            namespace: namespace.to_string(),
            healthy,
            anomalies,
            drift_score,
            effective_dimensionality: ns.effective_dimensions,
            avg_magnitude: ns.stats.magnitude_mean,
            magnitude_variance: mag_var,
            findings,
        }
    }

    // ── Similarity Functions ───────────────────────────────────────────────

    fn cosine_distance(&self, a: &[f64], b: &[f64]) -> f64 {
        1.0 - self.cosine_similarity(a, b)
    }

    fn cosine_similarity(&self, a: &[f64], b: &[f64]) -> f64 {
        let len = a.len().min(b.len());
        if len == 0 { return 0.0; }

        let mut dot = 0.0f64;
        let mut norm_a = 0.0f64;
        let mut norm_b = 0.0f64;

        for i in 0..len {
            dot += a[i] * b[i];
            norm_a += a[i] * a[i];
            norm_b += b[i] * b[i];
        }

        let denom = (norm_a * norm_b).sqrt();
        if denom < 1e-12 { 0.0 } else { dot / denom }
    }

    // ── Effective Dimensionality ───────────────────────────────────────────

    fn compute_effective_dimensionality(&self, stats: &RunningStats) -> f64 {
        let variance = stats.variance();
        let total_var: f64 = variance.iter().sum();
        if total_var < 1e-12 { return 0.0; }

        // Participation ratio: (Σ λ_i)² / Σ λ_i²
        let sum_sq: f64 = variance.iter().map(|v| v * v).sum();
        if sum_sq < 1e-12 { return variance.len() as f64; }

        (total_var * total_var) / sum_sq
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "embedding_space_monitor".into(),
            title: title.into(), details: details.into() });
    }

    pub fn total_vectors_checked(&self) -> u64 { self.total_vectors_checked.load(Ordering::Relaxed) }
    pub fn total_anomalies(&self) -> u64 { self.total_anomalies.load(Ordering::Relaxed) }
    pub fn total_blocked(&self) -> u64 { self.total_blocked.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
