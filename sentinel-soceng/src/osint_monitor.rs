//! OSINT Monitor — World-class open-source intelligence engine
//!
//! Features:
//! - OSINT feed ingestion with relevance scoring
//! - Critical threat type classification (zero-day, APT, ransomware, etc.)
//! - Graduated severity alerting based on relevance + threat type
//! - Threat type filtering
//! - Per-source profiling
//! - Audit trail with compression
//! - Reporting and statistics
//! - Compliance mapping (threat intelligence controls)
//!
//! Memory optimizations (10 techniques):
//! - **#1 HierarchicalState**: OSINT state snapshots O(log n)
//! - **#2 TieredCache**: Hot intelligence lookups
//! - **#3 ReversibleComputation**: Recompute threat rate
//! - **#5 StreamAccumulator**: Stream OSINT events
//! - **#6 MemoryMetrics**: Bounded memory
//! - **#461 DifferentialStore**: Track source changes
//! - **#569 PruningMap**: Auto-expire old items
//! - **#592 DedupStore**: Dedup source names
//! - **#593 Compression**: LZ4 compress audit
//! - **#627 SparseMatrix**: Sparse source × threat-type matrix

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::hierarchical::HierarchicalState;
use sentinel_core::reversible::ReversibleComputation;
use sentinel_core::streaming::StreamAccumulator;
use sentinel_core::differential::DifferentialStore;
use sentinel_core::pruning::PruningMap;
use sentinel_core::dedup::DedupStore;
use sentinel_core::compression;
use sentinel_core::sparse::SparseMatrix;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_RECORDS: usize = 10_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OsintItem {
    pub source: String,
    pub title: String,
    pub relevance_score: f64,
    pub threat_type: String,
    pub collected_at: i64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct OsintReport {
    pub total_collected: u64,
    pub high_relevance: u64,
}

pub struct OsintMonitor {
    items: RwLock<Vec<OsintItem>>,
    /// #2 TieredCache
    item_cache: TieredCache<String, f64>,
    /// #1 HierarchicalState
    state_history: RwLock<HierarchicalState<OsintReport>>,
    /// #3 ReversibleComputation
    threat_rate_computer: RwLock<ReversibleComputation<(String, f64), f64>>,
    /// #5 StreamAccumulator
    event_accumulator: RwLock<StreamAccumulator<f64, f64>>,
    /// #461 DifferentialStore
    source_diffs: RwLock<DifferentialStore<String, String>>,
    /// #569 PruningMap
    stale_items: RwLock<PruningMap<String, i64>>,
    /// #592 DedupStore
    source_dedup: RwLock<DedupStore<String, String>>,
    /// #627 SparseMatrix
    source_threat_matrix: RwLock<SparseMatrix<String, String, f64>>,
    /// #593 Compression
    compressed_audit: RwLock<Vec<Vec<u8>>>,
    alerts: RwLock<Vec<SocengAlert>>,
    total_collected: AtomicU64,
    high_relevance: AtomicU64,
    /// #6 MemoryMetrics
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl OsintMonitor {
    pub fn new() -> Self {
        let threat_rate_computer = ReversibleComputation::new(4096, |inputs: &[(String, f64)]| {
            if inputs.is_empty() { return 0.0f64; }
            let critical = inputs.iter().filter(|(_, v)| *v > 0.8).count();
            critical as f64 / inputs.len() as f64 * 100.0
        });
        let event_accumulator = StreamAccumulator::new(128, 0.0f64, |acc: &mut f64, items: &[f64]| {
            for &v in items { *acc = *acc * 0.9 + v * 0.1; }
        });
        Self {
            items: RwLock::new(Vec::new()),
            item_cache: TieredCache::new(10_000),
            state_history: RwLock::new(HierarchicalState::new(6, 64)),
            threat_rate_computer: RwLock::new(threat_rate_computer),
            event_accumulator: RwLock::new(event_accumulator),
            source_diffs: RwLock::new(DifferentialStore::new()),
            stale_items: RwLock::new(PruningMap::new(MAX_RECORDS)),
            source_dedup: RwLock::new(DedupStore::new()),
            source_threat_matrix: RwLock::new(SparseMatrix::new(0.0f64)),
            compressed_audit: RwLock::new(Vec::new()),
            alerts: RwLock::new(Vec::new()),
            total_collected: AtomicU64::new(0),
            high_relevance: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("osint_cache", 4 * 1024 * 1024);
        metrics.register_component("osint_audit", 256 * 1024);
        self.item_cache = self.item_cache.with_metrics(metrics.clone(), "osint_cache");
        self.metrics = Some(metrics);
        self
    }

    const CRITICAL_THREAT_TYPES: &'static [&'static str] = &[
        "zero-day", "apt", "ransomware", "supply-chain",
        "data-breach", "credential-dump", "nation-state",
    ];

    const SCORE_CRITICAL: f64 = 0.95;
    const SCORE_HIGH: f64 = 0.8;
    const SCORE_MEDIUM: f64 = 0.6;

    pub fn ingest(&self, item: OsintItem) {
        if !self.enabled { return; }
        self.total_collected.fetch_add(1, Ordering::Relaxed);
        { let mut acc = self.event_accumulator.write(); acc.push(item.relevance_score); }
        { let mut rc = self.threat_rate_computer.write(); rc.push((item.source.clone(), item.relevance_score)); }
        { let mut m = self.source_threat_matrix.write(); let cur = *m.get(&item.source, &item.threat_type); m.set(item.source.clone(), item.threat_type.clone(), cur + 1.0); }
        { let mut diffs = self.source_diffs.write(); diffs.record_update(item.source.clone(), item.threat_type.clone()); }
        { let mut dedup = self.source_dedup.write(); dedup.insert(item.source.clone(), item.threat_type.clone()); }
        { let mut prune = self.stale_items.write(); prune.insert(format!("{}-{}", item.source, item.collected_at), item.collected_at); }
        self.item_cache.insert(item.title.clone(), item.relevance_score);

        let now = item.collected_at;
        let threat_lower = item.threat_type.to_lowercase();
        let is_critical_threat = Self::CRITICAL_THREAT_TYPES.iter().any(|t| threat_lower.contains(t));

        if item.relevance_score >= Self::SCORE_CRITICAL || is_critical_threat {
            self.high_relevance.fetch_add(1, Ordering::Relaxed);
            let sev = if is_critical_threat { Severity::Critical } else { Severity::High };
            warn!(source = %item.source, threat = %item.threat_type, score = item.relevance_score, "Critical OSINT intel");
            self.add_alert(now, sev, "Critical OSINT", &format!("{}: {} [{}] (score {:.2})", item.source, item.title, item.threat_type, item.relevance_score));
        } else if item.relevance_score >= Self::SCORE_HIGH {
            self.high_relevance.fetch_add(1, Ordering::Relaxed);
            warn!(source = %item.source, threat = %item.threat_type, score = item.relevance_score, "High-relevance OSINT");
            self.add_alert(now, Severity::High, "High-relevance OSINT", &format!("{}: {} (score {:.2})", item.source, item.title, item.relevance_score));
        } else if item.relevance_score >= Self::SCORE_MEDIUM {
            self.add_alert(now, Severity::Medium, "Notable OSINT", &format!("{}: {} (score {:.2})", item.source, item.title, item.relevance_score));
        }

        self.record_audit(&format!("ingest|{}|{}|{}|{:.2}", item.source, item.threat_type, item.title, item.relevance_score));
        let mut i = self.items.write();
        if i.len() >= MAX_RECORDS { i.remove(0); }
        i.push(item);
    }

    pub fn by_threat_type(&self, threat_type: &str) -> Vec<OsintItem> {
        self.items.read().iter().filter(|i| i.threat_type == threat_type).cloned().collect()
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_RECORDS { let drain = a.len() - MAX_RECORDS + 1; a.drain(..drain); }
        a.push(SocengAlert { timestamp: ts, severity: sev, component: "osint_monitor".into(), title: title.into(), details: details.into() });
    }

    fn record_audit(&self, entry: &str) {
        let compressed = compression::compress_lz4(entry.as_bytes());
        let mut audit = self.compressed_audit.write();
        if audit.len() >= MAX_RECORDS { let half = audit.len() / 2; audit.drain(..half); }
        audit.push(compressed);
    }

    pub fn total_collected(&self) -> u64 { self.total_collected.load(Ordering::Relaxed) }
    pub fn high_relevance(&self) -> u64 { self.high_relevance.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<SocengAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }

    pub fn report(&self) -> OsintReport {
        let report = OsintReport {
            total_collected: self.total_collected.load(Ordering::Relaxed),
            high_relevance: self.high_relevance.load(Ordering::Relaxed),
        };
        { let mut h = self.state_history.write(); h.checkpoint(report.clone()); }
        report
    }
}
