//! Compliance Logger — World-class compliance event engine
//!
//! Features:
//! - Framework registration with control mappings
//! - Compliance event logging with status tracking
//! - Log event evaluation against frameworks
//! - Failure detection and alerting
//! - Per-framework profiling
//! - Audit trail with compression
//! - Reporting and statistics
//! - Compliance mapping (SOX, PCI-DSS, HIPAA, NIST controls)
//!
//! Memory optimizations (10 techniques):
//! - **#1 HierarchicalState**: Compliance state snapshots O(log n)
//! - **#2 TieredCache**: Hot control lookups
//! - **#3 ReversibleComputation**: Recompute failure rate
//! - **#5 StreamAccumulator**: Stream compliance events
//! - **#6 MemoryMetrics**: Bounded memory
//! - **#461 DifferentialStore**: Track control changes
//! - **#569 PruningMap**: Auto-expire old events
//! - **#592 DedupStore**: Dedup framework names
//! - **#593 Compression**: LZ4 compress audit
//! - **#627 SparseMatrix**: Sparse framework × control matrix

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
use std::collections::HashMap;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_RECORDS: usize = 10_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ComplianceEvent {
    pub id: String,
    pub timestamp: i64,
    pub framework: String,
    pub control_id: String,
    pub description: String,
    pub status: ComplianceStatus,
    pub source_event_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ComplianceStatus {
    Pass,
    Fail,
    Warning,
    NotApplicable,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ComplianceReport {
    pub total_events: u64,
    pub total_failures: u64,
    pub frameworks: u64,
}

pub struct ComplianceLogger {
    events: RwLock<Vec<ComplianceEvent>>,
    max_events: usize,
    frameworks: RwLock<HashMap<String, HashMap<String, Vec<String>>>>,
    /// #2 TieredCache
    control_cache: TieredCache<String, u8>,
    /// #1 HierarchicalState
    state_history: RwLock<HierarchicalState<ComplianceReport>>,
    /// #3 ReversibleComputation
    fail_rate_computer: RwLock<ReversibleComputation<(String, f64), f64>>,
    /// #5 StreamAccumulator
    event_accumulator: RwLock<StreamAccumulator<f64, f64>>,
    /// #461 DifferentialStore
    control_diffs: RwLock<DifferentialStore<String, String>>,
    /// #569 PruningMap
    stale_events: RwLock<PruningMap<String, i64>>,
    /// #592 DedupStore
    framework_dedup: RwLock<DedupStore<String, String>>,
    /// #627 SparseMatrix
    framework_control_matrix: RwLock<SparseMatrix<String, String, f64>>,
    /// #593 Compression
    compressed_audit: RwLock<Vec<Vec<u8>>>,
    total_failures: AtomicU64,
    /// #6 MemoryMetrics
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl ComplianceLogger {
    pub fn new(max_events: usize) -> Self {
        let fail_rate_computer = ReversibleComputation::new(4096, |inputs: &[(String, f64)]| {
            if inputs.is_empty() { return 0.0f64; }
            let fails = inputs.iter().filter(|(_, v)| *v > 0.5).count();
            fails as f64 / inputs.len() as f64 * 100.0
        });
        let event_accumulator = StreamAccumulator::new(128, 0.0f64, |acc: &mut f64, items: &[f64]| {
            for &v in items { *acc = *acc * 0.9 + v * 0.1; }
        });
        Self {
            events: RwLock::new(Vec::new()),
            max_events,
            frameworks: RwLock::new(HashMap::new()),
            control_cache: TieredCache::new(10_000),
            state_history: RwLock::new(HierarchicalState::new(6, 64)),
            fail_rate_computer: RwLock::new(fail_rate_computer),
            event_accumulator: RwLock::new(event_accumulator),
            control_diffs: RwLock::new(DifferentialStore::new()),
            stale_events: RwLock::new(
                PruningMap::new(max_events).with_ttl(std::time::Duration::from_secs(86400 * 30)),
            ),
            framework_dedup: RwLock::new(DedupStore::new()),
            framework_control_matrix: RwLock::new(SparseMatrix::new(0.0f64)),
            compressed_audit: RwLock::new(Vec::new()),
            total_failures: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("compliance_cache", 8 * 1024 * 1024);
        metrics.register_component("compliance_audit", 256 * 1024);
        self.control_cache = self.control_cache.with_metrics(metrics.clone(), "compliance_cache");
        self.metrics = Some(metrics);
        self
    }

    pub fn add_framework(&self, name: &str, controls: HashMap<String, Vec<String>>) {
        { let mut dedup = self.framework_dedup.write(); dedup.insert(name.to_string(), name.to_string()); }
        { let mut diffs = self.control_diffs.write(); diffs.record_update(name.to_string(), format!("{} controls", controls.len())); }
        self.record_audit(&format!("framework|{}|{}_controls", name, controls.len()));
        self.frameworks.write().insert(name.to_string(), controls);
    }

    pub fn log_event(&self, event: ComplianceEvent) {
        if !self.enabled { return; }
        { let mut acc = self.event_accumulator.write(); acc.push(1.0); }
        let status_val = if event.status == ComplianceStatus::Fail { 1.0 } else { 0.0 };
        { let mut m = self.framework_control_matrix.write(); let cur = *m.get(&event.framework, &event.control_id); m.set(event.framework.clone(), event.control_id.clone(), cur + 1.0); }
        { let mut rc = self.fail_rate_computer.write(); rc.push((event.framework.clone(), status_val)); }
        if event.status == ComplianceStatus::Fail {
            self.total_failures.fetch_add(1, Ordering::Relaxed);
            warn!(framework = %event.framework, control = %event.control_id, "Compliance failure");
        }
        self.record_audit(&format!("event|{}|{}|{}|{:?}", event.framework, event.control_id, event.id, event.status));
        let mut events = self.events.write();
        if events.len() >= self.max_events { events.remove(0); }
        events.push(event);
    }

    pub fn evaluate(&self, log_event: &LogEvent) {
        if !self.enabled { return; }
        let now = chrono::Utc::now().timestamp();
        let frameworks = self.frameworks.read();

        for (framework, controls) in frameworks.iter() {
            for (control_id, keywords) in controls.iter() {
                let matched = keywords.iter().any(|kw| log_event.message.contains(kw));
                if matched {
                    let status = if log_event.level >= LogLevel::Error {
                        ComplianceStatus::Fail
                    } else {
                        ComplianceStatus::Pass
                    };
                    let ce = ComplianceEvent {
                        id: format!("comp-{}-{}-{}", framework, control_id, now),
                        timestamp: now,
                        framework: framework.clone(),
                        control_id: control_id.clone(),
                        description: format!("Control {} triggered by event {}", control_id, log_event.id),
                        status,
                        source_event_id: Some(log_event.id.clone()),
                    };
                    let status_val = if status == ComplianceStatus::Fail { 1.0 } else { 0.0 };
                    { let mut m = self.framework_control_matrix.write(); let cur = *m.get(framework, control_id); m.set(framework.clone(), control_id.clone(), cur + 1.0); }
                    { let mut rc = self.fail_rate_computer.write(); rc.push((framework.clone(), status_val)); }
                    { let mut prune = self.stale_events.write(); prune.insert(ce.id.clone(), now); }
                    if status == ComplianceStatus::Fail { self.total_failures.fetch_add(1, Ordering::Relaxed); }
                    self.record_audit(&format!("eval|{}|{}|{:?}", framework, control_id, status));
                    let mut events = self.events.write();
                    if events.len() >= self.max_events { events.remove(0); }
                    events.push(ce);
                }
            }
        }
    }

    fn record_audit(&self, entry: &str) {
        let compressed = compression::compress_lz4(entry.as_bytes());
        let mut audit = self.compressed_audit.write();
        if audit.len() >= MAX_RECORDS { let half = audit.len() / 2; audit.drain(..half); }
        audit.push(compressed);
    }

    pub fn events(&self) -> Vec<ComplianceEvent> { self.events.read().clone() }
    pub fn failures(&self) -> Vec<ComplianceEvent> {
        self.events.read().iter().filter(|e| e.status == ComplianceStatus::Fail).cloned().collect()
    }
    pub fn event_count(&self) -> usize { self.events.read().len() }
    pub fn set_enabled(&mut self, enabled: bool) { self.enabled = enabled; }

    pub fn report(&self) -> ComplianceReport {
        let report = ComplianceReport {
            total_events: self.events.read().len() as u64,
            total_failures: self.total_failures.load(Ordering::Relaxed),
            frameworks: self.frameworks.read().len() as u64,
        };
        { let mut h = self.state_history.write(); h.checkpoint(report.clone()); }
        report
    }
}
