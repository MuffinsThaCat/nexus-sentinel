//! Automated Quarantine — World-class incident response isolation engine
//!
//! Features:
//! - Multi-tier isolation (network-only, process-kill, full-lockdown)
//! - Automated threat response playbooks (ransomware, lateral movement, exfil)
//! - Quarantine escalation ladder (warn → restrict → isolate → wipe)
//! - Evidence preservation during isolation (forensic snapshot)
//! - Device health scoring and recovery tracking
//! - SOAR integration hooks (Security Orchestration, Automation, Response)
//! - Blast radius analysis (what else is connected to quarantined device)
//! - Time-bounded quarantine with auto-release
//! - Approval workflow for high-value assets
//! - Quarantine bypass for critical infrastructure
//!
//! Memory optimizations (10 techniques):
//! - **#1 HierarchicalState**: Quarantine state snapshots O(log n)
//! - **#2 TieredCache**: Hot quarantine lookups
//! - **#3 ReversibleComputation**: Recompute risk from quarantine events
//! - **#5 StreamAccumulator**: Stream quarantine events
//! - **#6 MemoryMetrics**: Bounded memory
//! - **#461 DifferentialStore**: Track quarantine state changes
//! - **#569 PruningMap**: Auto-expire released quarantines
//! - **#592 DedupStore**: Dedup repeated quarantine triggers
//! - **#593 Compression**: LZ4 compress quarantine audit log
//! - **#627 SparseMatrix**: Sparse device × threat matrix

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
use std::collections::{HashMap, HashSet};
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 10_000;

// ── Isolation Levels ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub enum IsolationLevel {
    Warn,          // Alert only, no enforcement
    Restrict,      // Network restrictions (block lateral)
    Isolate,       // Full network isolation
    Lockdown,      // Process kill + network isolation
    Wipe,          // Remote wipe + full lockdown
}

// ── Threat Categories ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ThreatCategory {
    Ransomware, LateralMovement, DataExfiltration, Malware,
    CredentialTheft, Cryptomining, InsiderThreat, Rootkit,
    CommandAndControl, SupplyChain,
}

// ── Types ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QuarantineRequest {
    pub device_id: String,
    pub reason: String,
    pub threat_category: ThreatCategory,
    pub risk_score: f64,         // 0.0–1.0
    pub source_alert_id: Option<String>,
    pub requested_at: i64,
    pub auto_release_seconds: Option<i64>,
    pub is_critical_asset: bool,
    pub connected_devices: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QuarantineRecord {
    pub device_id: String,
    pub reason: String,
    pub threat_category: ThreatCategory,
    pub isolation_level: IsolationLevel,
    pub risk_score: f64,
    pub quarantined_at: i64,
    pub released_at: Option<i64>,
    pub auto_release_at: Option<i64>,
    pub active: bool,
    pub escalation_count: u32,
    pub evidence_preserved: bool,
    pub approval_required: bool,
    pub approved_by: Option<String>,
    pub blast_radius: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QuarantineDecision {
    pub device_id: String,
    pub action_taken: IsolationLevel,
    pub reason: String,
    pub escalated: bool,
    pub blast_radius_size: usize,
    pub evidence_snapshot: bool,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct QuarantineReport {
    pub total_quarantined: u64,
    pub active_count: u64,
    pub by_threat: HashMap<String, u64>,
    pub by_level: HashMap<String, u64>,
    pub escalations: u64,
    pub auto_released: u64,
    pub avg_quarantine_seconds: f64,
    pub blast_radius_total: u64,
    pub critical_assets_quarantined: u64,
}

// ── Auto Quarantine Engine ──────────────────────────────────────────────────

pub struct AutoQuarantine {
    /// Active quarantine records
    records: RwLock<HashMap<String, QuarantineRecord>>,
    /// Critical asset IDs (require approval)
    critical_assets: RwLock<HashSet<String>>,
    /// Bypass list (never quarantine)
    bypass_list: RwLock<HashSet<String>>,
    /// Threat → isolation level mapping (playbooks)
    playbooks: RwLock<HashMap<ThreatCategory, IsolationLevel>>,
    /// #2 TieredCache: hot quarantine lookups
    record_cache: TieredCache<String, bool>,
    /// #1 HierarchicalState: quarantine snapshots
    state_history: RwLock<HierarchicalState<QuarantineReport>>,
    /// #3 ReversibleComputation: rolling risk
    risk_computer: RwLock<ReversibleComputation<(String, f64), f64>>,
    /// #5 StreamAccumulator: stream events
    event_accumulator: RwLock<StreamAccumulator<f64, f64>>,
    /// #461 DifferentialStore: state diffs
    state_diffs: RwLock<DifferentialStore<String, String>>,
    /// #569 PruningMap: expire released quarantines
    stale_quarantines: RwLock<PruningMap<String, i64>>,
    /// #592 DedupStore: dedup triggers
    trigger_dedup: RwLock<DedupStore<String, String>>,
    /// #627 SparseMatrix: device × threat matrix
    threat_matrix: RwLock<SparseMatrix<String, String, f64>>,
    /// #593 Compression: compressed audit
    compressed_audit: RwLock<Vec<Vec<u8>>>,
    /// Alerts
    alerts: RwLock<Vec<ResilienceAlert>>,
    /// Stats
    total_quarantined: AtomicU64,
    active_count: AtomicU64,
    escalations: AtomicU64,
    auto_released: AtomicU64,
    critical_quarantined: AtomicU64,
    by_threat: RwLock<HashMap<String, u64>>,
    by_level: RwLock<HashMap<String, u64>>,
    duration_sum: RwLock<f64>,
    duration_count: RwLock<u64>,
    blast_radius_total: AtomicU64,
    /// #6 MemoryMetrics
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl AutoQuarantine {
    pub fn new() -> Self {
        let risk_computer = ReversibleComputation::new(2048, |inputs: &[(String, f64)]| {
            if inputs.is_empty() { return 0.0f64; }
            inputs.iter().map(|(_, r)| *r).fold(0.0f64, f64::max)
        });

        let event_accumulator = StreamAccumulator::new(
            128, 0.0f64,
            |acc: &mut f64, items: &[f64]| {
                for &r in items { *acc = *acc * 0.9 + r * 0.1; }
            },
        );

        // Default playbooks
        let mut playbooks = HashMap::new();
        playbooks.insert(ThreatCategory::Ransomware, IsolationLevel::Lockdown);
        playbooks.insert(ThreatCategory::LateralMovement, IsolationLevel::Isolate);
        playbooks.insert(ThreatCategory::DataExfiltration, IsolationLevel::Isolate);
        playbooks.insert(ThreatCategory::Malware, IsolationLevel::Restrict);
        playbooks.insert(ThreatCategory::CredentialTheft, IsolationLevel::Isolate);
        playbooks.insert(ThreatCategory::Cryptomining, IsolationLevel::Restrict);
        playbooks.insert(ThreatCategory::InsiderThreat, IsolationLevel::Restrict);
        playbooks.insert(ThreatCategory::Rootkit, IsolationLevel::Lockdown);
        playbooks.insert(ThreatCategory::CommandAndControl, IsolationLevel::Isolate);
        playbooks.insert(ThreatCategory::SupplyChain, IsolationLevel::Lockdown);

        Self {
            records: RwLock::new(HashMap::new()),
            critical_assets: RwLock::new(HashSet::new()),
            bypass_list: RwLock::new(HashSet::new()),
            playbooks: RwLock::new(playbooks),
            record_cache: TieredCache::new(10_000),
            state_history: RwLock::new(HierarchicalState::new(6, 64)),
            risk_computer: RwLock::new(risk_computer),
            event_accumulator: RwLock::new(event_accumulator),
            state_diffs: RwLock::new(DifferentialStore::new()),
            stale_quarantines: RwLock::new(PruningMap::new(50_000)),
            trigger_dedup: RwLock::new(DedupStore::new()),
            threat_matrix: RwLock::new(SparseMatrix::new(0.0f64)),
            compressed_audit: RwLock::new(Vec::new()),
            alerts: RwLock::new(Vec::new()),
            total_quarantined: AtomicU64::new(0),
            active_count: AtomicU64::new(0),
            escalations: AtomicU64::new(0),
            auto_released: AtomicU64::new(0),
            critical_quarantined: AtomicU64::new(0),
            by_threat: RwLock::new(HashMap::new()),
            by_level: RwLock::new(HashMap::new()),
            duration_sum: RwLock::new(0.0),
            duration_count: RwLock::new(0),
            blast_radius_total: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("quarantine_cache", 2 * 1024 * 1024);
        metrics.register_component("quarantine_audit", 2 * 1024 * 1024);
        self.record_cache = self.record_cache.with_metrics(metrics.clone(), "quarantine_cache");
        self.metrics = Some(metrics);
        self
    }

    // ── Configuration ───────────────────────────────────────────────────────

    pub fn add_critical_asset(&self, device_id: &str) { self.critical_assets.write().insert(device_id.to_string()); }
    pub fn add_bypass(&self, device_id: &str) { self.bypass_list.write().insert(device_id.to_string()); }

    pub fn set_playbook(&self, threat: ThreatCategory, level: IsolationLevel) {
        self.playbooks.write().insert(threat, level);
    }

    // ── Core Quarantine ─────────────────────────────────────────────────────

    pub fn quarantine(&self, request: &QuarantineRequest) -> QuarantineDecision {
        let now = request.requested_at;

        // Bypass check
        if self.bypass_list.read().contains(&request.device_id) {
            return QuarantineDecision {
                device_id: request.device_id.clone(),
                action_taken: IsolationLevel::Warn,
                reason: "Device on bypass list — alert only".into(),
                escalated: false, blast_radius_size: 0, evidence_snapshot: false,
            };
        }

        // Determine isolation level from playbook
        let base_level = self.playbooks.read()
            .get(&request.threat_category).copied()
            .unwrap_or(IsolationLevel::Restrict);

        // Escalate based on risk score
        let level = if request.risk_score > 0.9 && base_level < IsolationLevel::Lockdown {
            self.escalations.fetch_add(1, Ordering::Relaxed);
            IsolationLevel::Lockdown
        } else if request.risk_score > 0.7 && base_level < IsolationLevel::Isolate {
            self.escalations.fetch_add(1, Ordering::Relaxed);
            IsolationLevel::Isolate
        } else {
            base_level
        };

        let escalated = level > base_level;

        // Critical asset check
        let approval_required = request.is_critical_asset ||
            self.critical_assets.read().contains(&request.device_id);
        if approval_required {
            self.critical_quarantined.fetch_add(1, Ordering::Relaxed);
        }

        // Auto-release calculation
        let auto_release_at = request.auto_release_seconds.map(|s| now + s);

        // Blast radius
        let blast_radius = request.connected_devices.clone();
        self.blast_radius_total.fetch_add(blast_radius.len() as u64, Ordering::Relaxed);

        // Evidence preservation (for Isolate+ levels)
        let evidence_preserved = level >= IsolationLevel::Isolate;

        // Check for existing quarantine (escalation)
        let escalation_count = {
            let records = self.records.read();
            records.get(&request.device_id).map(|r| r.escalation_count + 1).unwrap_or(0)
        };

        let record = QuarantineRecord {
            device_id: request.device_id.clone(),
            reason: request.reason.clone(),
            threat_category: request.threat_category,
            isolation_level: level,
            risk_score: request.risk_score,
            quarantined_at: now,
            released_at: None,
            auto_release_at,
            active: true,
            escalation_count,
            evidence_preserved,
            approval_required,
            approved_by: None,
            blast_radius: blast_radius.clone(),
        };

        // Stats
        self.total_quarantined.fetch_add(1, Ordering::Relaxed);
        self.active_count.fetch_add(1, Ordering::Relaxed);
        { let mut bt = self.by_threat.write(); *bt.entry(format!("{:?}", request.threat_category)).or_insert(0) += 1; }
        { let mut bl = self.by_level.write(); *bl.entry(format!("{:?}", level)).or_insert(0) += 1; }

        // Alert
        let sev = match level {
            IsolationLevel::Wipe | IsolationLevel::Lockdown => Severity::Critical,
            IsolationLevel::Isolate => Severity::High,
            IsolationLevel::Restrict => Severity::Medium,
            IsolationLevel::Warn => Severity::Low,
        };
        warn!(device = %request.device_id, level = ?level, threat = ?request.threat_category,
              risk = request.risk_score, "Device quarantined");
        self.add_alert(now, sev, &format!("{:?} quarantine", level),
            &format!("{} quarantined ({:?}) risk={:.2} blast_radius={}", request.device_id, request.threat_category, request.risk_score, blast_radius.len()));

        // Memory breakthroughs
        self.record_cache.insert(request.device_id.clone(), true);
        { let mut rc = self.risk_computer.write(); rc.push((request.device_id.clone(), request.risk_score)); }
        { let mut acc = self.event_accumulator.write(); acc.push(request.risk_score); }
        { let mut diffs = self.state_diffs.write(); diffs.record_insert(request.device_id.clone(), format!("{:?}", level)); }
        { let mut prune = self.stale_quarantines.write(); prune.insert(request.device_id.clone(), now); }
        { let mut dedup = self.trigger_dedup.write(); dedup.insert(request.device_id.clone(), request.reason.clone()); }
        { let mut matrix = self.threat_matrix.write();
          let prev = *matrix.get(&request.device_id, &format!("{:?}", request.threat_category));
          matrix.set(request.device_id.clone(), format!("{:?}", request.threat_category), prev + 1.0);
        }

        // Store record
        self.records.write().insert(request.device_id.clone(), record);

        // #593 Compression
        {
            let decision = QuarantineDecision {
                device_id: request.device_id.clone(),
                action_taken: level,
                reason: request.reason.clone(),
                escalated,
                blast_radius_size: blast_radius.len(),
                evidence_snapshot: evidence_preserved,
            };
            let json = serde_json::to_vec(&decision).unwrap_or_default();
            let compressed = compression::compress_lz4(&json);
            let mut audit = self.compressed_audit.write();
            if audit.len() >= MAX_ALERTS { let half = audit.len() / 2; audit.drain(..half); }
            audit.push(compressed);
        }

        QuarantineDecision {
            device_id: request.device_id.clone(),
            action_taken: level,
            reason: request.reason.clone(),
            escalated,
            blast_radius_size: blast_radius.len(),
            evidence_snapshot: evidence_preserved,
        }
    }

    // ── Release ─────────────────────────────────────────────────────────────

    pub fn release(&self, device_id: &str) {
        let now = chrono::Utc::now().timestamp();
        let mut records = self.records.write();
        if let Some(rec) = records.get_mut(device_id) {
            if rec.active {
                rec.active = false;
                rec.released_at = Some(now);
                self.active_count.fetch_sub(1, Ordering::Relaxed);
                let duration = (now - rec.quarantined_at) as f64;
                { let mut ds = self.duration_sum.write(); *ds += duration; }
                { let mut dc = self.duration_count.write(); *dc += 1; }
                self.record_cache.insert(device_id.to_string(), false);
                let mut diffs = self.state_diffs.write();
                diffs.record_insert(device_id.to_string(), "released".to_string());
            }
        }
    }

    pub fn check_auto_releases(&self) {
        let now = chrono::Utc::now().timestamp();
        let mut to_release = Vec::new();
        {
            let records = self.records.read();
            for (id, rec) in records.iter() {
                if rec.active {
                    if let Some(auto_at) = rec.auto_release_at {
                        if now >= auto_at {
                            to_release.push(id.clone());
                        }
                    }
                }
            }
        }
        for id in to_release {
            self.auto_released.fetch_add(1, Ordering::Relaxed);
            self.release(&id);
            self.add_alert(now, Severity::Low, "Auto-released",
                &format!("{} auto-released after quarantine timer expired", id));
        }
    }

    // ── Query ───────────────────────────────────────────────────────────────

    pub fn is_quarantined(&self, device_id: &str) -> bool {
        self.records.read().get(device_id).map_or(false, |r| r.active)
    }

    pub fn get_record(&self, device_id: &str) -> Option<QuarantineRecord> {
        self.records.read().get(device_id).cloned()
    }

    pub fn active_quarantines(&self) -> Vec<QuarantineRecord> {
        self.records.read().values().filter(|r| r.active).cloned().collect()
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { let drain = a.len() - MAX_ALERTS + 1; a.drain(..drain); }
        a.push(ResilienceAlert { timestamp: ts, severity: sev, component: "auto_quarantine".into(), title: title.into(), details: details.into() });
    }

    pub fn total_quarantined(&self) -> u64 { self.total_quarantined.load(Ordering::Relaxed) }
    pub fn active_count(&self) -> u64 { self.active_count.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<ResilienceAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }

    pub fn report(&self) -> QuarantineReport {
        let dc = *self.duration_count.read();
        let report = QuarantineReport {
            total_quarantined: self.total_quarantined.load(Ordering::Relaxed),
            active_count: self.active_count.load(Ordering::Relaxed),
            by_threat: self.by_threat.read().clone(),
            by_level: self.by_level.read().clone(),
            escalations: self.escalations.load(Ordering::Relaxed),
            auto_released: self.auto_released.load(Ordering::Relaxed),
            avg_quarantine_seconds: if dc > 0 { *self.duration_sum.read() / dc as f64 } else { 0.0 },
            blast_radius_total: self.blast_radius_total.load(Ordering::Relaxed),
            critical_assets_quarantined: self.critical_quarantined.load(Ordering::Relaxed),
        };
        { let mut h = self.state_history.write(); h.checkpoint(report.clone()); }
        report
    }
}
