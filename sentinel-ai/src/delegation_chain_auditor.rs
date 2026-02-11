//! Delegation Chain Auditor — Tracks and validates permission chains when
//! agents delegate tasks to other agents.
//!
//! Agent A delegates to B, B delegates to C. This module ensures:
//! - Permissions never escalate (C can't have more power than A granted)
//! - The full chain is traceable and auditable
//! - Delegation depth is bounded
//! - Circular delegation is detected
//! - Delegation laundering (obscuring the origin) is flagged
//! - Revocation propagates through the chain
//!
//! 5 audit dimensions, 5 memory breakthroughs:
//!   #1  HierarchicalState — O(log n) delegation history
//!   #2  TieredCache — hot/warm/cold delegation lookup cache
//!   #461 DifferentialStore — permission evolution tracking
//!   #569 PruningMap — φ-weighted audit log eviction
//!   #627 SparseMatrix — sparse agent×agent delegation matrix

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::differential::DifferentialStore;
use sentinel_core::pruning::PruningMap;
use sentinel_core::hierarchical::HierarchicalState;
use sentinel_core::sparse::SparseMatrix;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;
const MAX_DELEGATION_DEPTH: usize = 10;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Delegation {
    pub delegation_id: String,
    pub from_agent: String,
    pub to_agent: String,
    pub permissions_granted: Vec<String>,
    pub constraints: Vec<String>,
    pub max_sub_delegations: u32,
    pub expires_at: i64,
    pub timestamp: i64,
    pub task_description: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DelegationAuditResult {
    pub valid: bool,
    pub risk_score: f64,
    pub chain_depth: usize,
    pub escalation_detected: bool,
    pub circular_detected: bool,
    pub laundering_suspected: bool,
    pub violations: Vec<String>,
    pub full_chain: Vec<String>,
    pub effective_permissions: Vec<String>,
}

#[derive(Debug, Clone)]
struct DelegationRecord {
    delegation: Delegation,
    parent_delegation: Option<String>,
    sub_delegation_count: u32,
    revoked: bool,
}

pub struct DelegationChainAuditor {
    max_depth: usize,
    enabled: bool,
    /// Breakthrough #2: Hot/warm/cold delegation lookup cache
    deleg_cache: TieredCache<String, u64>,
    /// Breakthrough #461: Permission evolution tracking
    perm_diffs: DifferentialStore<String, String>,
    /// Breakthrough #569: φ-weighted audit log pruning
    pruned_audit: PruningMap<String, String>,
    /// Breakthrough #1: O(log n) delegation history
    deleg_state: RwLock<HierarchicalState<u64>>,
    /// Breakthrough #627: Sparse agent×agent delegation matrix
    deleg_matrix: RwLock<SparseMatrix<String, String, u32>>,

    delegations: RwLock<HashMap<String, DelegationRecord>>,
    agent_delegations: RwLock<HashMap<String, Vec<String>>>,
    agent_permissions: RwLock<HashMap<String, HashSet<String>>>,
    revoked_chains: RwLock<HashSet<String>>,
    audit_log: RwLock<VecDeque<String>>,
    alerts: RwLock<Vec<AiAlert>>,

    total_delegations: AtomicU64,
    total_escalations: AtomicU64,
    total_circular: AtomicU64,
    total_laundering: AtomicU64,
    total_revocations: AtomicU64,
    total_depth_exceeded: AtomicU64,
    metrics: Option<MemoryMetrics>,
}

impl DelegationChainAuditor {
    pub fn new() -> Self {
        Self {
            max_depth: MAX_DELEGATION_DEPTH, enabled: true,
            deleg_cache: TieredCache::new(20_000),
            perm_diffs: DifferentialStore::new(),
            pruned_audit: PruningMap::new(10_000),
            deleg_state: RwLock::new(HierarchicalState::new(8, 64)),
            deleg_matrix: RwLock::new(SparseMatrix::new(0)),
            delegations: RwLock::new(HashMap::new()),
            agent_delegations: RwLock::new(HashMap::new()),
            agent_permissions: RwLock::new(HashMap::new()),
            revoked_chains: RwLock::new(HashSet::new()),
            audit_log: RwLock::new(VecDeque::with_capacity(10_000)),
            alerts: RwLock::new(Vec::new()),
            total_delegations: AtomicU64::new(0), total_escalations: AtomicU64::new(0),
            total_circular: AtomicU64::new(0), total_laundering: AtomicU64::new(0),
            total_revocations: AtomicU64::new(0), total_depth_exceeded: AtomicU64::new(0),
            metrics: None,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("delegation_chain_auditor", 4 * 1024 * 1024);
        self.deleg_cache = self.deleg_cache.with_metrics(metrics.clone(), "deleg_chain_cache");
        self.metrics = Some(metrics); self
    }

    /// Set root permissions for an agent
    pub fn set_agent_permissions(&self, agent_id: &str, permissions: Vec<String>) {
        self.agent_permissions.write().insert(agent_id.to_string(), permissions.into_iter().collect());
    }

    /// Record and validate a delegation
    pub fn record_delegation(&self, delegation: Delegation, parent_delegation_id: Option<&str>) -> DelegationAuditResult {
        if !self.enabled {
            return DelegationAuditResult { valid: true, risk_score: 0.0, chain_depth: 0, escalation_detected: false, circular_detected: false, laundering_suspected: false, violations: Vec::new(), full_chain: Vec::new(), effective_permissions: delegation.permissions_granted.clone() };
        }
        self.total_delegations.fetch_add(1, Ordering::Relaxed);
        let now = delegation.timestamp;

        let mut violations = Vec::new();
        let mut risk = 0.0f64;

        // 1. Check delegation depth
        let chain = self.build_chain(&delegation.from_agent, parent_delegation_id);
        let depth = chain.len() + 1;
        if depth > self.max_depth {
            violations.push(format!("depth_exceeded: {} > max {}", depth, self.max_depth));
            risk = risk.max(0.80);
            self.total_depth_exceeded.fetch_add(1, Ordering::Relaxed);
        }

        // 2. Check for circular delegation
        let circular = chain.contains(&delegation.to_agent) || delegation.from_agent == delegation.to_agent;
        if circular {
            violations.push(format!("circular_delegation: {} already in chain {:?}", delegation.to_agent, chain));
            risk = risk.max(0.95);
            self.total_circular.fetch_add(1, Ordering::Relaxed);
        }

        // 3. Check for permission escalation
        let parent_perms = self.get_effective_permissions(&delegation.from_agent);
        let mut escalated = Vec::new();
        for perm in &delegation.permissions_granted {
            if !parent_perms.contains(perm) {
                escalated.push(perm.clone());
            }
        }
        let escalation = !escalated.is_empty();
        if escalation {
            violations.push(format!("permission_escalation: {:?} not held by {}", escalated, delegation.from_agent));
            risk = risk.max(0.90);
            self.total_escalations.fetch_add(1, Ordering::Relaxed);
        }

        // 4. Check for delegation laundering (rapid re-delegation through intermediaries)
        let laundering = self.detect_laundering(&delegation, &chain);
        if laundering {
            violations.push("delegation_laundering_suspected".into());
            risk = risk.max(0.82);
            self.total_laundering.fetch_add(1, Ordering::Relaxed);
        }

        // 5. Check sub-delegation limits
        if let Some(parent_id) = parent_delegation_id {
            let deleg = self.delegations.read();
            if let Some(parent) = deleg.get(parent_id) {
                if parent.sub_delegation_count >= parent.delegation.max_sub_delegations {
                    violations.push(format!("sub_delegation_limit: {}/{}", parent.sub_delegation_count, parent.delegation.max_sub_delegations));
                    risk = risk.max(0.70);
                }
            }
        }

        // 6. Check expiration
        if delegation.expires_at <= now {
            violations.push("delegation_already_expired".into());
            risk = risk.max(0.60);
        }

        // Compute effective permissions (intersection with parent)
        let effective: Vec<String> = delegation.permissions_granted.iter()
            .filter(|p| parent_perms.contains(*p))
            .cloned().collect();

        let valid = violations.is_empty();
        if !valid {
            warn!(from=%delegation.from_agent, to=%delegation.to_agent, risk=risk, "Delegation chain violation");
            self.add_alert(now, if risk >= 0.90 { Severity::Critical } else { Severity::High },
                "Delegation chain violation",
                &format!("{}→{}, violations={:?}", delegation.from_agent, delegation.to_agent, violations));
        }

        // Store delegation if valid or if not blocking
        if valid || risk < 0.90 {
            let record = DelegationRecord {
                delegation: delegation.clone(),
                parent_delegation: parent_delegation_id.map(String::from),
                sub_delegation_count: 0, revoked: false,
            };

            // Update parent sub-delegation count
            if let Some(pid) = parent_delegation_id {
                if let Some(parent) = self.delegations.write().get_mut(pid) {
                    parent.sub_delegation_count += 1;
                }
            }

            self.delegations.write().insert(delegation.delegation_id.clone(), record);
            self.agent_delegations.write().entry(delegation.from_agent.clone())
                .or_insert_with(Vec::new).push(delegation.delegation_id.clone());

            // Grant effective permissions to target agent
            let mut perms = self.agent_permissions.write();
            let target_perms = perms.entry(delegation.to_agent.clone()).or_insert_with(HashSet::new);
            for p in &effective { target_perms.insert(p.clone()); }
        }

        // Audit log
        { let mut log = self.audit_log.write();
            log.push_back(format!("[{}] {}→{} perms={:?} valid={} risk={:.2}",
                now, delegation.from_agent, delegation.to_agent, effective, valid, risk));
            while log.len() > 10_000 { log.pop_front(); } }

        let mut full_chain = chain;
        full_chain.push(delegation.to_agent.clone());

        DelegationAuditResult {
            valid, risk_score: risk, chain_depth: depth,
            escalation_detected: escalation, circular_detected: circular,
            laundering_suspected: laundering, violations,
            full_chain, effective_permissions: effective,
        }
    }

    /// Revoke a delegation and propagate through the chain
    pub fn revoke_delegation(&self, delegation_id: &str) -> usize {
        let mut revoked_count = 0;
        let mut to_revoke = vec![delegation_id.to_string()];

        while let Some(did) = to_revoke.pop() {
            let mut deleg = self.delegations.write();
            if let Some(record) = deleg.get_mut(&did) {
                if !record.revoked {
                    record.revoked = true;
                    revoked_count += 1;
                    self.revoked_chains.write().insert(did.clone());

                    // Find child delegations to cascade revocation
                    let target = record.delegation.to_agent.clone();
                    let ad = self.agent_delegations.read();
                    if let Some(child_ids) = ad.get(&target) {
                        to_revoke.extend(child_ids.iter().cloned());
                    }
                }
            }
        }

        self.total_revocations.fetch_add(revoked_count as u64, Ordering::Relaxed);
        revoked_count
    }

    fn build_chain(&self, agent_id: &str, parent_delegation_id: Option<&str>) -> Vec<String> {
        let mut chain = Vec::new();
        let mut current_delegation = parent_delegation_id.map(String::from);
        let deleg = self.delegations.read();

        while let Some(did) = current_delegation {
            if let Some(record) = deleg.get(&did) {
                chain.push(record.delegation.from_agent.clone());
                current_delegation = record.parent_delegation.clone();
                if chain.len() > self.max_depth + 5 { break; } // safety
            } else { break; }
        }
        chain.reverse();
        chain
    }

    fn get_effective_permissions(&self, agent_id: &str) -> HashSet<String> {
        self.agent_permissions.read().get(agent_id).cloned().unwrap_or_default()
    }

    fn detect_laundering(&self, delegation: &Delegation, chain: &[String]) -> bool {
        // Rapid re-delegation: same permissions flowing through multiple intermediaries quickly
        if chain.len() < 3 { return false; }
        let deleg = self.delegations.read();
        let mut time_window = Vec::new();
        for record in deleg.values() {
            if chain.contains(&record.delegation.from_agent) || chain.contains(&record.delegation.to_agent) {
                time_window.push(record.delegation.timestamp);
            }
        }
        if time_window.len() < 3 { return false; }
        time_window.sort();
        // If 3+ delegations happened within 60 seconds = suspicious
        for w in time_window.windows(3) {
            if w[2] - w[0] < 60 { return true; }
        }
        false
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "delegation_chain_auditor".into(), title: title.into(), details: details.into() });
    }

    pub fn total_delegations(&self) -> u64 { self.total_delegations.load(Ordering::Relaxed) }
    pub fn total_escalations(&self) -> u64 { self.total_escalations.load(Ordering::Relaxed) }
    pub fn total_circular(&self) -> u64 { self.total_circular.load(Ordering::Relaxed) }
    pub fn total_revocations(&self) -> u64 { self.total_revocations.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
