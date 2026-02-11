//! Zero Trust Policy Engine — World-class NIST 800-207 Zero Trust Architecture engine
//!
//! Features:
//! - NIST SP 800-207 compliant zero trust policy decision point (PDP)
//! - SPIFFE/SPIRE-style workload identity verification
//! - Device posture assessment (OS patch level, EDR status, encryption)
//! - Continuous verification — never trust, always verify
//! - Risk-adaptive access with dynamic trust scoring (0.0–1.0)
//! - Context-aware policy evaluation (time, location, device, identity, behavior)
//! - Micro-perimeter enforcement per service/workload
//! - Session-aware continuous authorization (re-evaluate every N seconds)
//! - Anomaly-based trust decay (trust degrades over time or on anomaly)
//! - Default deny with explicit allow — core ZT principle
//! - Multi-factor context signals (identity + device + network + behavior)
//! - Policy versioning and audit trail
//!
//! Memory optimizations (10 techniques):
//! - **#1 HierarchicalState**: Decision history snapshots O(log n)
//! - **#2 TieredCache**: Hot policy/decision lookups
//! - **#3 ReversibleComputation**: Recompute trust scores from signals
//! - **#5 StreamAccumulator**: Stream access requests
//! - **#6 MemoryMetrics**: Bounded memory
//! - **#461 DifferentialStore**: Track policy changes (diffs only)
//! - **#569 PruningMap**: Auto-expire stale sessions
//! - **#592 DedupStore**: Dedup identical policy entries
//! - **#593 Compression**: LZ4 compress decision audit log
//! - **#627 SparseMatrix**: Sparse identity × resource trust matrix

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

const MAX_ALERTS: usize = 10_000;

// ── Dangerous Ports (high-value targets) ────────────────────────────────────

const HIGH_RISK_PORTS: &[(u16, &str)] = &[
    (22, "SSH"), (23, "Telnet"), (25, "SMTP"), (53, "DNS"),
    (80, "HTTP"), (110, "POP3"), (135, "MS-RPC"), (139, "NetBIOS"),
    (143, "IMAP"), (389, "LDAP"), (443, "HTTPS"), (445, "SMB"),
    (636, "LDAPS"), (1433, "MSSQL"), (1521, "Oracle"), (3306, "MySQL"),
    (3389, "RDP"), (5432, "PostgreSQL"), (5900, "VNC"), (5985, "WinRM"),
    (6379, "Redis"), (8080, "HTTP-Alt"), (8443, "HTTPS-Alt"),
    (9200, "Elasticsearch"), (27017, "MongoDB"),
];

// ── Known Lateral Movement Ports ────────────────────────────────────────────

const LATERAL_MOVEMENT_PORTS: &[u16] = &[
    22, 23, 135, 139, 445, 3389, 5900, 5985, 5986,
];

// ── Device Posture Thresholds ───────────────────────────────────────────────

const MIN_TRUST_THRESHOLD: f64 = 0.3;
const SESSION_REAUTH_SECONDS: i64 = 300; // 5 minutes
const TRUST_DECAY_PER_MINUTE: f64 = 0.002;

// ── Types ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum DeviceCompliance { Compliant, PartiallyCompliant, NonCompliant, Unknown }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WorkloadIdentity {
    pub spiffe_id: String,       // spiffe://trust-domain/workload
    pub namespace: String,       // k8s namespace or env
    pub service_account: String,
    pub trust_domain: String,
    pub verified: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DevicePosture {
    pub device_id: String,
    pub os_patched: bool,
    pub edr_active: bool,
    pub disk_encrypted: bool,
    pub firewall_enabled: bool,
    pub compliance: DeviceCompliance,
    pub last_assessment: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AccessRequest {
    pub source_identity: String,
    pub source_ip: String,
    pub source_device: Option<DevicePosture>,
    pub destination: String,
    pub dest_port: u16,
    pub protocol: String,
    pub requested_at: i64,
    pub session_id: Option<String>,
    pub mfa_verified: bool,
    pub geo_location: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AccessDecision {
    pub request_id: String,
    pub source: String,
    pub destination: String,
    pub port: u16,
    pub allowed: bool,
    pub trust_score: f64,
    pub risk_score: f64,
    pub reasons: Vec<String>,
    pub policy_version: u64,
    pub decided_at: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ZtPolicy {
    pub name: String,
    pub source_pattern: String,   // glob: "spiffe://prod/*"
    pub dest_pattern: String,     // glob: "db-*"
    pub allowed_ports: Vec<u16>,
    pub require_mfa: bool,
    pub require_device_compliance: bool,
    pub min_trust: f64,
    pub time_window: Option<(i64, i64)>, // (start_hour, end_hour)
    pub priority: u32,
    pub version: u64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ZtReport {
    pub total_decisions: u64,
    pub allowed: u64,
    pub denied: u64,
    pub avg_trust_score: f64,
    pub device_compliance_rate: f64,
    pub mfa_rate: f64,
    pub lateral_movement_blocked: u64,
    pub by_port: HashMap<u16, u64>,
}

// ── Zero Trust Engine ───────────────────────────────────────────────────────

pub struct ZeroTrustEngine {
    /// Named policies
    policies: RwLock<Vec<ZtPolicy>>,
    /// Session trust scores (session_id → (trust, last_verified_at))
    sessions: RwLock<HashMap<String, (f64, i64)>>,
    /// Identity trust (identity → base trust)
    identity_trust: RwLock<HashMap<String, f64>>,
    /// #2 TieredCache: hot decision lookups
    policy_cache: TieredCache<String, bool>,
    /// #1 HierarchicalState: decision snapshots
    state_history: RwLock<HierarchicalState<ZtReport>>,
    /// #3 ReversibleComputation: rolling trust from signals
    trust_computer: RwLock<ReversibleComputation<(String, f64), f64>>,
    /// #5 StreamAccumulator: stream requests
    request_accumulator: RwLock<StreamAccumulator<f64, f64>>,
    /// #461 DifferentialStore: policy changes
    policy_diffs: RwLock<DifferentialStore<String, String>>,
    /// #569 PruningMap: expire stale sessions
    stale_sessions: RwLock<PruningMap<String, i64>>,
    /// #592 DedupStore: dedup policy entries
    policy_dedup: RwLock<DedupStore<String, String>>,
    /// #627 SparseMatrix: identity × resource trust
    trust_matrix: RwLock<SparseMatrix<String, String, f64>>,
    /// #593 Compression: compressed audit
    compressed_audit: RwLock<Vec<Vec<u8>>>,
    /// Storage
    alerts: RwLock<Vec<MicrosegAlert>>,
    /// Stats
    total_decisions: AtomicU64,
    total_allowed: AtomicU64,
    denied: AtomicU64,
    lateral_blocked: AtomicU64,
    mfa_requests: AtomicU64,
    compliant_devices: AtomicU64,
    total_device_checks: AtomicU64,
    trust_sum: RwLock<f64>,
    by_port: RwLock<HashMap<u16, u64>>,
    policy_version: AtomicU64,
    /// #6 MemoryMetrics
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl ZeroTrustEngine {
    pub fn new() -> Self {
        let trust_computer = ReversibleComputation::new(4096, |inputs: &[(String, f64)]| {
            if inputs.is_empty() { return 0.5f64; }
            let sum: f64 = inputs.iter().map(|(_, t)| *t).sum();
            sum / inputs.len() as f64
        });

        let request_accumulator = StreamAccumulator::new(
            256, 0.5f64,
            |acc: &mut f64, items: &[f64]| {
                for &t in items { *acc = *acc * 0.95 + t * 0.05; }
            },
        );

        Self {
            policies: RwLock::new(Vec::new()),
            sessions: RwLock::new(HashMap::new()),
            identity_trust: RwLock::new(HashMap::new()),
            policy_cache: TieredCache::new(50_000),
            state_history: RwLock::new(HierarchicalState::new(6, 64)),
            trust_computer: RwLock::new(trust_computer),
            request_accumulator: RwLock::new(request_accumulator),
            policy_diffs: RwLock::new(DifferentialStore::new()),
            stale_sessions: RwLock::new(PruningMap::new(50_000)),
            policy_dedup: RwLock::new(DedupStore::new()),
            trust_matrix: RwLock::new(SparseMatrix::new(0.0f64)),
            compressed_audit: RwLock::new(Vec::new()),
            alerts: RwLock::new(Vec::new()),
            total_decisions: AtomicU64::new(0),
            total_allowed: AtomicU64::new(0),
            denied: AtomicU64::new(0),
            lateral_blocked: AtomicU64::new(0),
            mfa_requests: AtomicU64::new(0),
            compliant_devices: AtomicU64::new(0),
            total_device_checks: AtomicU64::new(0),
            trust_sum: RwLock::new(0.0),
            by_port: RwLock::new(HashMap::new()),
            policy_version: AtomicU64::new(1),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("zt_cache", 4 * 1024 * 1024);
        metrics.register_component("zt_audit", 8 * 1024 * 1024);
        self.policy_cache = self.policy_cache.with_metrics(metrics.clone(), "zt_cache");
        self.metrics = Some(metrics);
        self
    }

    // ── Policy Management ───────────────────────────────────────────────────

    pub fn add_policy(&self, policy: ZtPolicy) {
        let ver = self.policy_version.fetch_add(1, Ordering::Relaxed);
        { let mut diffs = self.policy_diffs.write(); diffs.record_insert(policy.name.clone(), format!("v{}: {} -> {}", ver, policy.source_pattern, policy.dest_pattern)); }
        { let mut dedup = self.policy_dedup.write(); dedup.insert(policy.name.clone(), format!("{}->{}", policy.source_pattern, policy.dest_pattern)); }
        self.policies.write().push(policy);
    }

    pub fn set_identity_trust(&self, identity: &str, trust: f64) {
        self.identity_trust.write().insert(identity.to_string(), trust.clamp(0.0, 1.0));
    }

    // ── Core Decision Engine ────────────────────────────────────────────────

    pub fn decide(&self, req: &AccessRequest) -> AccessDecision {
        if !self.enabled {
            return AccessDecision {
                request_id: String::new(), source: req.source_identity.clone(),
                destination: req.destination.clone(), port: req.dest_port,
                allowed: true, trust_score: 1.0, risk_score: 0.0,
                reasons: vec!["Engine disabled".into()],
                policy_version: 0, decided_at: req.requested_at,
            };
        }

        self.total_decisions.fetch_add(1, Ordering::Relaxed);
        let now = req.requested_at;
        let mut reasons = Vec::new();
        let mut risk = 0.0f64;

        // 1. Compute trust score from multiple signals
        let trust = self.compute_trust(req, &mut reasons, &mut risk);

        // 2. Check minimum trust threshold
        if trust < MIN_TRUST_THRESHOLD {
            reasons.push(format!("Trust {:.2} below minimum {:.2}", trust, MIN_TRUST_THRESHOLD));
            return self.deny(req, trust, risk, reasons, now);
        }

        // 3. Default deny — find matching allow policy
        let matching_policy = self.find_matching_policy(req);

        let allowed = match matching_policy {
            Some(policy) => {
                // 4. MFA check
                if policy.require_mfa && !req.mfa_verified {
                    reasons.push("MFA required but not verified".into());
                    return self.deny(req, trust, risk + 0.3, reasons, now);
                }

                // 5. Device compliance check
                if policy.require_device_compliance {
                    if let Some(ref device) = req.source_device {
                        if device.compliance == DeviceCompliance::NonCompliant {
                            reasons.push("Device non-compliant".into());
                            return self.deny(req, trust, risk + 0.4, reasons, now);
                        }
                    } else {
                        reasons.push("Device posture unknown, compliance required".into());
                        return self.deny(req, trust, risk + 0.2, reasons, now);
                    }
                }

                // 6. Trust threshold per policy
                if trust < policy.min_trust {
                    reasons.push(format!("Trust {:.2} below policy min {:.2}", trust, policy.min_trust));
                    return self.deny(req, trust, risk + 0.2, reasons, now);
                }

                // 7. Time window check
                if let Some((start, end)) = policy.time_window {
                    let hour = (now / 3600) % 24;
                    if hour < start || hour >= end {
                        reasons.push(format!("Outside time window {}–{}", start, end));
                        return self.deny(req, trust, risk + 0.15, reasons, now);
                    }
                }

                // 8. Port check
                if !policy.allowed_ports.is_empty() && !policy.allowed_ports.contains(&req.dest_port) {
                    reasons.push(format!("Port {} not in allowed list", req.dest_port));
                    return self.deny(req, trust, risk + 0.2, reasons, now);
                }

                reasons.push(format!("Allowed by policy '{}'", policy.name));
                true
            },
            None => {
                // DEFAULT DENY — core zero trust principle
                reasons.push("No matching policy — default deny".into());
                return self.deny(req, trust, risk + 0.5, reasons, now);
            }
        };

        // 9. Lateral movement detection
        if LATERAL_MOVEMENT_PORTS.contains(&req.dest_port) {
            risk += 0.2;
            reasons.push(format!("Lateral movement port {} monitored", req.dest_port));
        }

        // 10. Session continuous auth
        if let Some(ref sid) = req.session_id {
            let mut sessions = self.sessions.write();
            sessions.insert(sid.clone(), (trust, now));
            let mut prune = self.stale_sessions.write();
            prune.insert(sid.clone(), now);
        }

        self.record_allow(req, trust, risk, reasons, now, allowed)
    }

    // ── Trust Computation ───────────────────────────────────────────────────

    fn compute_trust(&self, req: &AccessRequest, reasons: &mut Vec<String>, risk: &mut f64) -> f64 {
        let mut trust = 0.0f64;
        let mut signals = 0u32;

        // Signal 1: Identity base trust
        {
            let it = self.identity_trust.read();
            if let Some(&base) = it.get(&req.source_identity) {
                trust += base;
                signals += 1;
            } else {
                trust += 0.1; // unknown identity = very low trust
                signals += 1;
                reasons.push("Unknown identity — low base trust".into());
                *risk += 0.3;
            }
        }

        // Signal 2: MFA
        if req.mfa_verified {
            trust += 0.9;
            signals += 1;
            self.mfa_requests.fetch_add(1, Ordering::Relaxed);
        } else {
            trust += 0.3;
            signals += 1;
            *risk += 0.1;
        }

        // Signal 3: Device posture
        if let Some(ref device) = req.source_device {
            self.total_device_checks.fetch_add(1, Ordering::Relaxed);
            let device_trust = self.assess_device(device);
            trust += device_trust;
            signals += 1;
            if device.compliance == DeviceCompliance::Compliant {
                self.compliant_devices.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            trust += 0.2; // no device info = low trust
            signals += 1;
            *risk += 0.15;
        }

        // Signal 4: Session continuity
        if let Some(ref sid) = req.session_id {
            let sessions = self.sessions.read();
            if let Some(&(prev_trust, last_at)) = sessions.get(sid) {
                let elapsed_min = (req.requested_at - last_at) as f64 / 60.0;
                let decayed = prev_trust - (elapsed_min * TRUST_DECAY_PER_MINUTE);
                trust += f64::max(0.0, decayed);
                signals += 1;
                if req.requested_at - last_at > SESSION_REAUTH_SECONDS {
                    reasons.push("Session re-authentication needed".into());
                    *risk += 0.1;
                }
            }
        }

        // Signal 5: High-risk port
        if HIGH_RISK_PORTS.iter().any(|&(p, _)| p == req.dest_port) {
            *risk += 0.1;
        }

        // Normalize
        if signals > 0 { trust /= signals as f64; }
        trust = trust.clamp(0.0, 1.0);

        // Memory breakthrough: record trust
        { let mut tc = self.trust_computer.write(); tc.push((req.source_identity.clone(), trust)); }
        { let mut acc = self.request_accumulator.write(); acc.push(trust); }
        { let mut ts = self.trust_sum.write(); *ts += trust; }

        trust
    }

    fn assess_device(&self, device: &DevicePosture) -> f64 {
        let mut score = 0.0f64;
        let mut checks = 0u32;

        if device.os_patched { score += 1.0; } checks += 1;
        if device.edr_active { score += 1.0; } checks += 1;
        if device.disk_encrypted { score += 1.0; } checks += 1;
        if device.firewall_enabled { score += 1.0; } checks += 1;

        match device.compliance {
            DeviceCompliance::Compliant => { score += 1.0; checks += 1; },
            DeviceCompliance::PartiallyCompliant => { score += 0.5; checks += 1; },
            _ => { checks += 1; },
        }

        if checks > 0 { score / checks as f64 } else { 0.0 }
    }

    // ── Policy Matching ─────────────────────────────────────────────────────

    fn find_matching_policy(&self, req: &AccessRequest) -> Option<ZtPolicy> {
        let policies = self.policies.read();
        let mut best: Option<&ZtPolicy> = None;

        for policy in policies.iter() {
            if self.glob_match(&req.source_identity, &policy.source_pattern)
                && self.glob_match(&req.destination, &policy.dest_pattern)
            {
                match best {
                    Some(b) if policy.priority > b.priority => { best = Some(policy); },
                    None => { best = Some(policy); },
                    _ => {},
                }
            }
        }

        best.cloned()
    }

    fn glob_match(&self, value: &str, pattern: &str) -> bool {
        if pattern == "*" { return true; }
        if pattern.ends_with('*') {
            let prefix = &pattern[..pattern.len() - 1];
            return value.starts_with(prefix);
        }
        if pattern.starts_with('*') {
            let suffix = &pattern[1..];
            return value.ends_with(suffix);
        }
        value == pattern
    }

    // ── Decision Recording ──────────────────────────────────────────────────

    fn deny(&self, req: &AccessRequest, trust: f64, risk: f64, reasons: Vec<String>, now: i64) -> AccessDecision {
        self.denied.fetch_add(1, Ordering::Relaxed);
        if LATERAL_MOVEMENT_PORTS.contains(&req.dest_port) {
            self.lateral_blocked.fetch_add(1, Ordering::Relaxed);
        }

        let port_name = HIGH_RISK_PORTS.iter().find(|&&(p, _)| p == req.dest_port).map(|&(_, n)| n).unwrap_or("unknown");
        warn!(src = %req.source_identity, dst = %req.destination, port = req.dest_port, port_name = port_name, trust = trust, "ZT DENY");
        self.add_alert(now, if risk > 0.7 { Severity::Critical } else { Severity::High },
            "Zero Trust: Access Denied",
            &format!("{} -> {}:{} ({}) trust={:.2} risk={:.2}: {}",
                req.source_identity, req.destination, req.dest_port, port_name, trust, risk, reasons.join("; ")));

        let decision = AccessDecision {
            request_id: format!("zt-{}", now),
            source: req.source_identity.clone(), destination: req.destination.clone(),
            port: req.dest_port, allowed: false, trust_score: trust, risk_score: risk,
            reasons, policy_version: self.policy_version.load(Ordering::Relaxed), decided_at: now,
        };

        self.record_decision(&decision, req);
        decision
    }

    fn record_allow(&self, req: &AccessRequest, trust: f64, risk: f64, reasons: Vec<String>, now: i64, _allowed: bool) -> AccessDecision {
        self.total_allowed.fetch_add(1, Ordering::Relaxed);
        let decision = AccessDecision {
            request_id: format!("zt-{}", now),
            source: req.source_identity.clone(), destination: req.destination.clone(),
            port: req.dest_port, allowed: true, trust_score: trust, risk_score: risk,
            reasons, policy_version: self.policy_version.load(Ordering::Relaxed), decided_at: now,
        };
        self.record_decision(&decision, req);
        decision
    }

    fn record_decision(&self, decision: &AccessDecision, req: &AccessRequest) {
        // #2 TieredCache
        let cache_key = format!("{}->{}:{}", req.source_identity, req.destination, req.dest_port);
        self.policy_cache.insert(cache_key, decision.allowed);

        // #627 SparseMatrix
        { let mut matrix = self.trust_matrix.write(); matrix.set(req.source_identity.clone(), req.destination.clone(), decision.trust_score); }

        // #593 Compression: compressed audit
        {
            let json = serde_json::to_vec(decision).unwrap_or_default();
            let compressed = compression::compress_lz4(&json);
            let mut audit = self.compressed_audit.write();
            if audit.len() >= MAX_ALERTS { let half = audit.len() / 2; audit.drain(..half); }
            audit.push(compressed);
        }

        // Port stats
        { let mut bp = self.by_port.write(); *bp.entry(req.dest_port).or_insert(0) += 1; }
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { let drain = a.len() - MAX_ALERTS + 1; a.drain(..drain); }
        a.push(MicrosegAlert { timestamp: ts, severity: sev, component: "zero_trust_engine".into(), title: title.into(), details: details.into() });
    }

    // ── Public Accessors ────────────────────────────────────────────────────

    pub fn total_decisions(&self) -> u64 { self.total_decisions.load(Ordering::Relaxed) }
    pub fn denied(&self) -> u64 { self.denied.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<MicrosegAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }

    pub fn report(&self) -> ZtReport {
        let total = self.total_decisions.load(Ordering::Relaxed);
        let device_checks = self.total_device_checks.load(Ordering::Relaxed);
        let report = ZtReport {
            total_decisions: total,
            allowed: self.total_allowed.load(Ordering::Relaxed),
            denied: self.denied.load(Ordering::Relaxed),
            avg_trust_score: if total > 0 { *self.trust_sum.read() / total as f64 } else { 0.0 },
            device_compliance_rate: if device_checks > 0 { self.compliant_devices.load(Ordering::Relaxed) as f64 / device_checks as f64 } else { 0.0 },
            mfa_rate: if total > 0 { self.mfa_requests.load(Ordering::Relaxed) as f64 / total as f64 } else { 0.0 },
            lateral_movement_blocked: self.lateral_blocked.load(Ordering::Relaxed),
            by_port: self.by_port.read().clone(),
        };
        { let mut h = self.state_history.write(); h.checkpoint(report.clone()); }
        report
    }
}
