//! Security Pipeline — Unified defense-in-depth orchestrator for all 52 AI security modules.
//!
//! Chains all AI security modules into a coherent flow:
//!
//! **Pre-Inference** (input validation):
//!   prompt_guard → semantic_firewall → jailbreak_classifier →
//!   system_prompt_guardian → indirect_injection_scanner → multi_turn_tracker →
//!   token_smuggling_detector → context_window_stuffing_guard →
//!   multimodal_injection_scanner → instruction_hierarchy_enforcer →
//!   training_data_extraction_guard → capability_probe_detector
//!
//! **Tool/Agent Layer** (runtime checks):
//!   tool_call_validator → tool_integrity_verifier → mcp_protocol_security →
//!   agent_permission_boundary → agent_network_fence → cross_plugin_data_fence →
//!   delegation_chain_auditor → agent_identity_attestation →
//!   autonomous_agent_containment → reward_hacking_detector
//!
//! **Post-Inference** (output validation):
//!   output_filter → output_watermarker → hallucination_detector →
//!   clipboard_exfil_detector → conversation_state_integrity →
//!   synthetic_content_detector → training_data_extraction_guard (output scan)
//!
//! **Continuous Monitoring** (async/background):
//!   shadow_ai_detector → data_poisoning_detector → model_scanner →
//!   model_extraction_guard → adversarial_input_detector → rag_poisoning_detector →
//!   memory_poisoning_guard → sleeper_agent_detector (behavioral) →
//!   agent_behavior_baseline → agentic_loop_detector → goal_drift_monitor →
//!   multi_agent_conflict → reasoning_trace_auditor → agent_cost_monitor →
//!   agent_session_recorder → agent_action_logger → human_in_the_loop_enforcer →
//!   api_key_monitor → ai_supply_chain_attestation → embedding_space_monitor →
//!   fine_tuning_attack_detector → model_drift_sentinel
//!
//! **Cross-Domain Integration** (when Pro/Enterprise modules available):
//!   Correlates AI alerts with SIEM, identity, cloud, data, exfiltration signals
//!   for multi-vector attack detection.
//!
//! All AI modules are Free tier (Community Shield). The pipeline itself is free.
//! Cross-domain correlation enriches results when higher-tier modules are active.

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::differential::DifferentialStore;
use sentinel_core::pruning::PruningMap;
use sentinel_core::hierarchical::HierarchicalState;
use sentinel_core::sparse::SparseMatrix;
use sentinel_core::dedup::DedupStore;
use sentinel_core::MemoryMetrics;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_ALERTS: usize = 10_000;
const MAX_DECISIONS: usize = 50_000;

// ── Pipeline Types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PipelineAction {
    Allow,
    Flag,
    Block,
    RequireHumanReview,
    Quarantine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PipelinePhase {
    PreInference,
    ToolRuntime,
    PostInference,
    ContinuousMonitoring,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PipelineSignal {
    pub source_module: String,
    pub phase: PipelinePhase,
    pub severity: Severity,
    pub risk_score: f64,
    pub finding: String,
    pub timestamp: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PipelineDecision {
    pub request_id: String,
    pub action: PipelineAction,
    pub composite_risk: f64,
    pub signals: Vec<PipelineSignal>,
    pub phase_risks: HashMap<String, f64>,
    pub decided_at: i64,
    pub blocking_module: Option<String>,
    pub cross_domain_enrichment: Vec<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PipelineStats {
    pub total_requests: u64,
    pub total_allowed: u64,
    pub total_flagged: u64,
    pub total_blocked: u64,
    pub total_human_review: u64,
    pub total_quarantined: u64,
    pub avg_risk_score: f64,
    pub avg_signals_per_request: f64,
    pub top_blocking_modules: Vec<(String, u64)>,
    pub cross_domain_correlations: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CrossDomainSignal {
    pub domain: String,
    pub module: String,
    pub alert_type: String,
    pub severity: Severity,
    pub timestamp: i64,
    pub context: String,
}

// ── Pipeline Configuration ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PipelineConfig {
    pub block_threshold: f64,
    pub flag_threshold: f64,
    pub human_review_threshold: f64,
    pub quarantine_threshold: f64,
    pub enable_cross_domain: bool,
    pub max_signals_per_request: usize,
    pub early_exit_on_block: bool,
    pub correlation_window_secs: i64,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            block_threshold: 0.80,
            flag_threshold: 0.40,
            human_review_threshold: 0.90,
            quarantine_threshold: 0.95,
            enable_cross_domain: true,
            max_signals_per_request: 100,
            early_exit_on_block: true,
            correlation_window_secs: 300,
        }
    }
}

// ── Security Pipeline Engine ────────────────────────────────────────────────

pub struct SecurityPipeline {
    config: RwLock<PipelineConfig>,
    enabled: bool,

    /// Recent decisions (bounded)
    decisions: RwLock<Vec<PipelineDecision>>,
    /// Cross-domain signal buffer (from Pro/Enterprise modules)
    cross_domain_signals: RwLock<Vec<CrossDomainSignal>>,

    /// Per-module block counts for top-blocking-module stats
    module_block_counts: RwLock<HashMap<String, u64>>,

    /// Breakthrough #2: Hot/warm/cold decision cache
    decision_cache: TieredCache<String, PipelineAction>,
    /// Breakthrough #461: Pipeline config baseline evolution
    config_diffs: DifferentialStore<String, String>,
    /// Breakthrough #569: φ-weighted signal pruning
    signal_pruning: RwLock<PruningMap<String, AiAlert>>,
    /// Breakthrough #1: O(log n) composite risk trajectory checkpoints
    risk_checkpoints: RwLock<HierarchicalState<f64>>,
    /// Breakthrough #627: Sparse module×phase risk matrix
    module_phase_matrix: RwLock<SparseMatrix<String, String, f64>>,
    /// Content-addressed dedup for signal fingerprints
    signal_dedup: DedupStore<String, String>,

    alerts: RwLock<Vec<AiAlert>>,
    total_requests: AtomicU64,
    total_allowed: AtomicU64,
    total_flagged: AtomicU64,
    total_blocked: AtomicU64,
    total_human_review: AtomicU64,
    total_quarantined: AtomicU64,
    total_cross_domain: AtomicU64,
    cumulative_risk: RwLock<f64>,
    cumulative_signals: RwLock<u64>,
    metrics: Option<MemoryMetrics>,
}

impl SecurityPipeline {
    pub fn new() -> Self {
        Self {
            config: RwLock::new(PipelineConfig::default()),
            enabled: true,
            decisions: RwLock::new(Vec::new()),
            cross_domain_signals: RwLock::new(Vec::new()),
            module_block_counts: RwLock::new(HashMap::new()),
            decision_cache: TieredCache::new(50_000),
            config_diffs: DifferentialStore::new(),
            signal_pruning: RwLock::new(PruningMap::new(MAX_DECISIONS)),
            risk_checkpoints: RwLock::new(HierarchicalState::new(8, 64)),
            module_phase_matrix: RwLock::new(SparseMatrix::new(0.0)),
            signal_dedup: DedupStore::new(),
            alerts: RwLock::new(Vec::new()),
            total_requests: AtomicU64::new(0),
            total_allowed: AtomicU64::new(0),
            total_flagged: AtomicU64::new(0),
            total_blocked: AtomicU64::new(0),
            total_human_review: AtomicU64::new(0),
            total_quarantined: AtomicU64::new(0),
            total_cross_domain: AtomicU64::new(0),
            cumulative_risk: RwLock::new(0.0),
            cumulative_signals: RwLock::new(0),
            metrics: None,
        }
    }

    pub fn with_config(mut self, config: PipelineConfig) -> Self {
        *self.config.write() = config;
        self
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("security_pipeline_cache", 4 * 1024 * 1024);
        self.decision_cache = self.decision_cache.with_metrics(metrics.clone(), "security_pipeline_cache");
        self.metrics = Some(metrics);
        self
    }

    // ── Core Pipeline Evaluation ────────────────────────────────────────────

    /// Evaluate a set of signals from AI security modules and produce a unified decision.
    ///
    /// Callers collect signals from individual modules (prompt_guard, output_filter, etc.)
    /// and feed them here. The pipeline aggregates, correlates, and decides.
    pub fn evaluate(&self, request_id: &str, signals: Vec<PipelineSignal>) -> PipelineDecision {
        if !self.enabled {
            return PipelineDecision {
                request_id: request_id.into(), action: PipelineAction::Allow,
                composite_risk: 0.0, signals: vec![], phase_risks: HashMap::new(),
                decided_at: 0, blocking_module: None, cross_domain_enrichment: vec![],
            };
        }

        let now = chrono::Utc::now().timestamp();
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        let config = self.config.read().clone();
        let capped_signals: Vec<PipelineSignal> = signals.into_iter()
            .take(config.max_signals_per_request)
            .collect();

        // 1. Compute per-phase risk scores
        let phase_risks = self.compute_phase_risks(&capped_signals);

        // 2. Compute composite risk (weighted by phase importance)
        let composite_risk = self.compute_composite_risk(&phase_risks);

        // 3. Find the highest-severity blocking module
        let blocking_module = capped_signals.iter()
            .filter(|s| s.risk_score >= config.block_threshold)
            .max_by(|a, b| a.risk_score.partial_cmp(&b.risk_score).unwrap_or(std::cmp::Ordering::Equal))
            .map(|s| s.source_module.clone());

        // 4. Cross-domain correlation (enrichment from Pro/Enterprise signals)
        let enrichment = if config.enable_cross_domain {
            self.correlate_cross_domain(request_id, &capped_signals, now, config.correlation_window_secs)
        } else {
            vec![]
        };

        // 5. Boost risk if cross-domain correlation found
        let boosted_risk = if !enrichment.is_empty() {
            self.total_cross_domain.fetch_add(1, Ordering::Relaxed);
            (composite_risk + 0.10 * enrichment.len() as f64).min(1.0)
        } else {
            composite_risk
        };

        // 6. Determine action
        let action = if boosted_risk >= config.quarantine_threshold {
            PipelineAction::Quarantine
        } else if boosted_risk >= config.human_review_threshold {
            PipelineAction::RequireHumanReview
        } else if boosted_risk >= config.block_threshold {
            PipelineAction::Block
        } else if boosted_risk >= config.flag_threshold {
            PipelineAction::Flag
        } else {
            PipelineAction::Allow
        };

        // 7. Update counters
        match action {
            PipelineAction::Allow => { self.total_allowed.fetch_add(1, Ordering::Relaxed); }
            PipelineAction::Flag => { self.total_flagged.fetch_add(1, Ordering::Relaxed); }
            PipelineAction::Block => {
                self.total_blocked.fetch_add(1, Ordering::Relaxed);
                if let Some(ref m) = blocking_module {
                    *self.module_block_counts.write().entry(m.clone()).or_insert(0) += 1;
                }
            }
            PipelineAction::RequireHumanReview => { self.total_human_review.fetch_add(1, Ordering::Relaxed); }
            PipelineAction::Quarantine => { self.total_quarantined.fetch_add(1, Ordering::Relaxed); }
        }

        // 8. Update rolling averages
        { *self.cumulative_risk.write() += boosted_risk; }
        { *self.cumulative_signals.write() += capped_signals.len() as u64; }

        // 9. Cache decision
        self.decision_cache.insert(request_id.to_string(), action);

        // 10. Alert on high-risk decisions
        if action != PipelineAction::Allow && action != PipelineAction::Flag {
            let desc = format!("request={}, action={:?}, risk={:.3}, signals={}, blocking={:?}, cross_domain={}",
                request_id, action, boosted_risk, capped_signals.len(), blocking_module, enrichment.len());
            let sev = match action {
                PipelineAction::Quarantine => Severity::Critical,
                PipelineAction::RequireHumanReview => Severity::Critical,
                PipelineAction::Block => Severity::High,
                _ => Severity::Medium,
            };
            self.add_alert(now, sev, "Pipeline decision", &desc);
        }

        let decision = PipelineDecision {
            request_id: request_id.into(),
            action,
            composite_risk: boosted_risk,
            signals: capped_signals,
            phase_risks,
            decided_at: now,
            blocking_module,
            cross_domain_enrichment: enrichment,
        };

        // Store decision
        let mut d = self.decisions.write();
        if d.len() >= MAX_DECISIONS { let drain = d.len() - MAX_DECISIONS + 1; d.drain(..drain); }
        d.push(decision.clone());

        decision
    }

    // ── Phase Risk Computation ──────────────────────────────────────────────

    fn compute_phase_risks(&self, signals: &[PipelineSignal]) -> HashMap<String, f64> {
        let mut phase_map: HashMap<String, Vec<f64>> = HashMap::new();
        for s in signals {
            let key = format!("{:?}", s.phase);
            phase_map.entry(key).or_default().push(s.risk_score);
        }

        let mut result = HashMap::new();
        for (phase, scores) in &phase_map {
            // Use max-of-means: the phase risk is the max individual signal
            // combined with mean signal (weighted 70/30) to avoid single-signal dominance
            let max = scores.iter().cloned().fold(0.0f64, f64::max);
            let mean = scores.iter().sum::<f64>() / scores.len() as f64;
            let phase_risk = max * 0.70 + mean * 0.30;
            result.insert(phase.clone(), phase_risk);
        }
        result
    }

    fn compute_composite_risk(&self, phase_risks: &HashMap<String, f64>) -> f64 {
        // Phase weights: PreInference is most critical (catches attacks before they run),
        // ToolRuntime second (prevents unauthorized actions), PostInference third
        let weights: &[(&str, f64)] = &[
            ("PreInference", 0.40),
            ("ToolRuntime", 0.30),
            ("PostInference", 0.20),
            ("ContinuousMonitoring", 0.10),
        ];

        let mut weighted_sum = 0.0f64;
        let mut weight_total = 0.0f64;
        let mut max_risk = 0.0f64;

        for (phase, weight) in weights {
            if let Some(&risk) = phase_risks.get(*phase) {
                weighted_sum += risk * weight;
                weight_total += weight;
                max_risk = max_risk.max(risk);
            }
        }

        // Composite = 60% weighted average + 40% max (ensures single critical signal isn't diluted)
        let weighted_avg = if weight_total > 0.0 { weighted_sum / weight_total } else { 0.0 };
        (weighted_avg * 0.60 + max_risk * 0.40).min(1.0)
    }

    // ── Cross-Domain Correlation ────────────────────────────────────────────
    //
    // When Pro/Enterprise domains (SIEM, identity, cloud, data, exfiltration, etc.)
    // feed signals via `ingest_cross_domain_signal`, we correlate them with AI
    // pipeline activity to detect multi-vector attacks.
    //
    // Example correlations:
    //   AI prompt injection + identity/auth anomaly = credential-leveraged attack
    //   AI shadow service + exfiltration/volume spike = data theft via shadow AI
    //   AI model extraction + API/rate anomaly = systematic model stealing
    //   AI sleeper activation + network/lateral movement = coordinated compromise

    pub fn ingest_cross_domain_signal(&self, signal: CrossDomainSignal) {
        let mut sigs = self.cross_domain_signals.write();
        if sigs.len() >= MAX_ALERTS {
            let drain = sigs.len() - MAX_ALERTS + 1;
            sigs.drain(..drain);
        }
        let key = format!("{}:{}:{}", signal.domain, signal.module, signal.timestamp);
        let pruning_alert = AiAlert {
            timestamp: signal.timestamp,
            severity: signal.severity.clone(),
            component: signal.module.clone(),
            title: format!("Cross-domain: {}", signal.alert_type),
            details: signal.context.clone(),
        };
        self.signal_pruning.write().insert(key, pruning_alert);
        sigs.push(signal);
    }

    fn correlate_cross_domain(
        &self, _request_id: &str, ai_signals: &[PipelineSignal],
        now: i64, window_secs: i64,
    ) -> Vec<String> {
        let cross_sigs = self.cross_domain_signals.read();
        if cross_sigs.is_empty() || ai_signals.is_empty() { return vec![]; }

        let recent_cross: Vec<&CrossDomainSignal> = cross_sigs.iter()
            .filter(|s| now - s.timestamp < window_secs)
            .collect();

        if recent_cross.is_empty() { return vec![]; }

        let mut correlations = Vec::new();

        // Collect AI signal categories
        let has_injection = ai_signals.iter().any(|s|
            s.source_module.contains("prompt_guard") || s.source_module.contains("injection")
            || s.source_module.contains("jailbreak") || s.source_module.contains("semantic_firewall")
            || s.source_module.contains("system_prompt_guardian") || s.source_module.contains("multimodal"));
        let has_shadow_ai = ai_signals.iter().any(|s| s.source_module.contains("shadow_ai"));
        let has_extraction = ai_signals.iter().any(|s|
            s.source_module.contains("extraction") || s.source_module.contains("training_data"));
        let has_sleeper = ai_signals.iter().any(|s|
            s.source_module.contains("sleeper") || s.source_module.contains("fine_tuning"));
        let has_exfil = ai_signals.iter().any(|s|
            s.source_module.contains("clipboard_exfil") || s.source_module.contains("exfil"));
        let has_permission = ai_signals.iter().any(|s|
            s.source_module.contains("permission") || s.source_module.contains("fence"));
        let has_model_risk = ai_signals.iter().any(|s|
            s.source_module.contains("model_drift") || s.source_module.contains("embedding")
            || s.source_module.contains("reward_hacking") || s.source_module.contains("synthetic"));
        let has_agent_risk = ai_signals.iter().any(|s|
            s.source_module.contains("containment") || s.source_module.contains("loop_detector")
            || s.source_module.contains("goal_drift") || s.source_module.contains("delegation"));

        for cs in &recent_cross {
            let d = cs.domain.as_str();
            match d {
                "identity" => {
                    if has_injection {
                        correlations.push(format!("CORR:injection+identity_anomaly:{}", cs.alert_type));
                    }
                    if has_permission {
                        correlations.push(format!("CORR:permission_breach+auth_anomaly:{}", cs.alert_type));
                    }
                }
                "exfiltration" => {
                    if has_shadow_ai {
                        correlations.push(format!("CORR:shadow_ai+exfil_spike:{}", cs.alert_type));
                    }
                    if has_exfil {
                        correlations.push(format!("CORR:ai_exfil+data_exfil:{}", cs.alert_type));
                    }
                }
                "api" => {
                    if has_extraction {
                        correlations.push(format!("CORR:model_extraction+api_abuse:{}", cs.alert_type));
                    }
                }
                "network" => {
                    if has_sleeper {
                        correlations.push(format!("CORR:sleeper_activation+lateral_movement:{}", cs.alert_type));
                    }
                }
                "siem" => {
                    if has_injection || has_sleeper {
                        correlations.push(format!("CORR:ai_attack+siem_correlation:{}", cs.alert_type));
                    }
                }
                "cloud" => {
                    if has_shadow_ai {
                        correlations.push(format!("CORR:shadow_ai+cloud_anomaly:{}", cs.alert_type));
                    }
                }
                "data" => {
                    if has_exfil || has_shadow_ai {
                        correlations.push(format!("CORR:ai_data_risk+dlp_alert:{}", cs.alert_type));
                    }
                    if has_extraction {
                        correlations.push(format!("CORR:training_data_extraction+dlp_alert:{}", cs.alert_type));
                    }
                }
                "model" | "ml" => {
                    if has_model_risk {
                        correlations.push(format!("CORR:model_integrity_risk+{}:{}", d, cs.alert_type));
                    }
                    if has_sleeper {
                        correlations.push(format!("CORR:fine_tuning_attack+model_anomaly:{}", cs.alert_type));
                    }
                }
                "agent" | "orchestration" => {
                    if has_agent_risk {
                        correlations.push(format!("CORR:agent_anomaly+orchestration_alert:{}", cs.alert_type));
                    }
                    if has_permission {
                        correlations.push(format!("CORR:agent_permission+orchestration_alert:{}", cs.alert_type));
                    }
                }
                _ => {
                    // Generic high-severity cross-domain correlation
                    if cs.severity >= Severity::High && ai_signals.iter().any(|s| s.risk_score >= 0.70) {
                        correlations.push(format!("CORR:high_risk_ai+{}:{}", d, cs.alert_type));
                    }
                    if has_model_risk && cs.severity >= Severity::Medium {
                        correlations.push(format!("CORR:model_risk+{}:{}", d, cs.alert_type));
                    }
                }
            }
        }

        correlations.sort();
        correlations.dedup();
        correlations
    }

    // ── Convenience: Build Signals from Module Results ──────────────────────

    /// Create a signal from any module's detection result.
    pub fn signal(module: &str, phase: PipelinePhase, severity: Severity, risk: f64, finding: &str) -> PipelineSignal {
        PipelineSignal {
            source_module: module.into(),
            phase,
            severity,
            risk_score: risk.min(1.0),
            finding: finding.into(),
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    // ── Stats & Reporting ───────────────────────────────────────────────────

    pub fn stats(&self) -> PipelineStats {
        let total = self.total_requests.load(Ordering::Relaxed);
        let cumulative_risk = *self.cumulative_risk.read();
        let cumulative_signals = *self.cumulative_signals.read();

        let mut top_modules: Vec<(String, u64)> = self.module_block_counts.read()
            .iter().map(|(k, v)| (k.clone(), *v)).collect();
        top_modules.sort_by(|a, b| b.1.cmp(&a.1));
        top_modules.truncate(10);

        PipelineStats {
            total_requests: total,
            total_allowed: self.total_allowed.load(Ordering::Relaxed),
            total_flagged: self.total_flagged.load(Ordering::Relaxed),
            total_blocked: self.total_blocked.load(Ordering::Relaxed),
            total_human_review: self.total_human_review.load(Ordering::Relaxed),
            total_quarantined: self.total_quarantined.load(Ordering::Relaxed),
            avg_risk_score: if total > 0 { cumulative_risk / total as f64 } else { 0.0 },
            avg_signals_per_request: if total > 0 { cumulative_signals as f64 / total as f64 } else { 0.0 },
            top_blocking_modules: top_modules,
            cross_domain_correlations: self.total_cross_domain.load(Ordering::Relaxed),
        }
    }

    /// Get the last N decisions.
    pub fn recent_decisions(&self, n: usize) -> Vec<PipelineDecision> {
        let d = self.decisions.read();
        d.iter().rev().take(n).cloned().collect()
    }

    /// Lookup a cached decision for a request.
    pub fn cached_decision(&self, request_id: &str) -> Option<PipelineAction> {
        self.decision_cache.get(&request_id.to_string())
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { let drain = a.len() - MAX_ALERTS + 1; a.drain(..drain); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "security_pipeline".into(), title: title.into(), details: details.into() });
    }

    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
    pub fn update_config(&self, config: PipelineConfig) { *self.config.write() = config; }
}
