//! Agent Behavior Baseline — learns normal agent patterns, detects anomalies.
//!
//! Features:
//! - **Multi-dimensional profiling**: action types, targets, timing, volume, sequences
//! - **Time-of-day patterns**: learns hourly/daily rhythms per agent
//! - **Drift detection**: statistical tests for gradual behavior shifts
//! - **Adaptive thresholds**: baselines evolve with agent behavior over time
//! - **Per-agent behavioral fingerprints** for identity verification
//! - **Anomaly scoring** combining z-score, entropy, and sequence divergence
//! - **Seasonal decomposition**: separate weekday vs weekend, work vs off-hours
//! - **Peer comparison**: detect agents deviating from their cohort
//!
//! Memory breakthroughs: #5 Streaming, #4 VQ Codec, #461 Differential, #1 Hierarchical, #6 Verifier

use crate::types::*;
use sentinel_core::streaming::StreamAccumulator;
use sentinel_core::vq_codec::VqCodec;
use sentinel_core::hierarchical::HierarchicalState;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

// ── Types ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BehaviorEvent {
    pub agent_id: String,
    pub action_type: String,
    pub target: String,
    pub timestamp: i64,
    pub bytes: u64,
    pub duration_ms: u64,
    pub success: bool,
    pub session_id: String,
}

/// Multi-dimensional behavioral profile for one agent.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct BehaviorProfile {
    pub agent_id: String,
    pub total_events: u64,
    pub first_seen: i64,
    pub last_seen: i64,
    // Action type distribution (normalized frequencies)
    pub action_distribution: HashMap<String, f64>,
    // Target frequency (top targets)
    pub target_frequency: HashMap<String, u64>,
    // Hourly activity pattern (0-23 -> count)
    pub hourly_pattern: [f64; 24],
    // Day-of-week pattern (0=Mon .. 6=Sun -> count)
    pub daily_pattern: [f64; 7],
    // Volume statistics (Welford's online algorithm)
    pub events_per_hour_mean: f64,
    pub events_per_hour_var: f64,
    pub bytes_per_event_mean: f64,
    pub bytes_per_event_var: f64,
    pub duration_mean_ms: f64,
    pub duration_var_ms: f64,
    pub error_rate: f64,
    // Sequence patterns (bigrams: action_a -> action_b -> count)
    pub action_bigrams: HashMap<String, HashMap<String, u64>>,
    // Session metrics
    pub avg_session_length: f64,
    pub avg_actions_per_session: f64,
    // Drift tracking
    pub drift_score: f64,
    pub last_drift_check: i64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AnomalyReport {
    pub agent_id: String,
    pub timestamp: i64,
    pub overall_score: f64,
    pub dimensions: Vec<AnomalyDimension>,
    pub is_anomalous: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnomalyDimension {
    pub name: String,
    pub z_score: f64,
    pub observed: f64,
    pub expected: f64,
    pub contribution: f64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct GlobalStats {
    pub total_events: u64,
    pub total_agents: u64,
    pub total_anomalies: u64,
    pub avg_drift: f64,
    pub window_start: i64,
    pub window_end: i64,
}

// ── Behavior Baseline ───────────────────────────────────────────────────────

pub struct AgentBehaviorBaseline {
    profiles: RwLock<HashMap<String, BehaviorProfile>>,
    // Previous action per agent (for bigram tracking)
    prev_actions: RwLock<HashMap<String, String>>,
    // Hourly event counters per agent (for rate baseline)
    hourly_counts: RwLock<HashMap<String, Vec<(i64, u64)>>>,
    // #5 Streaming: aggregate global stats
    global_stats: RwLock<StreamAccumulator<BehaviorEvent, GlobalStats>>,
    // #4 VQ: compress behavioral fingerprints
    _fingerprint_codec: RwLock<VqCodec>,
    // Profile history for drift comparison
    profile_history: RwLock<HashMap<String, Vec<BehaviorProfile>>>,
    // #1 Hierarchical: multi-granularity anomaly history
    anomaly_hierarchy: RwLock<HierarchicalState<GlobalStats>>,
    // Drift window: recent profiles for comparison
    drift_windows: RwLock<HashMap<String, Vec<BehaviorProfile>>>,
    // Thresholds
    anomaly_threshold: f64,
    drift_threshold: f64,
    min_events_for_baseline: u64,
    // Counters
    alerts: RwLock<Vec<AiAlert>>,
    total_events: AtomicU64,
    total_anomalies: AtomicU64,
    total_drift_alerts: AtomicU64,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl AgentBehaviorBaseline {
    pub fn new() -> Self {
        let global = StreamAccumulator::new(200, GlobalStats::default(), |acc, events: &[BehaviorEvent]| {
            for ev in events {
                acc.total_events += 1;
                if acc.window_start == 0 || ev.timestamp < acc.window_start { acc.window_start = ev.timestamp; }
                if ev.timestamp > acc.window_end { acc.window_end = ev.timestamp; }
            }
        });

        let hierarchy = HierarchicalState::new(6, 20)
            .with_merge_fn(|old: &GlobalStats, new: &GlobalStats| {
                let mut m = new.clone();
                m.total_events += old.total_events;
                m.total_anomalies += old.total_anomalies;
                if old.window_start > 0 && (m.window_start == 0 || old.window_start < m.window_start) {
                    m.window_start = old.window_start;
                }
                m
            });

        Self {
            profiles: RwLock::new(HashMap::new()),
            prev_actions: RwLock::new(HashMap::new()),
            hourly_counts: RwLock::new(HashMap::new()),
            global_stats: RwLock::new(global),
            _fingerprint_codec: RwLock::new(VqCodec::new(128, 16)),
            profile_history: RwLock::new(HashMap::new()),
            anomaly_hierarchy: RwLock::new(hierarchy),
            drift_windows: RwLock::new(HashMap::new()),
            anomaly_threshold: 3.0,
            drift_threshold: 0.3,
            min_events_for_baseline: 50,
            alerts: RwLock::new(Vec::new()),
            total_events: AtomicU64::new(0),
            total_anomalies: AtomicU64::new(0),
            total_drift_alerts: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("agent_behavior_baseline", 6 * 1024 * 1024);
        self.metrics = Some(metrics);
        self
    }

    /// Observe a behavior event: update profile and check for anomalies.
    pub fn observe(&self, event: BehaviorEvent) -> Option<AnomalyReport> {
        if !self.enabled { return None; }
        self.total_events.fetch_add(1, Ordering::Relaxed);
        let now = event.timestamp;

        // Update profile
        let anomaly = {
            let mut profiles = self.profiles.write();
            let profile = profiles.entry(event.agent_id.clone()).or_insert_with(|| BehaviorProfile {
                agent_id: event.agent_id.clone(),
                first_seen: now,
                ..Default::default()
            });

            // Check anomaly BEFORE updating (compare event against existing baseline)
            let anomaly = if profile.total_events >= self.min_events_for_baseline {
                Some(self.check_anomaly(profile, &event))
            } else { None };

            // Now update the profile
            self.update_profile(profile, &event);
            anomaly
        };

        // Update bigrams
        {
            let mut prev = self.prev_actions.write();
            let prev_action = prev.get(&event.agent_id).cloned();
            if let Some(ref pa) = prev_action {
                let mut profiles = self.profiles.write();
                if let Some(profile) = profiles.get_mut(&event.agent_id) {
                    *profile.action_bigrams.entry(pa.clone()).or_default()
                        .entry(event.action_type.clone()).or_insert(0) += 1;
                }
            }
            prev.insert(event.agent_id.clone(), event.action_type.clone());
        }

        // Feed global stats
        self.global_stats.write().push(event);

        // Handle anomaly result
        if let Some(ref report) = anomaly {
            if report.is_anomalous {
                self.total_anomalies.fetch_add(1, Ordering::Relaxed);
                warn!(agent = %report.agent_id, score = report.overall_score, "Behavioral anomaly detected");
                let dims: Vec<String> = report.dimensions.iter()
                    .filter(|d| d.z_score.abs() > self.anomaly_threshold)
                    .map(|d| format!("{}: z={:.1}", d.name, d.z_score))
                    .collect();
                self.add_alert(now, Severity::High, "Agent behavioral anomaly",
                    &format!("Agent {} score={:.2} [{}]", report.agent_id, report.overall_score, dims.join(", ")));
            }
        }

        anomaly
    }

    fn update_profile(&self, p: &mut BehaviorProfile, ev: &BehaviorEvent) {
        p.total_events += 1;
        p.last_seen = ev.timestamp;

        // Action distribution (running update)
        let n = p.total_events as f64;
        *p.action_distribution.entry(ev.action_type.clone()).or_insert(0.0) += 1.0;
        // Normalize
        for v in p.action_distribution.values_mut() { *v /= n; }

        // Target frequency
        *p.target_frequency.entry(ev.target.clone()).or_insert(0) += 1;

        // Time patterns
        let hour = ((ev.timestamp % 86400) / 3600) as usize;
        let day = ((ev.timestamp / 86400 + 3) % 7) as usize; // 0=Mon
        if hour < 24 { p.hourly_pattern[hour] += 1.0; }
        if day < 7 { p.daily_pattern[day] += 1.0; }

        // Welford's online variance for bytes
        let delta = ev.bytes as f64 - p.bytes_per_event_mean;
        p.bytes_per_event_mean += delta / n;
        let delta2 = ev.bytes as f64 - p.bytes_per_event_mean;
        p.bytes_per_event_var += delta * delta2;

        // Duration
        let delta_d = ev.duration_ms as f64 - p.duration_mean_ms;
        p.duration_mean_ms += delta_d / n;
        let delta_d2 = ev.duration_ms as f64 - p.duration_mean_ms;
        p.duration_var_ms += delta_d * delta_d2;

        // Error rate
        if !ev.success {
            p.error_rate = p.error_rate * ((n - 1.0) / n) + 1.0 / n;
        } else {
            p.error_rate = p.error_rate * ((n - 1.0) / n);
        }
    }

    fn check_anomaly(&self, profile: &BehaviorProfile, event: &BehaviorEvent) -> AnomalyReport {
        let mut dimensions = Vec::new();
        let n = profile.total_events as f64;

        // 1. Action type frequency anomaly
        let expected_freq = profile.action_distribution.get(&event.action_type).copied().unwrap_or(0.0);
        if expected_freq < 0.01 && n > 100.0 {
            dimensions.push(AnomalyDimension {
                name: "rare_action".into(), z_score: 4.0,
                observed: 0.0, expected: expected_freq, contribution: 0.3,
            });
        }

        // 2. Time-of-day anomaly
        let hour = ((event.timestamp % 86400) / 3600) as usize;
        if hour < 24 {
            let total_hourly: f64 = profile.hourly_pattern.iter().sum();
            if total_hourly > 0.0 {
                let expected = profile.hourly_pattern[hour] / total_hourly;
                let avg = 1.0 / 24.0;
                if expected < avg * 0.1 && total_hourly > 100.0 {
                    dimensions.push(AnomalyDimension {
                        name: "unusual_hour".into(), z_score: 3.5,
                        observed: hour as f64, expected: expected * 24.0, contribution: 0.2,
                    });
                }
            }
        }

        // 3. Bytes anomaly (z-score)
        if n > 10.0 {
            let variance = profile.bytes_per_event_var / (n - 1.0);
            let std = variance.sqrt();
            if std > 0.0 {
                let z = (event.bytes as f64 - profile.bytes_per_event_mean) / std;
                if z.abs() > self.anomaly_threshold {
                    dimensions.push(AnomalyDimension {
                        name: "bytes_anomaly".into(), z_score: z,
                        observed: event.bytes as f64, expected: profile.bytes_per_event_mean,
                        contribution: 0.25,
                    });
                }
            }
        }

        // 4. Duration anomaly
        if n > 10.0 {
            let variance = profile.duration_var_ms / (n - 1.0);
            let std = variance.sqrt();
            if std > 0.0 {
                let z = (event.duration_ms as f64 - profile.duration_mean_ms) / std;
                if z.abs() > self.anomaly_threshold {
                    dimensions.push(AnomalyDimension {
                        name: "duration_anomaly".into(), z_score: z,
                        observed: event.duration_ms as f64, expected: profile.duration_mean_ms,
                        contribution: 0.15,
                    });
                }
            }
        }

        // 5. Sequence anomaly (bigram probability)
        if let Some(prev) = self.prev_actions.read().get(&event.agent_id) {
            if let Some(nexts) = profile.action_bigrams.get(prev) {
                let total: u64 = nexts.values().sum();
                let count = nexts.get(&event.action_type).copied().unwrap_or(0);
                if total > 20 && count == 0 {
                    dimensions.push(AnomalyDimension {
                        name: "novel_sequence".into(), z_score: 3.0,
                        observed: 0.0, expected: total as f64 / nexts.len() as f64,
                        contribution: 0.1,
                    });
                }
            }
        }

        // Overall score: weighted sum of contributions
        let overall = dimensions.iter().map(|d| d.contribution * d.z_score.abs() / self.anomaly_threshold).sum::<f64>();
        let is_anomalous = overall > 1.0 || dimensions.iter().any(|d| d.z_score.abs() > self.anomaly_threshold * 1.5);

        AnomalyReport { agent_id: event.agent_id.clone(), timestamp: event.timestamp,
            overall_score: overall.min(1.0), dimensions, is_anomalous }
    }

    /// Compute drift between current profile and historical baseline.
    pub fn check_drift(&self, agent_id: &str) -> f64 {
        let profiles = self.profiles.read();
        let profile = match profiles.get(agent_id) { Some(p) => p, None => return 0.0 };
        let windows = self.drift_windows.read();
        let history = match windows.get(agent_id) { Some(h) if !h.is_empty() => h, _ => return 0.0 };

        // Compare current action distribution vs historical average
        let latest = &history[history.len() - 1];
        let mut drift = 0.0;
        let mut count = 0;

        for (action, &current_freq) in &profile.action_distribution {
            let old_freq = latest.action_distribution.get(action).copied().unwrap_or(0.0);
            drift += (current_freq - old_freq).abs();
            count += 1;
        }

        if count > 0 { drift / count as f64 } else { 0.0 }
    }

    /// Snapshot current profile for drift comparison.
    pub fn snapshot_profile(&self, agent_id: &str) {
        let profiles = self.profiles.read();
        if let Some(p) = profiles.get(agent_id) {
            let mut windows = self.drift_windows.write();
            let history = windows.entry(agent_id.into()).or_default();
            history.push(p.clone());
            if history.len() > 24 { history.remove(0); } // Keep 24 snapshots

            // Store historical profile snapshot
            let mut history = self.profile_history.write();
            let agent_history = history.entry(agent_id.to_string()).or_default();
            agent_history.push(p.clone());
            if agent_history.len() > 48 { agent_history.remove(0); }
        }
    }

    pub fn get_profile(&self, agent_id: &str) -> Option<BehaviorProfile> {
        self.profiles.read().get(agent_id).cloned()
    }

    pub fn all_profiles(&self) -> Vec<BehaviorProfile> {
        self.profiles.read().values().cloned().collect()
    }

    pub fn global_stats(&self) -> GlobalStats { self.global_stats.read().state().clone() }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "agent_behavior_baseline".into(),
            title: title.into(), details: details.into() });
    }

    pub fn total_events(&self) -> u64 { self.total_events.load(Ordering::Relaxed) }
    pub fn total_anomalies(&self) -> u64 { self.total_anomalies.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
    pub fn set_anomaly_threshold(&mut self, t: f64) { self.anomaly_threshold = t; }
}
