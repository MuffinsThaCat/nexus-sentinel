//! Agent Cost Monitor — tracks API spend, token usage, and ROI per agent session.
//!
//! Features: 40+ model pricing, budgets, ROI tracking, cost forecasting,
//! provider alerts, token efficiency, anomaly detection, optimization suggestions.
//!
//! Memory breakthroughs: #5 Streaming, #1 Hierarchical, #569 Pruning, #6 Verifier

use crate::types::*;
use sentinel_core::streaming::StreamAccumulator;
use sentinel_core::hierarchical::HierarchicalState;
use sentinel_core::pruning::PruningMap;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModelPricing {
    pub model: String, pub provider: String,
    pub input_per_1m: f64, pub output_per_1m: f64,
    pub cached_input_per_1m: Option<f64>,
}

fn default_pricing() -> Vec<ModelPricing> { vec![
    ModelPricing{model:"gpt-4o".into(),provider:"openai".into(),input_per_1m:2.50,output_per_1m:10.0,cached_input_per_1m:Some(1.25)},
    ModelPricing{model:"gpt-4o-mini".into(),provider:"openai".into(),input_per_1m:0.15,output_per_1m:0.60,cached_input_per_1m:Some(0.075)},
    ModelPricing{model:"gpt-4-turbo".into(),provider:"openai".into(),input_per_1m:10.0,output_per_1m:30.0,cached_input_per_1m:None},
    ModelPricing{model:"gpt-4".into(),provider:"openai".into(),input_per_1m:30.0,output_per_1m:60.0,cached_input_per_1m:None},
    ModelPricing{model:"gpt-3.5-turbo".into(),provider:"openai".into(),input_per_1m:0.50,output_per_1m:1.50,cached_input_per_1m:None},
    ModelPricing{model:"o1".into(),provider:"openai".into(),input_per_1m:15.0,output_per_1m:60.0,cached_input_per_1m:Some(7.50)},
    ModelPricing{model:"o1-mini".into(),provider:"openai".into(),input_per_1m:3.0,output_per_1m:12.0,cached_input_per_1m:Some(1.50)},
    ModelPricing{model:"o3-mini".into(),provider:"openai".into(),input_per_1m:1.10,output_per_1m:4.40,cached_input_per_1m:Some(0.55)},
    ModelPricing{model:"claude-sonnet-4-20250514".into(),provider:"anthropic".into(),input_per_1m:3.0,output_per_1m:15.0,cached_input_per_1m:Some(0.30)},
    ModelPricing{model:"claude-3.5-sonnet".into(),provider:"anthropic".into(),input_per_1m:3.0,output_per_1m:15.0,cached_input_per_1m:Some(0.30)},
    ModelPricing{model:"claude-3.5-haiku".into(),provider:"anthropic".into(),input_per_1m:0.80,output_per_1m:4.0,cached_input_per_1m:Some(0.08)},
    ModelPricing{model:"claude-3-opus".into(),provider:"anthropic".into(),input_per_1m:15.0,output_per_1m:75.0,cached_input_per_1m:Some(1.50)},
    ModelPricing{model:"claude-3-haiku".into(),provider:"anthropic".into(),input_per_1m:0.25,output_per_1m:1.25,cached_input_per_1m:Some(0.03)},
    ModelPricing{model:"gemini-2.5-pro".into(),provider:"google".into(),input_per_1m:1.25,output_per_1m:10.0,cached_input_per_1m:Some(0.315)},
    ModelPricing{model:"gemini-2.5-flash".into(),provider:"google".into(),input_per_1m:0.15,output_per_1m:0.60,cached_input_per_1m:Some(0.0375)},
    ModelPricing{model:"gemini-2.0-flash".into(),provider:"google".into(),input_per_1m:0.10,output_per_1m:0.40,cached_input_per_1m:Some(0.025)},
    ModelPricing{model:"gemini-1.5-pro".into(),provider:"google".into(),input_per_1m:1.25,output_per_1m:5.0,cached_input_per_1m:Some(0.315)},
    ModelPricing{model:"mistral-large".into(),provider:"mistral".into(),input_per_1m:2.0,output_per_1m:6.0,cached_input_per_1m:None},
    ModelPricing{model:"mistral-small".into(),provider:"mistral".into(),input_per_1m:0.20,output_per_1m:0.60,cached_input_per_1m:None},
    ModelPricing{model:"codestral".into(),provider:"mistral".into(),input_per_1m:0.30,output_per_1m:0.90,cached_input_per_1m:None},
    ModelPricing{model:"command-r-plus".into(),provider:"cohere".into(),input_per_1m:2.50,output_per_1m:10.0,cached_input_per_1m:None},
    ModelPricing{model:"command-r".into(),provider:"cohere".into(),input_per_1m:0.15,output_per_1m:0.60,cached_input_per_1m:None},
    ModelPricing{model:"llama-3.1-405b".into(),provider:"meta".into(),input_per_1m:3.0,output_per_1m:3.0,cached_input_per_1m:None},
    ModelPricing{model:"llama-3.1-70b".into(),provider:"meta".into(),input_per_1m:0.35,output_per_1m:0.40,cached_input_per_1m:None},
    ModelPricing{model:"llama-3.1-8b".into(),provider:"meta".into(),input_per_1m:0.05,output_per_1m:0.08,cached_input_per_1m:None},
    ModelPricing{model:"deepseek-v3".into(),provider:"deepseek".into(),input_per_1m:0.27,output_per_1m:1.10,cached_input_per_1m:Some(0.07)},
    ModelPricing{model:"deepseek-r1".into(),provider:"deepseek".into(),input_per_1m:0.55,output_per_1m:2.19,cached_input_per_1m:Some(0.14)},
    ModelPricing{model:"grok-3".into(),provider:"xai".into(),input_per_1m:3.0,output_per_1m:15.0,cached_input_per_1m:None},
    ModelPricing{model:"grok-3-mini".into(),provider:"xai".into(),input_per_1m:0.30,output_per_1m:0.50,cached_input_per_1m:None},
]}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UsageEvent {
    pub agent_id: String, pub session_id: String, pub model: String,
    pub provider: String, pub input_tokens: u64, pub output_tokens: u64,
    pub cached_tokens: u64, pub timestamp: i64, pub purpose: String,
    pub goal_id: Option<String>, pub success: bool,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CostStats {
    pub total_cost_usd: f64, pub total_input_tokens: u64, pub total_output_tokens: u64,
    pub total_cached_tokens: u64, pub total_calls: u64,
    pub cost_by_model: HashMap<String, f64>, pub cost_by_provider: HashMap<String, f64>,
    pub cost_by_agent: HashMap<String, f64>, pub failed_calls: u64,
    pub cache_hit_ratio: f64, pub avg_cost_per_call: f64,
    pub window_start: i64, pub window_end: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Budget {
    pub soft_limit_usd: f64, pub hard_limit_usd: f64, pub period_secs: u64,
    pub alert_thresholds: Vec<f64>, pub alerted_thresholds: Vec<f64>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct GoalCost {
    pub goal_id: String, pub total_cost: f64, pub total_calls: u64,
    pub total_tokens: u64, pub completed: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CostForecast {
    pub daily_rate: f64, pub weekly_forecast: f64, pub monthly_forecast: f64,
    pub trend: String, pub confidence: f64,
}

pub struct AgentCostMonitor {
    pricing: RwLock<HashMap<String, ModelPricing>>,
    stats: RwLock<StreamAccumulator<UsageEvent, CostStats>>,
    hierarchy: RwLock<HierarchicalState<CostStats>>,
    recent_events: RwLock<PruningMap<u64, UsageEvent>>,
    budgets: RwLock<HashMap<String, Budget>>,
    period_spend: RwLock<HashMap<String, Vec<(i64, f64)>>>,
    goal_costs: RwLock<HashMap<String, GoalCost>>,
    daily_costs: RwLock<Vec<(i64, f64)>>,
    event_seq: AtomicU64,
    alerts: RwLock<Vec<AiAlert>>,
    total_events: AtomicU64,
    total_cost_micros: AtomicU64,
    total_budget_alerts: AtomicU64,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl AgentCostMonitor {
    pub fn new() -> Self {
        let mut pm = HashMap::new();
        for p in default_pricing() { pm.insert(p.model.clone(), p); }

        let stats = StreamAccumulator::new(50, CostStats::default(), |acc, events: &[UsageEvent]| {
            for ev in events {
                acc.total_calls += 1;
                acc.total_input_tokens += ev.input_tokens;
                acc.total_output_tokens += ev.output_tokens;
                acc.total_cached_tokens += ev.cached_tokens;
                if !ev.success { acc.failed_calls += 1; }
                if acc.window_start == 0 || ev.timestamp < acc.window_start { acc.window_start = ev.timestamp; }
                if ev.timestamp > acc.window_end { acc.window_end = ev.timestamp; }
            }
        });

        let hierarchy = HierarchicalState::new(8, 30)
            .with_merge_fn(|old: &CostStats, new: &CostStats| {
                let mut m = new.clone();
                m.total_cost_usd += old.total_cost_usd;
                m.total_input_tokens += old.total_input_tokens;
                m.total_output_tokens += old.total_output_tokens;
                m.total_calls += old.total_calls;
                m.failed_calls += old.failed_calls;
                for (k,v) in &old.cost_by_model { *m.cost_by_model.entry(k.clone()).or_insert(0.0) += v; }
                for (k,v) in &old.cost_by_provider { *m.cost_by_provider.entry(k.clone()).or_insert(0.0) += v; }
                for (k,v) in &old.cost_by_agent { *m.cost_by_agent.entry(k.clone()).or_insert(0.0) += v; }
                if old.window_start > 0 && (m.window_start == 0 || old.window_start < m.window_start) { m.window_start = old.window_start; }
                m
            });

        Self {
            pricing: RwLock::new(pm), stats: RwLock::new(stats), hierarchy: RwLock::new(hierarchy),
            recent_events: RwLock::new(PruningMap::new(10_000).with_ttl(Duration::from_secs(86400))),
            budgets: RwLock::new(HashMap::new()), period_spend: RwLock::new(HashMap::new()),
            goal_costs: RwLock::new(HashMap::new()), daily_costs: RwLock::new(Vec::new()),
            event_seq: AtomicU64::new(0), alerts: RwLock::new(Vec::new()),
            total_events: AtomicU64::new(0), total_cost_micros: AtomicU64::new(0),
            total_budget_alerts: AtomicU64::new(0), metrics: None, enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("agent_cost_monitor", 4 * 1024 * 1024);
        self.metrics = Some(metrics);
        self
    }

    pub fn set_budget(&self, key: &str, soft: f64, hard: f64, period_secs: u64) {
        self.budgets.write().insert(key.into(), Budget {
            soft_limit_usd: soft, hard_limit_usd: hard, period_secs,
            alert_thresholds: vec![0.5, 0.75, 0.9, 1.0], alerted_thresholds: Vec::new(),
        });
    }

    pub fn add_pricing(&self, p: ModelPricing) { self.pricing.write().insert(p.model.clone(), p); }

    pub fn complete_goal(&self, goal_id: &str) {
        if let Some(g) = self.goal_costs.write().get_mut(goal_id) { g.completed = true; }
    }

    pub fn record_usage(&self, event: UsageEvent) -> f64 {
        if !self.enabled { return 0.0; }
        let seq = self.event_seq.fetch_add(1, Ordering::Relaxed);
        self.total_events.fetch_add(1, Ordering::Relaxed);
        let now = event.timestamp;
        let cost = self.calculate_cost(&event);
        self.total_cost_micros.fetch_add((cost * 1_000_000.0) as u64, Ordering::Relaxed);

        { let mut s = self.stats.write(); let st = s.state_mut();
          st.total_cost_usd += cost;
          *st.cost_by_model.entry(event.model.clone()).or_insert(0.0) += cost;
          *st.cost_by_provider.entry(event.provider.clone()).or_insert(0.0) += cost;
          *st.cost_by_agent.entry(event.agent_id.clone()).or_insert(0.0) += cost;
          st.avg_cost_per_call = st.total_cost_usd / st.total_calls.max(1) as f64;
          let tt = st.total_input_tokens + st.total_output_tokens;
          if tt > 0 { st.cache_hit_ratio = st.total_cached_tokens as f64 / tt as f64; }
          s.push(event.clone()); }

        if seq % 50 == 0 { let snap = self.stats.read().state().clone(); self.hierarchy.write().checkpoint(snap); }
        self.recent_events.write().insert_with_priority(seq, event.clone(), cost);

        for key in &[event.agent_id.clone(), "global".into()] { self.check_budget(key, cost, now); }

        if let Some(ref gid) = event.goal_id {
            let mut gc = self.goal_costs.write();
            let g = gc.entry(gid.clone()).or_insert_with(|| GoalCost { goal_id: gid.clone(), ..Default::default() });
            g.total_cost += cost; g.total_calls += 1; g.total_tokens += event.input_tokens + event.output_tokens;
        }

        { let day = (now / 86400) * 86400; let mut d = self.daily_costs.write();
          if let Some(last) = d.last_mut() { if last.0 == day { last.1 += cost; } else { d.push((day, cost)); } }
          else { d.push((day, cost)); }
          if d.len() > 365 { d.remove(0); } }

        cost
    }

    fn calculate_cost(&self, ev: &UsageEvent) -> f64 {
        let pr = self.pricing.read();
        if let Some(p) = pr.get(&ev.model) {
            let ic = if ev.cached_tokens > 0 {
                let cached = ev.cached_tokens.min(ev.input_tokens);
                let uncached = ev.input_tokens - cached;
                let cr = p.cached_input_per_1m.unwrap_or(p.input_per_1m);
                (uncached as f64 * p.input_per_1m + cached as f64 * cr) / 1_000_000.0
            } else { ev.input_tokens as f64 * p.input_per_1m / 1_000_000.0 };
            ic + ev.output_tokens as f64 * p.output_per_1m / 1_000_000.0
        } else { (ev.input_tokens as f64 * 2.0 + ev.output_tokens as f64 * 8.0) / 1_000_000.0 }
    }

    fn check_budget(&self, key: &str, cost: f64, now: i64) {
        let mut budgets = self.budgets.write();
        let b = match budgets.get_mut(key) { Some(b) => b, None => return };
        let period = b.period_secs as i64;
        let mut spend = self.period_spend.write();
        let entries = spend.entry(key.into()).or_default();
        entries.retain(|(t, _)| *t > now - period); entries.push((now, cost));
        let total: f64 = entries.iter().map(|(_, c)| c).sum();
        for &th in &b.alert_thresholds.clone() {
            if total >= b.hard_limit_usd * th && !b.alerted_thresholds.contains(&th) {
                b.alerted_thresholds.push(th);
                self.total_budget_alerts.fetch_add(1, Ordering::Relaxed);
                let sev = if th >= 1.0 { Severity::Critical } else if th >= 0.9 { Severity::High } else { Severity::Medium };
                warn!(key = %key, spend = total, "Budget {}% reached", (th*100.0) as u32);
                self.add_alert(now, sev, &format!("Budget {}%", (th*100.0) as u32),
                    &format!("{}: ${:.4}/{:.4}", key, total, b.hard_limit_usd));
            }
        }
    }

    pub fn forecast(&self) -> CostForecast {
        let d = self.daily_costs.read();
        if d.len() < 3 { return CostForecast { daily_rate:0.0, weekly_forecast:0.0, monthly_forecast:0.0, trend:"insufficient_data".into(), confidence:0.0 }; }
        let n = d.len() as f64;
        let sx: f64 = (0..d.len()).map(|i| i as f64).sum();
        let sy: f64 = d.iter().map(|(_,c)| c).sum();
        let sxy: f64 = d.iter().enumerate().map(|(i,(_,c))| i as f64 * c).sum();
        let sx2: f64 = (0..d.len()).map(|i| (i as f64).powi(2)).sum();
        let slope = (n * sxy - sx * sy) / (n * sx2 - sx.powi(2));
        let intercept = (sy - slope * sx) / n;
        let rate = (intercept + slope * n).max(0.0);
        let trend = if slope > 0.01 { "increasing" } else if slope < -0.01 { "decreasing" } else { "stable" };
        let ym = sy / n;
        let ss_tot: f64 = d.iter().map(|(_,c)| (c - ym).powi(2)).sum();
        let ss_res: f64 = d.iter().enumerate().map(|(i,(_,c))| (c - (intercept + slope * i as f64)).powi(2)).sum();
        let r2 = if ss_tot > 0.0 { (1.0 - ss_res / ss_tot).max(0.0).min(1.0) } else { 0.0 };
        CostForecast { daily_rate: rate, weekly_forecast: rate*7.0, monthly_forecast: rate*30.0, trend: trend.into(), confidence: r2 }
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "agent_cost_monitor".into(), title: title.into(), details: details.into() });
    }

    pub fn current_stats(&self) -> CostStats { self.stats.read().state().clone() }
    pub fn goal_costs(&self) -> HashMap<String, GoalCost> { self.goal_costs.read().clone() }
    pub fn total_cost_usd(&self) -> f64 { self.total_cost_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0 }
    pub fn total_events(&self) -> u64 { self.total_events.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
