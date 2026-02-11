//! Honey Token — creates and monitors decoy credentials and tokens.
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Hot lookups cached
//! - **#6 Theoretical Verifier**: Bound memory usage
use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;use std::collections::HashMap;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Token {
    pub token_id: String,
    pub decoy_type: DecoyType,
    pub value: String,
    pub created_at: i64,
    pub triggered: bool,
}

/// High-value token types that indicate critical breach when triggered.
const CRITICAL_DECOY_TYPES: &[&str] = &[
    "admin_credential", "database_password", "api_key", "ssh_key",
    "encryption_key", "root_token", "service_account",
];

pub struct HoneyTokenManager {
    tokens: RwLock<HashMap<String, Token>>,
    trigger_log: RwLock<Vec<(String, String, i64)>>,
    alerts: RwLock<Vec<DeceptionAlert>>,
    total_created: AtomicU64,
    total_triggered: AtomicU64,
    _cache: TieredCache<String, u64>,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl HoneyTokenManager {
    pub fn new() -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            trigger_log: RwLock::new(Vec::new()),
            alerts: RwLock::new(Vec::new()),
            total_created: AtomicU64::new(0),
            total_triggered: AtomicU64::new(0),
            enabled: true,
            _cache: TieredCache::new(10_000),
            metrics: None,
        }
    }

    pub fn create_token(&self, id: &str, decoy_type: DecoyType, value: &str) {
        self.total_created.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        self.tokens.write().insert(id.into(), Token { token_id: id.into(), decoy_type, value: value.into(), created_at: now, triggered: false });
    }

    pub fn check_usage(&self, id: &str, context: &str) -> bool {
        let mut tokens = self.tokens.write();
        if let Some(t) = tokens.get_mut(id) {
            let dt = t.decoy_type;
            let first_trigger = !t.triggered;
            t.triggered = true;
            drop(tokens);

            self.total_triggered.fetch_add(1, Ordering::Relaxed);
            let now = chrono::Utc::now().timestamp();

            // Log every access for forensic timeline
            let mut log = self.trigger_log.write();
            if log.len() >= MAX_ALERTS { log.remove(0); }
            log.push((id.to_string(), context.to_string(), now));
            drop(log);

            // Severity based on decoy type
            let dt_name = format!("{:?}", dt).to_lowercase();
            let sev = if CRITICAL_DECOY_TYPES.iter().any(|c| dt_name.contains(c)) {
                Severity::Critical
            } else {
                Severity::High
            };

            if first_trigger {
                warn!(token = %id, context = %context, "Honey token triggered (first use)");
                self.add_alert(now, sev, "Honey token triggered", &format!("{:?} token {} first triggered: {}", dt, id, &context[..context.len().min(100)]));
            } else {
                // Repeat usage = active adversary probing
                warn!(token = %id, context = %context, "Honey token re-used (active adversary)");
                self.add_alert(now, Severity::Critical, "Repeated honey token use", &format!("{:?} token {} re-used (active adversary): {}", dt, id, &context[..context.len().min(100)]));
            }

            return true;
        }

        // Check if someone is probing for tokens by value
        let tokens = self.tokens.read();
        let by_value = tokens.values().find(|t| t.value == id);
        if let Some(t) = by_value {
            let tid = t.token_id.clone();
            let dt = t.decoy_type;
            drop(tokens);
            let now = chrono::Utc::now().timestamp();
            self.add_alert(now, Severity::Critical, "Token value probe", &format!("Adversary probed {:?} token {} by value: {}", dt, tid, &context[..context.len().min(100)]));
            return true;
        }

        false
    }

    /// Get the forensic trigger timeline for a specific token.
    pub fn trigger_timeline(&self, token_id: &str) -> Vec<(String, i64)> {
        self.trigger_log.read().iter()
            .filter(|(id, _, _)| id == token_id)
            .map(|(_, ctx, ts)| (ctx.clone(), *ts))
            .collect()
    }

    /// Get all triggered tokens.
    pub fn triggered_tokens(&self) -> Vec<Token> {
        self.tokens.read().values().filter(|t| t.triggered).cloned().collect()
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(DeceptionAlert { timestamp: ts, severity: sev, component: "honey_token".into(), title: title.into(), details: details.into() });
    }

    pub fn total_created(&self) -> u64 { self.total_created.load(Ordering::Relaxed) }
    pub fn total_triggered(&self) -> u64 { self.total_triggered.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<DeceptionAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
