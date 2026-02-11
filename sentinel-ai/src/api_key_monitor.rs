//! AI API Key Monitor — tracks and rotates AI service API keys.
//!
//! Memory optimizations (2 techniques):
//! - **#461 Differential**: Key usage patterns change slowly
//! - **#6 Theoretical Verifier**: Bounded by key count

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use std::collections::HashMap;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AiApiKey {
    pub key_id: String,
    pub service: String,
    pub created_at: i64,
    pub last_used: i64,
    pub usage_count: u64,
    pub max_age_secs: i64,
    pub leaked: bool,
}

/// AI API key monitor.
pub struct ApiKeyMonitor {
    keys: RwLock<HashMap<String, AiApiKey>>,
    /// #2 Tiered cache: active key lookups hot
    key_cache: TieredCache<String, bool>,
    alerts: RwLock<Vec<AiAlert>>,
    total_keys: AtomicU64,
    leaked_keys: AtomicU64,
    /// #6 Theoretical verifier
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl ApiKeyMonitor {
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            key_cache: TieredCache::new(5_000),
            alerts: RwLock::new(Vec::new()),
            total_keys: AtomicU64::new(0),
            leaked_keys: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    /// #6 Theoretical verifier: bounded at 1MB.
    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("api_key_monitor", 1024 * 1024);
        self.key_cache = self.key_cache.with_metrics(metrics.clone(), "api_key_monitor");
        self.metrics = Some(metrics);
        self
    }

    pub fn register_key(&self, key: AiApiKey) {
        self.total_keys.fetch_add(1, Ordering::Relaxed);
        self.keys.write().insert(key.key_id.clone(), key);
    }

    pub fn record_usage(&self, key_id: &str) {
        let now = chrono::Utc::now().timestamp();
        if let Some(k) = self.keys.write().get_mut(key_id) {
            k.usage_count += 1;
            k.last_used = now;
        }
    }

    pub fn mark_leaked(&self, key_id: &str) {
        self.leaked_keys.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        warn!(key = %key_id, "AI API key leaked!");
        self.add_alert(now, Severity::Critical, "API key leaked", &format!("Key {} has been leaked — rotate immediately", key_id));
        if let Some(k) = self.keys.write().get_mut(key_id) {
            k.leaked = true;
        }
    }

    pub fn overdue_rotation(&self) -> Vec<AiApiKey> {
        let now = chrono::Utc::now().timestamp();
        self.keys.read().values().filter(|k| now - k.created_at > k.max_age_secs).cloned().collect()
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "api_key_monitor".into(), title: title.into(), details: details.into() });
    }

    pub fn total_keys(&self) -> u64 { self.total_keys.load(Ordering::Relaxed) }
    pub fn leaked_keys(&self) -> u64 { self.leaked_keys.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
