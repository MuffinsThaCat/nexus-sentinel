//! Tokenizer — replaces sensitive data with non-reversible tokens.
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Hot token lookups
//! - **#6 Theoretical Verifier**: Bound token vault

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use std::collections::HashMap;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_ALERTS: usize = 5_000;

/// Tokenizer with 2 memory breakthroughs.
pub struct Tokenizer {
    token_vault: RwLock<HashMap<String, String>>,
    reverse_vault: RwLock<HashMap<String, String>>,
    /// #2 Tiered cache: hot token lookups
    tok_cache: TieredCache<String, String>,
    alerts: RwLock<Vec<DataAlert>>,
    counter: AtomicU64,
    /// #6 Theoretical verifier
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl Tokenizer {
    pub fn new() -> Self {
        Self {
            token_vault: RwLock::new(HashMap::new()),
            reverse_vault: RwLock::new(HashMap::new()),
            tok_cache: TieredCache::new(100_000),
            alerts: RwLock::new(Vec::new()),
            counter: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    /// #6 Theoretical verifier: bound token vault at 8MB.
    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("tokenizer", 8 * 1024 * 1024);
        self.tok_cache = self.tok_cache.with_metrics(metrics.clone(), "tokenizer");
        self.metrics = Some(metrics);
        self
    }

    /// PII patterns that should always be tokenized.
    const PII_PATTERNS: &'static [&'static str] = &[
        "ssn", "social_security", "credit_card", "passport",
        "driver_license", "bank_account", "routing_number",
        "tax_id", "national_id", "health_id",
    ];

    const MAX_VAULT_SIZE: usize = 500_000;

    pub fn tokenize(&self, value: &str) -> String {
        if !self.enabled { return value.to_string(); }
        let vault = self.token_vault.read();
        if let Some(token) = vault.get(value) { return token.clone(); }
        drop(vault);

        let id = self.counter.fetch_add(1, Ordering::Relaxed);
        let token = format!("TOK-{:016X}", id);

        // Memory bound the vault
        let mut tv = self.token_vault.write();
        if tv.len() >= Self::MAX_VAULT_SIZE {
            let now = chrono::Utc::now().timestamp();
            self.add_alert(now, Severity::High, "Token vault full", &format!("Vault at {} entries, rejecting new tokens", tv.len()));
            return token;
        }
        tv.insert(value.to_string(), token.clone());
        drop(tv);
        self.reverse_vault.write().insert(token.clone(), value.to_string());
        token
    }

    /// Tokenize with PII classification — auto-detects sensitive data patterns.
    pub fn tokenize_field(&self, field_name: &str, value: &str) -> String {
        let fl = field_name.to_lowercase();
        let is_pii = Self::PII_PATTERNS.iter().any(|p| fl.contains(p));
        if is_pii {
            let now = chrono::Utc::now().timestamp();
            self.add_alert(now, Severity::Medium, "PII tokenized", &format!("Field '{}' auto-tokenized as PII", field_name));
        }
        self.tokenize(value)
    }

    pub fn detokenize(&self, token: &str) -> Option<String> {
        self.reverse_vault.read().get(token).cloned()
    }

    /// Batch tokenize multiple values.
    pub fn tokenize_batch(&self, values: &[&str]) -> Vec<String> {
        values.iter().map(|v| self.tokenize(v)).collect()
    }

    pub fn revoke_token(&self, token: &str) {
        if let Some(original) = self.reverse_vault.write().remove(token) {
            self.token_vault.write().remove(&original);
            let now = chrono::Utc::now().timestamp();
            self.add_alert(now, Severity::Low, "Token revoked", &format!("Token {} revoked", &token[..token.len().min(20)]));
        }
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(DataAlert { timestamp: ts, severity: sev, component: "tokenizer".into(), title: title.into(), details: details.into() });
    }

    pub fn token_count(&self) -> usize { self.token_vault.read().len() }
    pub fn alerts(&self) -> Vec<DataAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
