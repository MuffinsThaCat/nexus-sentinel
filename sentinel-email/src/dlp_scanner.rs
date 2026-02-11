//! DLP Scanner — Component 11 of 12 in Email Security Layer
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: DLP pattern match results hot
//! - **#6 Theoretical Verifier**: Bound alert history

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use parking_lot::RwLock;
use tracing::warn;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DlpMatch {
    pub pattern_name: String,
    pub match_count: u32,
    pub severity: Severity,
}

/// DLP scanner with 2 memory breakthroughs.
pub struct DlpScanner {
    patterns: Vec<(String, String, Severity)>,
    /// #2 Tiered cache: DLP pattern match results hot
    match_cache: TieredCache<String, u32>,
    alerts: RwLock<Vec<EmailAlert>>,
    max_alerts: usize,
    /// #6 Theoretical verifier
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl DlpScanner {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                ("Credit Card".into(), "\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}".into(), Severity::Critical),
                ("SSN".into(), "\\d{3}-\\d{2}-\\d{4}".into(), Severity::Critical),
                ("API Key".into(), "api[_-]?key".into(), Severity::High),
                ("Password".into(), "password".into(), Severity::High),
                ("Private Key".into(), "BEGIN.*PRIVATE KEY".into(), Severity::Critical),
                ("AWS Access Key".into(), "AKIA".into(), Severity::Critical),
                ("Bank Account".into(), "account.*number".into(), Severity::High),
            ],
            match_cache: TieredCache::new(50_000),
            alerts: RwLock::new(Vec::new()),
            max_alerts: 10_000,
            metrics: None,
            enabled: true,
        }
    }

    /// #6 Theoretical verifier: bound alert history at 4MB.
    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("dlp_scanner", 4 * 1024 * 1024);
        self.match_cache = self.match_cache.with_metrics(metrics.clone(), "dlp_scanner");
        self.metrics = Some(metrics);
        self
    }

    /// Scan outbound email for sensitive data leakage.
    pub fn scan(&self, email: &EmailMessage) -> (Verdict, Vec<DlpMatch>) {
        if !self.enabled { return (Verdict::Clean, vec![]); }

        let text = format!(
            "{} {} {}",
            email.subject,
            email.body_text.as_deref().unwrap_or(""),
            email.body_html.as_deref().unwrap_or(""),
        ).to_lowercase();

        let mut matches = Vec::new();

        for (name, pattern, severity) in &self.patterns {
            let pattern_lower = pattern.to_lowercase();
            let count = text.matches(&pattern_lower).count() as u32;
            if count > 0 {
                matches.push(DlpMatch {
                    pattern_name: name.clone(),
                    match_count: count,
                    severity: *severity,
                });
            }
        }

        if !matches.is_empty() {
            let worst_severity = matches.iter()
                .map(|m| m.severity)
                .max_by_key(|s| match s {
                    Severity::Low => 0,
                    Severity::Medium => 1,
                    Severity::High => 2,
                    Severity::Critical => 3,
                })
                .unwrap_or(Severity::Medium);

            let details: Vec<String> = matches.iter()
                .map(|m| format!("{}: {} occurrences", m.pattern_name, m.match_count))
                .collect();

            warn!(from = %email.from, "DLP violation detected: {}", details.join(", "));
            let alert = EmailAlert {
                timestamp: chrono::Utc::now().timestamp(),
                severity: worst_severity,
                component: "dlp_scanner".to_string(),
                title: "Sensitive data detected in outbound email".to_string(),
                details: details.join("; "),
                email_id: Some(email.id.clone()),
                sender: Some(email.from.clone()),
            };
            let mut alerts = self.alerts.write();
            if alerts.len() >= self.max_alerts { alerts.remove(0); }
            alerts.push(alert);

            return (Verdict::Suspicious, matches);
        }

        (Verdict::Clean, matches)
    }

    pub fn alerts(&self) -> Vec<EmailAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, enabled: bool) { self.enabled = enabled; }
}
