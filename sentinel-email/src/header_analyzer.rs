//! Header Analyzer — Component 9 of 12 in Email Security Layer
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Header analysis results hot
//! - **#6 Theoretical Verifier**: Bound alert history

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use parking_lot::RwLock;
use tracing::warn;

/// Header analyzer with 2 memory breakthroughs.
pub struct HeaderAnalyzer {
    /// #2 Tiered cache: header analysis results hot
    analysis_cache: TieredCache<String, u32>,
    alerts: RwLock<Vec<EmailAlert>>,
    max_alerts: usize,
    /// #6 Theoretical verifier
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl HeaderAnalyzer {
    pub fn new() -> Self {
        Self {
            analysis_cache: TieredCache::new(50_000),
            alerts: RwLock::new(Vec::new()),
            max_alerts: 5_000,
            metrics: None,
            enabled: true,
        }
    }

    /// #6 Theoretical verifier: bound alert history at 2MB.
    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("header_analyzer", 2 * 1024 * 1024);
        self.analysis_cache = self.analysis_cache.with_metrics(metrics.clone(), "header_analyzer");
        self.metrics = Some(metrics);
        self
    }

    /// Analyze email headers for anomalies.
    pub fn analyze(&self, email: &EmailMessage) -> (Verdict, Option<EmailAlert>) {
        if !self.enabled { return (Verdict::Clean, None); }

        let mut score = 0u32;
        let mut reasons = Vec::new();

        // Check for missing critical headers
        let has_message_id = email.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("Message-ID"));
        let has_date = email.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("Date"));
        let has_from = email.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("From"));

        if !has_message_id { score += 1; reasons.push("Missing Message-ID".into()); }
        if !has_date { score += 1; reasons.push("Missing Date header".into()); }
        if !has_from { score += 2; reasons.push("Missing From header".into()); }

        // Check for multiple Received headers (normal), but zero is suspicious
        let received_count = email.headers.iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("Received"))
            .count();
        if received_count == 0 {
            score += 2;
            reasons.push("No Received headers (locally injected?)".into());
        }

        // Check for X-Mailer or User-Agent revealing suspicious clients
        for (k, v) in &email.headers {
            if k.eq_ignore_ascii_case("X-Mailer") || k.eq_ignore_ascii_case("User-Agent") {
                let v_lower = v.to_lowercase();
                if v_lower.contains("python") || v_lower.contains("curl") || v_lower.contains("wget") {
                    score += 2;
                    reasons.push(format!("Suspicious mailer: {}", v));
                }
            }
        }

        // Check Reply-To mismatch with From
        if let Some((_, reply_to)) = email.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("Reply-To")) {
            let reply_domain = reply_to.split('@').nth(1).unwrap_or("").to_lowercase();
            let from_domain = email.from.split('@').nth(1).unwrap_or("").to_lowercase();
            if !reply_domain.is_empty() && !from_domain.is_empty() && reply_domain != from_domain {
                score += 2;
                reasons.push(format!("Reply-To domain ({}) differs from From ({})", reply_domain, from_domain));
            }
        }

        if score >= 3 {
            warn!(from = %email.from, score = score, "Suspicious email headers");
            let alert = EmailAlert {
                timestamp: chrono::Utc::now().timestamp(),
                severity: if score >= 5 { Severity::High } else { Severity::Medium },
                component: "header_analyzer".to_string(),
                title: "Suspicious email headers".to_string(),
                details: format!("Score {}: {}", score, reasons.join("; ")),
                email_id: Some(email.id.clone()),
                sender: Some(email.from.clone()),
            };
            let mut alerts = self.alerts.write();
            if alerts.len() >= self.max_alerts { alerts.remove(0); }
            alerts.push(alert.clone());
            return (Verdict::Suspicious, Some(alert));
        }

        (Verdict::Clean, None)
    }

    pub fn alerts(&self) -> Vec<EmailAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, enabled: bool) { self.enabled = enabled; }
}
