//! Cloud Credential Leak Detector — scans for leaked cloud credentials.
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Known credential patterns hot
//! - **#6 Theoretical Verifier**: Bounded

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CredentialLeak {
    pub source: String,
    pub credential_type: String,
    pub partial_key: String,
    pub detected_at: i64,
}

/// Credential leak detector.
pub struct CredentialLeakDetector {
    leaks: RwLock<Vec<CredentialLeak>>,
    leak_cache: TieredCache<String, bool>,
    alerts: RwLock<Vec<CloudAlert>>,
    total_scanned: AtomicU64,
    leaks_found: AtomicU64,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl CredentialLeakDetector {
    pub fn new() -> Self {
        Self {
            leaks: RwLock::new(Vec::new()),
            leak_cache: TieredCache::new(10_000),
            alerts: RwLock::new(Vec::new()),
            total_scanned: AtomicU64::new(0),
            leaks_found: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("credential_leak_detector", 2 * 1024 * 1024);
        self.leak_cache = self.leak_cache.with_metrics(metrics.clone(), "credential_leak_detector");
        self.metrics = Some(metrics);
        self
    }

    pub fn report_leak(&self, source: &str, cred_type: &str, partial: &str) {
        self.leaks_found.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        warn!(source = %source, cred_type = %cred_type, "Cloud credential leak detected");
        self.add_alert(now, Severity::Critical, "Credential leak", &format!("{} key found in {}", cred_type, source));
        let mut l = self.leaks.write();
        if l.len() >= MAX_ALERTS { l.remove(0); }
        l.push(CredentialLeak { source: source.into(), credential_type: cred_type.into(), partial_key: partial.into(), detected_at: now });
    }

    pub fn scan_text(&self, text: &str, source: &str) -> u32 {
        self.total_scanned.fetch_add(1, Ordering::Relaxed);
        let mut found = 0u32;

        // AWS access key IDs (AKIA/ASIA prefix + 16 alphanum)
        let aws_prefixes = ["AKIA", "ASIA", "ABIA", "ACCA"];
        for prefix in &aws_prefixes {
            if let Some(pos) = text.find(prefix) {
                let candidate = &text[pos..text.len().min(pos + 20)];
                if candidate.len() >= 20 && candidate.chars().all(|c| c.is_alphanumeric()) {
                    found += 1;
                    self.report_leak(source, "aws_access_key", &format!("{}...{}", &candidate[..4], &candidate[16..20]));
                }
            }
        }

        // AWS secret key (40-char base64-like after common labels)
        let secret_labels = ["aws_secret_access_key", "AWS_SECRET_ACCESS_KEY", "aws_secret"];
        for label in &secret_labels {
            if text.contains(label) {
                found += 1;
                self.report_leak(source, "aws_secret_key", &format!("{} reference", label));
            }
        }

        // GCP service account JSON
        if text.contains("\"type\": \"service_account\"") || text.contains("\"type\":\"service_account\"") {
            found += 1;
            self.report_leak(source, "gcp_service_account", "service_account JSON");
        }

        // GCP API key
        if text.contains("AIzaSy") {
            found += 1;
            self.report_leak(source, "gcp_api_key", "AIzaSy...");
        }

        // Azure connection strings
        let azure_patterns = [
            "AccountKey=", "SharedAccessKey=", "AZURE_STORAGE_KEY",
            "DefaultEndpointsProtocol=https;AccountName=",
        ];
        for pat in &azure_patterns {
            if text.contains(pat) {
                found += 1;
                self.report_leak(source, "azure_credential", pat);
                break;
            }
        }

        // GitHub tokens
        if text.contains("ghp_") || text.contains("gho_") || text.contains("ghu_")
            || text.contains("ghs_") || text.contains("ghr_")
        {
            found += 1;
            self.report_leak(source, "github_token", "gh*_ prefix");
        }

        // Slack tokens
        if text.contains("xoxb-") || text.contains("xoxp-") || text.contains("xoxs-") {
            found += 1;
            self.report_leak(source, "slack_token", "xox*- prefix");
        }

        // Private keys (PEM)
        let key_markers = ["-----BEGIN RSA PRIVATE", "-----BEGIN PRIVATE KEY",
            "-----BEGIN EC PRIVATE", "-----BEGIN OPENSSH PRIVATE"];
        for marker in &key_markers {
            if text.contains(marker) {
                found += 1;
                self.report_leak(source, "private_key_pem", marker);
                break;
            }
        }

        // Generic high-entropy secret detection
        if Self::has_high_entropy_token(text) {
            found += 1;
            self.report_leak(source, "high_entropy_secret", "base64-like token detected");
        }

        found
    }

    fn has_high_entropy_token(text: &str) -> bool {
        for word in text.split_whitespace() {
            let w = word.trim_matches(|c: char| c == '"' || c == '\'' || c == ',' || c == ';');
            if w.len() >= 32 && w.len() <= 128 {
                let alphanum = w.chars().filter(|c| c.is_alphanumeric() || *c == '+' || *c == '/' || *c == '=').count();
                if alphanum as f64 / w.len() as f64 > 0.9 {
                    // Shannon entropy check
                    let mut freq = [0u32; 256];
                    for b in w.bytes() { freq[b as usize] += 1; }
                    let len = w.len() as f64;
                    let entropy: f64 = freq.iter()
                        .filter(|&&c| c > 0)
                        .map(|&c| { let p = c as f64 / len; -p * p.log2() })
                        .sum();
                    if entropy > 4.0 {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(CloudAlert { timestamp: ts, severity: sev, component: "credential_leak_detector".into(), title: title.into(), details: details.into() });
    }

    pub fn total_scanned(&self) -> u64 { self.total_scanned.load(Ordering::Relaxed) }
    pub fn leaks_found(&self) -> u64 { self.leaks_found.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<CloudAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
