//! Registry Guard — secures container image registries.
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Hot registry lookups
//! - **#6 Theoretical Verifier**: Bound registry store

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use std::collections::HashSet;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ImageVerdict {
    pub allowed: bool,
    pub reason: String,
    pub risk_factors: Vec<String>,
}

/// Registry guard with 2 memory breakthroughs.
pub struct RegistryGuard {
    trusted_registries: RwLock<HashSet<String>>,
    blocked_patterns: RwLock<Vec<String>>,
    registry_cache: TieredCache<String, bool>,
    alerts: RwLock<Vec<ContainerAlert>>,
    total_checked: AtomicU64,
    total_blocked: AtomicU64,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl RegistryGuard {
    pub fn new() -> Self {
        let mut trusted = HashSet::new();
        // Default trusted registries
        let defaults = [
            "docker.io/library/", "ghcr.io/", "gcr.io/", "registry.k8s.io/",
            "quay.io/", "mcr.microsoft.com/", "public.ecr.aws/",
        ];
        for d in &defaults { trusted.insert(d.to_string()); }

        Self {
            trusted_registries: RwLock::new(trusted),
            blocked_patterns: RwLock::new(vec![
                "latest".into(), // mutable tags are risky
            ]),
            registry_cache: TieredCache::new(10_000),
            alerts: RwLock::new(Vec::new()),
            total_checked: AtomicU64::new(0),
            total_blocked: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    /// #6 Theoretical verifier: bound registry store at 2MB.
    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("registry_guard", 2 * 1024 * 1024);
        self.registry_cache = self.registry_cache.with_metrics(metrics.clone(), "registry_guard");
        self.metrics = Some(metrics);
        self
    }

    pub fn add_trusted(&self, registry: &str) { self.trusted_registries.write().insert(registry.to_string()); }

    /// Validate a container image reference.
    pub fn validate_image(&self, image: &str) -> ImageVerdict {
        if !self.enabled {
            return ImageVerdict { allowed: true, reason: "guard disabled".into(), risk_factors: vec![] };
        }
        self.total_checked.fetch_add(1, Ordering::Relaxed);
        let mut risk_factors = Vec::new();
        let lower = image.to_lowercase();

        // Check trusted registry
        let registries = self.trusted_registries.read();
        let from_trusted = registries.iter().any(|r| lower.starts_with(r.as_str()));
        drop(registries);
        if !from_trusted {
            risk_factors.push("untrusted_registry".into());
        }

        // Check for mutable tag `:latest` or no tag at all
        if lower.ends_with(":latest") || !lower.contains(':') {
            risk_factors.push("mutable_tag".into());
        }

        // Check for digest pinning (sha256)
        let has_digest = lower.contains("@sha256:");
        if !has_digest && !risk_factors.is_empty() {
            risk_factors.push("no_digest_pin".into());
        }

        // Check for suspicious image names
        let suspicious_names = ["test", "debug", "dev", "hack", "exploit", "backdoor", "rootkit"];
        for s in &suspicious_names {
            if lower.contains(s) {
                risk_factors.push(format!("suspicious_name:{}", s));
            }
        }

        // Check for IP-based registry (not a domain name)
        let registry_part = lower.split('/').next().unwrap_or("");
        if registry_part.chars().all(|c| c.is_ascii_digit() || c == '.' || c == ':') && registry_part.contains('.') {
            risk_factors.push("ip_based_registry".into());
        }

        // Check blocked patterns
        let blocked = self.blocked_patterns.read();
        for pat in blocked.iter() {
            if lower.contains(pat.as_str()) && !risk_factors.iter().any(|r: &String| r.contains("mutable_tag")) {
                risk_factors.push(format!("blocked_pattern:{}", pat));
            }
        }
        drop(blocked);

        let allowed = risk_factors.is_empty() || (risk_factors.len() == 1 && has_digest);
        if !allowed {
            self.total_blocked.fetch_add(1, Ordering::Relaxed);
            let now = chrono::Utc::now().timestamp();
            let reasons = risk_factors.join(", ");
            warn!(image = %image, risks = %reasons, "Container image blocked");
            self.add_alert(now, Severity::High, "Container image blocked",
                &format!("{}: {}", image, reasons));
        }

        let reason = if allowed { "passed".into() } else { risk_factors.join(", ") };
        ImageVerdict { allowed, reason, risk_factors }
    }

    /// Legacy API.
    pub fn is_trusted(&self, image: &str) -> bool {
        self.validate_image(image).allowed
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(ContainerAlert { timestamp: ts, severity: sev, component: "registry_guard".into(), title: title.into(), details: details.into() });
    }

    pub fn total_blocked(&self) -> u64 { self.total_blocked.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<ContainerAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
