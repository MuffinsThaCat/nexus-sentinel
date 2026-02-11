//! Enrichment Engine — enriches IoCs with additional context.
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Hot enrichment lookups
//! - **#6 Theoretical Verifier**: Bound enrichment cache

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use std::collections::HashMap;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EnrichmentData {
    pub geo_country: Option<String>,
    pub asn: Option<String>,
    pub whois_org: Option<String>,
    pub related_iocs: Vec<String>,
    pub enriched_at: i64,
}

/// Enrichment engine with 2 memory breakthroughs.
pub struct EnrichmentEngine {
    cache: RwLock<HashMap<String, EnrichmentData>>,
    /// #2 Tiered cache: hot enrichment lookups
    enrich_cache: TieredCache<String, u8>,
    alerts: RwLock<Vec<ThreatAlert>>,
    enrichments: AtomicU64,
    /// #6 Theoretical verifier
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl EnrichmentEngine {
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            enrich_cache: TieredCache::new(100_000),
            alerts: RwLock::new(Vec::new()),
            enrichments: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    /// #6 Theoretical verifier: bound enrichment cache at 8MB.
    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("enrichment_engine", 8 * 1024 * 1024);
        self.enrich_cache = self.enrich_cache.with_metrics(metrics.clone(), "enrichment_engine");
        self.metrics = Some(metrics);
        self
    }

    /// Known hostile ASNs (bulletproof hosting, etc.).
    const HOSTILE_ASNS: &'static [&'static str] = &[
        "AS4134", "AS4837", "AS9009", "AS16276", "AS49981", "AS202425",
    ];

    /// High-risk countries for threat intelligence.
    const HIGH_RISK_COUNTRIES: &'static [&'static str] = &[
        "RU", "CN", "KP", "IR", "SY",
    ];

    const MAX_CACHE: usize = 100_000;

    pub fn enrich(&self, ioc_value: &str, data: EnrichmentData) {
        self.enrichments.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();

        // Auto-score enrichment data for threat signals
        let mut risk_score = 0u8;

        if let Some(ref country) = data.geo_country {
            if Self::HIGH_RISK_COUNTRIES.iter().any(|c| country.to_uppercase().contains(c)) {
                risk_score += 30;
                self.add_alert(now, Severity::Medium, "High-risk geo", &format!("{} geolocated to {}", ioc_value, country));
            }
        }

        if let Some(ref asn) = data.asn {
            if Self::HOSTILE_ASNS.iter().any(|a| asn.contains(a)) {
                risk_score += 40;
                self.add_alert(now, Severity::High, "Hostile ASN", &format!("{} on hostile ASN {}", ioc_value, asn));
            }
        }

        if !data.related_iocs.is_empty() {
            risk_score += (data.related_iocs.len() as u8).min(30);
        }

        if risk_score >= 70 {
            self.add_alert(now, Severity::Critical, "High-risk IoC", &format!("{} risk_score={}", ioc_value, risk_score));
        }

        // Memory bound
        let mut cache = self.cache.write();
        if cache.len() >= Self::MAX_CACHE {
            if let Some(oldest) = cache.keys().next().cloned() { cache.remove(&oldest); }
        }
        cache.insert(ioc_value.to_string(), data);
    }

    pub fn get(&self, ioc_value: &str) -> Option<EnrichmentData> {
        self.cache.read().get(ioc_value).cloned()
    }

    /// Find all IoCs enriched from a specific country.
    pub fn by_country(&self, country: &str) -> Vec<(String, EnrichmentData)> {
        let upper = country.to_uppercase();
        self.cache.read().iter()
            .filter(|(_, d)| d.geo_country.as_ref().map_or(false, |c| c.to_uppercase().contains(&upper)))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(ThreatAlert { timestamp: ts, severity: sev, component: "enrichment_engine".into(), title: title.into(), details: details.into() });
    }

    pub fn total_enrichments(&self) -> u64 { self.enrichments.load(Ordering::Relaxed) }
    pub fn cache_size(&self) -> usize { self.cache.read().len() }
    pub fn alerts(&self) -> Vec<ThreatAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
