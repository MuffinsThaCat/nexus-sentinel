//! DNS Rebinding Protection — Component 9 of 10 in DNS Security Layer
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Domain-to-IP mappings hot
//! - **#6 Theoretical Verifier**: Bound rebind tables

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use parking_lot::RwLock;
use tracing::warn;

/// DNS rebinding protection with 2 memory breakthroughs.
pub struct DnsRebindProtect {
    private_ranges: Vec<(u32, u32)>,
    /// #2 Tiered cache: domain-to-IP mappings hot
    domain_cache: TieredCache<String, String>,
    alerts: RwLock<Vec<DnsAlert>>,
    max_alerts: usize,
    /// #6 Theoretical verifier
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl DnsRebindProtect {
    pub fn new() -> Self {
        Self {
            private_ranges: vec![
                (0x0A000000, 0xFF000000), // 10.0.0.0/8
                (0xAC100000, 0xFFF00000), // 172.16.0.0/12
                (0xC0A80000, 0xFFFF0000), // 192.168.0.0/16
                (0x7F000000, 0xFF000000), // 127.0.0.0/8
                (0x00000000, 0xFF000000), // 0.0.0.0/8
            ],
            domain_cache: TieredCache::new(100_000),
            alerts: RwLock::new(Vec::new()),
            max_alerts: 5_000,
            metrics: None,
            enabled: true,
        }
    }

    /// #6 Theoretical verifier: bound rebind tables at 2MB.
    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("dns_rebind_protect", 2 * 1024 * 1024);
        self.domain_cache = self.domain_cache.with_metrics(metrics.clone(), "dns_rebind_protect");
        self.metrics = Some(metrics);
        self
    }

    /// Check a DNS response for rebinding indicators.
    pub fn check(&self, response: &DnsResponse) -> Option<DnsAlert> {
        if !self.enabled { return None; }
        if response.record_type != RecordType::A { return None; }

        for answer in &response.answers {
            if let Some(ip_u32) = Self::parse_ipv4(answer) {
                if self.is_private(ip_u32) {
                    warn!(domain = %response.domain, ip = %answer, "DNS rebinding detected");
                    let alert = DnsAlert {
                        timestamp: chrono::Utc::now().timestamp(),
                        severity: Severity::Critical,
                        component: "dns_rebind_protect".to_string(),
                        title: "DNS rebinding attack detected".to_string(),
                        details: format!("Domain '{}' resolved to private IP {}", response.domain, answer),
                        domain: Some(response.domain.clone()),
                        source_ip: None,
                    };
                    let mut alerts = self.alerts.write();
                    if alerts.len() >= self.max_alerts { alerts.remove(0); }
                    alerts.push(alert.clone());
                    return Some(alert);
                }
            }
        }
        None
    }

    fn parse_ipv4(s: &str) -> Option<u32> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 4 { return None; }
        let octets: Vec<u8> = parts.iter()
            .filter_map(|p| p.parse().ok())
            .collect();
        if octets.len() != 4 { return None; }
        Some(
            (octets[0] as u32) << 24
            | (octets[1] as u32) << 16
            | (octets[2] as u32) << 8
            | octets[3] as u32
        )
    }

    fn is_private(&self, ip: u32) -> bool {
        self.private_ranges.iter().any(|(net, mask)| (ip & mask) == *net)
    }

    pub fn alerts(&self) -> Vec<DnsAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, enabled: bool) { self.enabled = enabled; }
}
