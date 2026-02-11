//! Identity Federation — Component 7 of 9 in Identity Security Layer
//!
//! Manages federated identity across organizational boundaries.
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Hot federation lookups
//! - **#6 Theoretical Verifier**: Bound federation store

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use std::collections::HashMap;
use parking_lot::RwLock;
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FederatedPartner {
    pub name: String,
    pub domain: String,
    pub trust_level: TrustLevel,
    pub enabled: bool,
    pub metadata_url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum TrustLevel { Untrusted, Basic, Verified, Full }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FederatedIdentity {
    pub local_user_id: String,
    pub partner_name: String,
    pub external_id: String,
    pub linked_at: i64,
}

/// Identity federation with 2 memory breakthroughs.
pub struct IdentityFederation {
    partners: RwLock<Vec<FederatedPartner>>,
    links: RwLock<HashMap<String, Vec<FederatedIdentity>>>,
    /// #2 Tiered cache: hot federation lookups
    fed_cache: TieredCache<String, u8>,
    alerts: RwLock<Vec<IdentityAlert>>,
    /// #6 Theoretical verifier
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl IdentityFederation {
    pub fn new() -> Self {
        Self {
            partners: RwLock::new(Vec::new()),
            links: RwLock::new(HashMap::new()),
            fed_cache: TieredCache::new(50_000),
            alerts: RwLock::new(Vec::new()),
            metrics: None,
            enabled: true,
        }
    }

    /// #6 Theoretical verifier: bound federation store at 4MB.
    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("identity_federation", 4 * 1024 * 1024);
        self.fed_cache = self.fed_cache.with_metrics(metrics.clone(), "identity_federation");
        self.metrics = Some(metrics);
        self
    }

    pub fn add_partner(&self, partner: FederatedPartner) {
        self.partners.write().push(partner);
    }

    pub fn link_identity(&self, local_user_id: &str, partner_name: &str, external_id: &str) -> bool {
        if !self.enabled { return false; }
        let now = chrono::Utc::now().timestamp();
        let partners = self.partners.read();
        let partner = partners.iter().find(|p| p.name == partner_name && p.enabled);
        if partner.is_none() {
            warn!(partner = %partner_name, "Federation link to unknown/disabled partner");
            self.add_alert(now, Severity::High, "Invalid federation link",
                &format!("Attempt to link to unknown partner {}", partner_name), Some(local_user_id));
            return false;
        }

        self.links.write().entry(local_user_id.to_string()).or_default().push(FederatedIdentity {
            local_user_id: local_user_id.to_string(),
            partner_name: partner_name.to_string(),
            external_id: external_id.to_string(),
            linked_at: now,
        });
        true
    }

    pub fn unlink(&self, local_user_id: &str, partner_name: &str) {
        if let Some(links) = self.links.write().get_mut(local_user_id) {
            links.retain(|l| l.partner_name != partner_name);
        }
    }

    pub fn resolve(&self, partner_name: &str, external_id: &str) -> Option<String> {
        let links = self.links.read();
        for (_, user_links) in links.iter() {
            for link in user_links {
                if link.partner_name == partner_name && link.external_id == external_id {
                    return Some(link.local_user_id.clone());
                }
            }
        }
        None
    }

    fn add_alert(&self, ts: i64, severity: Severity, title: &str, details: &str, user: Option<&str>) {
        let mut alerts = self.alerts.write();
        if alerts.len() >= MAX_ALERTS { alerts.remove(0); }
        alerts.push(IdentityAlert {
            timestamp: ts, severity, component: "identity_federation".into(),
            title: title.into(), details: details.into(),
            user_id: user.map(|s| s.to_string()), source_ip: None,
        });
    }

    pub fn partner_count(&self) -> usize { self.partners.read().len() }
    pub fn link_count(&self) -> usize { self.links.read().values().map(|v| v.len()).sum() }
    pub fn alerts(&self) -> Vec<IdentityAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, enabled: bool) { self.enabled = enabled; }
}
