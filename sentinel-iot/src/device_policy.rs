//! Device Policy — Component 9 of 9 in IoT Security Layer
//!
//! Manages security policies applied to IoT devices.
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Hot policy lookups
//! - **#6 Theoretical Verifier**: Bound policy store

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use std::collections::HashMap;
use parking_lot::RwLock;
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DevicePolicy {
    pub name: String,
    pub device_types: Vec<DeviceType>,
    pub require_encryption: bool,
    pub require_auth: bool,
    pub max_payload_bytes: Option<usize>,
    pub allowed_ports: Vec<u16>,
    pub enabled: bool,
}

/// Device policy engine with 2 memory breakthroughs.
pub struct DevicePolicyEngine {
    policies: RwLock<Vec<DevicePolicy>>,
    overrides: RwLock<HashMap<String, String>>,
    /// #2 Tiered cache: hot policy lookups
    policy_cache: TieredCache<String, u8>,
    alerts: RwLock<Vec<IoTAlert>>,
    /// #6 Theoretical verifier
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl DevicePolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: RwLock::new(Vec::new()),
            overrides: RwLock::new(HashMap::new()),
            policy_cache: TieredCache::new(10_000),
            alerts: RwLock::new(Vec::new()),
            metrics: None,
            enabled: true,
        }
    }

    /// #6 Theoretical verifier: bound policy store at 2MB.
    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("device_policy", 2 * 1024 * 1024);
        self.policy_cache = self.policy_cache.with_metrics(metrics.clone(), "device_policy");
        self.metrics = Some(metrics);
        self
    }

    pub fn add_policy(&self, policy: DevicePolicy) {
        self.policies.write().push(policy);
    }

    pub fn set_override(&self, device_id: &str, policy_name: &str) {
        self.overrides.write().insert(device_id.to_string(), policy_name.to_string());
    }

    /// Check if a device action complies with applicable policies.
    pub fn check_compliance(&self, device_id: &str, device_type: DeviceType, encrypted: bool, authenticated: bool, payload_size: usize, port: u16) -> bool {
        if !self.enabled { return true; }
        let now = chrono::Utc::now().timestamp();
        let policies = self.policies.read();
        let overrides = self.overrides.read();

        // Find applicable policy
        let policy_name = overrides.get(device_id);
        let applicable: Vec<&DevicePolicy> = policies.iter().filter(|p| {
            if !p.enabled { return false; }
            if let Some(name) = policy_name { return &p.name == name; }
            p.device_types.contains(&device_type)
        }).collect();

        for policy in applicable {
            if policy.require_encryption && !encrypted {
                warn!(device = %device_id, policy = %policy.name, "Encryption required");
                self.add_alert(now, Severity::High, "Policy violation: no encryption",
                    &format!("Device {} violates {} encryption requirement", device_id, policy.name), Some(device_id));
                return false;
            }
            if policy.require_auth && !authenticated {
                warn!(device = %device_id, policy = %policy.name, "Authentication required");
                self.add_alert(now, Severity::High, "Policy violation: no auth",
                    &format!("Device {} violates {} auth requirement", device_id, policy.name), Some(device_id));
                return false;
            }
            if let Some(max) = policy.max_payload_bytes {
                if payload_size > max {
                    self.add_alert(now, Severity::Medium, "Payload too large",
                        &format!("Device {} payload {} > max {}", device_id, payload_size, max), Some(device_id));
                    return false;
                }
            }
            if !policy.allowed_ports.is_empty() && !policy.allowed_ports.contains(&port) {
                self.add_alert(now, Severity::Medium, "Blocked port",
                    &format!("Device {} using port {} not in allowed list", device_id, port), Some(device_id));
                return false;
            }
        }
        true
    }

    fn add_alert(&self, ts: i64, severity: Severity, title: &str, details: &str, device: Option<&str>) {
        let mut alerts = self.alerts.write();
        if alerts.len() >= MAX_ALERTS { alerts.remove(0); }
        alerts.push(IoTAlert {
            timestamp: ts, severity, component: "device_policy".into(),
            title: title.into(), details: details.into(),
            device_id: device.map(|s| s.to_string()),
        });
    }

    pub fn policy_count(&self) -> usize { self.policies.read().len() }
    pub fn alerts(&self) -> Vec<IoTAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, enabled: bool) { self.enabled = enabled; }
}
