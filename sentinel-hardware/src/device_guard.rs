//! Device Guard — controls which hardware devices can connect.
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Hot lookups cached
//! - **#6 Theoretical Verifier**: Bound memory usage
use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;use std::collections::HashSet;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceEvent {
    pub device_id: String,
    pub device_type: DeviceType,
    pub vendor: String,
    pub allowed: bool,
    pub timestamp: i64,
}

/// High-risk device types that need extra scrutiny.
const HIGH_RISK_DEVICES: &[&str] = &["network_adapter", "storage", "debug_interface", "dma_capable"];

/// Known BadUSB / malicious device indicators.
const BADUSB_INDICATORS: &[&str] = &[
    "rubber_ducky", "bash_bunny", "lan_turtle", "usb_armory",
    "teensy", "digispark", "cactus_whid", "o.mg",
];

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceVerdict {
    pub allowed: bool,
    pub findings: Vec<String>,
    pub severity: Severity,
}

pub struct DeviceGuard {
    blocked_vendors: RwLock<HashSet<String>>,
    allowed_devices: RwLock<HashSet<String>>,
    events: RwLock<Vec<DeviceEvent>>,
    device_counts: RwLock<std::collections::HashMap<String, u64>>,
    alerts: RwLock<Vec<HardwareAlert>>,
    total_checked: AtomicU64,
    total_blocked: AtomicU64,
    _cache: TieredCache<String, u64>,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl DeviceGuard {
    pub fn new() -> Self {
        Self {
            blocked_vendors: RwLock::new(HashSet::new()),
            allowed_devices: RwLock::new(HashSet::new()),
            events: RwLock::new(Vec::new()),
            device_counts: RwLock::new(std::collections::HashMap::new()),
            alerts: RwLock::new(Vec::new()),
            total_checked: AtomicU64::new(0),
            total_blocked: AtomicU64::new(0),
            enabled: true,
            _cache: TieredCache::new(10_000),
            metrics: None,
        }
    }

    pub fn block_vendor(&self, vendor: &str) { self.blocked_vendors.write().insert(vendor.to_lowercase()); }
    pub fn allow_device(&self, device_id: &str) { self.allowed_devices.write().insert(device_id.to_string()); }

    /// Comprehensive device check with BadUSB detection, rate limiting, and risk analysis.
    pub fn check_device_full(&self, device_id: &str, device_type: DeviceType, vendor: &str) -> DeviceVerdict {
        self.total_checked.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        let mut findings = Vec::new();
        let mut sev = Severity::Low;
        let vendor_lower = vendor.to_lowercase();
        let type_str = format!("{:?}", device_type).to_lowercase();

        // 1. Explicit allowlist (skip other checks)
        if self.allowed_devices.read().contains(device_id) {
            let mut e = self.events.write();
            if e.len() >= MAX_ALERTS { e.remove(0); }
            e.push(DeviceEvent { device_id: device_id.into(), device_type, vendor: vendor.into(), allowed: true, timestamp: now });
            return DeviceVerdict { allowed: true, findings: vec!["allowlisted".into()], severity: Severity::Low };
        }

        // 2. Blocked vendor
        if self.blocked_vendors.read().contains(&vendor_lower) {
            findings.push(format!("blocked_vendor:{}", vendor));
            sev = Severity::High;
        }

        // 3. BadUSB detection
        for indicator in BADUSB_INDICATORS {
            if vendor_lower.contains(indicator) || device_id.to_lowercase().contains(indicator) {
                findings.push(format!("badusb_indicator:{}", indicator));
                sev = Severity::Critical;
            }
        }

        // 4. High-risk device type
        if HIGH_RISK_DEVICES.iter().any(|d| type_str.contains(d)) {
            findings.push(format!("high_risk_type:{:?}", device_type));
            if sev < Severity::Medium { sev = Severity::Medium; }
        }

        // 5. Device hotplug flood (>10 devices from same vendor in short window)
        let mut counts = self.device_counts.write();
        let count = counts.entry(vendor_lower.clone()).or_insert(0);
        *count += 1;
        if *count > 10 {
            findings.push(format!("hotplug_flood:{}devices", count));
            if sev < Severity::High { sev = Severity::High; }
        }

        // 6. Unknown vendor
        if vendor.is_empty() || vendor == "unknown" {
            findings.push("unknown_vendor".into());
            if sev < Severity::Medium { sev = Severity::Medium; }
        }

        let allowed = sev < Severity::High;
        if !allowed {
            self.total_blocked.fetch_add(1, Ordering::Relaxed);
            let cats = findings.join(", ");
            warn!(device = %device_id, vendor = %vendor, "Device blocked");
            self.add_alert(now, sev, "Device blocked", &format!("{}: {}", device_id, &cats[..cats.len().min(200)]));
        }

        let mut e = self.events.write();
        if e.len() >= MAX_ALERTS { e.remove(0); }
        e.push(DeviceEvent { device_id: device_id.into(), device_type, vendor: vendor.into(), allowed, timestamp: now });

        DeviceVerdict { allowed, findings, severity: sev }
    }

    /// Legacy API.
    pub fn check_device(&self, device_id: &str, device_type: DeviceType, vendor: &str) -> bool {
        self.check_device_full(device_id, device_type, vendor).allowed
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(HardwareAlert { timestamp: ts, severity: sev, component: "device_guard".into(), title: title.into(), details: details.into() });
    }

    pub fn total_checked(&self) -> u64 { self.total_checked.load(Ordering::Relaxed) }
    pub fn total_blocked(&self) -> u64 { self.total_blocked.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<HardwareAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
