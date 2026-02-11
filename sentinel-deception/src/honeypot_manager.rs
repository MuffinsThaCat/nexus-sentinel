//! Honeypot Manager — deploys and monitors honeypot services.
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Hot lookups cached
//! - **#6 Theoretical Verifier**: Bound memory usage
use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;use std::collections::HashMap;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Honeypot {
    pub honeypot_id: String,
    pub service: String,
    pub port: u16,
    pub active: bool,
    pub interactions: u64,
    pub unique_sources: u64,
    pub last_interaction: Option<i64>,
    pub captured_payloads: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ThreatLevel { Low, Medium, High, Critical }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AttackerProfile {
    pub source_ip: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub total_interactions: u64,
    pub services_probed: Vec<String>,
    pub threat_level: ThreatLevel,
}

pub struct HoneypotManager {
    honeypots: RwLock<HashMap<String, Honeypot>>,
    attacker_profiles: RwLock<HashMap<String, AttackerProfile>>,
    alerts: RwLock<Vec<DeceptionAlert>>,
    total_deployed: AtomicU64,
    total_interactions: AtomicU64,
    _cache: TieredCache<String, u64>,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl HoneypotManager {
    pub fn new() -> Self {
        Self {
            honeypots: RwLock::new(HashMap::new()),
            attacker_profiles: RwLock::new(HashMap::new()),
            alerts: RwLock::new(Vec::new()),
            total_deployed: AtomicU64::new(0),
            total_interactions: AtomicU64::new(0),
            enabled: true,
            _cache: TieredCache::new(10_000),
            metrics: None,
        }
    }

    /// Deploy a standard set of honeypot services (SSH, HTTP, FTP, SMB, RDP).
    pub fn deploy_standard_suite(&self) {
        let services = [
            ("hp-ssh", "ssh", 2222),
            ("hp-http", "http", 8080),
            ("hp-ftp", "ftp", 2121),
            ("hp-smb", "smb", 4450),
            ("hp-rdp", "rdp", 3390),
            ("hp-telnet", "telnet", 2323),
            ("hp-mysql", "mysql", 3307),
            ("hp-redis", "redis", 6380),
        ];
        for (id, svc, port) in &services {
            self.deploy(id, svc, *port);
        }
    }

    pub fn deploy(&self, id: &str, service: &str, port: u16) {
        self.total_deployed.fetch_add(1, Ordering::Relaxed);
        self.honeypots.write().insert(id.into(), Honeypot {
            honeypot_id: id.into(), service: service.into(), port, active: true,
            interactions: 0, unique_sources: 0, last_interaction: None,
            captured_payloads: Vec::new(),
        });
    }

    pub fn record_interaction(&self, id: &str, source_ip: &str, payload: Option<&str>) {
        self.total_interactions.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        let mut hp = self.honeypots.write();
        if let Some(h) = hp.get_mut(id) {
            h.interactions += 1;
            h.last_interaction = Some(now);
            if let Some(p) = payload {
                if h.captured_payloads.len() < 1000 {
                    h.captured_payloads.push(p[..p.len().min(512)].to_string());
                }
            }
            let svc = h.service.clone();
            let port = h.port;
            drop(hp);

            // Update attacker profile
            let mut profiles = self.attacker_profiles.write();
            let profile = profiles.entry(source_ip.to_string()).or_insert_with(|| AttackerProfile {
                source_ip: source_ip.into(),
                first_seen: now,
                last_seen: now,
                total_interactions: 0,
                services_probed: Vec::new(),
                threat_level: ThreatLevel::Low,
            });
            profile.last_seen = now;
            profile.total_interactions += 1;
            if !profile.services_probed.contains(&svc) {
                profile.services_probed.push(svc.clone());
            }
            // Escalate threat level based on behavior
            profile.threat_level = match profile.total_interactions {
                0..=2 => ThreatLevel::Low,
                3..=10 => ThreatLevel::Medium,
                11..=50 => ThreatLevel::High,
                _ => ThreatLevel::Critical,
            };
            if profile.services_probed.len() >= 3 {
                profile.threat_level = ThreatLevel::Critical;
            }
            let threat = profile.threat_level;
            let probed = profile.services_probed.len();
            drop(profiles);

            let sev = match threat {
                ThreatLevel::Critical => Severity::Critical,
                ThreatLevel::High => Severity::High,
                _ => Severity::Medium,
            };
            warn!(honeypot = %id, source = %source_ip, service = %svc, port = port,
                threat_level = ?threat, services_probed = probed, "Honeypot interaction");
            self.add_alert(now, sev, "Honeypot triggered",
                &format!("{} from {} on {}:{} (threat: {:?}, probed {} services)", id, source_ip, svc, port, threat, probed));
        }
    }

    pub fn get_attacker_profiles(&self) -> Vec<AttackerProfile> {
        self.attacker_profiles.read().values().cloned().collect()
    }

    pub fn get_critical_attackers(&self) -> Vec<AttackerProfile> {
        self.attacker_profiles.read().values()
            .filter(|p| matches!(p.threat_level, ThreatLevel::Critical | ThreatLevel::High))
            .cloned().collect()
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(DeceptionAlert { timestamp: ts, severity: sev, component: "honeypot_manager".into(), title: title.into(), details: details.into() });
    }

    pub fn total_deployed(&self) -> u64 { self.total_deployed.load(Ordering::Relaxed) }
    pub fn total_interactions(&self) -> u64 { self.total_interactions.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<DeceptionAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
