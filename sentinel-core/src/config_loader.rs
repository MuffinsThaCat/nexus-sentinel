//! # Config Loader — Loads and validates TOML configuration
//!
//! Reads `sentinel.toml` (or a custom path) and deserializes into typed config structs.
//! Each security layer gets its own config section with enable/disable flags.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::{info, warn};

/// Top-level sentinel configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelConfig {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub core: crate::config::CoreConfig,
    #[serde(default)]
    pub io: IoConfig,
    #[serde(default)]
    pub network: LayerConfig,
    #[serde(default)]
    pub endpoint: LayerConfig,
    #[serde(default)]
    pub dns: LayerConfig,
    #[serde(default)]
    pub email: LayerConfig,
    #[serde(default)]
    pub identity: LayerConfig,
    #[serde(default)]
    pub iot: LayerConfig,
    #[serde(default)]
    pub data: LayerConfig,
    #[serde(default)]
    pub threat_intel: LayerConfig,
    #[serde(default)]
    pub forensics: LayerConfig,
    #[serde(default)]
    pub vuln: LayerConfig,
    #[serde(default)]
    pub web: LayerConfig,
    #[serde(default)]
    pub container: LayerConfig,
    #[serde(default)]
    pub supply_chain: LayerConfig,
    #[serde(default)]
    pub compliance: LayerConfig,
    #[serde(default)]
    pub privacy: LayerConfig,
    #[serde(default)]
    pub ai: LayerConfig,
    #[serde(default)]
    pub deception: LayerConfig,
    #[serde(default)]
    pub browser: LayerConfig,
    #[serde(default)]
    pub api: LayerConfig,
    #[serde(default)]
    pub vpn: LayerConfig,
    #[serde(default)]
    pub hardware: LayerConfig,
    #[serde(default)]
    pub exfiltration: LayerConfig,
    #[serde(default)]
    pub mgmt: LayerConfig,
    #[serde(default)]
    pub selfprotect: LayerConfig,
    #[serde(default)]
    pub phishing: LayerConfig,
    #[serde(default)]
    pub crypto: LayerConfig,
    #[serde(default)]
    pub resilience: LayerConfig,
    #[serde(default)]
    pub mobile: LayerConfig,
    #[serde(default)]
    pub darkweb: LayerConfig,
    #[serde(default)]
    pub ot: LayerConfig,
    #[serde(default)]
    pub microseg: LayerConfig,
    #[serde(default)]
    pub backup: LayerConfig,
    #[serde(default)]
    pub cloud: LayerConfig,
    #[serde(default)]
    pub time: LayerConfig,
    #[serde(default)]
    pub soceng: LayerConfig,
    #[serde(default)]
    pub regulatory: LayerConfig,
    #[serde(default)]
    pub ops: LayerConfig,
    #[serde(default)]
    pub pipelines: Vec<PipelineConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    pub memory_budget_mb: usize,
    pub log_level: String,
    pub snapshot_dir: String,
    pub snapshot_interval_secs: u64,
    pub event_bus_enabled: bool,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            memory_budget_mb: 512,
            log_level: "info".into(),
            snapshot_dir: "/var/lib/nexus-sentinel/snapshots".into(),
            snapshot_interval_secs: 300,
            event_bus_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoConfig {
    pub capture_interface: String,
    pub watch_paths: Vec<String>,
    pub webhook_enabled: bool,
    pub webhook_bind: String,
    pub syslog_enabled: bool,
    pub syslog_bind: String,
}

impl Default for IoConfig {
    fn default() -> Self {
        Self {
            capture_interface: String::new(),
            watch_paths: vec!["/etc".into()],
            webhook_enabled: false,
            webhook_bind: "127.0.0.1:9090".into(),
            syslog_enabled: false,
            syslog_bind: "127.0.0.1:1514".into(),
        }
    }
}

/// Generic per-layer config — each layer has at minimum an `enabled` flag
/// plus arbitrary key-value settings that the layer can interpret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// All other settings as a flat map (layer-specific)
    #[serde(flatten)]
    pub settings: HashMap<String, toml::Value>,
}

impl Default for LayerConfig {
    fn default() -> Self {
        Self { enabled: true, settings: HashMap::new() }
    }
}

fn default_true() -> bool { true }

/// Pipeline configuration from TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineConfig {
    pub name: String,
    pub description: String,
    pub trigger_category: String,
    pub trigger_severity_min: String,
    pub trigger_tags: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl SentinelConfig {
    /// Load config from a TOML file path.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        if !path.exists() {
            warn!(path = %path.display(), "Config file not found, using defaults");
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config: {}", e))?;
        let config: SentinelConfig = toml::from_str(&content)
            .map_err(|e| format!("Failed to parse config: {}", e))?;
        info!(
            path = %path.display(),
            budget_mb = config.general.memory_budget_mb,
            layers_enabled = config.enabled_layer_count(),
            pipelines = config.pipelines.len(),
            "Configuration loaded"
        );
        Ok(config)
    }

    /// Save current config to a TOML file.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), String> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize config: {}", e))?;
        std::fs::write(path, content)
            .map_err(|e| format!("Failed to write config: {}", e))?;
        Ok(())
    }

    /// Count how many security layers are enabled.
    pub fn enabled_layer_count(&self) -> usize {
        let layers = [
            self.network.enabled, self.endpoint.enabled, self.dns.enabled,
            self.email.enabled, self.identity.enabled, self.iot.enabled,
            self.data.enabled, self.threat_intel.enabled, self.forensics.enabled,
            self.vuln.enabled, self.web.enabled, self.container.enabled,
            self.supply_chain.enabled, self.compliance.enabled, self.privacy.enabled,
            self.ai.enabled, self.deception.enabled, self.browser.enabled,
            self.api.enabled, self.vpn.enabled, self.hardware.enabled,
            self.exfiltration.enabled, self.mgmt.enabled, self.selfprotect.enabled,
            self.phishing.enabled, self.crypto.enabled, self.resilience.enabled,
            self.mobile.enabled, self.darkweb.enabled, self.ot.enabled,
            self.microseg.enabled, self.backup.enabled, self.cloud.enabled,
            self.time.enabled, self.soceng.enabled, self.regulatory.enabled,
            self.ops.enabled,
        ];
        layers.iter().filter(|&&e| e).count()
    }

    /// Get a layer config by name.
    pub fn layer(&self, name: &str) -> Option<&LayerConfig> {
        match name {
            "network" => Some(&self.network),
            "endpoint" => Some(&self.endpoint),
            "dns" => Some(&self.dns),
            "email" => Some(&self.email),
            "identity" => Some(&self.identity),
            "iot" => Some(&self.iot),
            "data" => Some(&self.data),
            "threat_intel" => Some(&self.threat_intel),
            "forensics" => Some(&self.forensics),
            "vuln" => Some(&self.vuln),
            "web" => Some(&self.web),
            "container" => Some(&self.container),
            "supply_chain" => Some(&self.supply_chain),
            "compliance" => Some(&self.compliance),
            "privacy" => Some(&self.privacy),
            "ai" => Some(&self.ai),
            "deception" => Some(&self.deception),
            "browser" => Some(&self.browser),
            "api" => Some(&self.api),
            "vpn" => Some(&self.vpn),
            "hardware" => Some(&self.hardware),
            "exfiltration" => Some(&self.exfiltration),
            "mgmt" => Some(&self.mgmt),
            "selfprotect" => Some(&self.selfprotect),
            "phishing" => Some(&self.phishing),
            "crypto" => Some(&self.crypto),
            "resilience" => Some(&self.resilience),
            "mobile" => Some(&self.mobile),
            "darkweb" => Some(&self.darkweb),
            "ot" => Some(&self.ot),
            "microseg" => Some(&self.microseg),
            "backup" => Some(&self.backup),
            "cloud" => Some(&self.cloud),
            "time" => Some(&self.time),
            "soceng" => Some(&self.soceng),
            "regulatory" => Some(&self.regulatory),
            "ops" => Some(&self.ops),
            _ => None,
        }
    }

    /// Check if a specific layer setting is truthy.
    pub fn layer_setting_bool(&self, layer: &str, key: &str) -> bool {
        self.layer(layer)
            .and_then(|l| l.settings.get(key))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }
}

impl Default for SentinelConfig {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            core: crate::config::CoreConfig::default(),
            io: IoConfig::default(),
            network: LayerConfig::default(),
            endpoint: LayerConfig::default(),
            dns: LayerConfig::default(),
            email: LayerConfig::default(),
            identity: LayerConfig::default(),
            iot: LayerConfig::default(),
            data: LayerConfig::default(),
            threat_intel: LayerConfig::default(),
            forensics: LayerConfig::default(),
            vuln: LayerConfig::default(),
            web: LayerConfig::default(),
            container: LayerConfig::default(),
            supply_chain: LayerConfig::default(),
            compliance: LayerConfig::default(),
            privacy: LayerConfig::default(),
            ai: LayerConfig::default(),
            deception: LayerConfig::default(),
            browser: LayerConfig::default(),
            api: LayerConfig::default(),
            vpn: LayerConfig::default(),
            hardware: LayerConfig::default(),
            exfiltration: LayerConfig::default(),
            mgmt: LayerConfig::default(),
            selfprotect: LayerConfig::default(),
            phishing: LayerConfig::default(),
            crypto: LayerConfig::default(),
            resilience: LayerConfig::default(),
            mobile: LayerConfig::default(),
            darkweb: LayerConfig::default(),
            ot: LayerConfig::default(),
            microseg: LayerConfig::default(),
            backup: LayerConfig::default(),
            cloud: LayerConfig::default(),
            time: LayerConfig::default(),
            soceng: LayerConfig::default(),
            regulatory: LayerConfig::default(),
            ops: LayerConfig::default(),
            pipelines: Vec::new(),
        }
    }
}
