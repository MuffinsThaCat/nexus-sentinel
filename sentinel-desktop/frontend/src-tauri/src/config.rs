use serde::{Serialize, Deserialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelConfig {
    pub stripe: StripeConfig,
    pub server_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeConfig {
    pub pro_payment_link: String,
    pub enterprise_payment_link: String,
}


impl Default for SentinelConfig {
    fn default() -> Self {
        SentinelConfig {
            stripe: StripeConfig {
                pro_payment_link: "https://buy.stripe.com/test_bJe8wPaJw0xz0eI0B3bjW00".to_string(),
                enterprise_payment_link: "https://buy.stripe.com/test_8x228r8BogwxgdG4RjbjW01".to_string(),
            },
            server_url: "https://beaverwarrior.com/api".to_string(),
        }
    }
}

impl SentinelConfig {
    pub fn load() -> Self {
        let defaults = Self::default();
        let path = Self::config_path();
        let mut cfg = if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(json) => match serde_json::from_str(&json) {
                    Ok(cfg) => cfg,
                    Err(e) => {
                        log::warn!("Failed to parse config.json: {}", e);
                        defaults.clone()
                    }
                },
                Err(e) => {
                    log::warn!("Failed to read config.json: {}", e);
                    defaults.clone()
                }
            }
        } else {
            defaults.clone()
        };

        // Always use the compiled-in server_url (prevents stale cached URLs)
        cfg.server_url = defaults.server_url;
        cfg.save();
        cfg
    }

    pub fn save(&self) {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(&path, json);
        }
    }

    fn config_path() -> PathBuf {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("beaver-warrior")
            .join("config.json")
    }

    pub fn has_stripe(&self) -> bool {
        !self.stripe.pro_payment_link.is_empty() && !self.stripe.enterprise_payment_link.is_empty()
    }

}
