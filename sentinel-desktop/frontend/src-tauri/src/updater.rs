use serde::{Deserialize, Serialize};

const VERSION_URL: &str = "https://beaverwarrior.com/version.json";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub version: String,
    pub download_url: String,
    pub release_notes: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateCheck {
    pub current_version: String,
    pub latest_version: String,
    pub update_available: bool,
    pub download_url: String,
    pub release_notes: String,
}

fn version_tuple(v: &str) -> (u32, u32, u32) {
    let parts: Vec<u32> = v.split('.').filter_map(|p| p.parse().ok()).collect();
    (
        parts.first().copied().unwrap_or(0),
        parts.get(1).copied().unwrap_or(0),
        parts.get(2).copied().unwrap_or(0),
    )
}

fn is_newer(remote: &str, local: &str) -> bool {
    version_tuple(remote) > version_tuple(local)
}

#[tauri::command]
pub async fn check_for_update() -> UpdateCheck {
    match reqwest::get(VERSION_URL).await {
        Ok(resp) => match resp.json::<VersionInfo>().await {
            Ok(info) => {
                let available = is_newer(&info.version, CURRENT_VERSION);
                log::info!(
                    "Update check: current={} latest={} update={}",
                    CURRENT_VERSION, info.version, available
                );
                UpdateCheck {
                    current_version: CURRENT_VERSION.to_string(),
                    latest_version: info.version,
                    update_available: available,
                    download_url: info.download_url,
                    release_notes: info.release_notes,
                }
            }
            Err(e) => {
                log::warn!("Failed to parse version info: {}", e);
                no_update()
            }
        },
        Err(e) => {
            log::warn!("Failed to check for updates: {}", e);
            no_update()
        }
    }
}

fn no_update() -> UpdateCheck {
    UpdateCheck {
        current_version: CURRENT_VERSION.to_string(),
        latest_version: CURRENT_VERSION.to_string(),
        update_available: false,
        download_url: String::new(),
        release_notes: String::new(),
    }
}
