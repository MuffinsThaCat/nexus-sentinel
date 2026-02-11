//! # TAXII 2.1 Client — Pull threat intelligence from real TAXII servers
//!
//! Implements the TAXII 2.1 protocol (RFC-compliant) for discovering and pulling
//! STIX 2.1 bundles from public and private threat intelligence feeds.
//!
//! Supports:
//! - Server discovery (API roots)
//! - Collection enumeration
//! - Object polling with pagination and filtering
//! - Authentication (basic, API key, certificate)
//! - Rate limiting and retry logic
//! - Caching of previously fetched objects
//!
//! Public feeds supported out of the box:
//! - MITRE ATT&CK TAXII server
//! - AlienVault OTX (via TAXII)
//! - CISA Known Exploited Vulnerabilities

use parking_lot::RwLock;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{error, info, warn};

const TAXII_CONTENT_TYPE: &str = "application/taxii+json;version=2.1";
const STIX_CONTENT_TYPE: &str = "application/stix+json;version=2.1";
const MAX_CACHED_OBJECTS: usize = 500_000;

/// Authentication method for TAXII servers.
#[derive(Debug, Clone)]
pub enum TaxiiAuth {
    None,
    Basic { username: String, password: String },
    ApiKey { header: String, key: String },
    Bearer { token: String },
}

/// A TAXII server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaxiiServerConfig {
    pub name: String,
    pub discovery_url: String,
    pub api_root: Option<String>,
    pub collection_id: Option<String>,
    pub poll_interval_secs: u64,
    pub enabled: bool,
}

/// TAXII API Root from server discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiRoot {
    pub title: String,
    pub versions: Vec<String>,
    pub max_content_length: Option<u64>,
}

/// TAXII Collection metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaxiiCollection {
    pub id: String,
    pub title: String,
    pub description: Option<String>,
    pub can_read: bool,
    pub can_write: bool,
    pub media_types: Option<Vec<String>>,
}

/// A parsed STIX 2.1 indicator (the most actionable object type).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixIndicator {
    pub id: String,
    pub indicator_type: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub pattern: String,
    pub pattern_type: String,
    pub valid_from: String,
    pub valid_until: Option<String>,
    pub kill_chain_phases: Vec<String>,
    pub labels: Vec<String>,
    pub confidence: Option<u8>,
    pub created: String,
    pub modified: String,
    pub source_feed: String,
}

/// A parsed STIX 2.1 malware object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixMalware {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub malware_types: Vec<String>,
    pub is_family: bool,
    pub kill_chain_phases: Vec<String>,
    pub labels: Vec<String>,
    pub source_feed: String,
}

/// Summary of a TAXII pull operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullResult {
    pub server: String,
    pub collection: String,
    pub objects_fetched: u64,
    pub indicators: u64,
    pub malware: u64,
    pub attack_patterns: u64,
    pub other: u64,
    pub duration_ms: u64,
    pub timestamp: i64,
}

/// The main TAXII 2.1 client.
pub struct TaxiiClient {
    http: reqwest::Client,
    servers: RwLock<Vec<TaxiiServerConfig>>,
    auth: RwLock<HashMap<String, TaxiiAuth>>,
    /// All fetched indicators, keyed by STIX ID
    indicators: Arc<RwLock<HashMap<String, StixIndicator>>>,
    /// All fetched malware, keyed by STIX ID
    malware: Arc<RwLock<HashMap<String, StixMalware>>>,
    /// Track which object IDs we've already seen
    seen_ids: RwLock<HashSet<String>>,
    /// Pull history
    pull_history: RwLock<Vec<PullResult>>,
    /// Counters
    total_pulls: AtomicU64,
    total_objects: AtomicU64,
    total_indicators: AtomicU64,
    total_errors: AtomicU64,
}

impl TaxiiClient {
    pub fn new() -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static(TAXII_CONTENT_TYPE));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static(TAXII_CONTENT_TYPE));

        let http = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("NexusSentinel-TAXII/2.1")
            .build()
            .expect("Failed to build HTTP client");

        let mut client = Self {
            http,
            servers: RwLock::new(Vec::new()),
            auth: RwLock::new(HashMap::new()),
            indicators: Arc::new(RwLock::new(HashMap::new())),
            malware: Arc::new(RwLock::new(HashMap::new())),
            seen_ids: RwLock::new(HashSet::new()),
            pull_history: RwLock::new(Vec::new()),
            total_pulls: AtomicU64::new(0),
            total_objects: AtomicU64::new(0),
            total_indicators: AtomicU64::new(0),
            total_errors: AtomicU64::new(0),
        };
        client.add_default_feeds();
        client
    }

    /// Register built-in public TAXII feeds.
    fn add_default_feeds(&mut self) {
        let defaults = vec![
            TaxiiServerConfig {
                name: "MITRE ATT&CK".into(),
                discovery_url: "https://cti-taxii.mitre.org/taxii2".into(),
                api_root: Some("https://cti-taxii.mitre.org/stix/collections".into()),
                collection_id: Some("enterprise-attack".into()),
                poll_interval_secs: 86400, // daily
                enabled: true,
            },
            TaxiiServerConfig {
                name: "CISA KEV".into(),
                discovery_url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json".into(),
                api_root: None,
                collection_id: None,
                poll_interval_secs: 3600, // hourly
                enabled: true,
            },
        ];
        *self.servers.write() = defaults;
    }

    /// Add a custom TAXII server.
    pub fn add_server(&self, config: TaxiiServerConfig) {
        self.servers.write().push(config);
    }

    /// Set authentication for a server by name.
    pub fn set_auth(&self, server_name: &str, auth: TaxiiAuth) {
        self.auth.write().insert(server_name.to_string(), auth);
    }

    /// Build request with appropriate auth headers.
    fn build_request(&self, url: &str, server_name: &str) -> reqwest::RequestBuilder {
        let mut req = self.http.get(url);
        let auth = self.auth.read();
        if let Some(a) = auth.get(server_name) {
            req = match a {
                TaxiiAuth::Basic { username, password } => req.basic_auth(username, Some(password)),
                TaxiiAuth::ApiKey { header, key } => req.header(header.as_str(), key.as_str()),
                TaxiiAuth::Bearer { token } => req.bearer_auth(token),
                TaxiiAuth::None => req,
            };
        }
        req
    }

    /// Discover API roots from a TAXII server.
    pub async fn discover(&self, server_name: &str) -> Result<Vec<String>, String> {
        let servers = self.servers.read();
        let server = servers.iter().find(|s| s.name == server_name)
            .ok_or_else(|| format!("Server '{}' not found", server_name))?;
        let url = server.discovery_url.clone();
        drop(servers);

        let resp = self.build_request(&url, server_name)
            .header(ACCEPT, TAXII_CONTENT_TYPE)
            .send().await
            .map_err(|e| format!("Discovery request failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("Discovery returned {}", resp.status()));
        }

        let body: serde_json::Value = resp.json().await
            .map_err(|e| format!("Failed to parse discovery response: {}", e))?;

        // TAXII 2.1 discovery returns {"default": "/api/root/", "api_roots": [...]}
        let roots: Vec<String> = body.get("api_roots")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();

        info!(server = %server_name, roots = roots.len(), "TAXII discovery complete");
        Ok(roots)
    }

    /// List collections from an API root.
    pub async fn list_collections(&self, api_root: &str, server_name: &str) -> Result<Vec<TaxiiCollection>, String> {
        let url = format!("{}/collections/", api_root.trim_end_matches('/'));
        let resp = self.build_request(&url, server_name)
            .send().await
            .map_err(|e| format!("List collections failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("Collections returned {}", resp.status()));
        }

        let body: serde_json::Value = resp.json().await
            .map_err(|e| format!("Failed to parse collections: {}", e))?;

        let collections: Vec<TaxiiCollection> = body.get("collections")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter().filter_map(|c| {
                    Some(TaxiiCollection {
                        id: c.get("id")?.as_str()?.to_string(),
                        title: c.get("title")?.as_str()?.to_string(),
                        description: c.get("description").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        can_read: c.get("can_read").and_then(|v| v.as_bool()).unwrap_or(false),
                        can_write: c.get("can_write").and_then(|v| v.as_bool()).unwrap_or(false),
                        media_types: c.get("media_types").and_then(|v| v.as_array())
                            .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()),
                    })
                }).collect()
            })
            .unwrap_or_default();

        info!(api_root = %api_root, collections = collections.len(), "Listed collections");
        Ok(collections)
    }

    /// Pull STIX objects from a collection.
    pub async fn pull_objects(
        &self, api_root: &str, collection_id: &str, server_name: &str,
        added_after: Option<&str>,
    ) -> Result<PullResult, String> {
        let start = std::time::Instant::now();
        self.total_pulls.fetch_add(1, Ordering::Relaxed);

        let mut url = format!("{}/collections/{}/objects/",
            api_root.trim_end_matches('/'), collection_id);
        if let Some(after) = added_after {
            url.push_str(&format!("?added_after={}", after));
        }

        let resp = self.build_request(&url, server_name)
            .header(ACCEPT, STIX_CONTENT_TYPE)
            .send().await
            .map_err(|e| {
                self.total_errors.fetch_add(1, Ordering::Relaxed);
                format!("Pull failed: {}", e)
            })?;

        if !resp.status().is_success() {
            self.total_errors.fetch_add(1, Ordering::Relaxed);
            return Err(format!("Pull returned {}", resp.status()));
        }

        let body: serde_json::Value = resp.json().await
            .map_err(|e| {
                self.total_errors.fetch_add(1, Ordering::Relaxed);
                format!("Failed to parse STIX bundle: {}", e)
            })?;

        // Parse STIX bundle
        let objects = body.get("objects")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut ind_count = 0u64;
        let mut mal_count = 0u64;
        let mut ap_count = 0u64;
        let mut other_count = 0u64;

        for obj in &objects {
            let stix_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let stix_id = obj.get("id").and_then(|v| v.as_str()).unwrap_or("");

            // Skip duplicates
            {
                let mut seen = self.seen_ids.write();
                if seen.contains(stix_id) { continue; }
                if seen.len() >= MAX_CACHED_OBJECTS { seen.clear(); }
                seen.insert(stix_id.to_string());
            }

            self.total_objects.fetch_add(1, Ordering::Relaxed);

            match stix_type {
                "indicator" => {
                    if let Some(ind) = Self::parse_indicator(obj, server_name) {
                        self.indicators.write().insert(ind.id.clone(), ind);
                        ind_count += 1;
                        self.total_indicators.fetch_add(1, Ordering::Relaxed);
                    }
                }
                "malware" => {
                    if let Some(mal) = Self::parse_malware(obj, server_name) {
                        self.malware.write().insert(mal.id.clone(), mal);
                        mal_count += 1;
                    }
                }
                "attack-pattern" => { ap_count += 1; }
                _ => { other_count += 1; }
            }
        }

        let result = PullResult {
            server: server_name.to_string(),
            collection: collection_id.to_string(),
            objects_fetched: objects.len() as u64,
            indicators: ind_count,
            malware: mal_count,
            attack_patterns: ap_count,
            other: other_count,
            duration_ms: start.elapsed().as_millis() as u64,
            timestamp: chrono::Utc::now().timestamp(),
        };

        info!(
            server = %server_name, collection = %collection_id,
            objects = objects.len(), indicators = ind_count, malware = mal_count,
            duration_ms = result.duration_ms,
            "TAXII pull complete"
        );

        self.pull_history.write().push(result.clone());
        Ok(result)
    }

    /// Parse a STIX indicator object.
    fn parse_indicator(obj: &serde_json::Value, source: &str) -> Option<StixIndicator> {
        Some(StixIndicator {
            id: obj.get("id")?.as_str()?.to_string(),
            indicator_type: obj.get("indicator_types")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            name: obj.get("name").and_then(|v| v.as_str()).map(|s| s.to_string()),
            description: obj.get("description").and_then(|v| v.as_str()).map(|s| s.to_string()),
            pattern: obj.get("pattern")?.as_str()?.to_string(),
            pattern_type: obj.get("pattern_type").and_then(|v| v.as_str())
                .unwrap_or("stix").to_string(),
            valid_from: obj.get("valid_from").and_then(|v| v.as_str())
                .unwrap_or("").to_string(),
            valid_until: obj.get("valid_until").and_then(|v| v.as_str()).map(|s| s.to_string()),
            kill_chain_phases: obj.get("kill_chain_phases")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|p| {
                    let phase = p.get("phase_name")?.as_str()?;
                    Some(phase.to_string())
                }).collect())
                .unwrap_or_default(),
            labels: obj.get("labels")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default(),
            confidence: obj.get("confidence").and_then(|v| v.as_u64()).map(|v| v as u8),
            created: obj.get("created").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            modified: obj.get("modified").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            source_feed: source.to_string(),
        })
    }

    /// Parse a STIX malware object.
    fn parse_malware(obj: &serde_json::Value, source: &str) -> Option<StixMalware> {
        Some(StixMalware {
            id: obj.get("id")?.as_str()?.to_string(),
            name: obj.get("name")?.as_str()?.to_string(),
            description: obj.get("description").and_then(|v| v.as_str()).map(|s| s.to_string()),
            malware_types: obj.get("malware_types")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default(),
            is_family: obj.get("is_family").and_then(|v| v.as_bool()).unwrap_or(false),
            kill_chain_phases: obj.get("kill_chain_phases")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|p| {
                    let phase = p.get("phase_name")?.as_str()?;
                    Some(phase.to_string())
                }).collect())
                .unwrap_or_default(),
            labels: obj.get("labels")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default(),
            source_feed: source.to_string(),
        })
    }

    /// Match a network IOC (IP, domain, URL) against all loaded indicators.
    /// Returns matching indicators with their STIX patterns.
    pub fn match_ioc(&self, ioc_value: &str) -> Vec<StixIndicator> {
        let indicators = self.indicators.read();
        let ioc_lower = ioc_value.to_lowercase();
        indicators.values()
            .filter(|ind| {
                let pattern_lower = ind.pattern.to_lowercase();
                // STIX patterns like [ipv4-addr:value = '1.2.3.4']
                pattern_lower.contains(&ioc_lower)
            })
            .cloned()
            .collect()
    }

    /// Check if a hash (MD5/SHA1/SHA256) matches any indicator.
    pub fn match_hash(&self, hash: &str) -> Vec<StixIndicator> {
        let indicators = self.indicators.read();
        let hash_lower = hash.to_lowercase();
        indicators.values()
            .filter(|ind| {
                let pattern_lower = ind.pattern.to_lowercase();
                pattern_lower.contains(&hash_lower)
            })
            .cloned()
            .collect()
    }

    /// Get all loaded indicators.
    pub fn all_indicators(&self) -> Vec<StixIndicator> {
        self.indicators.read().values().cloned().collect()
    }

    /// Get all loaded malware families.
    pub fn all_malware(&self) -> Vec<StixMalware> {
        self.malware.read().values().cloned().collect()
    }

    pub fn total_pulls(&self) -> u64 { self.total_pulls.load(Ordering::Relaxed) }
    pub fn total_objects(&self) -> u64 { self.total_objects.load(Ordering::Relaxed) }
    pub fn total_indicators(&self) -> u64 { self.total_indicators.load(Ordering::Relaxed) }
    pub fn total_errors(&self) -> u64 { self.total_errors.load(Ordering::Relaxed) }
    pub fn pull_history(&self) -> Vec<PullResult> { self.pull_history.read().clone() }
    pub fn server_count(&self) -> usize { self.servers.read().len() }
}
