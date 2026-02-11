//! # Threat Intelligence Feed Fetcher
//!
//! Fetches indicators of compromise (IOCs) from public OSINT sources:
//! - abuse.ch URLhaus (malicious URLs)
//! - abuse.ch Feodo Tracker (C2 IPs)
//! - abuse.ch SSL Blacklist (malicious SSL certs)
//! - Emerging Threats (Suricata/Snort rules)

use crate::event_bus::{EventBus, EventSeverity};
use parking_lot::RwLock;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{info, warn, error};

/// Types of threat indicators.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum IndicatorType {
    MaliciousUrl,
    CommandAndControlIp,
    MaliciousDomain,
    MaliciousSslFingerprint,
    MaliciousFileHash,
}

/// A single indicator of compromise.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Indicator {
    pub indicator_type: IndicatorType,
    pub value: String,
    pub source: String,
    pub description: String,
    pub added_at: i64,
}

/// Feed source configuration.
#[derive(Debug, Clone)]
pub struct FeedSource {
    pub name: String,
    pub url: String,
    pub indicator_type: IndicatorType,
    pub enabled: bool,
}

/// Threat intelligence feed manager.
pub struct ThreatIntelFeed {
    feeds: Vec<FeedSource>,
    malicious_urls: Arc<RwLock<HashSet<String>>>,
    malicious_ips: Arc<RwLock<HashSet<String>>>,
    malicious_domains: Arc<RwLock<HashSet<String>>>,
    malicious_hashes: Arc<RwLock<HashSet<String>>>,
    total_indicators: Arc<AtomicU64>,
    last_update: Arc<RwLock<Option<i64>>>,
    running: Arc<AtomicBool>,
}

impl ThreatIntelFeed {
    pub fn new() -> Self {
        Self {
            feeds: vec![
                FeedSource {
                    name: "URLhaus".into(),
                    url: "https://urlhaus.abuse.ch/downloads/csv_recent/".into(),
                    indicator_type: IndicatorType::MaliciousUrl,
                    enabled: true,
                },
                FeedSource {
                    name: "Feodo Tracker".into(),
                    url: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt".into(),
                    indicator_type: IndicatorType::CommandAndControlIp,
                    enabled: true,
                },
                FeedSource {
                    name: "SSL Blacklist".into(),
                    url: "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt".into(),
                    indicator_type: IndicatorType::MaliciousSslFingerprint,
                    enabled: true,
                },
            ],
            malicious_urls: Arc::new(RwLock::new(HashSet::new())),
            malicious_ips: Arc::new(RwLock::new(HashSet::new())),
            malicious_domains: Arc::new(RwLock::new(HashSet::new())),
            malicious_hashes: Arc::new(RwLock::new(HashSet::new())),
            total_indicators: Arc::new(AtomicU64::new(0)),
            last_update: Arc::new(RwLock::new(None)),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Add a custom feed source.
    pub fn add_feed(&mut self, source: FeedSource) {
        self.feeds.push(source);
    }

    /// Fetch all enabled feeds once.
    pub async fn fetch_all(&self) -> Result<usize, String> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("NexusSentinel/1.0")
            .build()
            .map_err(|e| format!("HTTP client error: {}", e))?;

        let mut total = 0usize;

        for feed in &self.feeds {
            if !feed.enabled { continue; }

            info!(feed = %feed.name, url = %feed.url, "Fetching threat intel feed");
            match client.get(&feed.url).send().await {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        warn!(feed = %feed.name, status = %resp.status(), "Feed fetch failed");
                        continue;
                    }
                    match resp.text().await {
                        Ok(body) => {
                            let count = self.parse_feed(&feed.name, &feed.indicator_type, &body);
                            total += count;
                            info!(feed = %feed.name, indicators = count, "Feed loaded");
                        }
                        Err(e) => warn!(feed = %feed.name, error = %e, "Failed to read feed body"),
                    }
                }
                Err(e) => warn!(feed = %feed.name, error = %e, "Failed to fetch feed"),
            }
        }

        self.total_indicators.store(total as u64, Ordering::Relaxed);
        *self.last_update.write() = Some(chrono::Utc::now().timestamp());

        Ok(total)
    }

    /// Parse a feed response into indicators.
    fn parse_feed(&self, source: &str, indicator_type: &IndicatorType, body: &str) -> usize {
        let mut count = 0;
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("\"") && line.contains("id") {
                continue;
            }

            match indicator_type {
                IndicatorType::MaliciousUrl => {
                    // URLhaus CSV: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
                    let parts: Vec<&str> = line.split(',').collect();
                    if parts.len() >= 3 {
                        let url = parts[2].trim_matches('"').to_string();
                        if url.starts_with("http") {
                            self.malicious_urls.write().insert(url);
                            count += 1;
                        }
                    }
                }
                IndicatorType::CommandAndControlIp => {
                    // Plain text IP list (one per line)
                    if Self::is_valid_ip(line) {
                        self.malicious_ips.write().insert(line.to_string());
                        count += 1;
                    }
                }
                IndicatorType::MaliciousSslFingerprint => {
                    // SSL blacklist: IP:port
                    if line.contains(':') || Self::is_valid_ip(line) {
                        let ip = line.split(':').next().unwrap_or(line);
                        if Self::is_valid_ip(ip) {
                            self.malicious_ips.write().insert(ip.to_string());
                            count += 1;
                        }
                    }
                }
                IndicatorType::MaliciousDomain => {
                    if !line.contains(' ') && line.contains('.') {
                        self.malicious_domains.write().insert(line.to_lowercase());
                        count += 1;
                    }
                }
                IndicatorType::MaliciousFileHash => {
                    if line.len() == 64 || line.len() == 32 || line.len() == 40 {
                        self.malicious_hashes.write().insert(line.to_lowercase());
                        count += 1;
                    }
                }
            }
        }
        count
    }

    fn is_valid_ip(s: &str) -> bool {
        s.parse::<std::net::IpAddr>().is_ok()
    }

    /// Check if a URL is known malicious.
    pub fn check_url(&self, url: &str) -> bool {
        self.malicious_urls.read().contains(url)
    }

    /// Check if an IP is known malicious.
    pub fn check_ip(&self, ip: &str) -> bool {
        self.malicious_ips.read().contains(ip)
    }

    /// Check if a domain is known malicious.
    pub fn check_domain(&self, domain: &str) -> bool {
        self.malicious_domains.read().contains(&domain.to_lowercase())
    }

    /// Check a file hash against known malware.
    pub fn check_hash(&self, hash: &str) -> bool {
        self.malicious_hashes.read().contains(&hash.to_lowercase())
    }

    /// Start periodic feed updates.
    pub fn start_periodic(&self, interval_secs: u64, bus: Arc<EventBus>) {
        self.running.store(true, Ordering::Relaxed);
        let running = self.running.clone();
        let urls = self.malicious_urls.clone();
        let ips = self.malicious_ips.clone();
        let domains = self.malicious_domains.clone();
        let total = self.total_indicators.clone();
        let last_update = self.last_update.clone();
        let feeds: Vec<FeedSource> = self.feeds.clone();

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .user_agent("NexusSentinel/1.0")
                .build()
                .unwrap();

            while running.load(Ordering::Relaxed) {
                ticker.tick().await;

                let mut count = 0usize;
                for feed in &feeds {
                    if !feed.enabled { continue; }
                    if let Ok(resp) = client.get(&feed.url).send().await {
                        if let Ok(body) = resp.text().await {
                            for line in body.lines() {
                                let line = line.trim();
                                if line.is_empty() || line.starts_with('#') { continue; }
                                match feed.indicator_type {
                                    IndicatorType::MaliciousUrl => {
                                        let parts: Vec<&str> = line.split(',').collect();
                                        if parts.len() >= 3 {
                                            let url = parts[2].trim_matches('"');
                                            if url.starts_with("http") {
                                                urls.write().insert(url.to_string());
                                                count += 1;
                                            }
                                        }
                                    }
                                    IndicatorType::CommandAndControlIp | IndicatorType::MaliciousSslFingerprint => {
                                        let ip = line.split(':').next().unwrap_or(line);
                                        if ip.parse::<std::net::IpAddr>().is_ok() {
                                            ips.write().insert(ip.to_string());
                                            count += 1;
                                        }
                                    }
                                    IndicatorType::MaliciousDomain => {
                                        if line.contains('.') { domains.write().insert(line.to_lowercase()); count += 1; }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }

                total.store(count as u64, Ordering::Relaxed);
                *last_update.write() = Some(chrono::Utc::now().timestamp());

                let mut details = std::collections::HashMap::new();
                details.insert("indicators".into(), count.to_string());
                bus.emit_detection(
                    "threat_intel", "sentinel-core", EventSeverity::Info,
                    "Threat intel feeds updated", details, vec!["threat-intel".into()],
                );
            }
        });
    }

    pub fn stop(&self) { self.running.store(false, Ordering::Relaxed); }
    pub fn total_indicators(&self) -> u64 { self.total_indicators.load(Ordering::Relaxed) }
    pub fn malicious_url_count(&self) -> usize { self.malicious_urls.read().len() }
    pub fn malicious_ip_count(&self) -> usize { self.malicious_ips.read().len() }
    pub fn malicious_domain_count(&self) -> usize { self.malicious_domains.read().len() }
    pub fn last_update(&self) -> Option<i64> { *self.last_update.read() }
}
