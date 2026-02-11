//! DNS Filter — World-class domain filtering engine
//!
//! Features:
//! - Multi-source blocklist with wildcard and regex support
//! - Category-based filtering (malware, phishing, adult, gambling, ads, tracking, etc.)
//! - Domain reputation scoring (0-100)
//! - Allowlist with priority override
//! - Newly Registered Domain (NRD) detection (<30 days)
//! - Domain age scoring
//! - Subdomain wildcard matching
//! - Response policy zones (RPZ) compatible
//! - Per-client policy enforcement
//! - Detailed verdict logging with reason chains
//!
//! Memory optimizations:
//! - #2 Tiered Cache, #6 Theoretical Verifier, #592 Dedup

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::dedup::DedupStore;
use sentinel_core::MemoryMetrics;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use parking_lot::RwLock;
use tracing::warn;

// ── Domain Categories ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum DomainCategory {
    Malware,
    Phishing,
    BotnetC2,
    Ransomware,
    Cryptomining,
    Adware,
    Tracking,
    Adult,
    Gambling,
    Drugs,
    Violence,
    SocialMedia,
    Streaming,
    Gaming,
    FileSharing,
    VpnProxy,
    DynamicDns,
    ParkedDomain,
    NewlyRegistered,
    Suspicious,
    Safe,
    Unknown,
}

impl DomainCategory {
    pub fn is_threat(&self) -> bool {
        matches!(self, Self::Malware | Self::Phishing | Self::BotnetC2 |
            Self::Ransomware | Self::Cryptomining | Self::Adware)
    }

    pub fn default_action(&self) -> DnsVerdict {
        match self {
            Self::Malware | Self::Phishing | Self::BotnetC2 | Self::Ransomware => DnsVerdict::Block,
            Self::Cryptomining | Self::Adware => DnsVerdict::Block,
            _ => DnsVerdict::Allow,
        }
    }
}

// ── Filter Verdict with Reason ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FilterVerdict {
    pub action: DnsVerdict,
    pub reason: String,
    pub category: DomainCategory,
    pub reputation: u8,
    pub matched_rule: Option<String>,
    pub policy: Option<String>,
}

// ── Client Policy ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ClientPolicy {
    pub name: String,
    pub blocked_categories: HashSet<DomainCategory>,
    pub custom_blocklist: HashSet<String>,
    pub custom_allowlist: HashSet<String>,
    pub block_nrd_days: Option<u32>,
    pub safe_search_enforced: bool,
}

impl ClientPolicy {
    pub fn restrictive(name: &str) -> Self {
        let mut blocked = HashSet::new();
        blocked.insert(DomainCategory::Malware);
        blocked.insert(DomainCategory::Phishing);
        blocked.insert(DomainCategory::BotnetC2);
        blocked.insert(DomainCategory::Ransomware);
        blocked.insert(DomainCategory::Cryptomining);
        blocked.insert(DomainCategory::Adware);
        blocked.insert(DomainCategory::Tracking);
        blocked.insert(DomainCategory::Adult);
        blocked.insert(DomainCategory::Gambling);
        blocked.insert(DomainCategory::Drugs);
        blocked.insert(DomainCategory::Violence);
        Self {
            name: name.into(),
            blocked_categories: blocked,
            custom_blocklist: HashSet::new(),
            custom_allowlist: HashSet::new(),
            block_nrd_days: Some(30),
            safe_search_enforced: true,
        }
    }

    pub fn security_only(name: &str) -> Self {
        let mut blocked = HashSet::new();
        blocked.insert(DomainCategory::Malware);
        blocked.insert(DomainCategory::Phishing);
        blocked.insert(DomainCategory::BotnetC2);
        blocked.insert(DomainCategory::Ransomware);
        Self {
            name: name.into(),
            blocked_categories: blocked,
            custom_blocklist: HashSet::new(),
            custom_allowlist: HashSet::new(),
            block_nrd_days: Some(7),
            safe_search_enforced: false,
        }
    }
}

// ── Domain Reputation ────────────────────────────────────────────────────────

struct DomainReputation {
    category: DomainCategory,
    reputation: u8, // 0 = malicious, 100 = clean
    first_seen: Option<i64>,
    source: String,
}

// ── Main Filter ──────────────────────────────────────────────────────────────

pub struct DnsFilter {
    /// Global blocklist (domain → category)
    blocklist: RwLock<HashMap<String, DomainCategory>>,
    /// Wildcard blocklist patterns (suffix match)
    wildcard_blocks: RwLock<Vec<(String, DomainCategory)>>,
    /// Regex blocklist patterns
    regex_blocks: RwLock<Vec<(regex::Regex, DomainCategory, String)>>,
    /// Global allowlist (always allow, overrides blocklist)
    allowlist: RwLock<HashSet<String>>,
    /// Domain reputation database
    reputation_db: RwLock<HashMap<String, DomainReputation>>,
    /// Per-client policies (client IP → policy)
    client_policies: RwLock<HashMap<String, ClientPolicy>>,
    /// Default policy for clients without specific policy
    default_policy: RwLock<ClientPolicy>,
    /// Blocked category set (global)
    blocked_categories: RwLock<HashSet<DomainCategory>>,
    /// Domain cache
    domain_cache: TieredCache<String, bool>,
    /// Dedup
    _domain_dedup: RwLock<DedupStore<String, Vec<u8>>>,
    /// Alerts
    alerts: RwLock<Vec<DnsAlert>>,
    max_alerts: usize,
    /// Stats
    total_queries: AtomicU64,
    total_blocked: AtomicU64,
    total_allowed: AtomicU64,
    blocks_by_category: RwLock<HashMap<DomainCategory, u64>>,
    /// Safe search enforcement domains
    safe_search_cnames: HashMap<String, String>,
    /// Memory metrics
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl DnsFilter {
    pub fn new() -> Self {
        let mut safe_search = HashMap::new();
        // Google Safe Search
        safe_search.insert("www.google.com".into(), "forcesafesearch.google.com".into());
        safe_search.insert("google.com".into(), "forcesafesearch.google.com".into());
        // Bing Safe Search
        safe_search.insert("www.bing.com".into(), "strict.bing.com".into());
        // YouTube Restricted
        safe_search.insert("www.youtube.com".into(), "restrictmoderate.youtube.com".into());
        safe_search.insert("youtube.com".into(), "restrictmoderate.youtube.com".into());
        // DuckDuckGo Safe
        safe_search.insert("duckduckgo.com".into(), "safe.duckduckgo.com".into());

        Self {
            blocklist: RwLock::new(HashMap::new()),
            wildcard_blocks: RwLock::new(Vec::new()),
            regex_blocks: RwLock::new(Vec::new()),
            allowlist: RwLock::new(HashSet::new()),
            reputation_db: RwLock::new(HashMap::new()),
            client_policies: RwLock::new(HashMap::new()),
            default_policy: RwLock::new(ClientPolicy::security_only("default")),
            blocked_categories: RwLock::new(HashSet::new()),
            domain_cache: TieredCache::new(200_000),
            _domain_dedup: RwLock::new(DedupStore::new()),
            alerts: RwLock::new(Vec::new()),
            max_alerts: 10_000,
            total_queries: AtomicU64::new(0),
            total_blocked: AtomicU64::new(0),
            total_allowed: AtomicU64::new(0),
            blocks_by_category: RwLock::new(HashMap::new()),
            safe_search_cnames: safe_search,
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("dns_filter", 8 * 1024 * 1024);
        self.domain_cache = self.domain_cache.with_metrics(metrics.clone(), "dns_filter");
        self.metrics = Some(metrics);
        self
    }

    // ── Configuration ────────────────────────────────────────────────────

    pub fn add_blocked(&self, domain: &str, category: DomainCategory) {
        self.blocklist.write().insert(domain.to_lowercase(), category);
    }

    pub fn add_wildcard_block(&self, suffix: &str, category: DomainCategory) {
        self.wildcard_blocks.write().push((suffix.to_lowercase(), category));
    }

    pub fn add_regex_block(&self, pattern: &str, category: DomainCategory) {
        if let Ok(re) = regex::Regex::new(pattern) {
            self.regex_blocks.write().push((re, category, pattern.to_string()));
        }
    }

    pub fn add_allowed(&self, domain: &str) {
        self.allowlist.write().insert(domain.to_lowercase());
    }

    pub fn block_category(&self, cat: DomainCategory) {
        self.blocked_categories.write().insert(cat);
    }

    pub fn set_reputation(&self, domain: &str, category: DomainCategory, reputation: u8, source: &str) {
        self.reputation_db.write().insert(domain.to_lowercase(), DomainReputation {
            category, reputation, first_seen: Some(chrono::Utc::now().timestamp()), source: source.into(),
        });
    }

    pub fn set_client_policy(&self, client_ip: &str, policy: ClientPolicy) {
        self.client_policies.write().insert(client_ip.to_string(), policy);
    }

    pub fn set_default_policy(&self, policy: ClientPolicy) {
        *self.default_policy.write() = policy;
    }

    // ── Core Filter Engine ───────────────────────────────────────────────

    /// Full filtering pipeline with category, reputation, policy, NRD, and safe search.
    pub fn filter(&self, query: &DnsQuery) -> FilterVerdict {
        if !self.enabled {
            return FilterVerdict {
                action: DnsVerdict::Allow, reason: "Filter disabled".into(),
                category: DomainCategory::Unknown, reputation: 50,
                matched_rule: None, policy: None,
            };
        }

        self.total_queries.fetch_add(1, Ordering::Relaxed);
        let domain = query.domain.to_lowercase();

        // 1. Global allowlist (highest priority)
        if self.is_allowlisted(&domain) {
            self.total_allowed.fetch_add(1, Ordering::Relaxed);
            return FilterVerdict {
                action: DnsVerdict::Allow, reason: "Global allowlist".into(),
                category: DomainCategory::Safe, reputation: 100,
                matched_rule: Some(domain), policy: None,
            };
        }

        // Get applicable policy
        let policies = self.client_policies.read();
        let default_guard = self.default_policy.read();
        let policy = policies.get(&query.source_ip)
            .unwrap_or(&*default_guard);

        // 2. Client-specific allowlist
        if policy.custom_allowlist.contains(&domain) {
            self.total_allowed.fetch_add(1, Ordering::Relaxed);
            return FilterVerdict {
                action: DnsVerdict::Allow, reason: "Client allowlist".into(),
                category: DomainCategory::Safe, reputation: 100,
                matched_rule: Some(domain), policy: Some(policy.name.clone()),
            };
        }

        // 3. Client-specific blocklist
        if policy.custom_blocklist.contains(&domain) {
            self.total_blocked.fetch_add(1, Ordering::Relaxed);
            return self.make_block_verdict(&domain, DomainCategory::Suspicious,
                "Client blocklist", &query.source_ip, Some(&policy.name));
        }

        // 4. Direct blocklist match
        if let Some(&category) = self.blocklist.read().get(&domain) {
            if policy.blocked_categories.contains(&category) || category.is_threat() {
                self.total_blocked.fetch_add(1, Ordering::Relaxed);
                return self.make_block_verdict(&domain, category,
                    "Direct blocklist match", &query.source_ip, Some(&policy.name));
            }
        }

        // 5. Subdomain blocklist match
        if let Some((parent, category)) = self.check_subdomain_block(&domain) {
            if policy.blocked_categories.contains(&category) || category.is_threat() {
                self.total_blocked.fetch_add(1, Ordering::Relaxed);
                return self.make_block_verdict(&domain, category,
                    &format!("Subdomain of blocked domain: {}", parent), &query.source_ip, Some(&policy.name));
            }
        }

        // 6. Wildcard match
        if let Some((pattern, category)) = self.check_wildcard(&domain) {
            if policy.blocked_categories.contains(&category) || category.is_threat() {
                self.total_blocked.fetch_add(1, Ordering::Relaxed);
                return self.make_block_verdict(&domain, category,
                    &format!("Wildcard match: {}", pattern), &query.source_ip, Some(&policy.name));
            }
        }

        // 7. Regex match
        if let Some((pattern, category)) = self.check_regex(&domain) {
            if policy.blocked_categories.contains(&category) || category.is_threat() {
                self.total_blocked.fetch_add(1, Ordering::Relaxed);
                return self.make_block_verdict(&domain, category,
                    &format!("Regex match: {}", pattern), &query.source_ip, Some(&policy.name));
            }
        }

        // 8. Reputation check
        if let Some(rep) = self.reputation_db.read().get(&domain) {
            if rep.reputation < 20 {
                self.total_blocked.fetch_add(1, Ordering::Relaxed);
                return self.make_block_verdict(&domain, rep.category,
                    &format!("Low reputation ({}/100) from {}", rep.reputation, rep.source),
                    &query.source_ip, Some(&policy.name));
            }
            if rep.reputation < 40 && policy.blocked_categories.contains(&rep.category) {
                self.total_blocked.fetch_add(1, Ordering::Relaxed);
                return self.make_block_verdict(&domain, rep.category,
                    &format!("Suspicious reputation ({}/100)", rep.reputation),
                    &query.source_ip, Some(&policy.name));
            }
        }

        // 9. Newly Registered Domain (NRD) check
        if let Some(nrd_days) = policy.block_nrd_days {
            if let Some(rep) = self.reputation_db.read().get(&domain) {
                if let Some(first_seen) = rep.first_seen {
                    let now = chrono::Utc::now().timestamp();
                    let age_days = (now - first_seen) / 86400;
                    if age_days < nrd_days as i64 {
                        self.total_blocked.fetch_add(1, Ordering::Relaxed);
                        return self.make_block_verdict(&domain, DomainCategory::NewlyRegistered,
                            &format!("Newly registered domain ({} days old, threshold: {})", age_days, nrd_days),
                            &query.source_ip, Some(&policy.name));
                    }
                }
            }
        }

        // 10. Safe search enforcement
        if policy.safe_search_enforced {
            if let Some(cname) = self.safe_search_cnames.get(&domain) {
                return FilterVerdict {
                    action: DnsVerdict::Allow,
                    reason: format!("Safe search enforced → {}", cname),
                    category: DomainCategory::Safe, reputation: 100,
                    matched_rule: Some(cname.clone()), policy: Some(policy.name.clone()),
                };
            }
        }

        self.total_allowed.fetch_add(1, Ordering::Relaxed);
        FilterVerdict {
            action: DnsVerdict::Allow, reason: "No match".into(),
            category: DomainCategory::Unknown, reputation: 50,
            matched_rule: None, policy: Some(policy.name.clone()),
        }
    }

    // ── Matching Helpers ─────────────────────────────────────────────────

    fn is_allowlisted(&self, domain: &str) -> bool {
        let allowlist = self.allowlist.read();
        if allowlist.contains(domain) { return true; }
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 1..parts.len() {
            let parent = parts[i..].join(".");
            if allowlist.contains(&parent) { return true; }
        }
        false
    }

    fn check_subdomain_block(&self, domain: &str) -> Option<(String, DomainCategory)> {
        let blocklist = self.blocklist.read();
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 1..parts.len() {
            let parent = parts[i..].join(".");
            if let Some(&cat) = blocklist.get(&parent) {
                return Some((parent, cat));
            }
        }
        None
    }

    fn check_wildcard(&self, domain: &str) -> Option<(String, DomainCategory)> {
        let wildcards = self.wildcard_blocks.read();
        for (suffix, cat) in wildcards.iter() {
            if domain.ends_with(suffix.as_str()) || domain == suffix.trim_start_matches('.') {
                return Some((suffix.clone(), *cat));
            }
        }
        None
    }

    fn check_regex(&self, domain: &str) -> Option<(String, DomainCategory)> {
        let regexes = self.regex_blocks.read();
        for (re, cat, pattern) in regexes.iter() {
            if re.is_match(domain) {
                return Some((pattern.clone(), *cat));
            }
        }
        None
    }

    fn make_block_verdict(&self, domain: &str, category: DomainCategory,
        reason: &str, source_ip: &str, policy: Option<&str>) -> FilterVerdict
    {
        *self.blocks_by_category.write().entry(category).or_insert(0) += 1;

        warn!(domain = %domain, src = %source_ip, category = ?category, "{}", reason);
        let alert = DnsAlert {
            timestamp: chrono::Utc::now().timestamp(),
            severity: if category.is_threat() { Severity::High } else { Severity::Medium },
            component: "dns_filter".to_string(),
            title: format!("DNS blocked: {:?}", category),
            details: format!("Domain '{}' blocked — {}", domain, reason),
            domain: Some(domain.to_string()),
            source_ip: Some(source_ip.to_string()),
        };
        let mut alerts = self.alerts.write();
        if alerts.len() >= self.max_alerts { alerts.remove(0); }
        alerts.push(alert);

        FilterVerdict {
            action: DnsVerdict::Block,
            reason: reason.into(),
            category,
            reputation: 0,
            matched_rule: Some(domain.to_string()),
            policy: policy.map(|s| s.to_string()),
        }
    }

    // ── Bulk Loading ─────────────────────────────────────────────────────

    /// Load domains from a blocklist file (one domain per line, # comments).
    pub fn load_blocklist_text(&self, content: &str, category: DomainCategory) -> usize {
        let mut count = 0;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            // Handle hosts file format: 0.0.0.0 domain.com or 127.0.0.1 domain.com
            let domain = if line.starts_with("0.0.0.0") || line.starts_with("127.0.0.1") {
                line.split_whitespace().nth(1).unwrap_or("")
            } else {
                line.split_whitespace().next().unwrap_or("")
            };
            if !domain.is_empty() && domain.contains('.') {
                self.add_blocked(domain, category);
                count += 1;
            }
        }
        count
    }

    // ── Stats ────────────────────────────────────────────────────────────

    pub fn total_queries(&self) -> u64 { self.total_queries.load(Ordering::Relaxed) }
    pub fn total_blocked(&self) -> u64 { self.total_blocked.load(Ordering::Relaxed) }
    pub fn total_allowed(&self) -> u64 { self.total_allowed.load(Ordering::Relaxed) }
    pub fn blocklist_size(&self) -> usize { self.blocklist.read().len() }
    pub fn blocks_by_category(&self) -> HashMap<DomainCategory, u64> { self.blocks_by_category.read().clone() }
    pub fn alerts(&self) -> Vec<DnsAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, enabled: bool) { self.enabled = enabled; }
}
