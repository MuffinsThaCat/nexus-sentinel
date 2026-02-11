//! DNS Tunnel Detection — World-class implementation
//!
//! Detection techniques:
//! - Shannon entropy analysis on domain labels
//! - Bigram/trigram frequency analysis (English vs random)
//! - Consonant ratio scoring (natural language vs encoded data)
//! - Hex/Base32/Base64 encoding detection
//! - Label length distribution analysis
//! - Query rate anomaly detection per source
//! - TXT/NULL/CNAME record type abuse detection
//! - Subdomain depth analysis
//! - Payload size anomaly (large queries = exfiltration)
//! - Known tunnel tool signatures (iodine, dnscat2, dns2tcp, Cobalt Strike)
//!
//! DGA (Domain Generation Algorithm) Detection:
//! - Bigram frequency deviation from English
//! - Digit-to-alpha ratio
//! - Vowel-to-consonant ratio
//! - Domain length distribution
//! - TLD reputation scoring
//! - NXDOMAIN response flood detection
//!
//! Memory optimizations:
//! - #2 Tiered Cache, #6 Theoretical Verifier, #569 Pruning

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::pruning::PruningMap;
use sentinel_core::MemoryMetrics;
use std::collections::HashMap;
use parking_lot::RwLock;
use tracing::warn;

// ── English bigram frequencies (top 50) for DGA detection ────────────────────
// Bigrams that appear frequently in real English words but rarely in DGA domains.

const ENGLISH_BIGRAMS: &[(&str, f64)] = &[
    ("th", 3.56), ("he", 3.07), ("in", 2.43), ("er", 2.05), ("an", 1.99),
    ("re", 1.85), ("on", 1.76), ("at", 1.49), ("en", 1.45), ("nd", 1.35),
    ("ti", 1.34), ("es", 1.34), ("or", 1.28), ("te", 1.27), ("of", 1.17),
    ("ed", 1.17), ("is", 1.13), ("it", 1.12), ("al", 1.09), ("ar", 1.07),
    ("st", 1.05), ("to", 1.04), ("nt", 1.04), ("ng", 0.95), ("se", 0.93),
    ("ha", 0.93), ("as", 0.87), ("ou", 0.87), ("io", 0.83), ("le", 0.83),
    ("ve", 0.83), ("co", 0.79), ("me", 0.79), ("de", 0.76), ("hi", 0.76),
    ("ri", 0.73), ("ro", 0.73), ("ic", 0.70), ("ne", 0.69), ("ea", 0.69),
    ("ra", 0.69), ("ce", 0.65), ("li", 0.62), ("ch", 0.60), ("ll", 0.58),
    ("be", 0.58), ("ma", 0.57), ("si", 0.55), ("om", 0.55), ("ur", 0.54),
];

/// Suspicious TLDs commonly used by DGA malware and phishing
const SUSPICIOUS_TLDS: &[&str] = &[
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "club", "work", "date",
    "racing", "win", "bid", "stream", "download", "loan", "trade", "webcam",
    "party", "review", "cricket", "science", "faith", "accountant", "click",
    "link", "gdn", "buzz", "surf", "cam", "icu", "monster", "rest",
    "beauty", "hair", "quest", "sbs", "cfd",
];

/// Known DNS tunnel tool signatures
const TUNNEL_SIGNATURES: &[(&str, &str)] = &[
    ("t.v0", "iodine"),
    ("p.v0", "iodine"),
    ("z.v0", "iodine"),
    ("dnscat", "dnscat2"),
    ("dns2tcp", "dns2tcp"),
    ("_dnscat", "dnscat2"),
    ("stage.", "Cobalt Strike DNS"),
    ("aaa.stage.", "Cobalt Strike DNS"),
    ("post.", "Cobalt Strike DNS"),
    ("cdn.", "Cobalt Strike DNS beacon"),
    ("www6.", "Cobalt Strike DNS"),
    ("api0.", "Cobalt Strike DNS"),
];

#[derive(Default, Clone)]
struct SourceStats {
    query_count: u64,
    total_label_len: u64,
    txt_query_count: u64,
    null_query_count: u64,
    nxdomain_count: u64,
    unique_domains: u64,
    high_entropy_count: u64,
    window_start: i64,
}

#[derive(Debug, Clone)]
pub struct TunnelScore {
    pub total_score: u32,
    pub entropy_score: f64,
    pub bigram_score: f64,
    pub consonant_ratio: f64,
    pub digit_ratio: f64,
    pub is_dga: bool,
    pub is_tunnel: bool,
    pub reasons: Vec<String>,
    pub tool_detected: Option<String>,
}

pub struct DnsTunnelDetector {
    source_stats: RwLock<HashMap<String, SourceStats>>,
    /// Domain → last seen timestamp (for NXDOMAIN tracking)
    nxdomain_tracker: RwLock<HashMap<String, Vec<i64>>>,
    /// #2 Tiered cache
    stats_cache: TieredCache<String, u64>,
    /// #569 Pruning
    _stale_sources: RwLock<PruningMap<String, i64>>,
    /// English bigram frequency map for DGA scoring
    bigram_freq: HashMap<String, f64>,
    entropy_threshold: f64,
    max_label_len: usize,
    dga_threshold: f64,
    alerts: RwLock<Vec<DnsAlert>>,
    max_alerts: usize,
    window_secs: i64,
    nxdomain_flood_threshold: u64,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl DnsTunnelDetector {
    pub fn new() -> Self {
        let mut bigram_freq = HashMap::new();
        for &(bg, freq) in ENGLISH_BIGRAMS {
            bigram_freq.insert(bg.to_string(), freq);
        }

        Self {
            source_stats: RwLock::new(HashMap::new()),
            nxdomain_tracker: RwLock::new(HashMap::new()),
            stats_cache: TieredCache::new(100_000),
            _stale_sources: RwLock::new(
                PruningMap::new(100_000).with_ttl(std::time::Duration::from_secs(600)),
            ),
            bigram_freq: bigram_freq,
            entropy_threshold: 3.5,
            max_label_len: 50,
            dga_threshold: 7.0,
            alerts: RwLock::new(Vec::new()),
            max_alerts: 10_000,
            window_secs: 300,
            nxdomain_flood_threshold: 50,
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("dns_tunnel_detect", 4 * 1024 * 1024);
        self.stats_cache = self.stats_cache.with_metrics(metrics.clone(), "dns_tunnel_detect");
        self.metrics = Some(metrics);
        self
    }

    // ── Core Analysis ────────────────────────────────────────────────────

    /// Full analysis pipeline: entropy + bigram + DGA + tunnel signatures + rate.
    pub fn analyze(&self, query: &DnsQuery) -> Option<DnsAlert> {
        if !self.enabled { return None; }

        let now = chrono::Utc::now().timestamp();
        let domain = &query.domain;
        let labels: Vec<&str> = domain.split('.').collect();
        if labels.len() < 2 { return None; }

        let score = self.score_domain(domain, query, now);

        if score.is_tunnel || score.is_dga || score.total_score >= 6 {
            let severity = if score.total_score >= 10 { Severity::Critical }
                else if score.total_score >= 7 { Severity::High }
                else { Severity::Medium };

            let title = if let Some(ref tool) = score.tool_detected {
                format!("DNS tunnel tool detected: {}", tool)
            } else if score.is_dga {
                "DGA domain detected".to_string()
            } else {
                "DNS tunneling suspected".to_string()
            };

            warn!(src = %query.source_ip, domain = %domain, score = score.total_score, "{}", title);
            let alert = DnsAlert {
                timestamp: now,
                severity,
                component: "dns_tunnel_detect".to_string(),
                title,
                details: format!("Score {}/15 — {}", score.total_score, score.reasons.join("; ")),
                domain: Some(domain.clone()),
                source_ip: Some(query.source_ip.clone()),
            };
            let mut alerts = self.alerts.write();
            if alerts.len() >= self.max_alerts { alerts.remove(0); }
            alerts.push(alert.clone());
            return Some(alert);
        }
        None
    }

    /// Comprehensive domain scoring — returns detailed breakdown.
    pub fn score_domain(&self, domain: &str, query: &DnsQuery, now: i64) -> TunnelScore {
        let labels: Vec<&str> = domain.split('.').collect();
        let mut score = 0u32;
        let mut reasons = Vec::new();
        let mut tool_detected = None;

        // Get the query part (everything except TLD and SLD)
        let query_labels = if labels.len() > 2 { &labels[..labels.len()-2] } else { &labels[..1] };
        let query_part = query_labels.join(".");

        // ── 1. Shannon entropy ──
        let entropy = Self::shannon_entropy(&query_part);
        if entropy > 4.5 {
            score += 3;
            reasons.push(format!("Very high entropy ({:.2})", entropy));
        } else if entropy > self.entropy_threshold {
            score += 2;
            reasons.push(format!("High entropy ({:.2})", entropy));
        }

        // ── 2. Bigram frequency deviation ──
        let bigram_score = self.bigram_deviation(&query_part);
        if bigram_score < 0.5 {
            score += 3;
            reasons.push(format!("Non-English bigrams ({:.2})", bigram_score));
        } else if bigram_score < 1.0 {
            score += 1;
            reasons.push(format!("Low English bigrams ({:.2})", bigram_score));
        }

        // ── 3. Consonant ratio ──
        let consonant_ratio = Self::consonant_ratio(&query_part);
        if consonant_ratio > 0.85 {
            score += 2;
            reasons.push(format!("Very high consonant ratio ({:.2})", consonant_ratio));
        } else if consonant_ratio > 0.75 {
            score += 1;
            reasons.push(format!("High consonant ratio ({:.2})", consonant_ratio));
        }

        // ── 4. Digit ratio ──
        let digit_ratio = Self::digit_ratio(&query_part);
        if digit_ratio > 0.5 {
            score += 2;
            reasons.push(format!("High digit ratio ({:.2})", digit_ratio));
        } else if digit_ratio > 0.3 {
            score += 1;
            reasons.push(format!("Elevated digit ratio ({:.2})", digit_ratio));
        }

        // ── 5. Label length ──
        for label in query_labels {
            if label.len() > 50 {
                score += 3;
                reasons.push(format!("Very long label ({})", label.len()));
            } else if label.len() > self.max_label_len {
                score += 2;
                reasons.push(format!("Long label ({})", label.len()));
            }
        }

        // ── 6. Subdomain depth ──
        if labels.len() > 6 {
            score += 2;
            reasons.push(format!("Deep subdomain ({} levels)", labels.len()));
        } else if labels.len() > 4 {
            score += 1;
            reasons.push(format!("Unusual depth ({} levels)", labels.len()));
        }

        // ── 7. Hex/Base32/Base64 encoding detection ──
        if Self::looks_hex(&query_part) {
            score += 2;
            reasons.push("Hex-encoded subdomain".into());
        } else if Self::looks_base32(&query_part) {
            score += 2;
            reasons.push("Base32-encoded subdomain".into());
        } else if Self::looks_base64(&query_part) {
            score += 2;
            reasons.push("Base64-encoded subdomain".into());
        }

        // ── 8. Record type abuse ──
        match query.record_type {
            RecordType::TXT => { score += 1; reasons.push("TXT query".into()); }
            RecordType::NULL => { score += 2; reasons.push("NULL record query (tunnel indicator)".into()); }
            RecordType::CNAME => {
                if query_part.len() > 30 {
                    score += 1; reasons.push("Long CNAME query".into());
                }
            }
            _ => {}
        }

        // ── 9. Known tunnel tool signatures ──
        let domain_lower = domain.to_lowercase();
        for &(sig, tool) in TUNNEL_SIGNATURES {
            if domain_lower.contains(sig) {
                score += 5;
                reasons.push(format!("Known tunnel signature: {}", tool));
                tool_detected = Some(tool.to_string());
                break;
            }
        }

        // ── 10. Suspicious TLD ──
        if let Some(tld) = labels.last() {
            if SUSPICIOUS_TLDS.contains(tld) {
                score += 1;
                reasons.push(format!("Suspicious TLD: .{}", tld));
            }
        }

        // ── 11. Per-source rate tracking ──
        {
            let mut stats = self.source_stats.write();
            let entry = stats.entry(query.source_ip.clone()).or_insert_with(|| SourceStats {
                window_start: now, ..Default::default()
            });
            if now - entry.window_start > self.window_secs {
                *entry = SourceStats { window_start: now, ..Default::default() };
            }
            entry.query_count += 1;
            entry.total_label_len += query_part.len() as u64;
            if query.record_type == RecordType::TXT { entry.txt_query_count += 1; }
            if query.record_type == RecordType::NULL { entry.null_query_count += 1; }
            if entropy > self.entropy_threshold { entry.high_entropy_count += 1; }
            entry.unique_domains += 1;

            let elapsed = (now - entry.window_start).max(1) as f64;
            let qps = entry.query_count as f64 / elapsed;
            if qps > 20.0 {
                score += 2;
                reasons.push(format!("Very high query rate ({:.1} qps)", qps));
            } else if qps > 10.0 {
                score += 1;
                reasons.push(format!("High query rate ({:.1} qps)", qps));
            }

            // High ratio of high-entropy queries = systematic tunneling
            if entry.query_count > 20 {
                let entropy_ratio = entry.high_entropy_count as f64 / entry.query_count as f64;
                if entropy_ratio > 0.7 {
                    score += 2;
                    reasons.push(format!("{}% queries high-entropy", (entropy_ratio * 100.0) as u32));
                }
            }

            // TXT query abuse
            if entry.query_count > 10 && entry.txt_query_count as f64 / entry.query_count as f64 > 0.5 {
                score += 1;
                reasons.push("Excessive TXT queries".into());
            }
        }

        // DGA determination
        let is_dga = entropy > 3.8 && bigram_score < 1.0 && consonant_ratio > 0.65 && query_part.len() > 8;

        TunnelScore {
            total_score: score,
            entropy_score: entropy,
            bigram_score,
            consonant_ratio,
            digit_ratio,
            is_dga,
            is_tunnel: score >= 6,
            reasons,
            tool_detected,
        }
    }

    // ── NXDOMAIN Flood Detection ─────────────────────────────────────────

    /// Track NXDOMAIN responses — DGA malware generates hundreds of failed lookups.
    pub fn record_nxdomain(&self, domain: &str, source_ip: &str) -> Option<DnsAlert> {
        let now = chrono::Utc::now().timestamp();
        let mut tracker = self.nxdomain_tracker.write();
        let times = tracker.entry(source_ip.to_string()).or_insert_with(Vec::new);
        times.push(now);

        // Keep last 5 minutes
        times.retain(|&t| now - t < 300);

        if times.len() as u64 > self.nxdomain_flood_threshold {
            let count = times.len();
            times.clear(); // Reset to avoid alert storm
            warn!(src = %source_ip, count, "NXDOMAIN flood detected — possible DGA activity");
            let alert = DnsAlert {
                timestamp: now,
                severity: Severity::Critical,
                component: "dns_tunnel_detect".to_string(),
                title: "NXDOMAIN flood — DGA activity suspected".to_string(),
                details: format!("{} NXDOMAIN responses from {} in 5min — domain generation algorithm likely active. Last domain: {}", count, source_ip, domain),
                domain: Some(domain.to_string()),
                source_ip: Some(source_ip.to_string()),
            };
            let mut alerts = self.alerts.write();
            if alerts.len() >= self.max_alerts { alerts.remove(0); }
            alerts.push(alert.clone());
            return Some(alert);
        }
        None
    }

    // ── Scoring Helper Functions ─────────────────────────────────────────

    fn shannon_entropy(s: &str) -> f64 {
        if s.is_empty() { return 0.0; }
        let mut freq = [0u32; 256];
        for b in s.bytes() { freq[b as usize] += 1; }
        let len = s.len() as f64;
        freq.iter().filter(|&&c| c > 0).map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        }).sum()
    }

    /// Bigram deviation from English: higher = more English-like.
    fn bigram_deviation(&self, s: &str) -> f64 {
        if s.len() < 4 { return 2.0; } // too short to judge
        let lower = s.to_lowercase();
        let bytes = lower.as_bytes();
        let mut total_score = 0.0f64;
        let mut count = 0u32;
        for i in 0..bytes.len()-1 {
            if !bytes[i].is_ascii_alphabetic() || !bytes[i+1].is_ascii_alphabetic() { continue; }
            let bg = format!("{}{}", bytes[i] as char, bytes[i+1] as char);
            total_score += self.bigram_freq.get(&bg).copied().unwrap_or(0.0);
            count += 1;
        }
        if count == 0 { return 0.0; }
        total_score / count as f64
    }

    /// Ratio of consonants to total alphabetic characters.
    fn consonant_ratio(s: &str) -> f64 {
        let alpha: Vec<char> = s.chars().filter(|c| c.is_ascii_alphabetic()).collect();
        if alpha.is_empty() { return 0.0; }
        let vowels = "aeiouAEIOU";
        let consonants = alpha.iter().filter(|c| !vowels.contains(**c)).count();
        consonants as f64 / alpha.len() as f64
    }

    /// Ratio of digits to total characters.
    fn digit_ratio(s: &str) -> f64 {
        if s.is_empty() { return 0.0; }
        let digits = s.chars().filter(|c| c.is_ascii_digit()).count();
        digits as f64 / s.len() as f64
    }

    /// Check if string looks hex-encoded (mostly 0-9a-f).
    fn looks_hex(s: &str) -> bool {
        if s.len() < 8 { return false; }
        let hex_chars = s.chars().filter(|c| c.is_ascii_hexdigit()).count();
        let ratio = hex_chars as f64 / s.len() as f64;
        ratio > 0.9 && s.len() >= 16
    }

    /// Check if string looks Base32-encoded (A-Z2-7, no lowercase, padded with =).
    fn looks_base32(s: &str) -> bool {
        if s.len() < 8 { return false; }
        let valid = s.chars().filter(|c| {
            c.is_ascii_uppercase() || ('2'..='7').contains(c) || *c == '='
        }).count();
        valid as f64 / s.len() as f64 > 0.9
    }

    /// Check if string looks Base64-encoded.
    fn looks_base64(s: &str) -> bool {
        if s.len() < 12 { return false; }
        let valid = s.chars().filter(|c| {
            c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '='
        }).count();
        let ratio = valid as f64 / s.len() as f64;
        // Must have mixed case to distinguish from normal domains
        let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
        let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
        ratio > 0.95 && has_upper && has_lower && s.len() >= 20
    }

    // ── Homoglyph / Typosquat Detection ──────────────────────────────────

    /// Detect domains that visually mimic legitimate brands using character substitution.
    pub fn check_typosquat(&self, domain: &str) -> Option<(String, String)> {
        let lower = domain.to_lowercase();
        let brands = [
            ("google", "google.com"), ("facebook", "facebook.com"), ("amazon", "amazon.com"),
            ("apple", "apple.com"), ("microsoft", "microsoft.com"), ("paypal", "paypal.com"),
            ("netflix", "netflix.com"), ("linkedin", "linkedin.com"), ("twitter", "twitter.com"),
            ("instagram", "instagram.com"), ("whatsapp", "whatsapp.com"), ("dropbox", "dropbox.com"),
            ("github", "github.com"), ("stackoverflow", "stackoverflow.com"),
            ("chase", "chase.com"), ("wellsfargo", "wellsfargo.com"), ("bankofamerica", "bankofamerica.com"),
            ("coinbase", "coinbase.com"), ("binance", "binance.com"), ("kraken", "kraken.com"),
        ];

        // Common homoglyph substitutions
        let homoglyphs: &[(char, char)] = &[
            ('o', '0'), ('l', '1'), ('i', '1'), ('e', '3'), ('a', '4'),
            ('s', '5'), ('g', '9'), ('b', '6'), ('t', '7'),
            ('o', 'q'),
            ('n', 'r'), ('i', 'l'), ('l', 'I'),
        ];

        // Extract domain name without TLD
        let parts: Vec<&str> = lower.split('.').collect();
        if parts.len() < 2 { return None; }
        let name = parts[..parts.len()-1].join(".");

        for &(brand, legit) in &brands {
            if name == brand { continue; } // exact match is fine

            // Check edit distance
            let dist = Self::levenshtein(&name, brand);
            if dist == 1 || dist == 2 {
                return Some((brand.to_string(), legit.to_string()));
            }

            // Check homoglyph substitution
            let deglyphed = Self::deglyph(&name);
            if deglyphed == brand && name != brand {
                return Some((brand.to_string(), legit.to_string()));
            }

            // Check with common chars removed/swapped
            if name.contains(brand) && name.len() <= brand.len() + 3 {
                return Some((brand.to_string(), legit.to_string()));
            }
        }
        None
    }

    fn deglyph(s: &str) -> String {
        s.replace('0', "o").replace('1', "l").replace('3', "e")
         .replace('4', "a").replace('5', "s").replace('9', "g")
         .replace('6', "b").replace('7', "t")
    }

    fn levenshtein(a: &str, b: &str) -> usize {
        let a: Vec<char> = a.chars().collect();
        let b: Vec<char> = b.chars().collect();
        let mut matrix = vec![vec![0usize; b.len() + 1]; a.len() + 1];
        for i in 0..=a.len() { matrix[i][0] = i; }
        for j in 0..=b.len() { matrix[0][j] = j; }
        for i in 1..=a.len() {
            for j in 1..=b.len() {
                let cost = if a[i-1] == b[j-1] { 0 } else { 1 };
                matrix[i][j] = (matrix[i-1][j] + 1)
                    .min(matrix[i][j-1] + 1)
                    .min(matrix[i-1][j-1] + cost);
            }
        }
        matrix[a.len()][b.len()]
    }

    // ── Fast-Flux Detection ──────────────────────────────────────────────

    /// Detect domains with abnormally high IP churn (fast-flux C2 infrastructure).
    /// Call this with DNS response data.
    pub fn check_fast_flux(&self, domain: &str, resolved_ips: &[String]) -> Option<DnsAlert> {
        // Fast-flux: >5 unique IPs for a single domain in short time
        if resolved_ips.len() >= 5 {
            let unique: std::collections::HashSet<&String> = resolved_ips.iter().collect();
            if unique.len() >= 5 {
                let now = chrono::Utc::now().timestamp();
                warn!(domain = %domain, ips = unique.len(), "Fast-flux DNS detected");
                let alert = DnsAlert {
                    timestamp: now,
                    severity: Severity::High,
                    component: "dns_tunnel_detect".to_string(),
                    title: "Fast-flux DNS detected".to_string(),
                    details: format!("Domain '{}' resolved to {} unique IPs — fast-flux C2 infrastructure", domain, unique.len()),
                    domain: Some(domain.to_string()),
                    source_ip: None,
                };
                let mut alerts = self.alerts.write();
                if alerts.len() >= self.max_alerts { alerts.remove(0); }
                alerts.push(alert.clone());
                return Some(alert);
            }
        }
        None
    }

    // ── DoH/DoT Detection ────────────────────────────────────────────────

    /// Known DNS-over-HTTPS resolver domains that bypass local DNS monitoring.
    pub fn is_doh_resolver(domain: &str) -> bool {
        let doh_resolvers = [
            "dns.google", "dns.google.com", "cloudflare-dns.com",
            "1dot1dot1dot1.cloudflare-dns.com", "dns.quad9.net",
            "doh.opendns.com", "dns.nextdns.io", "doh.cleanbrowsing.org",
            "dns.adguard.com", "doh.dns.sb", "dns.twnic.tw",
            "doh.li", "dns.switch.ch", "doh.centraleu.pi-dns.com",
            "dns.digitale-gesellschaft.ch", "doh.applied-privacy.net",
        ];
        let lower = domain.to_lowercase();
        doh_resolvers.iter().any(|r| lower.contains(r))
    }

    // ── Maintenance ──────────────────────────────────────────────────────

    pub fn prune_stale(&self) {
        let now = chrono::Utc::now().timestamp();
        let cutoff = now - self.window_secs * 2;
        self.source_stats.write().retain(|_, v| v.window_start > cutoff);
        self.nxdomain_tracker.write().retain(|_, v| !v.is_empty());
    }

    pub fn alerts(&self) -> Vec<DnsAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, enabled: bool) { self.enabled = enabled; }
}
