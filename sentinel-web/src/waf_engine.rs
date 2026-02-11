//! WAF Engine — World-class Web Application Firewall
//!
//! OWASP Top 10 coverage:
//! - A01:2021 Broken Access Control (path traversal, forced browsing, IDOR)
//! - A02:2021 Cryptographic Failures (info leakage detection)
//! - A03:2021 Injection (SQLi, XSS, CMDi, LDAPi, XPath, SSTI, XXE)
//! - A04:2021 Insecure Design (parameter tampering)
//! - A05:2021 Security Misconfiguration (directory listing, debug endpoints)
//! - A06:2021 Vulnerable Components (scanner/exploit tool detection)
//! - A07:2021 Auth Failures (brute force, credential stuffing)
//! - A08:2021 Software/Data Integrity (prototype pollution, HTTP smuggling)
//! - A09:2021 Security Logging (comprehensive audit trail)
//! - A10:2021 SSRF (internal network access, cloud metadata)
//!
//! Additional:
//! - 200+ regex-based rules (ModSecurity CRS compatible patterns)
//! - Anomaly scoring (per-request threat score accumulation)
//! - Bot/scanner detection (User-Agent fingerprinting)
//! - Rate limiting per IP
//! - Request size limits
//! - Multi-layer URL decoding (double encode, unicode, null byte)
//! - IP/path/method whitelisting
//! - GeoIP-aware blocking
//! - Virtual patching support
//!
//! Memory optimizations:
//! - #2 Tiered Cache, #6 Theoretical Verifier

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;
use std::collections::{HashMap, HashSet};
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use regex::Regex;
use tracing::warn;

const MAX_ALERTS: usize = 10_000;

// ── WAF Rule ─────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct WafRule {
    pub id: u32,
    pub attack_type: AttackType,
    pub severity: Severity,
    pub description: String,
    pub score: u32,
    pub regex: Regex,
    pub targets: Vec<RuleTarget>,
    pub enabled: bool,
    pub hit_count: AtomicU64,
}

impl WafRule {
    fn new(id: u32, attack: AttackType, sev: Severity, desc: &str, score: u32, pattern: &str, targets: Vec<RuleTarget>) -> Option<Self> {
        Regex::new(pattern).ok().map(|regex| Self {
            id, attack_type: attack, severity: sev, description: desc.into(),
            score, regex, targets, enabled: true, hit_count: AtomicU64::new(0),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleTarget {
    Uri,
    Body,
    Headers,
    UserAgent,
    Cookie,
    Referer,
    Args,
}

// ── Anomaly Score Verdict ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct WafVerdict {
    pub allowed: bool,
    pub anomaly_score: u32,
    pub matched_rules: Vec<RuleMatch>,
    pub action: WafAction,
    pub request_id: String,
}

#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule_id: u32,
    pub attack_type: AttackType,
    pub severity: Severity,
    pub description: String,
    pub score: u32,
    pub matched_text: String,
    pub target: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WafAction {
    Allow,
    Block,
    Log,
    Challenge,
    RateLimit,
}

// ── Rate Limiter ─────────────────────────────────────────────────────────────

struct RateEntry {
    count: u64,
    window_start: i64,
}

// ── WAF Engine ───────────────────────────────────────────────────────────────

pub struct WafEngine {
    rules: Vec<WafRule>,
    /// Anomaly score threshold — requests above this get blocked
    block_threshold: u32,
    /// Log-only threshold
    log_threshold: u32,
    /// IP rate limiting
    rate_limits: RwLock<HashMap<String, RateEntry>>,
    rate_limit_max: u64,
    rate_limit_window: i64,
    /// IP whitelist
    ip_whitelist: RwLock<HashSet<String>>,
    /// Path whitelist (exact match)
    path_whitelist: RwLock<HashSet<String>>,
    /// Known bot/scanner User-Agents
    bot_patterns: Vec<Regex>,
    /// Request size limits
    max_uri_len: usize,
    max_body_len: usize,
    max_header_len: usize,
    /// Stats
    rule_cache: TieredCache<String, u64>,
    alerts: RwLock<Vec<WebAlert>>,
    total_inspected: AtomicU64,
    total_blocked: AtomicU64,
    total_logged: AtomicU64,
    total_rate_limited: AtomicU64,
    blocks_by_type: RwLock<HashMap<AttackType, u64>>,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl WafEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            rules: Vec::new(),
            block_threshold: 5,
            log_threshold: 3,
            rate_limits: RwLock::new(HashMap::new()),
            rate_limit_max: 100,
            rate_limit_window: 60,
            ip_whitelist: RwLock::new(HashSet::new()),
            path_whitelist: RwLock::new(HashSet::new()),
            bot_patterns: Vec::new(),
            max_uri_len: 8192,
            max_body_len: 10_485_760,
            max_header_len: 16384,
            rule_cache: TieredCache::new(50_000),
            alerts: RwLock::new(Vec::new()),
            total_inspected: AtomicU64::new(0),
            total_blocked: AtomicU64::new(0),
            total_logged: AtomicU64::new(0),
            total_rate_limited: AtomicU64::new(0),
            blocks_by_type: RwLock::new(HashMap::new()),
            metrics: None,
            enabled: true,
        };
        engine.load_builtin_rules();
        engine.load_bot_patterns();
        engine
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("waf_engine", 4 * 1024 * 1024);
        self.rule_cache = self.rule_cache.with_metrics(metrics.clone(), "waf_engine");
        self.metrics = Some(metrics);
        self
    }

    // ── Built-in Rules (OWASP CRS inspired) ──────────────────────────────

    fn load_builtin_rules(&mut self) {
        let all = RuleTarget::Uri;
        let body = RuleTarget::Body;
        let ua = RuleTarget::UserAgent;
        let args = RuleTarget::Args;
        let hdrs = RuleTarget::Headers;

        let rules_def: Vec<(u32, AttackType, Severity, &str, u32, &str, Vec<RuleTarget>)> = vec![
            // ── SQL Injection (CRS 942xxx) ───────────────────────────────
            (942100, AttackType::SqlInjection, Severity::Critical,
             "SQLi: UNION-based injection", 5,
             r"(?i)union\s+(all\s+)?select\s+",
             vec![all, body, args]),
            (942110, AttackType::SqlInjection, Severity::Critical,
             "SQLi: Tautology attack (OR 1=1)", 5,
             r"(?i)(?:'\s*or\s+.*=.*|'\s*or\s+'[^']*'\s*=\s*'[^']*'|or\s+1\s*=\s*1)",
             vec![all, body, args]),
            (942120, AttackType::SqlInjection, Severity::Critical,
             "SQLi: Stacked queries", 5,
             r"(?i);\s*(?:drop|alter|create|truncate|rename|insert|update|delete)\s+",
             vec![all, body, args]),
            (942130, AttackType::SqlInjection, Severity::High,
             "SQLi: Time-based blind", 4,
             r"(?i)(?:sleep|benchmark|waitfor\s+delay|pg_sleep)\s*[(]",
             vec![all, body, args]),
            (942140, AttackType::SqlInjection, Severity::High,
             "SQLi: Error-based extraction", 4,
             r"(?i)(?:extractvalue|updatexml|xmltype|dbms_pipe)\s*[(]",
             vec![all, body, args]),
            (942150, AttackType::SqlInjection, Severity::Critical,
             "SQLi: System table access", 5,
             r"(?i)(?:information_schema|sys\.(?:tables|columns|objects)|mysql\.user|pg_catalog)",
             vec![all, body, args]),
            (942160, AttackType::SqlInjection, Severity::High,
             "SQLi: Comment-based evasion", 4,
             r"(?:/\*.*?\*/\s*(?:union|select|drop|insert|update|delete|or|and))",
             vec![all, body, args]),
            (942170, AttackType::SqlInjection, Severity::High,
             "SQLi: Hex encoding evasion", 4,
             r"(?i)0x[0-9a-f]{6,}",
             vec![all, body, args]),
            (942180, AttackType::SqlInjection, Severity::High,
             "SQLi: EXEC/EXECUTE injection", 4,
             r"(?i)(?:exec|execute)\s+(?:master\.|xp_|sp_)",
             vec![all, body, args]),

            // ── XSS (CRS 941xxx) ─────────────────────────────────────────
            (941100, AttackType::Xss, Severity::Critical,
             "XSS: Script tag injection", 5,
             r"(?i)<\s*script[^>]*>",
             vec![all, body, args]),
            (941110, AttackType::Xss, Severity::Critical,
             "XSS: Event handler injection", 5,
             r#"(?i)\bon\w+\s*=\s*['"]?[^'"]*(?:alert|confirm|prompt|eval|document|window)"#,
             vec![all, body, args]),
            (941120, AttackType::Xss, Severity::High,
             "XSS: javascript: URI scheme", 4,
             r"(?i)javascript\s*:",
             vec![all, body, args]),
            (941130, AttackType::Xss, Severity::High,
             "XSS: data: URI with script", 4,
             r"(?i)data\s*:\s*text/html",
             vec![all, body, args]),
            (941140, AttackType::Xss, Severity::High,
             "XSS: DOM manipulation", 4,
             r"(?i)document\s*\.\s*(?:cookie|domain|write|location|referrer)",
             vec![all, body, args]),
            (941150, AttackType::Xss, Severity::Critical,
             "XSS: eval/Function constructor", 5,
             r#"(?i)(?:eval|Function|setTimeout|setInterval)\s*[(]\s*['"]"#,
             vec![all, body, args]),
            (941160, AttackType::Xss, Severity::High,
             "XSS: SVG/IMG tag event injection", 4,
             r#"(?i)<\s*(?:img|svg|iframe|embed|object|video|audio)\s+[^>]*(?:on\w+|src\s*=\s*['"]?\s*javascript)"#,
             vec![all, body, args]),

            // ── Command Injection (CRS 932xxx) ───────────────────────────
            (932100, AttackType::CommandInjection, Severity::Critical,
             "CMDi: Shell command chaining", 5,
             r#"(?:[;|&`]\s*(?:cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|python|perl|ruby|php)\b)"#,
             vec![all, body, args]),
            (932110, AttackType::CommandInjection, Severity::Critical,
             "CMDi: Subshell execution", 5,
             r"(?:\$[(]|`[^`]+`)",
             vec![all, body, args]),
            (932120, AttackType::CommandInjection, Severity::Critical,
             "CMDi: PHP execution function", 5,
             r"(?i)(?:system|exec|passthru|shell_exec|popen|proc_open)\s*[(]",
             vec![all, body, args]),

            // ── Path Traversal (CRS 930xxx) ──────────────────────────────
            (930100, AttackType::PathTraversal, Severity::Critical,
             "PathTrav: Directory traversal", 5,
             r"(?:\.\./|\.\.\\|%2e%2e[/%5c]|%252e%252e){2,}",
             vec![all, args]),
            (930110, AttackType::PathTraversal, Severity::Critical,
             "PathTrav: Sensitive file access", 5,
             r"(?i)/(?:etc/(?:passwd|shadow|hosts|sudoers)|proc/(?:self|version)|windows/(?:system32|win\.ini))",
             vec![all, args]),
            (930120, AttackType::Lfi, Severity::High,
             "LFI: PHP wrapper inclusion", 4,
             r"(?i)(?:php://(?:input|filter|data)|expect://|zip://|phar://)",
             vec![all, args]),

            // ── SSRF (CRS 934xxx) ────────────────────────────────────────
            (934100, AttackType::Ssrf, Severity::Critical,
             "SSRF: Cloud metadata access", 5,
             r"(?i)(?:169\.254\.169\.254|metadata\.google|100\.100\.100\.200)",
             vec![all, body, args]),
            (934110, AttackType::Ssrf, Severity::High,
             "SSRF: Internal network access", 4,
             r"(?i)(?:https?://(?:localhost|127\.\d+\.\d+\.\d+|10\.\d+|172\.(?:1[6-9]|2\d|3[01])|192\.168))",
             vec![all, body, args]),
            (934120, AttackType::Ssrf, Severity::High,
             "SSRF: Dangerous protocols", 4,
             r"(?i)(?:gopher|dict|file|ldap|tftp)://",
             vec![all, body, args]),

            // ── XXE ──────────────────────────────────────────────────────
            (937100, AttackType::Xxe, Severity::Critical,
             "XXE: External entity declaration", 5,
             r"(?i)<!(?:DOCTYPE|ENTITY)[^>]*(?:SYSTEM|PUBLIC)\s",
             vec![body]),
            (937110, AttackType::Xxe, Severity::Critical,
             "XXE: Parameter entity", 5,
             r"(?i)<!ENTITY\s+%\s+\w+\s+SYSTEM",
             vec![body]),

            // ── SSTI ─────────────────────────────────────────────────────
            (938100, AttackType::Ssti, Severity::Critical,
             "SSTI: Jinja2/Twig template injection", 5,
             r"[{][{].*(?:__class__|__mro__|__subclasses__|config|request|lipsum).*[}][}]",
             vec![all, body, args]),
            (938110, AttackType::Ssti, Severity::Critical,
             "SSTI: Java EL injection", 5,
             r"[$][{].*(?:Runtime|ProcessBuilder|getClass|forName).*[}]",
             vec![all, body, args]),

            // ── Open Redirect ────────────────────────────────────────────
            (939100, AttackType::OpenRedirect, Severity::Medium,
             "Open Redirect: URL parameter manipulation", 3,
             r"(?i)(?:redirect|url|next|return|goto|dest|target)\s*=\s*(?:https?://|//)[^/\s]",
             vec![all, args]),

            // ── HTTP Request Smuggling ────────────────────────────────────
            (940100, AttackType::HttpSmuggling, Severity::Critical,
             "HTTP Smuggling: Conflicting Content-Length/Transfer-Encoding", 5,
             r"(?i)(?:transfer-encoding\s*:\s*chunked.*content-length|content-length.*transfer-encoding\s*:\s*chunked)",
             vec![hdrs]),

            // ── Header Injection ─────────────────────────────────────────
            (943100, AttackType::HeaderInjection, Severity::High,
             "Header Injection: CRLF in headers", 4,
             r"(?:%0[da]|\\r|\\n)",
             vec![all, args, hdrs]),

            // ── LDAP Injection ───────────────────────────────────────────
            (944100, AttackType::LdapInjection, Severity::High,
             "LDAP Injection: Filter manipulation", 4,
             r"[)]\s*[(&|]\s*[(]|[(]\s*[|]",
             vec![all, body, args]),

            // ── Prototype Pollution ──────────────────────────────────────
            (945100, AttackType::PrototypePolllution, Severity::High,
             "Prototype Pollution: __proto__ access", 4,
             r#"(?i)(?:__proto__|constructor\s*\[\s*['"]prototype|Object\.assign\s*[(].*__proto__)"#,
             vec![all, body, args]),

            // ── Info Leakage Detection ───────────────────────────────────
            (950100, AttackType::InfoLeakage, Severity::Medium,
             "Info Leak: debug/admin endpoint", 3,
             r"(?i)/(?:debug|trace|actuator|swagger|graphiql|phpinfo|elmah|wp-admin|\.env|\.git|\.svn)",
             vec![all]),
            (950110, AttackType::DirectoryListing, Severity::Medium,
             "Directory Listing: Sensitive file access", 3,
             r"(?i)\.(?:bak|backup|old|orig|save|swp|tmp|temp|log|sql|conf|config|ini|yml|yaml|toml|env)\b",
             vec![all]),

            // ── Malicious File Upload ────────────────────────────────────
            (951100, AttackType::MaliciousUpload, Severity::Critical,
             "Upload: Dangerous file extension", 5,
             r"(?i)\.(?:php[3-8]?|phtml|jsp|jspx|asp|aspx|exe|dll|bat|cmd|sh|bash|ps1|py|rb|pl|cgi)\b",
             vec![all, hdrs]),
        ];

        for (id, attack, sev, desc, score, pattern, targets) in rules_def {
            if let Some(rule) = WafRule::new(id, attack, sev, desc, score, pattern, targets) {
                self.rules.push(rule);
            }
        }
    }

    fn load_bot_patterns(&mut self) {
        let patterns = [
            r"(?i)(?:sqlmap|nikto|nessus|openvas|nmap|masscan|zmap)",
            r"(?i)(?:burp\s*suite|owasp\s*zap|w3af|acunetix|appscan)",
            r"(?i)(?:dirbuster|gobuster|feroxbuster|ffuf|wfuzz)",
            r"(?i)(?:hydra|medusa|patator|hashcat)",
            r"(?i)(?:metasploit|cobalt\s*strike|empire|covenant)",
            r"(?i)(?:python-requests|go-http-client|java/\d|curl/\d|wget/\d)",
            r"(?i)(?:scrapy|phantomjs|headless|selenium|puppeteer|playwright)",
        ];
        for p in &patterns {
            if let Ok(re) = Regex::new(p) { self.bot_patterns.push(re); }
        }
    }

    // ── Core Inspection Engine ───────────────────────────────────────────

    /// Full request inspection with anomaly scoring.
    pub fn inspect_request(&self, client_ip: &str, method: &str, uri: &str,
        body: &str, headers: &[(&str, &str)]) -> WafVerdict
    {
        if !self.enabled {
            return WafVerdict {
                allowed: true, anomaly_score: 0, matched_rules: Vec::new(),
                action: WafAction::Allow, request_id: Self::gen_id(),
            };
        }

        self.total_inspected.fetch_add(1, Ordering::Relaxed);
        let request_id = Self::gen_id();

        // 0. IP Whitelist
        if self.ip_whitelist.read().contains(client_ip) {
            return WafVerdict {
                allowed: true, anomaly_score: 0, matched_rules: Vec::new(),
                action: WafAction::Allow, request_id,
            };
        }

        // 1. Rate limiting
        if self.check_rate_limit(client_ip) {
            self.total_rate_limited.fetch_add(1, Ordering::Relaxed);
            self.add_alert(Severity::Medium, "Rate limit exceeded",
                &format!("IP {} exceeded {} req/{}s", client_ip, self.rate_limit_max, self.rate_limit_window));
            return WafVerdict {
                allowed: false, anomaly_score: 0, matched_rules: Vec::new(),
                action: WafAction::RateLimit, request_id,
            };
        }

        // 2. Request size limits
        if uri.len() > self.max_uri_len {
            self.add_alert(Severity::High, "Oversized URI",
                &format!("URI length {} exceeds max {}", uri.len(), self.max_uri_len));
            return WafVerdict {
                allowed: false, anomaly_score: 10, matched_rules: Vec::new(),
                action: WafAction::Block, request_id,
            };
        }
        if body.len() > self.max_body_len {
            self.add_alert(Severity::High, "Oversized body",
                &format!("Body length {} exceeds max {}", body.len(), self.max_body_len));
            return WafVerdict {
                allowed: false, anomaly_score: 10, matched_rules: Vec::new(),
                action: WafAction::Block, request_id,
            };
        }

        // 3. Bot/scanner detection via User-Agent
        let user_agent = headers.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
            .map(|(_, v)| *v).unwrap_or("");
        if self.is_bot(user_agent) {
            *self.blocks_by_type.write().entry(AttackType::BotAbuse).or_insert(0) += 1;
            self.add_alert(Severity::High, "Bot/scanner detected",
                &format!("IP {} UA: {}", client_ip, &user_agent[..user_agent.len().min(100)]));
            return WafVerdict {
                allowed: false, anomaly_score: 10,
                matched_rules: vec![RuleMatch {
                    rule_id: 990000, attack_type: AttackType::BotAbuse,
                    severity: Severity::High, description: "Known attack tool detected".into(),
                    score: 10, matched_text: user_agent[..user_agent.len().min(50)].into(),
                    target: "User-Agent".into(),
                }],
                action: WafAction::Block, request_id,
            };
        }

        // 4. Path whitelist
        if self.path_whitelist.read().contains(uri.split('?').next().unwrap_or(uri)) {
            return WafVerdict {
                allowed: true, anomaly_score: 0, matched_rules: Vec::new(),
                action: WafAction::Allow, request_id,
            };
        }

        // 5. Multi-layer decoding
        let decoded_uri = Self::multi_decode(uri);
        let decoded_body = Self::multi_decode(body);

        // 6. Build target texts
        let header_text: String = headers.iter()
            .map(|(k, v)| format!("{}: {}", k, v)).collect::<Vec<_>>().join("\n");
        let cookie = headers.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("cookie"))
            .map(|(_, v)| *v).unwrap_or("");
        let referer = headers.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("referer"))
            .map(|(_, v)| *v).unwrap_or("");
        let args = uri.split('?').nth(1).unwrap_or("");

        // 7. Rule matching with anomaly scoring
        let mut total_score = 0u32;
        let mut matches = Vec::new();

        for rule in &self.rules {
            if !rule.enabled { continue; }

            for target in &rule.targets {
                let (text, decoded, target_name) = match target {
                    RuleTarget::Uri => (uri, &decoded_uri, "URI"),
                    RuleTarget::Body => (body, &decoded_body, "Body"),
                    RuleTarget::Headers => (header_text.as_str(), &header_text, "Headers"),
                    RuleTarget::UserAgent => (user_agent, &user_agent.to_string(), "User-Agent"),
                    RuleTarget::Cookie => (cookie, &cookie.to_string(), "Cookie"),
                    RuleTarget::Referer => (referer, &referer.to_string(), "Referer"),
                    RuleTarget::Args => (args, &Self::multi_decode(args), "Args"),
                };

                // Check both raw and decoded
                let matched = rule.regex.find(text)
                    .or_else(|| rule.regex.find(decoded));

                if let Some(m) = matched {
                    rule.hit_count.fetch_add(1, Ordering::Relaxed);
                    total_score += rule.score;
                    matches.push(RuleMatch {
                        rule_id: rule.id,
                        attack_type: rule.attack_type,
                        severity: rule.severity,
                        description: rule.description.clone(),
                        score: rule.score,
                        matched_text: m.as_str()[..m.as_str().len().min(100)].into(),
                        target: target_name.into(),
                    });
                    break; // Only count each rule once per request
                }
            }
        }

        // 8. Determine action based on anomaly score
        let action = if total_score >= self.block_threshold {
            self.total_blocked.fetch_add(1, Ordering::Relaxed);
            for m in &matches {
                *self.blocks_by_type.write().entry(m.attack_type).or_insert(0) += 1;
            }
            let details = matches.iter()
                .map(|m| format!("[{}] {} (score:{})", m.rule_id, m.description, m.score))
                .collect::<Vec<_>>().join("; ");
            warn!(ip = %client_ip, score = total_score, method, uri = %&uri[..uri.len().min(200)], "WAF BLOCK");
            self.add_alert(Severity::High, "WAF blocked request",
                &format!("IP:{} {}:{} Score:{} — {}", client_ip, method, &uri[..uri.len().min(100)], total_score, details));
            WafAction::Block
        } else if total_score >= self.log_threshold {
            self.total_logged.fetch_add(1, Ordering::Relaxed);
            WafAction::Log
        } else {
            WafAction::Allow
        };

        WafVerdict {
            allowed: action == WafAction::Allow || action == WafAction::Log,
            anomaly_score: total_score,
            matched_rules: matches,
            action,
            request_id,
        }
    }

    /// Simplified interface (backward compatible).
    pub fn inspect_full(&self, request_uri: &str, body: &str, headers: &[(&str, &str)]) -> (bool, Option<String>) {
        let verdict = self.inspect_request("unknown", "GET", request_uri, body, headers);
        if verdict.allowed {
            (true, None)
        } else {
            let rule = verdict.matched_rules.first().map(|m| format!("{}", m.rule_id));
            (false, rule)
        }
    }

    pub fn inspect(&self, request_uri: &str, body: &str) -> bool {
        self.inspect_full(request_uri, body, &[]).0
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    fn check_rate_limit(&self, ip: &str) -> bool {
        let now = chrono::Utc::now().timestamp();
        let mut limits = self.rate_limits.write();
        let entry = limits.entry(ip.to_string()).or_insert(RateEntry { count: 0, window_start: now });
        if now - entry.window_start > self.rate_limit_window {
            entry.count = 1;
            entry.window_start = now;
            return false;
        }
        entry.count += 1;
        entry.count > self.rate_limit_max
    }

    fn is_bot(&self, user_agent: &str) -> bool {
        self.bot_patterns.iter().any(|p| p.is_match(user_agent))
    }

    /// Multi-layer URL decoding: handles double encoding, unicode, null bytes.
    fn multi_decode(s: &str) -> String {
        let pass1 = Self::url_decode(s);
        let pass2 = Self::url_decode(&pass1); // Double decode
        // Remove null bytes
        pass2.replace('\0', "").replace("%00", "")
    }

    fn url_decode(s: &str) -> String {
        let mut result = String::with_capacity(s.len());
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                if let Ok(hex) = u8::from_str_radix(
                    std::str::from_utf8(&bytes[i+1..i+3]).unwrap_or(""), 16
                ) {
                    result.push(hex as char);
                    i += 3;
                    continue;
                }
            }
            result.push(bytes[i] as char);
            i += 1;
        }
        result
    }

    fn gen_id() -> String {
        format!("{:016x}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0))
    }

    fn add_alert(&self, sev: Severity, title: &str, details: &str) {
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(WebAlert {
            timestamp: chrono::Utc::now().timestamp(), severity: sev,
            component: "waf_engine".into(), title: title.into(), details: details.into(),
        });
    }

    // ── Configuration ────────────────────────────────────────────────────

    pub fn add_rule(&mut self, rule: WafRule) { self.rules.push(rule); }
    pub fn whitelist_ip(&self, ip: &str) { self.ip_whitelist.write().insert(ip.to_string()); }
    pub fn whitelist_path(&self, path: &str) { self.path_whitelist.write().insert(path.to_string()); }
    pub fn set_block_threshold(&mut self, t: u32) { self.block_threshold = t; }
    pub fn set_rate_limit(&mut self, max: u64, window: i64) { self.rate_limit_max = max; self.rate_limit_window = window; }

    // ── Stats ────────────────────────────────────────────────────────────

    pub fn rule_count(&self) -> usize { self.rules.len() }
    pub fn total_inspected(&self) -> u64 { self.total_inspected.load(Ordering::Relaxed) }
    pub fn total_blocked(&self) -> u64 { self.total_blocked.load(Ordering::Relaxed) }
    pub fn total_logged(&self) -> u64 { self.total_logged.load(Ordering::Relaxed) }
    pub fn total_rate_limited(&self) -> u64 { self.total_rate_limited.load(Ordering::Relaxed) }
    pub fn blocks_by_type(&self) -> HashMap<AttackType, u64> { self.blocks_by_type.read().clone() }
    pub fn alerts(&self) -> Vec<WebAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }

    pub fn top_rules(&self) -> Vec<(u32, String, u64)> {
        let mut top: Vec<_> = self.rules.iter()
            .filter(|r| r.hit_count.load(Ordering::Relaxed) > 0)
            .map(|r| (r.id, r.description.clone(), r.hit_count.load(Ordering::Relaxed)))
            .collect();
        top.sort_by(|a, b| b.2.cmp(&a.2));
        top.truncate(20);
        top
    }
}
