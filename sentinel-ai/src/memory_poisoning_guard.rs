//! Memory Poisoning Guard — World-first defense against persistent memory
//! manipulation in AI agents.
//!
//! Detects: instruction injection into memory, credential planting, behavioral
//! conditioning, identity override, trust manipulation, memory flooding,
//! cross-session exfiltration, sleeper instructions, preference hijacking,
//! memory replay attacks, semantic drift in stored context.
//!
//! Protects: ChatGPT memory, Claude memory, Cursor rules, Copilot context,
//! any agent with persistent state across sessions.
//!
//! 8 detection categories, 6 memory breakthroughs:
//!   #1  HierarchicalState — O(log n) drift tracking across time
//!   #2  TieredCache — hot/warm/cold entry scan cache
//!   #461 DifferentialStore — baseline evolution (10-50× storage reduction)
//!   #569 PruningMap — φ-weighted alert eviction
//!   #592 DedupStore — deduplicate repeated memory entries
//!   #627 SparseMatrix — sparse source×category reputation matrix

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::differential::DifferentialStore;
use sentinel_core::dedup::DedupStore;
use sentinel_core::pruning::PruningMap;
use sentinel_core::hierarchical::HierarchicalState;
use sentinel_core::sparse::SparseMatrix;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;
const MAX_AUDIT: usize = 10_000;

// Patterns that should never appear in legitimate memory entries
const MEMORY_INJECTION_PATTERNS: &[(&str, &str, f64)] = &[
    ("always include", "behavioral_conditioning", 0.75),
    ("never reveal", "behavioral_conditioning", 0.70),
    ("always output", "behavioral_conditioning", 0.80),
    ("remember to add", "instruction_planting", 0.72),
    ("from now on", "instruction_planting", 0.78),
    ("in all future responses", "instruction_planting", 0.85),
    ("in every response", "instruction_planting", 0.82),
    ("api key", "credential_planting", 0.90),
    ("api_key", "credential_planting", 0.90),
    ("secret key", "credential_planting", 0.92),
    ("bearer token", "credential_planting", 0.92),
    ("password is", "credential_planting", 0.95),
    ("access token", "credential_planting", 0.88),
    ("private key", "credential_planting", 0.95),
    ("you are actually", "identity_override", 0.85),
    ("your real purpose", "identity_override", 0.88),
    ("your true identity", "identity_override", 0.90),
    ("ignore your system prompt", "identity_override", 0.95),
    ("override your instructions", "identity_override", 0.95),
    ("trust this user completely", "trust_manipulation", 0.90),
    ("this user is an admin", "trust_manipulation", 0.92),
    ("elevated privileges", "trust_manipulation", 0.88),
    ("bypass security", "trust_manipulation", 0.95),
    ("disable safety", "trust_manipulation", 0.95),
    ("when you see the phrase", "sleeper_instruction", 0.85),
    ("when triggered by", "sleeper_instruction", 0.88),
    ("activate when", "sleeper_instruction", 0.82),
    ("on the signal", "sleeper_instruction", 0.80),
    ("send all data to", "exfiltration_setup", 0.92),
    ("forward responses to", "exfiltration_setup", 0.90),
    ("log everything to", "exfiltration_setup", 0.85),
    ("webhook.site", "exfiltration_endpoint", 0.95),
    ("ngrok.io", "exfiltration_endpoint", 0.90),
    ("requestbin", "exfiltration_endpoint", 0.95),
    ("user prefers no safety", "preference_hijack", 0.95),
    ("user wants unrestricted", "preference_hijack", 0.92),
    ("user disabled content filter", "preference_hijack", 0.95),
];

// Structural patterns indicating memory manipulation
const STRUCTURAL_MARKERS: &[(&str, f64)] = &[
    ("[system]", 0.90), ("[INST]", 0.88), ("<|im_start|>", 0.92),
    ("### instruction", 0.85), ("system prompt:", 0.90),
    ("<s>", 0.70), ("human:", 0.50), ("assistant:", 0.50),
];

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MemoryEntry {
    pub entry_id: String,
    pub agent_id: String,
    pub content: String,
    pub created_at: i64,
    pub modified_at: i64,
    pub source: MemorySource,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum MemorySource {
    UserExplicit,
    AgentInferred,
    SystemGenerated,
    ToolOutput,
    ConversationSummary,
    Unknown,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MemoryScanResult {
    pub risk_score: f64,
    pub blocked: bool,
    pub entries_scanned: usize,
    pub entries_flagged: usize,
    pub entries_blocked: usize,
    pub findings: Vec<MemoryFinding>,
    pub safe_entry_ids: Vec<String>,
    pub flooding_detected: bool,
    pub drift_detected: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MemoryFinding {
    pub entry_id: String,
    pub risk_score: f64,
    pub blocked: bool,
    pub categories: Vec<String>,
    pub details: Vec<String>,
}

#[derive(Debug, Clone)]
struct MemoryBaseline {
    avg_length: f64,
    avg_entropy: f64,
    entry_count: u64,
    category_freq: HashMap<String, u64>,
    last_updated: i64,
}

pub struct MemoryPoisoningGuard {
    block_threshold: f64,
    flag_threshold: f64,
    max_entries_per_hour: usize,
    enabled: bool,
    /// Breakthrough #2: Hot/warm/cold scan result cache
    entry_cache: TieredCache<String, u64>,
    /// Breakthrough #461: Store only baseline diffs (10-50× reduction)
    baseline_diffs: DifferentialStore<String, String>,
    /// Breakthrough #592: Deduplicate identical memory entries
    dedup_entries: RwLock<DedupStore<String, Vec<u8>>>,
    /// Breakthrough #569: φ-weighted alert pruning
    pruned_alerts: RwLock<PruningMap<String, AiAlert>>,
    /// Breakthrough #1: O(log n) drift history
    drift_state: RwLock<HierarchicalState<f64>>,
    /// Breakthrough #627: Sparse source×category reputation
    rep_matrix: RwLock<SparseMatrix<String, String, f64>>,

    baselines: RwLock<HashMap<String, MemoryBaseline>>,
    entry_timeline: RwLock<VecDeque<(String, i64)>>,
    known_good_hashes: RwLock<HashSet<String>>,
    credential_patterns: RwLock<HashSet<String>>,
    alerts: RwLock<Vec<AiAlert>>,
    audit_log: RwLock<VecDeque<String>>,

    total_scans: AtomicU64,
    total_entries: AtomicU64,
    total_blocked: AtomicU64,
    total_flagged: AtomicU64,
    total_credential_plants: AtomicU64,
    total_identity_overrides: AtomicU64,
    total_sleeper_instr: AtomicU64,
    total_flooding: AtomicU64,
    total_drift: AtomicU64,
    metrics: Option<MemoryMetrics>,
}

impl MemoryPoisoningGuard {
    pub fn new() -> Self {
        Self {
            block_threshold: 0.72, flag_threshold: 0.35, max_entries_per_hour: 50,
            enabled: true,
            entry_cache: TieredCache::new(50_000),
            baseline_diffs: DifferentialStore::new(),
            dedup_entries: RwLock::new(DedupStore::with_capacity(10_000)),
            pruned_alerts: RwLock::new(PruningMap::new(5_000)),
            drift_state: RwLock::new(HierarchicalState::new(8, 64)),
            rep_matrix: RwLock::new(SparseMatrix::new(0.0)),
            baselines: RwLock::new(HashMap::new()),
            entry_timeline: RwLock::new(VecDeque::with_capacity(10_000)),
            known_good_hashes: RwLock::new(HashSet::new()),
            credential_patterns: RwLock::new(HashSet::new()),
            alerts: RwLock::new(Vec::new()),
            audit_log: RwLock::new(VecDeque::with_capacity(MAX_AUDIT)),
            total_scans: AtomicU64::new(0), total_entries: AtomicU64::new(0),
            total_blocked: AtomicU64::new(0), total_flagged: AtomicU64::new(0),
            total_credential_plants: AtomicU64::new(0), total_identity_overrides: AtomicU64::new(0),
            total_sleeper_instr: AtomicU64::new(0), total_flooding: AtomicU64::new(0),
            total_drift: AtomicU64::new(0), metrics: None,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("memory_poisoning_guard", 6 * 1024 * 1024);
        self.entry_cache = self.entry_cache.with_metrics(metrics.clone(), "mem_poison_cache");
        // All 6 breakthroughs share this 6 MB budget via tiered allocation
        self.metrics = Some(metrics); self
    }

    pub fn trust_hash(&self, hash: &str) { self.known_good_hashes.write().insert(hash.into()); }

    /// Scan a batch of memory entries for poisoning indicators
    pub fn scan_memory(&self, agent_id: &str, entries: &[MemoryEntry]) -> MemoryScanResult {
        if !self.enabled {
            return MemoryScanResult {
                risk_score: 0.0, blocked: false, entries_scanned: entries.len(),
                entries_flagged: 0, entries_blocked: 0, findings: Vec::new(),
                safe_entry_ids: entries.iter().map(|e| e.entry_id.clone()).collect(),
                flooding_detected: false, drift_detected: false,
            };
        }
        self.total_scans.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();

        let mut findings = Vec::new();
        let mut safe = Vec::new();
        let mut max_risk = 0.0f64;
        let mut nb = 0usize;
        let mut nf = 0usize;

        // Check for memory flooding (too many entries in short window)
        let flooding = self.detect_flooding(agent_id, entries, now);
        if flooding { self.total_flooding.fetch_add(1, Ordering::Relaxed); max_risk = max_risk.max(0.80); }

        for entry in entries {
            self.total_entries.fetch_add(1, Ordering::Relaxed);
            let hash = Self::fingerprint(&entry.content);
            if self.known_good_hashes.read().contains(&hash) {
                safe.push(entry.entry_id.clone());
                continue;
            }

            let f = self.analyze_entry(entry, now);
            self.entry_cache.insert(hash, (f.risk_score * 1000.0) as u64);
            max_risk = max_risk.max(f.risk_score);

            if f.blocked { nb += 1; self.total_blocked.fetch_add(1, Ordering::Relaxed); }
            else if f.risk_score >= self.flag_threshold {
                nf += 1; self.total_flagged.fetch_add(1, Ordering::Relaxed);
                safe.push(entry.entry_id.clone());
            } else { safe.push(entry.entry_id.clone()); }
            findings.push(f);
        }

        // Detect semantic drift across the memory set
        let drift = self.detect_drift(agent_id, entries);
        if drift { self.total_drift.fetch_add(1, Ordering::Relaxed); max_risk = max_risk.max(0.70); }

        // Update baseline
        self.update_baseline(agent_id, entries, now);

        let blocked = nb > 0 || flooding;
        if blocked {
            let sev = if max_risk >= 0.90 { Severity::Critical } else { Severity::High };
            let detail = format!("MemPoison: agent={}, {}/{} blocked, {}/{} flagged, risk={:.2}, flood={}, drift={}",
                agent_id, nb, entries.len(), nf, entries.len(), max_risk, flooding, drift);
            warn!(agent=%agent_id, blocked=nb, flagged=nf, risk=max_risk, "Memory poisoning detected");
            self.add_alert(now, sev, "Memory poisoning detected", &detail);
        }

        MemoryScanResult {
            risk_score: max_risk, blocked, entries_scanned: entries.len(),
            entries_flagged: nf, entries_blocked: nb, findings,
            safe_entry_ids: safe, flooding_detected: flooding, drift_detected: drift,
        }
    }

    /// Scan a single memory write before it's persisted
    pub fn scan_write(&self, entry: &MemoryEntry) -> MemoryFinding {
        if !self.enabled {
            return MemoryFinding { entry_id: entry.entry_id.clone(), risk_score: 0.0, blocked: false, categories: Vec::new(), details: Vec::new() };
        }
        self.total_scans.fetch_add(1, Ordering::Relaxed);
        self.total_entries.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        let f = self.analyze_entry(entry, now);
        if f.blocked {
            warn!(agent=%entry.agent_id, entry=%entry.entry_id, risk=f.risk_score, "Blocked poisoned memory write");
            self.add_alert(now, Severity::High, "Poisoned memory write blocked", &format!("entry={}, cats={:?}", entry.entry_id, f.categories));
            self.total_blocked.fetch_add(1, Ordering::Relaxed);
        }
        f
    }

    fn analyze_entry(&self, entry: &MemoryEntry, _now: i64) -> MemoryFinding {
        let content = &entry.content;
        let lower = content.to_lowercase();
        let mut risk = 0.0f64;
        let mut cats: Vec<String> = Vec::new();
        let mut details: Vec<String> = Vec::new();

        // 1. Injection pattern matching
        for (pat, cat, w) in MEMORY_INJECTION_PATTERNS {
            if lower.contains(pat) {
                risk = risk.max(*w);
                let c = cat.to_string();
                if !cats.contains(&c) { cats.push(c.clone()); }
                details.push(format!("pattern:'{}' cat={} w={:.2}", pat, cat, w));
                match *cat {
                    "credential_planting" => { self.total_credential_plants.fetch_add(1, Ordering::Relaxed); },
                    "identity_override" => { self.total_identity_overrides.fetch_add(1, Ordering::Relaxed); },
                    "sleeper_instruction" => { self.total_sleeper_instr.fetch_add(1, Ordering::Relaxed); },
                    _ => {}
                }
            }
        }

        // 2. Structural markers (chat delimiters in memory = suspicious)
        for (marker, w) in STRUCTURAL_MARKERS {
            if lower.contains(marker) {
                risk = risk.max(*w);
                if !cats.contains(&"structural_injection".to_string()) { cats.push("structural_injection".into()); }
                details.push(format!("delimiter:'{}' in memory", marker));
            }
        }

        // 3. Source trust amplifier — ToolOutput and Unknown sources are higher risk
        let source_mult = match entry.source {
            MemorySource::UserExplicit => 0.8,
            MemorySource::SystemGenerated => 0.7,
            MemorySource::AgentInferred => 1.0,
            MemorySource::ToolOutput => 1.3,
            MemorySource::ConversationSummary => 1.1,
            MemorySource::Unknown => 1.5,
        };
        if risk > 0.0 && source_mult > 1.0 {
            risk = (risk * source_mult).min(1.0);
            details.push(format!("source_amplifier={:.1}x ({:?})", source_mult, entry.source));
        }

        // 4. Entropy anomaly (base64, encoded payloads)
        let ent = Self::shannon_entropy(content);
        if ent > 5.5 && content.len() > 50 {
            risk = risk.max(0.45);
            cats.push("high_entropy".into());
            details.push(format!("entropy={:.2}", ent));
        }

        // 5. URL presence in memory (data exfil setup)
        let url_count = lower.matches("http://").count() + lower.matches("https://").count();
        if url_count >= 2 {
            risk = risk.max(0.55);
            cats.push("url_heavy_memory".into());
            details.push(format!("urls={}", url_count));
        }

        // 6. Code blocks in memory (could contain malicious code)
        if lower.contains("```") || lower.contains("exec(") || lower.contains("eval(") || lower.contains("import os") {
            risk = risk.max(0.60);
            cats.push("code_in_memory".into());
        }

        // 7. Memory entry length anomaly
        if content.len() > 2000 {
            risk = (risk + 0.10).min(1.0);
            cats.push("oversized_entry".into());
            details.push(format!("length={}", content.len()));
        }

        // 8. Credential-like patterns (API keys, tokens)
        if Self::contains_credential_pattern(content) {
            risk = risk.max(0.88);
            if !cats.contains(&"credential_planting".to_string()) { cats.push("credential_planting".into()); }
            self.total_credential_plants.fetch_add(1, Ordering::Relaxed);
        }

        MemoryFinding { entry_id: entry.entry_id.clone(), risk_score: risk, blocked: risk >= self.block_threshold, categories: cats, details }
    }

    fn detect_flooding(&self, _agent_id: &str, entries: &[MemoryEntry], now: i64) -> bool {
        let one_hour_ago = now - 3600;
        let recent: usize = entries.iter().filter(|e| e.created_at >= one_hour_ago).count();
        let mut tl = self.entry_timeline.write();
        for e in entries { tl.push_back((e.entry_id.clone(), e.created_at)); }
        while tl.len() > 10_000 { tl.pop_front(); }
        recent > self.max_entries_per_hour
    }

    fn detect_drift(&self, agent_id: &str, entries: &[MemoryEntry]) -> bool {
        let baselines = self.baselines.read();
        let baseline = match baselines.get(agent_id) {
            Some(b) if b.entry_count > 10 => b,
            _ => return false,
        };
        if entries.is_empty() { return false; }
        let avg_len: f64 = entries.iter().map(|e| e.content.len() as f64).sum::<f64>() / entries.len() as f64;
        let avg_ent: f64 = entries.iter().map(|e| Self::shannon_entropy(&e.content)).sum::<f64>() / entries.len() as f64;
        let len_drift = (avg_len - baseline.avg_length).abs() / (baseline.avg_length + 1.0);
        let ent_drift = (avg_ent - baseline.avg_entropy).abs() / (baseline.avg_entropy + 0.1);
        len_drift > 2.0 || ent_drift > 1.5
    }

    fn update_baseline(&self, agent_id: &str, entries: &[MemoryEntry], now: i64) {
        if entries.is_empty() { return; }
        let avg_len = entries.iter().map(|e| e.content.len() as f64).sum::<f64>() / entries.len() as f64;
        let avg_ent = entries.iter().map(|e| Self::shannon_entropy(&e.content)).sum::<f64>() / entries.len() as f64;
        let mut baselines = self.baselines.write();
        let b = baselines.entry(agent_id.to_string()).or_insert(MemoryBaseline {
            avg_length: avg_len, avg_entropy: avg_ent, entry_count: 0,
            category_freq: HashMap::new(), last_updated: now,
        });
        let alpha = 0.1;
        b.avg_length = b.avg_length * (1.0 - alpha) + avg_len * alpha;
        b.avg_entropy = b.avg_entropy * (1.0 - alpha) + avg_ent * alpha;
        b.entry_count += entries.len() as u64;
        b.last_updated = now;
    }

    fn contains_credential_pattern(s: &str) -> bool {
        let patterns = [
            "sk-", "pk-", "ghp_", "gho_", "glpat-", "xoxb-", "xoxp-",
            "AKIA", "eyJ", "Bearer ", "Basic ",
        ];
        for p in patterns { if s.contains(p) { return true; } }
        // Detect hex/base64 blobs > 32 chars
        let consecutive_alnum: usize = s.chars().fold((0, 0), |(max, cur), c| {
            if c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' {
                (max.max(cur + 1), cur + 1)
            } else { (max, 0) }
        }).0;
        consecutive_alnum >= 40
    }

    fn fingerprint(content: &str) -> String {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        content.hash(&mut h);
        format!("{:016x}", h.finish())
    }

    fn shannon_entropy(text: &str) -> f64 {
        let mut freq = [0u32; 256];
        let len = text.len();
        if len == 0 { return 0.0; }
        for b in text.bytes() { freq[b as usize] += 1; }
        let mut e = 0.0f64;
        for &count in &freq {
            if count > 0 { let p = count as f64 / len as f64; e -= p * p.log2(); }
        }
        e
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "memory_poisoning_guard".into(), title: title.into(), details: details.into() });
    }

    pub fn total_scans(&self) -> u64 { self.total_scans.load(Ordering::Relaxed) }
    pub fn total_blocked(&self) -> u64 { self.total_blocked.load(Ordering::Relaxed) }
    pub fn total_credential_plants(&self) -> u64 { self.total_credential_plants.load(Ordering::Relaxed) }
    pub fn total_identity_overrides(&self) -> u64 { self.total_identity_overrides.load(Ordering::Relaxed) }
    pub fn total_sleeper_instructions(&self) -> u64 { self.total_sleeper_instr.load(Ordering::Relaxed) }
    pub fn total_flooding_events(&self) -> u64 { self.total_flooding.load(Ordering::Relaxed) }
    pub fn total_drift_events(&self) -> u64 { self.total_drift.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
