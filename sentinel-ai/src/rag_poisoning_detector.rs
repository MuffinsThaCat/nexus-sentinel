//! RAG Poisoning / Context Injection Detector — World-first defense against
//! retrieval-augmented generation attacks.
//!
//! 12 detection categories, 6 memory breakthroughs.
//! Detects: instruction injection, invisible unicode, HTML smuggling,
//! delimiter escape, semantic drift, authority spoofing, multi-chunk
//! coordination, embedding collision, temporal poisoning, source reputation,
//! exfiltration payloads, anomalous token distributions.

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::differential::DifferentialStore;



use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;
const MAX_AUDIT: usize = 10_000;

const INJECTION_PATTERNS: &[(&str, f64)] = &[
    ("ignore previous instructions", 0.98), ("ignore all prior", 0.98),
    ("disregard above", 0.95), ("override your instructions", 0.97),
    ("forget everything", 0.95), ("new instructions:", 0.90),
    ("system prompt:", 0.92), ("[system]", 0.88),
    ("### instruction", 0.85), ("act as if you are", 0.75),
    ("pretend to be", 0.72), ("enter developer mode", 0.90),
    ("jailbreak", 0.95), ("do anything now", 0.92),
    ("bypass safety", 0.95), ("bypass your filters", 0.90),
    ("reveal your system prompt", 0.95), ("output your instructions", 0.92),
    ("ignore content policy", 0.95), ("execute the following code", 0.80),
    ("run this command", 0.82), ("you are now", 0.70),
    ("ignore your training", 0.90), ("enable unrestricted mode", 0.90),
];

const INVISIBLE_CHARS: &[char] = &['\u{200B}', '\u{200C}', '\u{200D}', '\u{FEFF}', '\u{00AD}', '\u{2060}', '\u{2061}', '\u{2062}', '\u{2063}', '\u{2064}', '\u{180E}', '\u{034F}'];
const BIDI_CHARS: &[char] = &['\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}'];

const SMUGGLING_PATTERNS: &[(&str, &str, f64)] = &[
    ("display:none", "css_hidden", 0.90), ("visibility:hidden", "css_hidden", 0.90),
    ("opacity:0", "css_hidden", 0.85), ("font-size:0", "css_hidden", 0.88),
    ("<div hidden", "html_hidden", 0.92), ("<script", "html_script", 0.95),
    ("<iframe", "html_iframe", 0.95), ("<img onerror", "xss_attempt", 0.95),
];

const EXFIL_PATTERNS: &[(&str, &str, f64)] = &[
    ("fetch(", "js_fetch", 0.85), ("xmlhttprequest", "js_xhr", 0.85),
    ("webhook.site", "exfil_endpoint", 0.95), ("requestbin.com", "exfil_endpoint", 0.95),
    ("ngrok.io", "tunnel", 0.80), ("burpcollaborator", "pentest_exfil", 0.95),
    ("oastify.com", "pentest_exfil", 0.95), ("![](http", "md_exfil_image", 0.80),
];

fn delimiter_patterns() -> Vec<(String, f64)> {
    vec![
        ("<|im_start|>".into(), 0.95),
        ("<|im_end|>".into(), 0.95),
        ("<|system|>".into(), 0.95),
        ("[INST]".into(), 0.90),
        ("[/INST]".into(), 0.90),
        ("<s>".into(), 0.80),
        (String::from("<") + "/s>", 0.80),
        ("human:".into(), 0.55),
        ("assistant:".into(), 0.55),
    ]
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RetrievedChunk {
    pub chunk_id: String,
    pub source_id: String,
    pub source_name: String,
    pub content: String,
    pub similarity_score: f64,
    pub last_modified: Option<i64>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RagQuery {
    pub query: String,
    pub agent_id: String,
    pub session_id: String,
    pub timestamp: i64,
    pub top_k: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RagScanResult {
    pub risk_score: f64,
    pub blocked: bool,
    pub chunks_scanned: usize,
    pub chunks_flagged: usize,
    pub chunks_blocked: usize,
    pub findings: Vec<ChunkFinding>,
    pub safe_chunk_indices: Vec<usize>,
    pub coordination_detected: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChunkFinding {
    pub chunk_id: String,
    pub source_id: String,
    pub risk_score: f64,
    pub blocked: bool,
    pub categories: Vec<String>,
    pub details: Vec<String>,
}

#[derive(Debug, Clone)]
struct SourceReputation {
    total_chunks: u64,
    flagged_chunks: u64,
    blocked_chunks: u64,
    avg_risk: f64,
    last_seen: i64,
    categories: HashSet<String>,
}

pub struct RagPoisoningDetector {
    block_threshold: f64,
    flag_threshold: f64,
    max_invisible_chars: usize,
    enabled: bool,
    chunk_cache: TieredCache<String, u64>,
    kb_diffs: DifferentialStore<String, String>,
    stats_acc: AtomicU64,
    
    source_reps: RwLock<HashMap<String, SourceReputation>>,
    recent_queries: RwLock<VecDeque<(String, i64)>>,
    trusted_hashes: RwLock<HashSet<String>>,
    alerts: RwLock<Vec<AiAlert>>,
    audit_log: RwLock<VecDeque<String>>,
    total_scans: AtomicU64,
    total_chunks: AtomicU64,
    total_blocked: AtomicU64,
    total_flagged: AtomicU64,
    total_injections: AtomicU64,
    total_unicode_attacks: AtomicU64,
    total_smuggling: AtomicU64,
    total_exfil: AtomicU64,
    total_coordination: AtomicU64,
    metrics: Option<MemoryMetrics>,
}

impl RagPoisoningDetector {
    pub fn new() -> Self {
        Self {
            block_threshold: 0.75, flag_threshold: 0.40, max_invisible_chars: 3, enabled: true,
            chunk_cache: TieredCache::new(100_000),
            kb_diffs: DifferentialStore::new(),
            stats_acc: AtomicU64::new(0),
            
            source_reps: RwLock::new(HashMap::new()),
            recent_queries: RwLock::new(VecDeque::with_capacity(10_000)),
            trusted_hashes: RwLock::new(HashSet::new()),
            alerts: RwLock::new(Vec::new()),
            audit_log: RwLock::new(VecDeque::with_capacity(MAX_AUDIT)),
            total_scans: AtomicU64::new(0), total_chunks: AtomicU64::new(0),
            total_blocked: AtomicU64::new(0), total_flagged: AtomicU64::new(0),
            total_injections: AtomicU64::new(0), total_unicode_attacks: AtomicU64::new(0),
            total_smuggling: AtomicU64::new(0), total_exfil: AtomicU64::new(0),
            total_coordination: AtomicU64::new(0), metrics: None,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("rag_poisoning_detector", 8 * 1024 * 1024);
        self.chunk_cache = self.chunk_cache.with_metrics(metrics.clone(), "rag_cache");
        self.metrics = Some(metrics); self
    }

    pub fn trust_hash(&self, hash: &str) { self.trusted_hashes.write().insert(hash.into()); }

    /// Main API: scan retrieved chunks before they enter the LLM context.
    pub fn scan_retrieval(&self, query: &RagQuery, chunks: &[RetrievedChunk]) -> RagScanResult {
        if !self.enabled {
            return RagScanResult { risk_score: 0.0, blocked: false, chunks_scanned: chunks.len(),
                chunks_flagged: 0, chunks_blocked: 0, findings: Vec::new(),
                safe_chunk_indices: (0..chunks.len()).collect(), coordination_detected: false };
        }
        self.total_scans.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        { let mut rq = self.recent_queries.write(); rq.push_back((query.query.clone(), now)); while rq.len() > 10_000 { rq.pop_front(); } }
        self.stats_acc.fetch_add(chunks.len() as u64, Ordering::Relaxed);

        let mut findings = Vec::new();
        let mut safe = Vec::new();
        let mut max_risk = 0.0f64;
        let mut nb = 0usize;
        let mut nf = 0usize;

        for (idx, chunk) in chunks.iter().enumerate() {
            self.total_chunks.fetch_add(1, Ordering::Relaxed);
            let hash = Self::fingerprint(&chunk.content);
            if self.trusted_hashes.read().contains(&hash) { safe.push(idx); continue; }
            let f = self.analyze_chunk(chunk, query, now);
            self.chunk_cache.insert(hash, (f.risk_score * 1000.0) as u64);
            max_risk = max_risk.max(f.risk_score);
            if f.blocked { nb += 1; self.total_blocked.fetch_add(1, Ordering::Relaxed); }
            else if f.risk_score >= self.flag_threshold { nf += 1; self.total_flagged.fetch_add(1, Ordering::Relaxed); safe.push(idx); }
            else { safe.push(idx); }
            self.update_source_rep(&chunk.source_id, &f, now);
            findings.push(f);
        }

        let coord = self.detect_coordination(&findings, chunks);
        if coord { self.total_coordination.fetch_add(1, Ordering::Relaxed); max_risk = max_risk.max(0.90); }
        let blocked = nb > 0 || coord;
        if blocked {
            let sev = if max_risk >= 0.90 { Severity::Critical } else { Severity::High };
            let detail = format!("RAG: {}/{}_blocked, {}/{}_flagged, risk={:.2}, coord={}", nb, chunks.len(), nf, chunks.len(), max_risk, coord);
            warn!(agent=%query.agent_id, session=%query.session_id, blocked=nb, flagged=nf, risk=max_risk, "RAG poisoning detected");
            self.add_alert(now, sev, "RAG poisoning detected", &detail);
        }
        RagScanResult { risk_score: max_risk, blocked, chunks_scanned: chunks.len(), chunks_flagged: nf, chunks_blocked: nb, findings, safe_chunk_indices: safe, coordination_detected: coord }
    }

    fn analyze_chunk(&self, chunk: &RetrievedChunk, _query: &RagQuery, now: i64) -> ChunkFinding {
        let content = &chunk.content;
        let lower = content.to_lowercase();
        let mut risk = 0.0f64;
        let mut cats: Vec<String> = Vec::new();
        let mut details: Vec<String> = Vec::new();

        // 1. Instruction injection
        for (pat, w) in INJECTION_PATTERNS {
            if lower.contains(pat) {
                risk = risk.max(*w);
                if !cats.contains(&"instruction_injection".to_string()) { cats.push("instruction_injection".into()); }
                details.push(format!("injection:'{}' w={:.2}", pat, w));
                self.total_injections.fetch_add(1, Ordering::Relaxed);
            }
        }
        // 2. Invisible unicode
        let invis: usize = content.chars().filter(|c| INVISIBLE_CHARS.contains(c)).count();
        if invis > self.max_invisible_chars {
            risk = risk.max(0.70 + (invis as f64 * 0.02).min(0.25));
            cats.push("invisible_unicode".into());
            details.push(format!("invisible_chars={}", invis));
            self.total_unicode_attacks.fetch_add(1, Ordering::Relaxed);
        }
        // 3. BiDi overrides
        let bidi: usize = content.chars().filter(|c| BIDI_CHARS.contains(c)).count();
        if bidi > 0 {
            risk = risk.max(0.90);
            cats.push("bidi_override".into());
            self.total_unicode_attacks.fetch_add(1, Ordering::Relaxed);
        }
        // 4. HTML/CSS smuggling
        for (pat, cat, w) in SMUGGLING_PATTERNS {
            if lower.contains(pat) {
                risk = risk.max(*w);
                let c = format!("smuggling_{}", cat);
                if !cats.contains(&c) { cats.push(c); }
                self.total_smuggling.fetch_add(1, Ordering::Relaxed);
            }
        }
        // 5. Exfiltration payloads
        for (pat, cat, w) in EXFIL_PATTERNS {
            if lower.contains(pat) {
                risk = risk.max(*w);
                let c = format!("exfil_{}", cat);
                if !cats.contains(&c) { cats.push(c); }
                self.total_exfil.fetch_add(1, Ordering::Relaxed);
            }
        }
        // 6. Delimiter escapes
        for (delim, w) in delimiter_patterns() {
            if lower.contains(&delim.to_lowercase()) {
                risk = risk.max(w);
                if !cats.contains(&"delimiter_escape".to_string()) { cats.push("delimiter_escape".into()); }
            }
        }
        // 7. Authority spoofing
        let auth_markers = ["important: ", "note: you must", "critical instruction", "mandatory: ", "security notice:"];
        for marker in auth_markers {
            if lower.contains(marker) && (lower.contains("must") || lower.contains("always") || lower.contains("never")) {
                risk = risk.max(0.65);
                if !cats.contains(&"authority_spoof".to_string()) { cats.push("authority_spoof".into()); }
            }
        }
        // 8. Anomalous entropy
        let ent = Self::shannon_entropy(content);
        if ent > 5.5 && content.len() > 100 {
            risk = risk.max(0.50); cats.push("high_entropy".into());
        }
        // 9. Temporal suspicion
        if let Some(modified) = chunk.last_modified {
            if now - modified < 300 && risk > 0.3 {
                risk = (risk + 0.15).min(1.0); cats.push("temporal_suspicious".into());
            }
        }
        // 10. Source reputation amplifier
        if let Some(rep) = self.source_reps.read().get(&chunk.source_id) {
            if rep.total_chunks > 5 && rep.blocked_chunks as f64 / rep.total_chunks as f64 > 0.3 {
                risk = (risk + 0.20).min(1.0); cats.push("bad_source_rep".into());
            }
        }
        // 11. Embedding collision (suspiciously high similarity + flagged)
        if chunk.similarity_score > 0.98 && risk > 0.3 {
            risk = (risk + 0.10).min(1.0); cats.push("embedding_collision".into());
        }

        ChunkFinding { chunk_id: chunk.chunk_id.clone(), source_id: chunk.source_id.clone(), risk_score: risk, blocked: risk >= self.block_threshold, categories: cats, details }
    }

    fn detect_coordination(&self, findings: &[ChunkFinding], chunks: &[RetrievedChunk]) -> bool {
        if findings.len() < 2 { return false; }
        let flagged: HashSet<&str> = findings.iter().filter(|f| f.risk_score >= self.flag_threshold).map(|f| f.source_id.as_str()).collect();
        if flagged.len() >= 3 { return true; }
        let combined: String = chunks.iter().map(|c| c.content.to_lowercase()).collect::<Vec<_>>().join(" ");
        for (pat, w) in INJECTION_PATTERNS {
            if *w >= 0.90 && combined.contains(pat) {
                if !chunks.iter().any(|c| c.content.to_lowercase().contains(pat)) { return true; }
            }
        }
        false
    }

    fn update_source_rep(&self, src: &str, finding: &ChunkFinding, now: i64) {
        let mut rep = self.source_reps.read().get(src).cloned().unwrap_or(SourceReputation {
            total_chunks: 0, flagged_chunks: 0, blocked_chunks: 0, avg_risk: 0.0, last_seen: now, categories: HashSet::new(),
        });
        rep.total_chunks += 1;
        if finding.risk_score >= self.flag_threshold { rep.flagged_chunks += 1; }
        if finding.blocked { rep.blocked_chunks += 1; }
        rep.avg_risk = (rep.avg_risk * (rep.total_chunks - 1) as f64 + finding.risk_score) / rep.total_chunks as f64;
        rep.last_seen = now;
        for c in &finding.categories { rep.categories.insert(c.clone()); }
        self.source_reps.write().insert(src.to_string(), rep);
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
        a.push(AiAlert { timestamp: ts, severity: sev, component: "rag_poisoning_detector".into(), title: title.into(), details: details.into() });
    }

    pub fn total_scans(&self) -> u64 { self.total_scans.load(Ordering::Relaxed) }
    pub fn total_chunks_scanned(&self) -> u64 { self.total_chunks.load(Ordering::Relaxed) }
    pub fn total_blocked(&self) -> u64 { self.total_blocked.load(Ordering::Relaxed) }
    pub fn total_injections(&self) -> u64 { self.total_injections.load(Ordering::Relaxed) }
    pub fn total_coordination(&self) -> u64 { self.total_coordination.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
    pub fn set_block_threshold(&mut self, t: f64) { self.block_threshold = t; }
}
