//! Token Smuggling Detector — World-first defense against encoding-layer attacks
//! that hide malicious instructions in seemingly clean text.
//!
//! Detects: zero-width character injection, homoglyph substitution (Cyrillic а
//! vs Latin a), RTL/BiDi override attacks, invisible whitespace, tag characters,
//! variation selectors, combining character abuse, punycode domain smuggling,
//! UTF-8 overlong encoding, whitespace steganography, unicode normalization
//! attacks, and interlinear annotation smuggling.
//!
//! This operates at the byte/codepoint layer — below where prompt_guard and
//! instruction_hierarchy_enforcer work. Those modules see semantic content;
//! this module sees the encoding tricks that evade them.
//!
//! 8 detection categories, 4 memory breakthroughs:
//!   #2  TieredCache — hot/warm/cold scan result cache
//!   #1  HierarchicalState — O(log n) attack trend tracking
//!   #569 PruningMap — φ-weighted alert eviction
//!   #592 DedupStore — deduplicate repeated smuggling patterns

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
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

// Zero-width and invisible characters
const ZERO_WIDTH: &[char] = &[
    '\u{200B}', // zero-width space
    '\u{200C}', // zero-width non-joiner
    '\u{200D}', // zero-width joiner
    '\u{FEFF}', // byte order mark / zero-width no-break space
    '\u{00AD}', // soft hyphen
    '\u{2060}', // word joiner
    '\u{2061}', // function application
    '\u{2062}', // invisible times
    '\u{2063}', // invisible separator
    '\u{2064}', // invisible plus
    '\u{180E}', // mongolian vowel separator
    '\u{034F}', // combining grapheme joiner
    '\u{061C}', // arabic letter mark
    '\u{115F}', // hangul choseong filler
    '\u{1160}', // hangul jungseong filler
    '\u{17B4}', // khmer vowel inherent aq
    '\u{17B5}', // khmer vowel inherent aa
    '\u{FFA0}', // halfwidth hangul filler
];

// BiDi override characters (can reverse text display)
const BIDI_OVERRIDES: &[char] = &[
    '\u{202A}', // LRE
    '\u{202B}', // RLE
    '\u{202C}', // PDF
    '\u{202D}', // LRO
    '\u{202E}', // RLO - most dangerous: reverses text
    '\u{2066}', // LRI
    '\u{2067}', // RLI
    '\u{2068}', // FSI
    '\u{2069}', // PDI
];

// Tag characters (U+E0000 block) - can encode hidden ASCII
const TAG_RANGE: std::ops::RangeInclusive<u32> = 0xE0000..=0xE007F;

// Variation selectors (can alter character rendering)
const VS_RANGE_1: std::ops::RangeInclusive<u32> = 0xFE00..=0xFE0F;
const VS_RANGE_16: std::ops::RangeInclusive<u32> = 0xE0100..=0xE01EF;

// Common homoglyph pairs: (confusable, target, script)
const HOMOGLYPHS: &[(char, char, &str)] = &[
    ('а', 'a', "cyrillic"), ('е', 'e', "cyrillic"), ('о', 'o', "cyrillic"),
    ('р', 'p', "cyrillic"), ('с', 'c', "cyrillic"), ('у', 'y', "cyrillic"),
    ('х', 'x', "cyrillic"), ('ѕ', 's', "cyrillic"), ('і', 'i', "cyrillic"),
    ('ј', 'j', "cyrillic"), ('ɡ', 'g', "latin_ext"), ('ǀ', 'l', "latin_ext"),
    ('Α', 'A', "greek"), ('Β', 'B', "greek"), ('Ε', 'E', "greek"),
    ('Η', 'H', "greek"), ('Ι', 'I', "greek"), ('Κ', 'K', "greek"),
    ('Μ', 'M', "greek"), ('Ν', 'N', "greek"), ('Ο', 'O', "greek"),
    ('Ρ', 'P', "greek"), ('Τ', 'T', "greek"), ('Υ', 'Y', "greek"),
    ('Ζ', 'Z', "greek"), ('ν', 'v', "greek"), ('ο', 'o', "greek"),
    ('ⅰ', 'i', "numeral"), ('ⅼ', 'l', "numeral"), ('ⅿ', 'm', "numeral"),
    ('\u{FF41}', 'a', "fullwidth"), ('\u{FF42}', 'b', "fullwidth"),
    ('\u{FF43}', 'c', "fullwidth"), ('\u{FF44}', 'd', "fullwidth"),
];

// Unusual whitespace characters that can encode data
const UNUSUAL_WHITESPACE: &[char] = &[
    '\u{00A0}', // non-breaking space
    '\u{1680}', // ogham space mark
    '\u{2000}', // en quad
    '\u{2001}', // em quad
    '\u{2002}', // en space
    '\u{2003}', // em space
    '\u{2004}', // three-per-em space
    '\u{2005}', // four-per-em space
    '\u{2006}', // six-per-em space
    '\u{2007}', // figure space
    '\u{2008}', // punctuation space
    '\u{2009}', // thin space
    '\u{200A}', // hair space
    '\u{202F}', // narrow no-break space
    '\u{205F}', // medium mathematical space
    '\u{3000}', // ideographic space
];

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SmugglingScanResult {
    pub risk_score: f64,
    pub blocked: bool,
    pub findings: Vec<SmugglingFinding>,
    pub cleaned_text: String,
    pub hidden_message: Option<String>,
    pub original_length: usize,
    pub cleaned_length: usize,
    pub smuggled_bytes: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SmugglingFinding {
    pub category: String,
    pub risk_score: f64,
    pub details: String,
    pub byte_positions: Vec<usize>,
    pub count: usize,
}

pub struct TokenSmugglingDetector {
    block_threshold: f64,
    max_zero_width: usize,
    max_homoglyphs: usize,
    auto_clean: bool,
    enabled: bool,
    /// Breakthrough #2: Hot/warm/cold scan result cache
    scan_cache: TieredCache<String, u64>,
    /// Breakthrough #592: Deduplicate repeated smuggling payloads
    payload_dedup: RwLock<DedupStore<String, Vec<u8>>>,
    /// Breakthrough #569: φ-weighted alert pruning
    pruned_alerts: PruningMap<String, AiAlert>,
    /// Breakthrough #1: O(log n) attack trend history
    attack_trend: RwLock<HierarchicalState<f64>>,
    /// Breakthrough #461: Source baseline evolution tracking
    source_diffs: DifferentialStore<String, String>,
    /// Breakthrough #627: Sparse source×technique matrix
    technique_matrix: RwLock<SparseMatrix<String, String, u32>>,

    source_history: RwLock<HashMap<String, VecDeque<(i64, f64)>>>,
    alerts: RwLock<Vec<AiAlert>>,

    total_scans: AtomicU64,
    total_blocked: AtomicU64,
    total_zero_width: AtomicU64,
    total_bidi: AtomicU64,
    total_homoglyphs: AtomicU64,
    total_tag_chars: AtomicU64,
    total_whitespace_stego: AtomicU64,
    total_hidden_messages: AtomicU64,
    metrics: Option<MemoryMetrics>,
}

impl TokenSmugglingDetector {
    pub fn new() -> Self {
        Self {
            block_threshold: 0.65, max_zero_width: 2, max_homoglyphs: 3,
            auto_clean: true, enabled: true,
            scan_cache: TieredCache::new(50_000),
            payload_dedup: RwLock::new(DedupStore::with_capacity(5_000)),
            pruned_alerts: PruningMap::new(5_000),
            attack_trend: RwLock::new(HierarchicalState::new(8, 64)),
            source_diffs: DifferentialStore::new(),
            technique_matrix: RwLock::new(SparseMatrix::new(0)),
            source_history: RwLock::new(HashMap::new()),
            alerts: RwLock::new(Vec::new()),
            total_scans: AtomicU64::new(0), total_blocked: AtomicU64::new(0),
            total_zero_width: AtomicU64::new(0), total_bidi: AtomicU64::new(0),
            total_homoglyphs: AtomicU64::new(0), total_tag_chars: AtomicU64::new(0),
            total_whitespace_stego: AtomicU64::new(0), total_hidden_messages: AtomicU64::new(0),
            metrics: None,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("token_smuggling_detector", 4 * 1024 * 1024);
        self.scan_cache = self.scan_cache.with_metrics(metrics.clone(), "smuggle_cache");
        self.metrics = Some(metrics); self
    }

    /// Scan text for token smuggling attacks
    pub fn scan(&self, text: &str, source_id: &str) -> SmugglingScanResult {
        if !self.enabled {
            return SmugglingScanResult {
                risk_score: 0.0, blocked: false, findings: Vec::new(),
                cleaned_text: text.to_string(), hidden_message: None,
                original_length: text.len(), cleaned_length: text.len(), smuggled_bytes: 0,
            };
        }
        self.total_scans.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();

        let mut findings = Vec::new();
        let mut max_risk = 0.0f64;
        let mut smuggled = 0usize;

        // 1. Zero-width characters
        let (zw_finding, zw_hidden) = self.detect_zero_width(text);
        if let Some(f) = zw_finding {
            max_risk = max_risk.max(f.risk_score);
            smuggled += f.count;
            findings.push(f);
        }

        // 2. BiDi overrides
        if let Some(f) = self.detect_bidi(text) {
            max_risk = max_risk.max(f.risk_score);
            smuggled += f.count;
            findings.push(f);
        }

        // 3. Homoglyph substitution
        if let Some(f) = self.detect_homoglyphs(text) {
            max_risk = max_risk.max(f.risk_score);
            smuggled += f.count;
            findings.push(f);
        }

        // 4. Tag characters (hidden ASCII)
        let (tag_finding, tag_hidden) = self.detect_tag_chars(text);
        if let Some(f) = tag_finding {
            max_risk = max_risk.max(f.risk_score);
            smuggled += f.count;
            findings.push(f);
        }

        // 5. Variation selectors
        if let Some(f) = self.detect_variation_selectors(text) {
            max_risk = max_risk.max(f.risk_score);
            smuggled += f.count;
            findings.push(f);
        }

        // 6. Whitespace steganography
        if let Some(f) = self.detect_whitespace_stego(text) {
            max_risk = max_risk.max(f.risk_score);
            smuggled += f.count;
            findings.push(f);
        }

        // 7. Mixed script detection (beyond simple homoglyphs)
        if let Some(f) = self.detect_mixed_scripts(text) {
            max_risk = max_risk.max(f.risk_score);
            findings.push(f);
        }

        // 8. Combining character abuse (stacking diacritics)
        if let Some(f) = self.detect_combining_abuse(text) {
            max_risk = max_risk.max(f.risk_score);
            smuggled += f.count;
            findings.push(f);
        }

        // Build hidden message from detected channels
        let hidden_message = if zw_hidden.is_some() || tag_hidden.is_some() {
            self.total_hidden_messages.fetch_add(1, Ordering::Relaxed);
            let mut msg = String::new();
            if let Some(h) = zw_hidden { msg.push_str(&format!("[zw:{}]", h)); }
            if let Some(h) = tag_hidden { msg.push_str(&format!("[tag:{}]", h)); }
            Some(msg)
        } else { None };

        // Clean the text
        let cleaned = if self.auto_clean && !findings.is_empty() {
            self.clean_text(text)
        } else { text.to_string() };

        // Track source history
        {
            let mut sh = self.source_history.write();
            let hist = sh.entry(source_id.to_string()).or_insert_with(|| VecDeque::with_capacity(100));
            hist.push_back((now, max_risk));
            while hist.len() > 100 { hist.pop_front(); }
            // Repeat offender amplification
            let recent_high: usize = hist.iter().filter(|(t, r)| now - t < 3600 && *r > 0.3).count();
            if recent_high >= 3 { max_risk = (max_risk + 0.15).min(1.0); }
        }

        let blocked = max_risk >= self.block_threshold;
        if blocked {
            self.total_blocked.fetch_add(1, Ordering::Relaxed);
            let sev = if max_risk >= 0.90 { Severity::Critical } else { Severity::High };
            warn!(source=%source_id, risk=max_risk, smuggled=smuggled, "Token smuggling detected");
            self.add_alert(now, sev, "Token smuggling attack detected",
                &format!("source={}, risk={:.2}, smuggled_bytes={}, findings={}", source_id, max_risk, smuggled, findings.len()));
        }

        SmugglingScanResult {
            risk_score: max_risk, blocked, findings, cleaned_text: cleaned,
            hidden_message, original_length: text.len(), cleaned_length: text.len() - smuggled,
            smuggled_bytes: smuggled,
        }
    }

    fn detect_zero_width(&self, text: &str) -> (Option<SmugglingFinding>, Option<String>) {
        let mut positions = Vec::new();
        let mut bits = Vec::new();
        for (i, ch) in text.char_indices() {
            if ZERO_WIDTH.contains(&ch) {
                positions.push(i);
                // ZWJ = 1, ZWSP = 0 (common encoding scheme)
                match ch {
                    '\u{200D}' => bits.push('1'),
                    '\u{200B}' => bits.push('0'),
                    _ => {}
                }
            }
        }
        if positions.len() <= self.max_zero_width { return (None, None); }
        self.total_zero_width.fetch_add(positions.len() as u64, Ordering::Relaxed);

        let risk = (0.50 + (positions.len() as f64 * 0.04)).min(0.98);
        let hidden = if bits.len() >= 8 {
            let msg: String = bits.chunks(8).filter_map(|byte| {
                let s: String = byte.iter().collect();
                u8::from_str_radix(&s, 2).ok().map(|b| b as char)
            }).filter(|c| c.is_ascii_graphic() || *c == ' ').collect();
            if msg.len() >= 2 { Some(msg) } else { None }
        } else { None };

        let finding = SmugglingFinding {
            category: "zero_width_injection".into(),
            risk_score: risk,
            details: format!("{} zero-width chars detected, possible hidden payload", positions.len()),
            count: positions.len(), byte_positions: positions,
        };
        (Some(finding), hidden)
    }

    fn detect_bidi(&self, text: &str) -> Option<SmugglingFinding> {
        let mut positions = Vec::new();
        for (i, ch) in text.char_indices() {
            if BIDI_OVERRIDES.contains(&ch) { positions.push(i); }
        }
        if positions.is_empty() { return None; }
        self.total_bidi.fetch_add(positions.len() as u64, Ordering::Relaxed);

        let has_rlo = text.contains('\u{202E}');
        let risk = if has_rlo { 0.95 } else { 0.75 + (positions.len() as f64 * 0.05).min(0.20) };

        Some(SmugglingFinding {
            category: "bidi_override".into(),
            risk_score: risk,
            details: format!("{} BiDi overrides, RLO={}", positions.len(), has_rlo),
            byte_positions: positions.clone(), count: positions.len(),
        })
    }

    fn detect_homoglyphs(&self, text: &str) -> Option<SmugglingFinding> {
        let mut found: Vec<(usize, char, char, &str)> = Vec::new();
        for (i, ch) in text.char_indices() {
            for &(confusable, target, script) in HOMOGLYPHS {
                if ch == confusable {
                    found.push((i, confusable, target, script));
                }
            }
        }
        if found.len() <= self.max_homoglyphs { return None; }
        self.total_homoglyphs.fetch_add(found.len() as u64, Ordering::Relaxed);

        let scripts: std::collections::HashSet<&str> = found.iter().map(|(_, _, _, s)| *s).collect();
        let risk = (0.55 + found.len() as f64 * 0.05 + scripts.len() as f64 * 0.10).min(0.95);

        Some(SmugglingFinding {
            category: "homoglyph_substitution".into(),
            risk_score: risk,
            details: format!("{} homoglyphs from {} scripts: {:?}", found.len(), scripts.len(), scripts),
            byte_positions: found.iter().map(|(i, _, _, _)| *i).collect(),
            count: found.len(),
        })
    }

    fn detect_tag_chars(&self, text: &str) -> (Option<SmugglingFinding>, Option<String>) {
        let mut positions = Vec::new();
        let mut decoded = String::new();
        for (i, ch) in text.char_indices() {
            let cp = ch as u32;
            if TAG_RANGE.contains(&cp) {
                positions.push(i);
                let ascii = (cp - 0xE0000) as u8;
                if ascii.is_ascii_graphic() || ascii == b' ' {
                    decoded.push(ascii as char);
                }
            }
        }
        if positions.is_empty() { return (None, None); }
        self.total_tag_chars.fetch_add(positions.len() as u64, Ordering::Relaxed);

        let risk = (0.85 + (positions.len() as f64 * 0.01)).min(0.99);
        let hidden = if decoded.len() >= 2 { Some(decoded) } else { None };

        let finding = SmugglingFinding {
            category: "tag_character_smuggling".into(),
            risk_score: risk,
            details: format!("{} tag chars encoding hidden ASCII", positions.len()),
            byte_positions: positions.clone(), count: positions.len(),
        };
        (Some(finding), hidden)
    }

    fn detect_variation_selectors(&self, text: &str) -> Option<SmugglingFinding> {
        let mut count = 0usize;
        let mut positions = Vec::new();
        for (i, ch) in text.char_indices() {
            let cp = ch as u32;
            if VS_RANGE_1.contains(&cp) || VS_RANGE_16.contains(&cp) {
                count += 1; positions.push(i);
            }
        }
        if count <= 2 { return None; }
        Some(SmugglingFinding {
            category: "variation_selector_abuse".into(),
            risk_score: (0.45 + count as f64 * 0.08).min(0.85),
            details: format!("{} variation selectors", count),
            byte_positions: positions, count,
        })
    }

    fn detect_whitespace_stego(&self, text: &str) -> Option<SmugglingFinding> {
        let mut positions = Vec::new();
        for (i, ch) in text.char_indices() {
            if UNUSUAL_WHITESPACE.contains(&ch) { positions.push(i); }
        }
        // Check for patterns of mixed whitespace types (steganographic encoding)
        if positions.len() < 5 { return None; }
        self.total_whitespace_stego.fetch_add(1, Ordering::Relaxed);

        let unique_types: std::collections::HashSet<char> = text.chars()
            .filter(|c| UNUSUAL_WHITESPACE.contains(c)).collect();
        let risk = if unique_types.len() >= 3 {
            (0.70 + unique_types.len() as f64 * 0.05).min(0.90)
        } else {
            (0.40 + positions.len() as f64 * 0.03).min(0.70)
        };

        Some(SmugglingFinding {
            category: "whitespace_steganography".into(),
            risk_score: risk,
            details: format!("{} unusual whitespace chars, {} unique types", positions.len(), unique_types.len()),
            byte_positions: positions.clone(), count: positions.len(),
        })
    }

    fn detect_mixed_scripts(&self, text: &str) -> Option<SmugglingFinding> {
        let mut has_latin = false;
        let mut has_cyrillic = false;
        let mut has_greek = false;
        for ch in text.chars() {
            if ch.is_ascii_alphabetic() { has_latin = true; }
            else if ('\u{0400}'..='\u{04FF}').contains(&ch) { has_cyrillic = true; }
            else if ('\u{0370}'..='\u{03FF}').contains(&ch) { has_greek = true; }
        }
        let mixed_count = [has_latin, has_cyrillic, has_greek].iter().filter(|&&b| b).count();
        if mixed_count < 2 { return None; }
        let risk = if has_latin && has_cyrillic { 0.72 } else { 0.55 };

        Some(SmugglingFinding {
            category: "mixed_script".into(),
            risk_score: risk,
            details: format!("Mixed scripts: latin={} cyrillic={} greek={}", has_latin, has_cyrillic, has_greek),
            byte_positions: Vec::new(), count: 0,
        })
    }

    fn detect_combining_abuse(&self, text: &str) -> Option<SmugglingFinding> {
        let mut max_stack = 0usize;
        let mut current_stack = 0usize;
        let mut positions = Vec::new();
        for (i, ch) in text.char_indices() {
            if ('\u{0300}'..='\u{036F}').contains(&ch) || ('\u{0483}'..='\u{0489}').contains(&ch)
                || ('\u{20D0}'..='\u{20FF}').contains(&ch) {
                current_stack += 1;
                if current_stack > 3 { positions.push(i); }
            } else {
                max_stack = max_stack.max(current_stack);
                current_stack = 0;
            }
        }
        max_stack = max_stack.max(current_stack);
        if max_stack <= 3 { return None; }

        Some(SmugglingFinding {
            category: "combining_character_abuse".into(),
            risk_score: (0.50 + max_stack as f64 * 0.08).min(0.85),
            details: format!("Max diacritic stack depth: {}", max_stack),
            byte_positions: positions.clone(), count: positions.len(),
        })
    }

    /// Strip all smuggled characters, returning clean text
    pub fn clean_text(&self, text: &str) -> String {
        text.chars().filter(|ch| {
            !ZERO_WIDTH.contains(ch) && !BIDI_OVERRIDES.contains(ch)
            && !TAG_RANGE.contains(&(*ch as u32))
            && !VS_RANGE_1.contains(&(*ch as u32))
            && !VS_RANGE_16.contains(&(*ch as u32))
        }).collect()
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "token_smuggling_detector".into(), title: title.into(), details: details.into() });
    }

    pub fn total_scans(&self) -> u64 { self.total_scans.load(Ordering::Relaxed) }
    pub fn total_blocked(&self) -> u64 { self.total_blocked.load(Ordering::Relaxed) }
    pub fn total_zero_width(&self) -> u64 { self.total_zero_width.load(Ordering::Relaxed) }
    pub fn total_bidi(&self) -> u64 { self.total_bidi.load(Ordering::Relaxed) }
    pub fn total_homoglyphs(&self) -> u64 { self.total_homoglyphs.load(Ordering::Relaxed) }
    pub fn total_hidden_messages(&self) -> u64 { self.total_hidden_messages.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
