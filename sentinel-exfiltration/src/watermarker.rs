//! Watermarker — embeds invisible watermarks in sensitive data for tracking.
//!
//! Memory optimizations (2 techniques):
//! - **#2 Tiered Cache**: Hot lookups cached
//! - **#6 Theoretical Verifier**: Bound memory usage
use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::MemoryMetrics;use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_ALERTS: usize = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum WatermarkMethod {
    ZeroWidth,
    Whitespace,
    Homoglyph,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Watermark {
    pub document_id: String,
    pub user_id: String,
    pub watermark_hash: String,
    pub applied_at: i64,
    pub method: WatermarkMethod,
}

pub struct Watermarker {
    watermarks: RwLock<Vec<Watermark>>,
    alerts: RwLock<Vec<ExfilAlert>>,
    total_applied: AtomicU64,
    /// #2 Tiered cache
    _cache: TieredCache<String, u64>,
    /// #6 Theoretical verifier
    metrics: Option<MemoryMetrics>,    enabled: bool,
}

/// Zero-width Unicode characters used for steganographic embedding.
const ZW_SPACE: char = '\u{200B}';      // zero-width space
const ZW_NON_JOINER: char = '\u{200C}'; // zero-width non-joiner
const ZW_JOINER: char = '\u{200D}';     // zero-width joiner
const ZW_NO_BREAK: char = '\u{FEFF}';   // zero-width no-break space

impl Watermarker {
    pub fn new() -> Self {
        Self {
            watermarks: RwLock::new(Vec::new()),
            alerts: RwLock::new(Vec::new()),
            total_applied: AtomicU64::new(0),
            enabled: true,
            _cache: TieredCache::new(10_000),
            metrics: None,
        }
    }

    /// Apply an invisible watermark to text content.
    /// Embeds the watermark hash as zero-width Unicode characters between words.
    pub fn apply_to_text(&self, document_id: &str, user_id: &str, content: &str) -> (String, Watermark) {
        self.total_applied.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        let hash = Self::compute_hash(document_id, user_id, now);

        // Encode hash bits as zero-width characters
        let zw_sequence = Self::encode_hash_to_zw(&hash);

        // Embed zero-width sequence at word boundaries
        let watermarked = Self::embed_in_text(content, &zw_sequence);

        let wm = Watermark {
            document_id: document_id.into(),
            user_id: user_id.into(),
            watermark_hash: hash.clone(),
            applied_at: now,
            method: WatermarkMethod::ZeroWidth,
        };

        let mut w = self.watermarks.write();
        if w.len() >= MAX_ALERTS { w.remove(0); }
        w.push(wm.clone());
        (watermarked, wm)
    }

    /// Apply whitespace steganography: encode data in trailing spaces on lines.
    pub fn apply_whitespace(&self, document_id: &str, user_id: &str, content: &str) -> (String, Watermark) {
        self.total_applied.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        let hash = Self::compute_hash(document_id, user_id, now);

        let hash_bytes = hash.as_bytes();
        let lines: Vec<&str> = content.lines().collect();
        let mut result = Vec::new();

        for (i, line) in lines.iter().enumerate() {
            let byte_idx = i % hash_bytes.len();
            let byte_val = hash_bytes[byte_idx];
            // Encode 2 bits per line as trailing spaces (1-4 spaces)
            let bit_pair = (byte_val >> ((i / hash_bytes.len()) % 4 * 2)) & 0x03;
            let spaces = " ".repeat((bit_pair as usize) + 1);
            result.push(format!("{}{}", line, spaces));
        }

        let wm = Watermark {
            document_id: document_id.into(),
            user_id: user_id.into(),
            watermark_hash: hash.clone(),
            applied_at: now,
            method: WatermarkMethod::Whitespace,
        };

        let mut w = self.watermarks.write();
        if w.len() >= MAX_ALERTS { w.remove(0); }
        w.push(wm.clone());
        (result.join("\n"), wm)
    }

    /// Apply Unicode homoglyph substitution watermark.
    pub fn apply_homoglyph(&self, document_id: &str, user_id: &str, content: &str) -> (String, Watermark) {
        self.total_applied.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        let hash = Self::compute_hash(document_id, user_id, now);

        // Homoglyph map: ASCII -> similar-looking Unicode
        let homoglyphs: &[(char, char)] = &[
            ('a', '\u{0430}'), // Cyrillic а
            ('e', '\u{0435}'), // Cyrillic е
            ('o', '\u{043E}'), // Cyrillic о
            ('p', '\u{0440}'), // Cyrillic р
            ('c', '\u{0441}'), // Cyrillic с
            ('x', '\u{0445}'), // Cyrillic х
        ];

        let hash_bits: Vec<bool> = hash.bytes().flat_map(|b| (0..8).map(move |i| (b >> i) & 1 == 1)).collect();
        let mut result = String::with_capacity(content.len());
        let mut bit_idx = 0;

        for ch in content.chars() {
            if bit_idx < hash_bits.len() && hash_bits[bit_idx] {
                if let Some(&(_, replacement)) = homoglyphs.iter().find(|&&(orig, _)| orig == ch) {
                    result.push(replacement);
                    bit_idx += 1;
                    continue;
                }
            }
            result.push(ch);
            if ch.is_alphabetic() { bit_idx += 1; }
        }

        let wm = Watermark {
            document_id: document_id.into(),
            user_id: user_id.into(),
            watermark_hash: hash.clone(),
            applied_at: now,
            method: WatermarkMethod::Homoglyph,
        };

        let mut w = self.watermarks.write();
        if w.len() >= MAX_ALERTS { w.remove(0); }
        w.push(wm.clone());
        (result, wm)
    }

    /// Extract a zero-width watermark from text.
    pub fn extract_zw(&self, content: &str) -> Option<String> {
        let zw_chars: Vec<char> = content.chars().filter(|&c|
            c == ZW_SPACE || c == ZW_NON_JOINER || c == ZW_JOINER || c == ZW_NO_BREAK
        ).collect();
        if zw_chars.len() < 8 { return None; }
        Some(Self::decode_zw_to_hash(&zw_chars))
    }

    /// Verify a watermark by hash lookup.
    pub fn verify(&self, hash: &str) -> Option<Watermark> {
        self.watermarks.read().iter().find(|w| w.watermark_hash == hash).cloned()
    }

    /// Legacy API.
    pub fn apply(&self, document_id: &str, user_id: &str) -> String {
        let now = chrono::Utc::now().timestamp();
        let hash = Self::compute_hash(document_id, user_id, now);
        self.total_applied.fetch_add(1, Ordering::Relaxed);
        let wm = Watermark { document_id: document_id.into(), user_id: user_id.into(), watermark_hash: hash.clone(), applied_at: now, method: WatermarkMethod::ZeroWidth };
        let mut w = self.watermarks.write();
        if w.len() >= MAX_ALERTS { w.remove(0); }
        w.push(wm);
        hash
    }

    fn compute_hash(doc: &str, user: &str, ts: i64) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        doc.hash(&mut h);
        user.hash(&mut h);
        ts.hash(&mut h);
        format!("{:016x}", h.finish())
    }

    fn encode_hash_to_zw(hash: &str) -> Vec<char> {
        let symbols = [ZW_SPACE, ZW_NON_JOINER, ZW_JOINER, ZW_NO_BREAK];
        hash.bytes().flat_map(|b| {
            vec![symbols[((b >> 6) & 0x03) as usize],
                 symbols[((b >> 4) & 0x03) as usize],
                 symbols[((b >> 2) & 0x03) as usize],
                 symbols[(b & 0x03) as usize]]
        }).collect()
    }

    fn decode_zw_to_hash(chars: &[char]) -> String {
        let symbol_val = |c: char| -> u8 {
            match c {
                c if c == ZW_SPACE => 0,
                c if c == ZW_NON_JOINER => 1,
                c if c == ZW_JOINER => 2,
                c if c == ZW_NO_BREAK => 3,
                _ => 0,
            }
        };
        chars.chunks(4).map(|chunk| {
            let b = (symbol_val(chunk[0]) << 6) | (symbol_val(chunk.get(1).copied().unwrap_or(ZW_SPACE)) << 4)
                  | (symbol_val(chunk.get(2).copied().unwrap_or(ZW_SPACE)) << 2) | symbol_val(chunk.get(3).copied().unwrap_or(ZW_SPACE));
            b as char
        }).collect()
    }

    fn embed_in_text(content: &str, zw: &[char]) -> String {
        let mut result = String::with_capacity(content.len() + zw.len());
        let words: Vec<&str> = content.split(' ').collect();
        let mut zw_idx = 0;
        for (i, word) in words.iter().enumerate() {
            result.push_str(word);
            if i < words.len() - 1 {
                result.push(' ');
                if zw_idx < zw.len() {
                    result.push(zw[zw_idx]);
                    zw_idx += 1;
                }
            }
        }
        result
    }

    pub fn total_applied(&self) -> u64 { self.total_applied.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<ExfilAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
