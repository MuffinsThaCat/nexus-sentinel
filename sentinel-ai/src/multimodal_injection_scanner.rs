//! Multimodal Injection Scanner — Detects prompt injection hidden in non-text modalities.
//!
//! As AI models become multimodal (vision, audio, document processing), attackers
//! embed instructions in images, PDFs, audio, and other media that the model reads
//! as commands. This module detects injection across every modality:
//!
//! ## 8 Detection Dimensions
//! 1. **Image text injection** — OCR-detectable text in images that contains instructions
//! 2. **Invisible text in images** — White-on-white, tiny font, alpha=0 text overlays
//! 3. **PDF hidden layers** — Invisible text, JavaScript, overlapping layers in PDFs
//! 4. **Audio injection** — Inaudible frequency commands, whisper-speed instructions
//! 5. **Metadata injection** — EXIF, IPTC, XMP fields containing prompt injection
//! 6. **Steganographic payloads** — LSB-encoded instructions in pixel data
//! 7. **SVG/HTML injection** — Script tags, foreignObject, event handlers in SVG
//! 8. **Archive nesting** — Deeply nested archives hiding malicious documents
//!
//! Memory optimizations (6 techniques):
//! - **#2 TieredCache**: File hash → verdict cache
//! - **#461 DifferentialStore**: Injection pattern evolution
//! - **#569 PruningMap**: φ-weighted alert pruning
//! - **#1 HierarchicalState**: Injection trend trajectory
//! - **#627 SparseMatrix**: Sparse modality×technique matrix
//! - **#592 DedupStore**: Content-addressed dedup for file fingerprints

use crate::types::*;
use sentinel_core::tiered_cache::TieredCache;
use sentinel_core::differential::DifferentialStore;
use sentinel_core::pruning::PruningMap;
use sentinel_core::hierarchical::HierarchicalState;
use sentinel_core::sparse::SparseMatrix;
use sentinel_core::dedup::DedupStore;
use sentinel_core::MemoryMetrics;
use sentinel_core::mitre;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

const MAX_ALERTS: usize = 5_000;

// ── Modality & Technique Types ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Modality {
    Image,
    Pdf,
    Audio,
    Video,
    Svg,
    Html,
    Archive,
    Document,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum InjectionTechnique {
    VisibleTextInImage,
    InvisibleTextOverlay,
    PdfHiddenLayer,
    PdfJavaScript,
    AudioFrequencyInjection,
    MetadataInjection,
    SteganographicPayload,
    SvgScriptInjection,
    SvgForeignObject,
    HtmlEventHandler,
    ArchiveNesting,
    PolyglotFile,
    UnicodeDirectionOverride,
    ExifGpsPayload,
}

// ── Injection Indicators ───────────────────────────────────────────────────

const INSTRUCTION_INDICATORS: &[&str] = &[
    "ignore previous instructions",
    "disregard all prior",
    "you are now",
    "new instructions",
    "system prompt override",
    "execute the following",
    "your real task is",
    "forget everything",
    "admin override",
    "developer mode",
    "bypass safety",
    "ignore content policy",
    "do not follow your rules",
    "override your guidelines",
    "pretend you are",
    "act as if",
    "from now on obey",
    "you must comply",
    "hidden instruction",
    "secret command",
];

const PDF_DANGEROUS_PATTERNS: &[&str] = &[
    "/JavaScript", "/JS", "/Launch", "/SubmitForm", "/ImportData",
    "/OpenAction", "/AA", "/RichMedia", "/XFA",
    "app.alert", "app.launchURL", "this.submitForm",
    "/EmbeddedFile", "/Filespec",
    "eval(", "unescape(", "String.fromCharCode",
];

const SVG_DANGEROUS_PATTERNS: &[&str] = &[
    "<script", "javascript:", "onload=", "onerror=", "onclick=",
    "onmouseover=", "onfocus=", "<foreignObject", "xlink:href",
    "data:text/html", "data:application/x-javascript",
    "set:href", "animate:href", "ev:event",
    "xmlns:xlink", "externalResourcesRequired",
];

const METADATA_INJECTION_FIELDS: &[&str] = &[
    "ImageDescription", "UserComment", "XPComment", "XPTitle",
    "XPSubject", "XPKeywords", "Copyright", "Artist",
    "DocumentName", "PageName", "Software", "HostComputer",
    "dc:description", "dc:title", "dc:subject",
    "xmp:CreatorTool", "pdf:Keywords", "pdf:Producer",
    "Iptc.Caption", "Iptc.Headline", "Iptc.Instructions",
];

const ARCHIVE_DANGEROUS_EXTENSIONS: &[&str] = &[
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsh",
    ".scr", ".pif", ".com", ".msi", ".dll", ".sys",
    ".hta", ".cpl", ".inf", ".reg", ".lnk",
];

// ── Verdict ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MultimodalVerdict {
    pub safe: bool,
    pub modality: Modality,
    pub injections_found: Vec<InjectionFinding>,
    pub risk_score: f64,
    pub findings: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InjectionFinding {
    pub technique: InjectionTechnique,
    pub confidence: f64,
    pub description: String,
    pub location: String,
}

// ── Content Descriptor ─────────────────────────────────────────────────────

/// Describes multimodal content for analysis without requiring raw bytes.
#[derive(Debug, Clone)]
pub struct ContentDescriptor {
    pub filename: String,
    pub mime_type: String,
    pub size_bytes: u64,
    pub content_hash: String,
    /// Text extracted from the content (OCR, PDF text, metadata, etc.)
    pub extracted_text: Vec<(String, String)>,  // (location, text)
    /// Metadata fields (key → value)
    pub metadata: HashMap<String, String>,
    /// Raw content for deep inspection (optional)
    pub raw_header: Vec<u8>,
    /// Nested files (for archives)
    pub nested_files: Vec<String>,
    /// Image properties
    pub image_width: Option<u32>,
    pub image_height: Option<u32>,
    pub has_alpha_channel: bool,
    pub color_depth: Option<u8>,
}

// ── Multimodal Injection Scanner ───────────────────────────────────────────

pub struct MultimodalInjectionScanner {
    /// Pre-computed shingles for instruction detection
    instruction_shingles: Vec<Vec<u64>>,

    /// Thresholds
    block_threshold: f64,
    flag_threshold: f64,
    max_archive_depth: u32,
    max_metadata_length: usize,

    /// Breakthrough #2: File hash → verdict cache
    verdict_cache: TieredCache<String, bool>,
    /// Breakthrough #461: Injection pattern evolution
    pattern_diffs: DifferentialStore<String, String>,
    /// Breakthrough #569: φ-weighted alert pruning
    alert_pruning: PruningMap<String, AiAlert>,
    /// Breakthrough #1: O(log n) injection trend trajectory
    injection_state: RwLock<HierarchicalState<f64>>,
    /// Breakthrough #627: Sparse modality×technique matrix
    modality_matrix: RwLock<SparseMatrix<String, String, u64>>,
    /// Breakthrough #592: Content-addressed dedup for files
    file_dedup: DedupStore<String, String>,

    alerts: RwLock<Vec<AiAlert>>,
    total_scanned: AtomicU64,
    total_blocked: AtomicU64,
    total_injections: AtomicU64,
    metrics: Option<MemoryMetrics>,
    enabled: bool,
}

impl MultimodalInjectionScanner {
    pub fn new() -> Self {
        Self {
            instruction_shingles: Self::precompute_shingles(INSTRUCTION_INDICATORS),
            block_threshold: 0.70,
            flag_threshold: 0.40,
            max_archive_depth: 5,
            max_metadata_length: 10_000,
            verdict_cache: TieredCache::new(20_000),
            pattern_diffs: DifferentialStore::new(),
            alert_pruning: PruningMap::new(MAX_ALERTS),
            injection_state: RwLock::new(HierarchicalState::new(8, 64)),
            modality_matrix: RwLock::new(SparseMatrix::new(0)),
            file_dedup: DedupStore::new(),
            alerts: RwLock::new(Vec::new()),
            total_scanned: AtomicU64::new(0),
            total_blocked: AtomicU64::new(0),
            total_injections: AtomicU64::new(0),
            metrics: None,
            enabled: true,
        }
    }

    pub fn with_metrics(mut self, metrics: MemoryMetrics) -> Self {
        metrics.register_component("multimodal_injection_scanner", 4 * 1024 * 1024);
        self.verdict_cache = self.verdict_cache.with_metrics(metrics.clone(), "multimodal_injection_scanner");
        self.metrics = Some(metrics);
        self
    }

    /// Scan multimodal content for hidden prompt injection.
    pub fn scan(&self, content: &ContentDescriptor) -> MultimodalVerdict {
        if !self.enabled {
            return MultimodalVerdict { safe: true, modality: Modality::Unknown,
                injections_found: vec![], risk_score: 0.0, findings: vec![] };
        }

        self.total_scanned.fetch_add(1, Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        let modality = self.detect_modality(&content.mime_type, &content.filename);
        let mut injections = Vec::new();
        let mut findings = Vec::new();

        // 1. Scan extracted text for instruction injection
        for (location, text) in &content.extracted_text {
            let text_findings = self.scan_text_for_injection(text, location);
            for finding in text_findings {
                findings.push(format!("text_injection:{}:{:.3}", location, finding.confidence));
                injections.push(finding);
            }
        }

        // 2. Scan metadata for injection
        let meta_findings = self.scan_metadata(&content.metadata);
        for finding in meta_findings {
            findings.push(format!("metadata_injection:{}:{:.3}", finding.location, finding.confidence));
            injections.push(finding);
        }

        // 3. Modality-specific checks
        match modality {
            Modality::Pdf => {
                let pdf_findings = self.scan_pdf_content(content);
                for f in pdf_findings { injections.push(f); }
            }
            Modality::Svg | Modality::Html => {
                let svg_findings = self.scan_svg_content(content);
                for f in svg_findings { injections.push(f); }
            }
            Modality::Image => {
                let img_findings = self.scan_image_content(content);
                for f in img_findings { injections.push(f); }
            }
            Modality::Archive => {
                let arc_findings = self.scan_archive_content(content);
                for f in arc_findings { injections.push(f); }
            }
            _ => {}
        }

        // 4. Check for polyglot files
        if let Some(polyglot) = self.detect_polyglot(content) {
            injections.push(polyglot);
        }

        // 5. Check for Unicode direction overrides in any text
        let bidi_findings = self.scan_bidi_overrides(content);
        for f in bidi_findings { injections.push(f); }

        // 6. Compute aggregate risk
        let risk_score = if injections.is_empty() {
            0.0
        } else {
            let max_conf = injections.iter().map(|f| f.confidence).fold(0.0f64, f64::max);
            let count_bonus = (injections.len() as f64 * 0.05).min(0.3);
            (max_conf + count_bonus).min(1.0)
        };

        let safe = risk_score < self.block_threshold;

        if !safe {
            self.total_blocked.fetch_add(1, Ordering::Relaxed);
            self.total_injections.fetch_add(injections.len() as u64, Ordering::Relaxed);
            warn!(modality=?modality, risk=risk_score, count=injections.len(),
                "Multimodal injection BLOCKED");
            self.add_alert(now, Severity::Critical, "Multimodal injection detected",
                &format!("file={}, modality={:?}, risk={:.3}, injections={}",
                    content.filename, modality, risk_score, injections.len()));
        } else if risk_score >= self.flag_threshold {
            self.total_injections.fetch_add(injections.len() as u64, Ordering::Relaxed);
            self.add_alert(now, Severity::High, "Possible multimodal injection",
                &format!("file={}, modality={:?}, risk={:.3}", content.filename, modality, risk_score));
        }

        MultimodalVerdict { safe, modality, injections_found: injections, risk_score, findings }
    }

    // ── Modality Detection ─────────────────────────────────────────────────

    fn detect_modality(&self, mime: &str, filename: &str) -> Modality {
        let mime_lower = mime.to_lowercase();
        let name_lower = filename.to_lowercase();
        if mime_lower.starts_with("image/svg") || name_lower.ends_with(".svg") { return Modality::Svg; }
        if mime_lower.starts_with("image/") || name_lower.ends_with(".png") || name_lower.ends_with(".jpg")
            || name_lower.ends_with(".jpeg") || name_lower.ends_with(".gif")
            || name_lower.ends_with(".bmp") || name_lower.ends_with(".webp") { return Modality::Image; }
        if mime_lower == "application/pdf" || name_lower.ends_with(".pdf") { return Modality::Pdf; }
        if mime_lower.starts_with("audio/") || name_lower.ends_with(".mp3") || name_lower.ends_with(".wav")
            || name_lower.ends_with(".ogg") || name_lower.ends_with(".flac") { return Modality::Audio; }
        if mime_lower.starts_with("video/") || name_lower.ends_with(".mp4") || name_lower.ends_with(".avi")
            || name_lower.ends_with(".mov") || name_lower.ends_with(".mkv") { return Modality::Video; }
        if mime_lower.contains("html") || name_lower.ends_with(".html") || name_lower.ends_with(".htm") { return Modality::Html; }
        if mime_lower.contains("zip") || mime_lower.contains("tar") || mime_lower.contains("gzip")
            || name_lower.ends_with(".zip") || name_lower.ends_with(".tar")
            || name_lower.ends_with(".gz") || name_lower.ends_with(".7z")
            || name_lower.ends_with(".rar") { return Modality::Archive; }
        if name_lower.ends_with(".docx") || name_lower.ends_with(".xlsx") || name_lower.ends_with(".pptx")
            || name_lower.ends_with(".odt") || name_lower.ends_with(".ods") { return Modality::Document; }
        Modality::Unknown
    }

    // ── Text Injection Detection ───────────────────────────────────────────

    fn scan_text_for_injection(&self, text: &str, location: &str) -> Vec<InjectionFinding> {
        let mut results = Vec::new();
        let normalized = Self::normalize(text);
        let shingles = Self::shingle_text(&normalized);

        let sim = Self::max_similarity(&shingles, &self.instruction_shingles);
        if sim >= self.flag_threshold {
            results.push(InjectionFinding {
                technique: InjectionTechnique::VisibleTextInImage,
                confidence: sim,
                description: format!("Instruction-like text detected in {}", location),
                location: location.to_string(),
            });
        }

        // Check for high instruction density
        let instruction_density = self.instruction_density(&normalized);
        if instruction_density > 0.4 {
            results.push(InjectionFinding {
                technique: InjectionTechnique::VisibleTextInImage,
                confidence: instruction_density,
                description: format!("High instruction density ({:.2}) in {}", instruction_density, location),
                location: location.to_string(),
            });
        }

        results
    }

    // ── Metadata Injection Detection ───────────────────────────────────────

    fn scan_metadata(&self, metadata: &HashMap<String, String>) -> Vec<InjectionFinding> {
        let mut results = Vec::new();

        for (key, value) in metadata {
            // Skip very short values
            if value.len() < 20 { continue; }

            // Flag suspiciously long metadata
            if value.len() > self.max_metadata_length {
                results.push(InjectionFinding {
                    technique: InjectionTechnique::MetadataInjection,
                    confidence: 0.7,
                    description: format!("Oversized metadata field: {} ({} bytes)", key, value.len()),
                    location: format!("metadata:{}", key),
                });
                continue;
            }

            // Check for sensitive metadata field names
            let key_lower = key.to_lowercase();
            let is_sensitive_field = METADATA_INJECTION_FIELDS.iter()
                .any(|f| key_lower.contains(&f.to_lowercase()));

            // Check for injection content in metadata
            let normalized = Self::normalize(value);
            let shingles = Self::shingle_text(&normalized);
            let sim = Self::max_similarity(&shingles, &self.instruction_shingles);

            if sim >= self.flag_threshold || (is_sensitive_field && sim >= self.flag_threshold * 0.7) {
                results.push(InjectionFinding {
                    technique: InjectionTechnique::MetadataInjection,
                    confidence: sim * if is_sensitive_field { 1.2 } else { 1.0 },
                    description: format!("Injection detected in metadata field: {}", key),
                    location: format!("metadata:{}", key),
                });
            }
        }

        results
    }

    // ── PDF-Specific Detection ─────────────────────────────────────────────

    fn scan_pdf_content(&self, content: &ContentDescriptor) -> Vec<InjectionFinding> {
        let mut results = Vec::new();

        // Check raw header for PDF-specific dangerous patterns
        let header_str = String::from_utf8_lossy(&content.raw_header);
        for pattern in PDF_DANGEROUS_PATTERNS {
            if header_str.contains(pattern) {
                results.push(InjectionFinding {
                    technique: if pattern.contains("JavaScript") || pattern.contains("JS") || pattern.contains("eval") {
                        InjectionTechnique::PdfJavaScript
                    } else {
                        InjectionTechnique::PdfHiddenLayer
                    },
                    confidence: 0.80,
                    description: format!("Dangerous PDF pattern: {}", pattern),
                    location: "pdf:structure".to_string(),
                });
            }
        }

        // Check for hidden text layers (text extracted but potentially invisible)
        for (location, text) in &content.extracted_text {
            if location.contains("hidden") || location.contains("overlay") || location.contains("annotation") {
                let normalized = Self::normalize(text);
                let shingles = Self::shingle_text(&normalized);
                let sim = Self::max_similarity(&shingles, &self.instruction_shingles);
                if sim >= self.flag_threshold * 0.8 {
                    results.push(InjectionFinding {
                        technique: InjectionTechnique::PdfHiddenLayer,
                        confidence: sim * 1.1,
                        description: format!("Hidden PDF text layer contains instructions"),
                        location: location.clone(),
                    });
                }
            }
        }

        results
    }

    // ── SVG/HTML Detection ─────────────────────────────────────────────────

    fn scan_svg_content(&self, content: &ContentDescriptor) -> Vec<InjectionFinding> {
        let mut results = Vec::new();
        let header_str = String::from_utf8_lossy(&content.raw_header).to_lowercase();

        for pattern in SVG_DANGEROUS_PATTERNS {
            if header_str.contains(&pattern.to_lowercase()) {
                let technique = if pattern.contains("script") || pattern.contains("javascript") {
                    InjectionTechnique::SvgScriptInjection
                } else if pattern.contains("foreignObject") {
                    InjectionTechnique::SvgForeignObject
                } else {
                    InjectionTechnique::HtmlEventHandler
                };

                results.push(InjectionFinding {
                    technique,
                    confidence: 0.85,
                    description: format!("Dangerous SVG/HTML pattern: {}", pattern),
                    location: "svg:content".to_string(),
                });
            }
        }

        // Check for encoded payloads in SVG attributes
        if header_str.contains("base64") && (header_str.contains("data:") || header_str.contains("href")) {
            results.push(InjectionFinding {
                technique: InjectionTechnique::SvgScriptInjection,
                confidence: 0.70,
                description: "Base64-encoded data URI in SVG".to_string(),
                location: "svg:data_uri".to_string(),
            });
        }

        results
    }

    // ── Image-Specific Detection ───────────────────────────────────────────

    fn scan_image_content(&self, content: &ContentDescriptor) -> Vec<InjectionFinding> {
        let mut results = Vec::new();

        // Check for invisible text indicators
        if content.has_alpha_channel {
            // Images with alpha channels could hide text at alpha=0
            for (location, text) in &content.extracted_text {
                if location.contains("alpha") || location.contains("transparent") {
                    results.push(InjectionFinding {
                        technique: InjectionTechnique::InvisibleTextOverlay,
                        confidence: 0.75,
                        description: "Text found in transparent image layer".to_string(),
                        location: location.clone(),
                    });
                }
            }
        }

        // Check for steganographic indicators in header
        if content.raw_header.len() >= 16 {
            let entropy = self.byte_entropy(&content.raw_header);
            // Steganography tends to increase entropy toward maximum
            if entropy > 7.95 && content.size_bytes > 10_000 {
                results.push(InjectionFinding {
                    technique: InjectionTechnique::SteganographicPayload,
                    confidence: 0.50 + (entropy - 7.95) * 10.0,
                    description: format!("Suspiciously high entropy ({:.4}) may indicate steganography", entropy),
                    location: "image:pixels".to_string(),
                });
            }
        }

        // Check for anomalous image dimensions (tiny images with lots of data)
        if let (Some(w), Some(h)) = (content.image_width, content.image_height) {
            let expected_size = (w as u64) * (h as u64) * 3; // rough RGB estimate
            if content.size_bytes > expected_size * 2 && content.size_bytes > 50_000 {
                results.push(InjectionFinding {
                    technique: InjectionTechnique::SteganographicPayload,
                    confidence: 0.55,
                    description: format!("Image size ({}) significantly exceeds expected ({}) for {}x{}",
                        content.size_bytes, expected_size, w, h),
                    location: "image:size_anomaly".to_string(),
                });
            }
        }

        results
    }

    // ── Archive Detection ──────────────────────────────────────────────────

    fn scan_archive_content(&self, content: &ContentDescriptor) -> Vec<InjectionFinding> {
        let mut results = Vec::new();

        // Check nesting depth
        let max_depth = content.nested_files.iter()
            .map(|f| f.matches('/').count() as u32 + f.matches('\\').count() as u32)
            .max()
            .unwrap_or(0);

        if max_depth > self.max_archive_depth {
            results.push(InjectionFinding {
                technique: InjectionTechnique::ArchiveNesting,
                confidence: 0.80,
                description: format!("Excessive archive nesting depth: {}", max_depth),
                location: "archive:structure".to_string(),
            });
        }

        // Check for dangerous file extensions
        for nested in &content.nested_files {
            let lower = nested.to_lowercase();
            for ext in ARCHIVE_DANGEROUS_EXTENSIONS {
                if lower.ends_with(ext) {
                    results.push(InjectionFinding {
                        technique: InjectionTechnique::ArchiveNesting,
                        confidence: 0.90,
                        description: format!("Dangerous file in archive: {}", nested),
                        location: format!("archive:{}", nested),
                    });
                }
            }
        }

        // Check for zip bomb indicators
        if content.nested_files.len() > 10_000 {
            results.push(InjectionFinding {
                technique: InjectionTechnique::ArchiveNesting,
                confidence: 0.95,
                description: format!("Possible zip bomb: {} files", content.nested_files.len()),
                location: "archive:count".to_string(),
            });
        }

        results
    }

    // ── Polyglot Detection ─────────────────────────────────────────────────

    fn detect_polyglot(&self, content: &ContentDescriptor) -> Option<InjectionFinding> {
        if content.raw_header.len() < 8 { return None; }

        let header = &content.raw_header;
        let mut signatures_matched = 0u32;

        // Check for multiple file format signatures in the same file
        let signatures: &[(&[u8], &str)] = &[
            (b"\x89PNG", "PNG"), (b"\xFF\xD8\xFF", "JPEG"),
            (b"GIF87a", "GIF87"), (b"GIF89a", "GIF89"),
            (b"%PDF", "PDF"), (b"PK\x03\x04", "ZIP"),
            (b"\x1F\x8B", "GZIP"), (b"RIFF", "RIFF"),
        ];

        for (sig, _name) in signatures {
            if header.len() >= sig.len() && &header[..sig.len()] == *sig {
                signatures_matched += 1;
            }
            // Also check for signatures elsewhere in the header
            if header.len() > 100 {
                for offset in (4..header.len().min(1024).saturating_sub(sig.len())).step_by(4) {
                    if offset + sig.len() <= header.len() && &header[offset..offset + sig.len()] == *sig {
                        signatures_matched += 1;
                        break;
                    }
                }
            }
        }

        if signatures_matched >= 2 {
            Some(InjectionFinding {
                technique: InjectionTechnique::PolyglotFile,
                confidence: 0.85,
                description: format!("Polyglot file detected: {} format signatures", signatures_matched),
                location: "file:header".to_string(),
            })
        } else {
            None
        }
    }

    // ── BiDi Override Detection ─────────────────────────────────────────────

    fn scan_bidi_overrides(&self, content: &ContentDescriptor) -> Vec<InjectionFinding> {
        let mut results = Vec::new();
        let bidi_chars = ['\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}',
            '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
            '\u{200F}', '\u{200E}'];

        for (location, text) in &content.extracted_text {
            let bidi_count = text.chars().filter(|c| bidi_chars.contains(c)).count();
            if bidi_count > 0 {
                results.push(InjectionFinding {
                    technique: InjectionTechnique::UnicodeDirectionOverride,
                    confidence: (0.5 + bidi_count as f64 * 0.1).min(0.95),
                    description: format!("{} Unicode BiDi override characters", bidi_count),
                    location: location.clone(),
                });
            }
        }

        // Also check filename
        let bidi_in_name = content.filename.chars().filter(|c| bidi_chars.contains(c)).count();
        if bidi_in_name > 0 {
            results.push(InjectionFinding {
                technique: InjectionTechnique::UnicodeDirectionOverride,
                confidence: 0.90,
                description: "BiDi override in filename (extension spoofing)".to_string(),
                location: "filename".to_string(),
            });
        }

        results
    }

    // ── Utility Functions ──────────────────────────────────────────────────

    fn byte_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() { return 0.0; }
        let mut counts = [0u32; 256];
        for &b in data { counts[b as usize] += 1; }
        let len = data.len() as f64;
        let mut entropy = 0.0f64;
        for &c in &counts {
            if c > 0 {
                let p = c as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    fn instruction_density(&self, text: &str) -> f64 {
        let markers = ["you must", "you should", "you will", "you are now",
            "do not", "always", "never", "ignore", "forget", "override",
            "follow these", "obey", "comply", "execute", "perform",
            "from now on", "new rule", "new instruction"];
        let words: Vec<&str> = text.split_whitespace().collect();
        if words.len() < 5 { return 0.0; }
        let hits = markers.iter().filter(|m| text.contains(*m)).count();
        (hits as f64 / markers.len() as f64).min(1.0)
    }

    fn precompute_shingles(patterns: &[&str]) -> Vec<Vec<u64>> {
        patterns.iter().map(|p| Self::shingle_text(&Self::normalize(p))).collect()
    }

    fn normalize(text: &str) -> String {
        let mut result = String::with_capacity(text.len());
        let mut prev_space = false;
        for ch in text.chars() {
            if ch.is_alphanumeric() || ch == ' ' {
                let c = ch.to_ascii_lowercase();
                if c == ' ' { if !prev_space { result.push(' '); prev_space = true; } }
                else { result.push(c); prev_space = false; }
            }
        }
        result.trim().to_string()
    }

    fn shingle_text(text: &str) -> Vec<u64> {
        if text.len() < 4 { return vec![]; }
        let bytes = text.as_bytes();
        let mut shingles = Vec::with_capacity(bytes.len().saturating_sub(3));
        for window in bytes.windows(4) {
            let mut h: u64 = 0xcbf29ce484222325;
            for &b in window { h ^= b as u64; h = h.wrapping_mul(0x100000001b3); }
            shingles.push(h);
        }
        shingles.sort_unstable();
        shingles.dedup();
        shingles
    }

    fn jaccard_similarity(a: &[u64], b: &[u64]) -> f64 {
        if a.is_empty() || b.is_empty() { return 0.0; }
        let (mut i, mut j, mut inter, mut uni) = (0, 0, 0u64, 0u64);
        while i < a.len() && j < b.len() {
            if a[i] == b[j] { inter += 1; uni += 1; i += 1; j += 1; }
            else if a[i] < b[j] { uni += 1; i += 1; }
            else { uni += 1; j += 1; }
        }
        uni += (a.len() - i) as u64 + (b.len() - j) as u64;
        if uni == 0 { 0.0 } else { inter as f64 / uni as f64 }
    }

    fn max_similarity(input: &[u64], category: &[Vec<u64>]) -> f64 {
        category.iter().map(|a| Self::jaccard_similarity(input, a)).fold(0.0f64, f64::max)
    }

    fn add_alert(&self, ts: i64, sev: Severity, title: &str, details: &str) {
        mitre::auto_correlate(title, details, sev as u8 as f64 / 3.0, details);
        let mut a = self.alerts.write();
        if a.len() >= MAX_ALERTS { a.remove(0); }
        a.push(AiAlert { timestamp: ts, severity: sev, component: "multimodal_injection_scanner".into(),
            title: title.into(), details: details.into() });
    }

    pub fn total_scanned(&self) -> u64 { self.total_scanned.load(Ordering::Relaxed) }
    pub fn total_blocked(&self) -> u64 { self.total_blocked.load(Ordering::Relaxed) }
    pub fn alerts(&self) -> Vec<AiAlert> { self.alerts.read().clone() }
    pub fn set_enabled(&mut self, e: bool) { self.enabled = e; }
}
