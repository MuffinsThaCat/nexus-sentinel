use serde::{Deserialize, Serialize};

/// Global configuration for the core memory optimization library.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreConfig {
    /// Total memory budget for the entire security suite in bytes
    pub total_memory_budget: usize,
    /// Whether to enable the theoretical verifier (#6) on all components
    pub verifier_enabled: bool,
    /// Tiered cache configuration
    pub tiered_cache: TieredCacheConfig,
    /// VQ codec configuration
    pub vq_codec: VqCodecConfig,
    /// Differential storage configuration
    pub differential: DifferentialConfig,
    /// Compression configuration
    pub compression: CompressionConfig,
    /// Paged memory configuration
    pub paged: PagedConfig,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            total_memory_budget: crate::DEFAULT_MEMORY_BUDGET_BYTES,
            verifier_enabled: true,
            tiered_cache: TieredCacheConfig::default(),
            vq_codec: VqCodecConfig::default(),
            differential: DifferentialConfig::default(),
            compression: CompressionConfig::default(),
            paged: PagedConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TieredCacheConfig {
    /// Fraction of cache capacity for hot tier (default: φ⁻² ≈ 0.382)
    pub hot_fraction: f64,
    /// Fraction of cache capacity for warm tier (default: φ⁻¹ ≈ 0.618 - 0.382 = 0.236)
    pub warm_fraction: f64,
    /// Whether to compress cold tier entries
    pub compress_cold: bool,
    /// Access count threshold to promote from cold → warm
    pub promote_threshold: u32,
    /// Idle duration (seconds) before demoting from hot → warm
    pub demote_after_secs: u64,
}

impl Default for TieredCacheConfig {
    fn default() -> Self {
        let inv_phi_sq = crate::INV_PHI * crate::INV_PHI;
        Self {
            hot_fraction: inv_phi_sq,
            warm_fraction: crate::INV_PHI - inv_phi_sq,
            compress_cold: true,
            promote_threshold: 3,
            demote_after_secs: 300,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VqCodecConfig {
    /// Number of codebook entries (default: 256)
    pub codebook_size: usize,
    /// Vector dimension for quantization (default: 16)
    pub vector_dim: usize,
    /// Number of residual stages (default: 2 for ~50× compression)
    pub residual_stages: usize,
}

impl Default for VqCodecConfig {
    fn default() -> Self {
        Self {
            codebook_size: 256,
            vector_dim: 16,
            residual_stages: 2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialConfig {
    /// Maximum number of diffs to chain before compacting to a new snapshot
    pub max_diff_chain: usize,
    /// Whether to compress diffs
    pub compress_diffs: bool,
}

impl Default for DifferentialConfig {
    fn default() -> Self {
        Self {
            max_diff_chain: 64,
            compress_diffs: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionConfig {
    /// Compression algorithm for cold data
    pub algorithm: CompressionAlgorithm,
    /// Compression level (1-9 for zlib, 1-12 for lz4)
    pub level: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum CompressionAlgorithm {
    Lz4,
    Zlib,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            algorithm: CompressionAlgorithm::Lz4,
            level: 4,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PagedConfig {
    /// Page size in bytes (default: 4KB matching OS page size)
    pub page_size: usize,
    /// Maximum resident pages in memory
    pub max_resident_pages: usize,
    /// Eviction policy
    pub eviction: EvictionPolicy,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum EvictionPolicy {
    Lru,
    PhiWeighted,
    Clock,
}

impl Default for PagedConfig {
    fn default() -> Self {
        Self {
            page_size: 4096,
            max_resident_pages: 1024,
            eviction: EvictionPolicy::PhiWeighted,
        }
    }
}
