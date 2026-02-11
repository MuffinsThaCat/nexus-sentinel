//! # Sentinel Core — Memory Optimization Library
//!
//! 13 breakthrough memory techniques ported from the Nexus LLM training system.
//! Every security component in Nexus Sentinel links against this library.
//!
//! ## Techniques (ordered by applicability across 250 components):
//! - **#6  Theoretical Verifier** — Runtime memory bounds checking (all 250 components)
//! - **#461 Differential Storage** — Store only changes from baseline (~135 components)
//! - **#5  Streaming Accumulation** — Process in chunks, discard raw (~115 components)
//! - **#2  Tiered Cache** — Hot/warm/cold with compression (~90 components)
//! - **#4  VQ Codec** — Vector quantization for structured data (~80 components)
//! - **#627 Sparse Representation** — Only store non-zero entries (~60 components)
//! - **#591 Streaming/mmap** — Memory-mapped I/O (~50 components)
//! - **#3  Reversible Computation** — Recompute instead of store (~48 components)
//! - **#1  Hierarchical State** — O(log n) state checkpoints (~38 components)
//! - **#592 Deduplication** — Content-addressed dedup (~32 components)
//! - **#573 Paged Memory** — Virtual paging with eviction (~27 components)
//! - **#593 Lossless Compression** — zlib/lz4 on cold data (~22 components)
//! - **#569 Entry Pruning** — Time/priority-based eviction (~24 components)

pub mod verifier;
pub mod differential;
pub mod streaming;
pub mod tiered_cache;
pub mod vq_codec;
pub mod sparse;
pub mod mmap_stream;
pub mod reversible;
pub mod hierarchical;
pub mod dedup;
pub mod paged;
pub mod compression;
pub mod pruning;
pub mod error;
pub mod config;
pub mod metrics;
pub mod event_bus;
pub mod pipeline;
pub mod persistence;
pub mod config_loader;
pub mod io_adapters;
pub mod packet_capture;
pub mod process_monitor;
pub mod tls_probe;
pub mod threat_intel;
pub mod file_integrity;
pub mod fs_watcher;
pub mod net_connections;
pub mod taxii_client;
pub mod dashboard;
pub mod mitre;
pub mod agent;

pub use error::{SentinelError, SentinelResult};
pub use config::CoreConfig;
pub use metrics::MemoryMetrics;

/// φ (golden ratio) — used throughout for optimal split points, scheduling, and thresholds
pub const PHI: f64 = 1.618033988749895;
/// 1/φ — the inverse golden ratio
pub const INV_PHI: f64 = 0.6180339887498949;

/// Memory budget for the entire security suite (default: 512MB)
pub const DEFAULT_MEMORY_BUDGET_BYTES: usize = 512 * 1024 * 1024;
