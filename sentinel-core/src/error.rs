use thiserror::Error;

pub type SentinelResult<T> = Result<T, SentinelError>;

#[derive(Error, Debug)]
pub enum SentinelError {
    #[error("Memory budget exceeded: {used} bytes used of {budget} bytes budget")]
    MemoryBudgetExceeded { used: usize, budget: usize },

    #[error("Component '{component}' exceeded its memory bound: {used} > {bound}")]
    ComponentBoundExceeded {
        component: String,
        used: usize,
        bound: usize,
    },

    #[error("Cache tier overflow: tier {tier} at capacity ({capacity} entries)")]
    CacheTierOverflow { tier: &'static str, capacity: usize },

    #[error("VQ codec error: {0}")]
    VqCodecError(String),

    #[error("Compression error: {0}")]
    CompressionError(String),

    #[error("Deduplication error: {0}")]
    DeduplicationError(String),

    #[error("Memory map error: {0}")]
    MmapError(String),

    #[error("Differential storage error: {0}")]
    DifferentialError(String),

    #[error("Paged memory error: {0}")]
    PagedMemoryError(String),

    #[error("Hierarchical state error: {0}")]
    HierarchicalError(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Component not enabled: {0}")]
    NotEnabled(String),

    #[error("{0}")]
    Other(String),
}
