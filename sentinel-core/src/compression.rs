//! Breakthrough #593: Lossless Compression
//!
//! LZ4 (fast) and zlib (high ratio) compression for cold-tier data.
//! Used by ~20 components for archival storage, plus internally by tiered cache.

use crate::error::{SentinelError, SentinelResult};
use serde::{Serialize, de::DeserializeOwned};
use std::io::{Read, Write};

/// Compress raw bytes using LZ4.
pub fn compress_lz4(data: &[u8]) -> Vec<u8> {
    lz4_flex::compress_prepend_size(data)
}

/// Decompress LZ4-compressed bytes.
pub fn decompress_lz4(data: &[u8]) -> SentinelResult<Vec<u8>> {
    lz4_flex::decompress_size_prepended(data)
        .map_err(|e| SentinelError::CompressionError(format!("LZ4 decompress: {}", e)))
}

/// Compress raw bytes using zlib (flate2).
pub fn compress_zlib(data: &[u8], level: u32) -> SentinelResult<Vec<u8>> {
    let mut encoder =
        flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(level));
    encoder
        .write_all(data)
        .map_err(|e| SentinelError::CompressionError(format!("Zlib compress write: {}", e)))?;
    encoder
        .finish()
        .map_err(|e| SentinelError::CompressionError(format!("Zlib compress finish: {}", e)))
}

/// Decompress zlib-compressed bytes.
pub fn decompress_zlib(data: &[u8]) -> SentinelResult<Vec<u8>> {
    let mut decoder = flate2::read::ZlibDecoder::new(data);
    let mut result = Vec::new();
    decoder
        .read_to_end(&mut result)
        .map_err(|e| SentinelError::CompressionError(format!("Zlib decompress: {}", e)))?;
    Ok(result)
}

/// Serialize a value to JSON bytes, then compress with LZ4.
/// This is the default path used by tiered cache cold tier.
pub fn serialize_and_compress<T: Serialize>(value: &T) -> SentinelResult<Vec<u8>> {
    let json = serde_json::to_vec(value)?;
    Ok(compress_lz4(&json))
}

/// Decompress LZ4 bytes, then deserialize from JSON.
pub fn decompress_and_deserialize<T: DeserializeOwned>(data: &[u8]) -> SentinelResult<T> {
    let decompressed = decompress_lz4(data)?;
    let value: T = serde_json::from_slice(&decompressed)?;
    Ok(value)
}

/// Compress with the configured algorithm.
pub fn compress(
    data: &[u8],
    algorithm: crate::config::CompressionAlgorithm,
    level: u32,
) -> SentinelResult<Vec<u8>> {
    match algorithm {
        crate::config::CompressionAlgorithm::Lz4 => Ok(compress_lz4(data)),
        crate::config::CompressionAlgorithm::Zlib => compress_zlib(data, level),
    }
}

/// Decompress with the configured algorithm.
pub fn decompress(
    data: &[u8],
    algorithm: crate::config::CompressionAlgorithm,
) -> SentinelResult<Vec<u8>> {
    match algorithm {
        crate::config::CompressionAlgorithm::Lz4 => decompress_lz4(data),
        crate::config::CompressionAlgorithm::Zlib => decompress_zlib(data),
    }
}

/// Calculate compression ratio: original_size / compressed_size.
pub fn compression_ratio(original: usize, compressed: usize) -> f64 {
    if compressed == 0 {
        return 0.0;
    }
    original as f64 / compressed as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lz4_roundtrip() {
        let data = b"Hello, Nexus Sentinel! This is a test of LZ4 compression.";
        let compressed = compress_lz4(data);
        let decompressed = decompress_lz4(&compressed).unwrap();
        assert_eq!(data.as_slice(), decompressed.as_slice());
    }

    #[test]
    fn test_zlib_roundtrip() {
        let data = b"Hello, Nexus Sentinel! This is a test of zlib compression.";
        let compressed = compress_zlib(data, 6).unwrap();
        let decompressed = decompress_zlib(&compressed).unwrap();
        assert_eq!(data.as_slice(), decompressed.as_slice());
    }

    #[test]
    fn test_serialize_compress_roundtrip() {
        let value = vec!["firewall_rule_1", "firewall_rule_2", "ids_signature_42"];
        let compressed = serialize_and_compress(&value).unwrap();
        let decompressed: Vec<String> = decompress_and_deserialize(&compressed).unwrap();
        assert_eq!(value, decompressed);
    }

    #[test]
    fn test_compression_ratio() {
        // Repetitive data should compress well
        let data: Vec<u8> = (0..10000).map(|i| (i % 10) as u8).collect();
        let compressed = compress_lz4(&data);
        let ratio = compression_ratio(data.len(), compressed.len());
        assert!(ratio > 1.0, "Repetitive data should compress: ratio = {}", ratio);
    }
}
