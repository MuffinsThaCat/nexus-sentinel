//! Breakthrough #591: Memory-Mapped I/O & Streaming
//!
//! Process files from disk without loading them entirely into RAM.
//! Uses OS virtual memory paging — only pages actually accessed are loaded.
//! Critical for: pcap analysis, log search, signature databases, forensic images.
//!
//! Used by ~50 of 203 security components.

use crate::error::{SentinelError, SentinelResult};
use memmap2::{Mmap, MmapOptions};
use std::fs::File;
use std::path::Path;

/// Memory-mapped file reader. The OS handles paging — only accessed regions
/// consume physical RAM.
pub struct MmapReader {
    mmap: Mmap,
    path: String,
}

impl MmapReader {
    /// Open a file for memory-mapped reading.
    pub fn open<P: AsRef<Path>>(path: P) -> SentinelResult<Self> {
        let path_str = path.as_ref().display().to_string();
        let file = File::open(&path)
            .map_err(|e| SentinelError::MmapError(format!("Failed to open {}: {}", path_str, e)))?;
        let mmap = unsafe {
            MmapOptions::new()
                .map(&file)
                .map_err(|e| SentinelError::MmapError(format!("Failed to mmap {}: {}", path_str, e)))?
        };
        Ok(Self {
            mmap,
            path: path_str,
        })
    }

    /// Get the full memory-mapped slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.mmap
    }

    /// Get a sub-slice at the given offset and length.
    pub fn slice(&self, offset: usize, len: usize) -> SentinelResult<&[u8]> {
        if offset + len > self.mmap.len() {
            return Err(SentinelError::MmapError(format!(
                "Slice out of bounds: offset={}, len={}, file_len={}",
                offset,
                len,
                self.mmap.len()
            )));
        }
        Ok(&self.mmap[offset..offset + len])
    }

    /// Total file size.
    pub fn len(&self) -> usize {
        self.mmap.len()
    }

    pub fn is_empty(&self) -> bool {
        self.mmap.is_empty()
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    /// Iterate over the file in chunks of the given size.
    /// Each chunk is a slice into the mmap — no copying.
    pub fn chunks(&self, chunk_size: usize) -> impl Iterator<Item = &[u8]> {
        self.mmap.chunks(chunk_size)
    }

    /// Search for a byte pattern in the mmap'd file.
    /// Returns offsets of all matches.
    pub fn find_all(&self, pattern: &[u8]) -> Vec<usize> {
        let data = self.as_slice();
        let mut offsets = Vec::new();
        let mut start = 0;
        while start + pattern.len() <= data.len() {
            if let Some(pos) = find_subsequence(&data[start..], pattern) {
                offsets.push(start + pos);
                start += pos + 1;
            } else {
                break;
            }
        }
        offsets
    }

    /// Iterate lines (for text files like logs).
    pub fn lines(&self) -> impl Iterator<Item = &[u8]> {
        self.mmap.split(|&b| b == b'\n')
    }
}

/// A streaming file processor that reads a file in chunks,
/// processes each chunk, and never holds the entire file in memory.
pub struct StreamingFileProcessor {
    chunk_size: usize,
}

impl StreamingFileProcessor {
    pub fn new(chunk_size: usize) -> Self {
        Self { chunk_size }
    }

    /// Process a file by streaming chunks through a callback.
    /// The callback receives (chunk_data, chunk_offset, is_last_chunk).
    pub fn process_file<P, F>(&self, path: P, mut callback: F) -> SentinelResult<()>
    where
        P: AsRef<Path>,
        F: FnMut(&[u8], usize, bool),
    {
        let reader = MmapReader::open(path)?;
        let total = reader.len();
        let mut offset = 0;

        for chunk in reader.chunks(self.chunk_size) {
            let is_last = offset + chunk.len() >= total;
            callback(chunk, offset, is_last);
            offset += chunk.len();
        }

        Ok(())
    }

    /// Process a file and accumulate results.
    pub fn process_and_accumulate<P, A, F>(
        &self,
        path: P,
        initial: A,
        mut accumulate: F,
    ) -> SentinelResult<A>
    where
        P: AsRef<Path>,
        F: FnMut(A, &[u8], usize) -> A,
    {
        let reader = MmapReader::open(path)?;
        let mut acc = initial;
        let mut offset = 0;

        for chunk in reader.chunks(self.chunk_size) {
            acc = accumulate(acc, chunk, offset);
            offset += chunk.len();
        }

        Ok(acc)
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Ring buffer file writer for continuous capture (e.g., packet capture).
/// Writes to a fixed-size file, wrapping around when full.
pub struct RingBufferWriter {
    path: String,
    max_size: usize,
    current_offset: usize,
    file: Option<File>,
}

impl RingBufferWriter {
    pub fn new<P: AsRef<Path>>(path: P, max_size: usize) -> SentinelResult<Self> {
        let path_str = path.as_ref().display().to_string();
        let file = File::create(&path)?;
        Ok(Self {
            path: path_str,
            max_size,
            current_offset: 0,
            file: Some(file),
        })
    }

    /// Write data to the ring buffer. Wraps around when full.
    pub fn write(&mut self, data: &[u8]) -> SentinelResult<()> {
        use std::io::Write;
        if let Some(ref mut file) = self.file {
            // If this write would exceed max_size, wrap around
            if self.current_offset + data.len() > self.max_size {
                self.current_offset = 0;
                use std::io::Seek;
                file.seek(std::io::SeekFrom::Start(0))?;
            }
            file.write_all(data)?;
            self.current_offset += data.len();
        }
        Ok(())
    }

    pub fn current_offset(&self) -> usize {
        self.current_offset
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn flush(&mut self) -> SentinelResult<()> {
        use std::io::Write;
        if let Some(ref mut file) = self.file {
            file.flush()?;
        }
        Ok(())
    }
}
