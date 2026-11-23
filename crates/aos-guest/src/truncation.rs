//! Bounded $O(\text{budget})$ head/tail truncation buffer and continuous stream drainer.
//!
//! Per `docs/ARCHITECTURE_V2.md` §7.1:
//! - Child stdout/stderr pipes MUST be drained continuously to EOF so subprocesses
//!   never stall on full OS pipe buffers.
//! - Retained output MUST stay bounded in memory using deterministic head + tail
//!   truncation with explicit omitted-byte accounting.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::io::{self, Read};

use crate::protocol::{BoundedOutput, BytesPayload};

/// Streaming accumulator retaining at most `max_bytes` total payload bytes
/// split deterministically between the head and a rolling tail ring buffer.
#[derive(Debug, Clone)]
pub struct HeadTailBuffer {
    max_bytes: usize,
    head_cap: usize,
    tail_cap: usize,
    head: Vec<u8>,
    tail: VecDeque<u8>,
    total_bytes: u64,
}

impl HeadTailBuffer {
    /// Create a new bounded buffer retaining up to `max_bytes` bytes.
    ///
    /// When truncated, retains `head_cap = (max_bytes + 1) / 2` leading bytes
    /// and `tail_cap = max_bytes / 2` trailing bytes.
    pub fn new(max_bytes: usize) -> Self {
        let tail_cap = max_bytes / 2;
        let head_cap = max_bytes - tail_cap;
        Self {
            max_bytes,
            head_cap,
            tail_cap,
            head: Vec::with_capacity(head_cap.min(4096)),
            tail: VecDeque::with_capacity(tail_cap.min(4096)),
            total_bytes: 0,
        }
    }

    /// Maximum retained payload bytes.
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Total bytes pushed so far (including truncated middle bytes).
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Push a slice of bytes into the bounded accumulator.
    ///
    /// Never fails and never allocates beyond `O(max_bytes)`.
    pub fn push(&mut self, mut chunk: &[u8]) {
        if chunk.is_empty() {
            return;
        }
        self.total_bytes = self.total_bytes.saturating_add(chunk.len() as u64);

        if self.max_bytes == 0 {
            return;
        }

        // Fill head buffer first.
        if self.head.len() < self.head_cap {
            let take = (self.head_cap - self.head.len()).min(chunk.len());
            self.head.extend_from_slice(&chunk[..take]);
            chunk = &chunk[take..];
        }

        if chunk.is_empty() || self.tail_cap == 0 {
            return;
        }

        // Feed remaining bytes into bounded tail ring buffer.
        if chunk.len() >= self.tail_cap {
            // Fast path: incoming chunk completely replaces tail.
            self.tail.clear();
            let start = chunk.len() - self.tail_cap;
            self.tail.extend(&chunk[start..]);
        } else {
            let overflow = (self.tail.len() + chunk.len()).saturating_sub(self.tail_cap);
            if overflow > 0 {
                self.tail.drain(..overflow);
            }
            self.tail.extend(chunk);
        }
    }

    /// Consume the buffer and emit the wire-ready [`BoundedOutput`].
    ///
    /// Invariants:
    /// - If `total_bytes <= max_bytes`: `truncated == false`, `omitted_bytes == 0`,
    ///   `head` contains the entire stream, and `tail` is empty.
    /// - If `total_bytes > max_bytes`: `truncated == true`,
    ///   `head.len() + omitted_bytes + tail.len() == total_bytes`,
    ///   `head.len() == head_cap`, `tail.len() == tail_cap`.
    pub fn finish(mut self) -> BoundedOutput {
        let total = self.total_bytes;
        let max_u64 = self.max_bytes as u64;

        if total <= max_u64 {
            // Untruncated: stitch head + tail into `head` so callers get contiguous bytes.
            if !self.tail.is_empty() {
                self.head.reserve(self.tail.len());
                let (s1, s2) = self.tail.as_slices();
                self.head.extend_from_slice(s1);
                self.head.extend_from_slice(s2);
            }
            BoundedOutput {
                head: BytesPayload::from(self.head),
                tail: BytesPayload::default(),
                total_bytes: total,
                omitted_bytes: 0,
                truncated: false,
            }
        } else {
            let mut tail_vec = Vec::with_capacity(self.tail.len());
            let (s1, s2) = self.tail.as_slices();
            tail_vec.extend_from_slice(s1);
            tail_vec.extend_from_slice(s2);

            let retained = (self.head.len() + tail_vec.len()) as u64;
            let omitted = total.saturating_sub(retained);

            BoundedOutput {
                head: BytesPayload::from(self.head),
                tail: BytesPayload::from(tail_vec),
                total_bytes: total,
                omitted_bytes: omitted,
                truncated: true,
            }
        }
    }
}

/// Drain `reader` completely to EOF in chunks of `chunk_size` (at least 1 byte),
/// invoking `on_chunk` for each non-empty chunk while accumulating into a
/// [`HeadTailBuffer`] bounded by `max_bytes`.
pub fn drain_stream<R, F>(
    mut reader: R,
    max_bytes: usize,
    chunk_size: usize,
    mut on_chunk: F,
) -> io::Result<BoundedOutput>
where
    R: Read,
    F: FnMut(&[u8]) -> io::Result<()>,
{
    let mut acc = HeadTailBuffer::new(max_bytes);
    let mut buf = vec![0u8; chunk_size.max(1)];

    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let slice = &buf[..n];
                acc.push(slice);
                on_chunk(slice)?;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }

    Ok(acc.finish())
}
