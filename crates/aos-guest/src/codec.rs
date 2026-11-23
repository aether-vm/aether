//! 4-byte big-endian length-prefixed JSON frame codec over any `Read` / `Write` transport.

#![forbid(unsafe_code)]

use std::io::{self, Read, Write};

use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

/// Default maximum allowed frame payload size (4 MiB).
pub const DEFAULT_MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum CodecError {
    #[error("empty frame (length prefix 0 is forbidden)")]
    ZeroLengthFrame,
    #[error("frame size {len} exceeds maximum allowed {max} bytes")]
    FrameTooLarge { len: usize, max: usize },
    #[error("unexpected EOF in middle of frame (expected {expected} bytes, got {got})")]
    TruncatedFrame { expected: usize, got: usize },
    #[error("JSON serialization/deserialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("transport I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Length-prefixed JSON frame encoder/decoder with strict size bounds.
#[derive(Debug, Clone, Copy)]
pub struct FrameCodec {
    max_frame_bytes: usize,
}

impl Default for FrameCodec {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_FRAME_BYTES)
    }
}

impl FrameCodec {
    pub fn new(max_frame_bytes: usize) -> Self {
        Self { max_frame_bytes }
    }

    pub fn max_frame_bytes(&self) -> usize {
        self.max_frame_bytes
    }

    /// Encode `value` as a single 4-byte big-endian length-prefixed JSON frame into `writer`
    /// and flush it.
    pub fn write_frame<W: Write, T: Serialize>(
        &self,
        writer: &mut W,
        value: &T,
    ) -> Result<(), CodecError> {
        let payload = serde_json::to_vec(value)?;
        if payload.is_empty() {
            return Err(CodecError::ZeroLengthFrame);
        }
        if payload.len() > self.max_frame_bytes {
            return Err(CodecError::FrameTooLarge {
                len: payload.len(),
                max: self.max_frame_bytes,
            });
        }
        let len_u32 = u32::try_from(payload.len()).map_err(|_| CodecError::FrameTooLarge {
            len: payload.len(),
            max: self.max_frame_bytes,
        })?;

        writer.write_all(&len_u32.to_be_bytes())?;
        writer.write_all(&payload)?;
        writer.flush()?;
        Ok(())
    }

    /// Read the next length-prefixed JSON frame from `reader`.
    ///
    /// Returns:
    /// - `Ok(None)` on clean EOF at a frame boundary (0 header bytes read).
    /// - `Ok(Some(T))` when a complete valid frame is decoded.
    /// - `Err(CodecError::TruncatedFrame)` if EOF occurs mid-header or mid-payload.
    /// - `Err(CodecError::ZeroLengthFrame | FrameTooLarge)` before allocating payload storage.
    pub fn read_frame<R: Read, T: DeserializeOwned>(
        &self,
        reader: &mut R,
    ) -> Result<Option<T>, CodecError> {
        let mut header = [0u8; 4];
        let mut header_read = 0usize;

        while header_read < 4 {
            match reader.read(&mut header[header_read..]) {
                Ok(0) => {
                    if header_read == 0 {
                        return Ok(None);
                    }
                    return Err(CodecError::TruncatedFrame {
                        expected: 4,
                        got: header_read,
                    });
                }
                Ok(n) => header_read += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(CodecError::Io(e)),
            }
        }

        let len = u32::from_be_bytes(header) as usize;
        if len == 0 {
            return Err(CodecError::ZeroLengthFrame);
        }
        if len > self.max_frame_bytes {
            return Err(CodecError::FrameTooLarge {
                len,
                max: self.max_frame_bytes,
            });
        }

        let mut payload = vec![0u8; len];
        let mut payload_read = 0usize;
        while payload_read < len {
            match reader.read(&mut payload[payload_read..]) {
                Ok(0) => {
                    return Err(CodecError::TruncatedFrame {
                        expected: len,
                        got: payload_read,
                    });
                }
                Ok(n) => payload_read += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(CodecError::Io(e)),
            }
        }

        let decoded = serde_json::from_slice(&payload)?;
        Ok(Some(decoded))
    }
}
