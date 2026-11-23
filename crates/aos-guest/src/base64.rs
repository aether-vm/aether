//! Minimal RFC 4648 standard Base64 encoder/decoder with zero external dependencies.

#![forbid(unsafe_code)]

use thiserror::Error;

const ENCODE_TABLE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Base64Error {
    #[error("invalid base64 length: {0} (must be a multiple of 4)")]
    InvalidLength(usize),
    #[error("invalid base64 character at byte offset {offset}: 0x{byte:02x}")]
    InvalidByte { offset: usize, byte: u8 },
    #[error("invalid base64 padding")]
    InvalidPadding,
    #[error("non-canonical trailing bits in base64 input")]
    NonCanonicalTrailingBits,
}

/// Encode arbitrary bytes as standard RFC 4648 Base64 with `=` padding.
pub fn encode(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }
    let out_len = input.len().div_ceil(3) * 4;
    let mut out = Vec::with_capacity(out_len);

    let mut chunks = input.chunks_exact(3);
    for chunk in &mut chunks {
        let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32);
        out.push(ENCODE_TABLE[((n >> 18) & 0x3f) as usize]);
        out.push(ENCODE_TABLE[((n >> 12) & 0x3f) as usize]);
        out.push(ENCODE_TABLE[((n >> 6) & 0x3f) as usize]);
        out.push(ENCODE_TABLE[(n & 0x3f) as usize]);
    }

    let rem = chunks.remainder();
    match rem.len() {
        0 => {}
        1 => {
            let n = (rem[0] as u32) << 16;
            out.push(ENCODE_TABLE[((n >> 18) & 0x3f) as usize]);
            out.push(ENCODE_TABLE[((n >> 12) & 0x3f) as usize]);
            out.push(b'=');
            out.push(b'=');
        }
        2 => {
            let n = ((rem[0] as u32) << 16) | ((rem[1] as u32) << 8);
            out.push(ENCODE_TABLE[((n >> 18) & 0x3f) as usize]);
            out.push(ENCODE_TABLE[((n >> 12) & 0x3f) as usize]);
            out.push(ENCODE_TABLE[((n >> 6) & 0x3f) as usize]);
            out.push(b'=');
        }
        _ => unreachable!(),
    }

    // All bytes pushed are guaranteed ASCII from ENCODE_TABLE or '='.
    String::from_utf8(out).expect("base64 output is valid ASCII")
}

#[inline]
fn decode_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode standard RFC 4648 Base64 with strict padding and canonical trailing-bit validation.
pub fn decode(input: &str) -> Result<Vec<u8>, Base64Error> {
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if !bytes.len().is_multiple_of(4) {
        return Err(Base64Error::InvalidLength(bytes.len()));
    }

    let mut out = Vec::with_capacity((bytes.len() / 4) * 3);
    let num_quads = bytes.len() / 4;

    for (q_idx, quad) in bytes.chunks_exact(4).enumerate() {
        let base = q_idx * 4;
        let is_last = q_idx + 1 == num_quads;

        let a = decode_val(quad[0]).ok_or(Base64Error::InvalidByte {
            offset: base,
            byte: quad[0],
        })?;
        let b = decode_val(quad[1]).ok_or(Base64Error::InvalidByte {
            offset: base + 1,
            byte: quad[1],
        })?;

        if quad[2] == b'=' {
            if !is_last || quad[3] != b'=' {
                return Err(Base64Error::InvalidPadding);
            }
            if (b & 0x0f) != 0 {
                return Err(Base64Error::NonCanonicalTrailingBits);
            }
            out.push((a << 2) | (b >> 4));
        } else if quad[3] == b'=' {
            if !is_last {
                return Err(Base64Error::InvalidPadding);
            }
            let c = decode_val(quad[2]).ok_or(Base64Error::InvalidByte {
                offset: base + 2,
                byte: quad[2],
            })?;
            if (c & 0x03) != 0 {
                return Err(Base64Error::NonCanonicalTrailingBits);
            }
            out.push((a << 2) | (b >> 4));
            out.push((b << 4) | (c >> 2));
        } else {
            let c = decode_val(quad[2]).ok_or(Base64Error::InvalidByte {
                offset: base + 2,
                byte: quad[2],
            })?;
            let d = decode_val(quad[3]).ok_or(Base64Error::InvalidByte {
                offset: base + 3,
                byte: quad[3],
            })?;
            out.push((a << 2) | (b >> 4));
            out.push((b << 4) | (c >> 2));
            out.push((c << 6) | d);
        }
    }

    Ok(out)
}
