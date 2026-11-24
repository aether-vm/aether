//! Streaming sliding-window multi-pattern anti-reflection scanner (ARCHITECTURE_V2 §6).
//!
//! Prevents a compromised sandbox from tricking an upstream API into echoing injected
//! host-side secrets back into the sandbox in raw, Base64, URL-encoded, or hex-encoded form,
//! even when the reflected secret is split across arbitrary network chunk boundaries.

use std::collections::HashSet;
use std::sync::Arc;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{GwError, Result};
use crate::policy::{ReflectionAction, SecretValue};

/// Replacement bytes written when [`ReflectionAction::Redact`] matches a secret.
pub const REDACTION_MARKER: &[u8] = b"[REDACTED_SECRET]";

/// Minimum length for phase-shifted Base64 interior substrings to avoid false positives.
const MIN_BASE64_SHIFTED_LEN: usize = 8;

/// Encoding variant matched by the anti-reflection scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EncodingVariant {
    /// Raw verbatim secret bytes.
    Raw,
    /// Standard or URL-safe Base64 (padded, unpadded, or phase-shifted interior).
    Base64,
    /// Percent-encoded / URL-encoded (RFC 3986, form-urlencoded, or full `%XX`).
    UrlEncoded,
    /// Hexadecimal encoding (lowercase or uppercase).
    Hex,
}

/// Non-secret metadata describing a detected reflection match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReflectionMatch {
    /// Non-secret label of the matched credential.
    pub label: String,
    /// Encoding variant that matched.
    pub variant: EncodingVariant,
}

#[derive(Debug, Clone)]
struct PatternMeta {
    label: String,
    variant: EncodingVariant,
}

/// Compiled immutable multi-pattern anti-reflection scanner shared across connections
/// belonging to a single `(slot_id, world_id, epoch)` binding.
#[derive(Debug)]
pub struct ReflectionScanner {
    automaton: Option<AhoCorasick>,
    pattern_meta: Vec<PatternMeta>,
    max_pattern_len: usize,
    action: ReflectionAction,
}

impl ReflectionScanner {
    /// Compile a scanner for all `(label, SecretValue)` pairs registered on a binding.
    pub fn compile<'a>(
        secrets: impl IntoIterator<Item = (String, &'a SecretValue)>,
        action: ReflectionAction,
    ) -> Result<Self> {
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut pattern_meta: Vec<PatternMeta> = Vec::new();

        let mut push_pattern = |pat: Vec<u8>, label: &str, variant: EncodingVariant| {
            if pat.is_empty() {
                return;
            }
            if seen.insert(pat.clone()) {
                patterns.push(pat);
                pattern_meta.push(PatternMeta {
                    label: label.to_owned(),
                    variant,
                });
            }
        };

        for (label, secret) in secrets {
            let raw = secret.as_bytes();
            if raw.is_empty() {
                continue;
            }

            // 1. Raw bytes.
            push_pattern(raw.to_vec(), &label, EncodingVariant::Raw);

            // 2. Base64 variants (standard, unpadded, URL-safe, unpadded URL-safe).
            for b64 in [
                STANDARD.encode(raw),
                STANDARD_NO_PAD.encode(raw),
                URL_SAFE.encode(raw),
                URL_SAFE_NO_PAD.encode(raw),
            ] {
                push_pattern(b64.into_bytes(), &label, EncodingVariant::Base64);
            }

            // Phase-shifted Base64 interior substrings (catches secret embedded at byte offset
            // 0, 1, or 2 mod 3 inside a larger base64-encoded blob).
            for interior in base64_phase_shifted_interiors(raw) {
                push_pattern(interior.into_bytes(), &label, EncodingVariant::Base64);
            }

            // 3. Hex variants (lowercase & uppercase).
            push_pattern(encode_hex(raw, false), &label, EncodingVariant::Hex);
            push_pattern(encode_hex(raw, true), &label, EncodingVariant::Hex);

            // 4. URL-encoded variants (RFC 3986 upper/lower, form-encoded upper/lower,
            //    and full every-byte %XX upper/lower).
            for url_pat in url_encoded_variants(raw) {
                push_pattern(url_pat, &label, EncodingVariant::UrlEncoded);
            }
        }

        if patterns.is_empty() {
            return Ok(Self {
                automaton: None,
                pattern_meta: Vec::new(),
                max_pattern_len: 0,
                action,
            });
        }

        let max_pattern_len = patterns.iter().map(Vec::len).max().unwrap_or(0);

        // Use LeftmostLongest so Redact mode consumes full padded encodings (e.g. `YWJjZA==`
        // rather than redacting `YWJjZA` and leaving `==`).
        let automaton = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&patterns)
            .map_err(|e| GwError::InvalidPolicy(format!("failed to compile reflection scanner: {e}")))?;

        // Zeroize temporary pattern copies containing secret derivations.
        for pat in &mut patterns {
            pat.zeroize();
        }
        for mut k in seen.drain() {
            k.zeroize();
        }

        Ok(Self {
            automaton: Some(automaton),
            pattern_meta,
            max_pattern_len,
            action,
        })
    }

    /// Empty scanner with no registered secrets (pass-through).
    #[must_use]
    pub fn empty(action: ReflectionAction) -> Self {
        Self {
            automaton: None,
            pattern_meta: Vec::new(),
            max_pattern_len: 0,
            action,
        }
    }

    /// Returns `true` if at least one secret is registered.
    #[must_use]
    pub fn has_secrets(&self) -> bool {
        self.automaton.is_some()
    }

    /// Configured reflection action (`Abort` or `Redact`).
    #[must_use]
    pub const fn action(&self) -> ReflectionAction {
        self.action
    }

    /// Maximum pattern length across all derived encodings (sliding window size).
    #[must_use]
    pub const fn max_pattern_len(&self) -> usize {
        self.max_pattern_len
    }

    /// Scan a complete buffer (e.g. an HTTP response header value).
    ///
    /// - Under [`ReflectionAction::Abort`], returns `Err(GwError::SecretReflected { .. })` on match.
    /// - Under [`ReflectionAction::Redact`], returns `Ok((redacted_bytes, matches))`.
    pub fn scan_complete(&self, input: &[u8]) -> Result<(Vec<u8>, Vec<ReflectionMatch>)> {
        let mut stream = self.new_stream();
        let mut out = stream.push_chunk(input)?;
        let tail = stream.finish()?;
        out.extend_from_slice(&tail);
        let matches = stream.matches().to_vec();
        Ok((out, matches))
    }

    /// Start a stateful streaming sliding-window scan over an arbitrary chunked byte stream.
    #[must_use]
    pub fn new_stream(&self) -> ReflectionStream<'_> {
        ReflectionStream {
            scanner: self,
            state: StreamState::default(),
        }
    }

    /// Start an owned (`'static`) stateful streaming scan suitable for async tasks.
    #[must_use]
    pub fn new_owned_stream(self: &Arc<Self>) -> OwnedReflectionStream {
        OwnedReflectionStream {
            scanner: Arc::clone(self),
            state: StreamState::default(),
        }
    }

    fn push_chunk_state(&self, state: &mut StreamState, chunk: &[u8]) -> Result<Vec<u8>> {
        if state.aborted {
            return Err(GwError::InvalidPolicy(
                "reflection stream already aborted".into(),
            ));
        }
        let Some(ac) = &self.automaton else {
            return Ok(chunk.to_vec());
        };
        if chunk.is_empty() {
            return Ok(Vec::new());
        }

        state.pending.extend_from_slice(chunk);
        let holdback = self.max_pattern_len.saturating_sub(1);

        match self.action {
            ReflectionAction::Abort => {
                if let Some(m) = ac.find(&state.pending) {
                    state.aborted = true;
                    state.pending.zeroize();
                    state.pending.clear();
                    let meta = &self.pattern_meta[m.pattern().as_usize()];
                    let matched = ReflectionMatch {
                        label: meta.label.clone(),
                        variant: meta.variant,
                    };
                    state.matches.push(matched.clone());
                    return Err(GwError::SecretReflected {
                        label: matched.label,
                        variant: matched.variant,
                    });
                }
                let emit_len = state.pending.len().saturating_sub(holdback);
                if emit_len == 0 {
                    return Ok(Vec::new());
                }
                let out = state.pending[..emit_len].to_vec();
                state.pending.drain(..emit_len);
                Ok(out)
            }
            ReflectionAction::Redact => Ok(self.process_redact_state(ac, state, false)),
        }
    }

    fn finish_state(&self, state: &mut StreamState) -> Result<Vec<u8>> {
        if state.aborted {
            return Err(GwError::InvalidPolicy(
                "reflection stream already aborted".into(),
            ));
        }
        let Some(ac) = &self.automaton else {
            return Ok(Vec::new());
        };

        match self.action {
            ReflectionAction::Abort => Ok(std::mem::take(&mut state.pending)),
            ReflectionAction::Redact => Ok(self.process_redact_state(ac, state, true)),
        }
    }

    fn process_redact_state(
        &self,
        ac: &AhoCorasick,
        state: &mut StreamState,
        is_eof: bool,
    ) -> Vec<u8> {
        let holdback = self.max_pattern_len.saturating_sub(1);
        let max_len = self.max_pattern_len;
        let mut out = Vec::new();
        let mut cursor = 0usize;

        while cursor < state.pending.len() {
            let slice = &state.pending[cursor..];
            match ac.find(slice) {
                Some(m) => {
                    let abs_start = cursor + m.start();
                    let abs_end = cursor + m.end();

                    if !is_eof && state.pending.len().saturating_sub(abs_start) < max_len {
                        if abs_start > cursor {
                            out.extend_from_slice(&state.pending[cursor..abs_start]);
                            cursor = abs_start;
                        }
                        break;
                    }

                    if abs_start > cursor {
                        out.extend_from_slice(&state.pending[cursor..abs_start]);
                    }
                    out.extend_from_slice(REDACTION_MARKER);
                    let meta = &self.pattern_meta[m.pattern().as_usize()];
                    state.matches.push(ReflectionMatch {
                        label: meta.label.clone(),
                        variant: meta.variant,
                    });
                    cursor = abs_end;
                }
                None => {
                    if is_eof {
                        out.extend_from_slice(&state.pending[cursor..]);
                        cursor = state.pending.len();
                    } else {
                        let remaining = state.pending.len() - cursor;
                        let safe = remaining.saturating_sub(holdback);
                        if safe > 0 {
                            out.extend_from_slice(&state.pending[cursor..cursor + safe]);
                            cursor += safe;
                        }
                    }
                    break;
                }
            }
        }

        if cursor > 0 {
            state.pending[..cursor].zeroize();
            state.pending.drain(..cursor);
        }
        out
    }
}

#[derive(Default)]
struct StreamState {
    pending: Vec<u8>,
    matches: Vec<ReflectionMatch>,
    aborted: bool,
}

impl Drop for StreamState {
    fn drop(&mut self) {
        self.pending.zeroize();
    }
}

/// Per-stream sliding-window scanner borrowing a [`ReflectionScanner`].
pub struct ReflectionStream<'a> {
    scanner: &'a ReflectionScanner,
    state: StreamState,
}

impl<'a> ReflectionStream<'a> {
    /// Process the next chunk of response bytes and return the prefix guaranteed to be safe
    /// (free of any secret match or partial match prefix).
    pub fn push_chunk(&mut self, chunk: &[u8]) -> Result<Vec<u8>> {
        self.scanner.push_chunk_state(&mut self.state, chunk)
    }

    /// Signal end-of-stream and flush any remaining held-back safe bytes.
    pub fn finish(&mut self) -> Result<Vec<u8>> {
        self.scanner.finish_state(&mut self.state)
    }

    /// All matches recorded on this stream.
    #[must_use]
    pub fn matches(&self) -> &[ReflectionMatch] {
        &self.state.matches
    }
}

/// Owned (`'static`) sliding-window reflection scanner backed by `Arc<ReflectionScanner>`
/// for async streaming tasks.
pub struct OwnedReflectionStream {
    scanner: Arc<ReflectionScanner>,
    state: StreamState,
}

impl OwnedReflectionStream {
    /// Process the next chunk of response bytes and return the safe prefix.
    pub fn push_chunk(&mut self, chunk: &[u8]) -> Result<Vec<u8>> {
        self.scanner.push_chunk_state(&mut self.state, chunk)
    }

    /// Signal end-of-stream and flush remaining held-back safe bytes.
    pub fn finish(&mut self) -> Result<Vec<u8>> {
        self.scanner.finish_state(&mut self.state)
    }

    /// All matches recorded on this stream.
    #[must_use]
    pub fn matches(&self) -> &[ReflectionMatch] {
        &self.state.matches
    }
}

fn encode_hex(bytes: &[u8], upper: bool) -> Vec<u8> {
    const LOWER: &[u8; 16] = b"0123456789abcdef";
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let table = if upper { UPPER } else { LOWER };
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(table[(b >> 4) as usize]);
        out.push(table[(b & 0x0f) as usize]);
    }
    out
}

/// Produce phase-shifted Base64 interior substrings so secrets embedded at offset 0/1/2 mod 3
/// inside a larger Base64 blob are still caught.
fn base64_phase_shifted_interiors(raw: &[u8]) -> Vec<String> {
    let mut results = Vec::new();
    for engine in [&STANDARD, &URL_SAFE] {
        for pad_prefix in 0usize..3 {
            let mut buf = Vec::with_capacity(pad_prefix + raw.len());
            buf.resize(pad_prefix, 0u8);
            buf.extend_from_slice(raw);
            let encoded = engine.encode(&buf);
            buf.zeroize();

            // Leading characters affected by the synthetic prefix bytes:
            // pad_prefix == 0 -> 0 chars affected
            // pad_prefix == 1 -> first 2 chars depend on byte 0
            // pad_prefix == 2 -> first 3 chars depend on bytes 0..2
            let start_char = match pad_prefix {
                0 => 0,
                1 => 2,
                _ => 3,
            };
            // Trailing partial group if `(pad_prefix + raw.len()) % 3 != 0`:
            // last 2 chars (or padding `=`) depend on trailing neighbor bytes.
            let total_bytes = pad_prefix + raw.len();
            let full_groups = total_bytes / 3;
            let end_char = full_groups * 4;

            if end_char > start_char && (end_char - start_char) >= MIN_BASE64_SHIFTED_LEN {
                results.push(encoded[start_char..end_char].to_owned());
            }
        }
    }
    results
}

fn url_encoded_variants(raw: &[u8]) -> Vec<Vec<u8>> {
    vec![
        // RFC 3986 percent-encoding (non-unreserved bytes encoded), uppercase & lowercase.
        percent_encode(raw, false, true, false),
        percent_encode(raw, false, false, false),
        // Form-urlencoded (space -> `+`), uppercase & lowercase.
        percent_encode(raw, true, true, false),
        percent_encode(raw, true, false, false),
        // Full percent-encoding (every byte `%XX`), uppercase & lowercase.
        percent_encode(raw, false, true, true),
        percent_encode(raw, false, false, true),
    ]
}

fn percent_encode(raw: &[u8], space_as_plus: bool, upper: bool, encode_all: bool) -> Vec<u8> {
    const LOWER: &[u8; 16] = b"0123456789abcdef";
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let hex = if upper { UPPER } else { LOWER };
    let mut out = Vec::with_capacity(raw.len() * 3);
    for &b in raw {
        if !encode_all && is_unreserved(b) {
            out.push(b);
        } else if !encode_all && space_as_plus && b == b' ' {
            out.push(b'+');
        } else {
            out.push(b'%');
            out.push(hex[(b >> 4) as usize]);
            out.push(hex[(b & 0x0f) as usize]);
        }
    }
    out
}

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abort_detects_raw_and_encoded_variants_across_1_byte_chunks() {
        let secret = SecretValue::new("sk-live-secret+key/42==").unwrap();
        let scanner =
            ReflectionScanner::compile([("api".to_owned(), &secret)], ReflectionAction::Abort)
                .unwrap();

        let payloads: Vec<(Vec<u8>, EncodingVariant)> = vec![
            (
                b"prefix sk-live-secret+key/42== suffix".to_vec(),
                EncodingVariant::Raw,
            ),
            (
                format!("b64:{}", STANDARD.encode(secret.as_bytes())).into_bytes(),
                EncodingVariant::Base64,
            ),
            (
                format!("b64np:{}", STANDARD_NO_PAD.encode(secret.as_bytes())).into_bytes(),
                EncodingVariant::Base64,
            ),
            (
                format!(
                    "embedded-b64:{}",
                    STANDARD.encode(format!("X{}Y", secret.as_str()))
                )
                .into_bytes(),
                EncodingVariant::Base64,
            ),
            (
                format!(
                    "hex:{}",
                    String::from_utf8(encode_hex(secret.as_bytes(), false)).unwrap()
                )
                .into_bytes(),
                EncodingVariant::Hex,
            ),
            (
                format!(
                    "HEX:{}",
                    String::from_utf8(encode_hex(secret.as_bytes(), true)).unwrap()
                )
                .into_bytes(),
                EncodingVariant::Hex,
            ),
            (
                format!(
                    "url:{}",
                    String::from_utf8(percent_encode(secret.as_bytes(), false, true, false))
                        .unwrap()
                )
                .into_bytes(),
                EncodingVariant::UrlEncoded,
            ),
            (
                format!(
                    "fullurl:{}",
                    String::from_utf8(percent_encode(secret.as_bytes(), false, false, true))
                        .unwrap()
                )
                .into_bytes(),
                EncodingVariant::UrlEncoded,
            ),
        ];

        for (payload, expected_variant) in payloads {
            // Feed 1 byte at a time to stress arbitrary chunk boundaries.
            let mut stream = scanner.new_stream();
            let mut emitted = Vec::new();
            let mut detected = None;
            for byte in payload.chunks(1) {
                match stream.push_chunk(byte) {
                    Ok(safe) => emitted.extend_from_slice(&safe),
                    Err(GwError::SecretReflected { variant, .. }) => {
                        detected = Some(variant);
                        break;
                    }
                    Err(other) => panic!("unexpected error: {other}"),
                }
            }
            assert_eq!(
                detected,
                Some(expected_variant),
                "failed to detect variant {expected_variant:?}"
            );
            // Crucial zero-leakage check: no byte of the raw secret may appear in emitted output.
            assert!(
                !emitted
                    .windows(secret.as_bytes().len())
                    .any(|w| w == secret.as_bytes()),
                "secret leaked before abort!"
            );
        }
    }

    #[test]
    fn redact_replaces_split_secrets_cleanly() {
        let secret = SecretValue::new("tok-9876543210").unwrap();
        let scanner =
            ReflectionScanner::compile([("tok".to_owned(), &secret)], ReflectionAction::Redact)
                .unwrap();

        let b64 = STANDARD.encode(secret.as_bytes());
        let full = format!("hello {} and {} bye", secret.as_str(), b64);

        let mut stream = scanner.new_stream();
        let mut out = Vec::new();
        for chunk in full.as_bytes().chunks(3) {
            out.extend_from_slice(&stream.push_chunk(chunk).unwrap());
        }
        out.extend_from_slice(&stream.finish().unwrap());

        let result = String::from_utf8(out).unwrap();
        assert_eq!(
            result,
            "hello [REDACTED_SECRET] and [REDACTED_SECRET] bye"
        );
        assert_eq!(stream.matches().len(), 2);
    }

    #[test]
    fn clean_stream_passes_through_unchanged() {
        let secret = SecretValue::new("super-secret-token-xyz").unwrap();
        let scanner =
            ReflectionScanner::compile([("s".to_owned(), &secret)], ReflectionAction::Abort)
                .unwrap();

        let body = b"completely normal json payload {\"ok\":true,\"data\":\"hello world\"}";
        let mut stream = scanner.new_stream();
        let mut out = Vec::new();
        for chunk in body.chunks(5) {
            out.extend_from_slice(&stream.push_chunk(chunk).unwrap());
        }
        out.extend_from_slice(&stream.finish().unwrap());
        assert_eq!(out, body);
    }
}
