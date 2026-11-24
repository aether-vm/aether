//! Segmented Hash-Chained Encrypted Audit Log & Honest Key-Slot Crypto-Shredding
//! (ARCHITECTURE_V2 §6.2).
//!
//! Security boundaries:
//! - Each world receives a 256-bit master wrap key stored in an independent `0600` key-slot file
//!   outside `redb` (`<key_dir>/<world_base32>.key`) so B-tree free pages never retain key material.
//! - Each audit segment (`<audit_dir>/<world_base32>/<seq:08>.aseg`) generates a fresh random
//!   256-bit segment DEK, wraps it under the world's master wrap key using XChaCha20-Poly1305,
//!   encrypts the segment records with the DEK using XChaCha20-Poly1305 (binding header +
//!   `prev_hash` + `seq` + `world_id` as AAD), and appends a `blake3` chain hash linking every
//!   segment to `prev_hash`.
//! - Segments are written atomically via `*.aseg.tmp` + `fsync` + `rename` + parent dir `fsync`.
//! - [`AuditStore::crypto_shred`] destroys a world's master wrap key by overwriting the key-slot
//!   file with CSPRNG random bytes + `fsync`, overwriting with zeros + `fsync`, unlinking, and
//!   `fsync`ing the directory. Physical flash wear-leveling remnants rely on full-disk LUKS
//!   encryption as the outer defense (ARCHITECTURE_V2 §6.2).

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use aos_types::{EpochId, WorldId};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{GwError, Result};

const KEY_SLOT_MAGIC: &[u8; 8] = b"FLKS0001";
const KEY_SLOT_LEN: usize = 8 + 16 + 32 + 32; // magic + world_id + master_key + blake3 checksum

const SEG_MAGIC: &[u8; 8] = b"FLAS0001";
const SEG_VERSION: u8 = 1;
const SEG_COMPRESSION_NONE: u8 = 0;

/// Fixed binary header size of an `.aseg` segment file.
///
/// Layout (180 bytes):
/// - `[0..8]`     `magic` (`b"FLAS0001"`)
/// - `[8..9]`     `version` (`1`)
/// - `[9..10]`    `compression` (`0 = none`)
/// - `[10..12]`   `reserved` (`[0, 0]`)
/// - `[12..28]`   `world_id` (16 raw bytes)
/// - `[28..36]`   `seq` (`u64` big-endian, 1-based contiguous)
/// - `[36..44]`   `record_count` (`u64` big-endian)
/// - `[44..76]`   `prev_hash` (`[u8; 32]`, all zeros for `seq == 1`)
/// - `[76..100]`  `wrap_nonce` (24-byte XChaCha20 nonce)
/// - `[100..148]` `wrapped_dek` (32B DEK + 16B Poly1305 tag)
/// - `[148..172]` `body_nonce` (24-byte XChaCha20 nonce)
/// - `[172..180]` `ciphertext_len` (`u64` big-endian)
const SEG_HEADER_LEN: usize = 180;
const SEG_HASH_LEN: usize = 32;
const AEAD_TAG_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const WRAPPED_DEK_LEN: usize = KEY_LEN + AEAD_TAG_LEN;

/// Maximum single segment file size accepted by `verify_chain` / `read_records` (64 MiB).
const MAX_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;

/// High-level outcome of a proxied or policy-evaluated gateway request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditOutcome {
    /// Request allowed and upstream response forwarded cleanly.
    Allowed,
    /// Request denied by capability policy (host/path/method/placeholder).
    Denied,
    /// Request blocked by SSRF IP filter.
    SsrfBlocked,
    /// Upstream response aborted because a secret reflection was detected.
    ReflectionBlocked,
    /// Upstream response had one or more secret reflections redacted.
    ReflectionRedacted,
    /// Upstream compressed response blocked while secrets were active.
    CompressedResponseBlocked,
    /// Request or connection terminated because the epoch fence advanced or slot was revoked.
    EpochRevoked,
    /// Upstream I/O, timeout, or protocol error.
    UpstreamError,
}

/// Sanitized, secret-free audit record persisted inside encrypted `.aseg` segments.
///
/// Raw secrets, authorization headers, and request/response bodies are NEVER stored here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Unix timestamp in milliseconds when the event was recorded.
    pub timestamp_ms: u64,
    /// Owning world identifier.
    pub world_id: WorldId,
    /// Gateway epoch under which the event occurred.
    pub epoch: EpochId,
    /// Network slot identifier.
    pub slot_id: String,
    /// HTTP method (e.g. `"GET"`, `"POST"`).
    pub method: String,
    /// Target canonical host.
    pub host: String,
    /// Sanitized request path (no query secrets).
    pub path: String,
    /// HTTP status code returned to the sandbox (if a response was produced).
    pub status_code: Option<u16>,
    /// Policy / security outcome.
    pub outcome: AuditOutcome,
    /// Request body bytes forwarded.
    pub bytes_in: u64,
    /// Response body bytes forwarded.
    pub bytes_out: u64,
    /// Optional non-secret detail note (e.g. matched credential label or denial reason).
    pub detail: Option<String>,
}

impl AuditRecord {
    /// Current wall-clock Unix time in milliseconds.
    #[must_use]
    pub fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }
}

/// Receipt returned after durably committing an encrypted audit segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentReceipt {
    /// 1-based contiguous segment sequence number.
    pub seq: u64,
    /// Number of audit records encrypted inside this segment.
    pub record_count: u64,
    /// `blake3` hash of `header || ciphertext` forming the chain link for `seq + 1`.
    pub segment_hash: [u8; 32],
}

/// Report returned by [`AuditStore::verify_chain`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainVerificationReport {
    /// Total contiguous segments verified (`1..=segment_count`).
    pub segment_count: u64,
    /// Total decrypted audit records across all verified segments.
    pub total_records: u64,
    /// Hash of the final segment (`[0; 32]` if zero segments exist).
    pub tip_hash: [u8; 32],
}

#[derive(Debug, Clone)]
struct WorldChainState {
    next_seq: u64,
    prev_hash: [u8; 32],
}

/// Segmented hash-chained encrypted audit store backed by independent `0600` per-world
/// key-slot files and atomic `audit/<world>/<seq>.aseg` segments.
#[derive(Debug)]
pub struct AuditStore {
    audit_dir: PathBuf,
    key_dir: PathBuf,
    state: Mutex<AuditRuntimeState>,
}

#[derive(Debug, Default)]
struct AuditRuntimeState {
    chains: HashMap<WorldId, WorldChainState>,
    shredded: HashSet<WorldId>,
}

impl AuditStore {
    /// Open or initialize an audit store with `audit_dir` (for `<world>/<seq>.aseg`) and
    /// independent `key_dir` (for `0600` `<world>.key` master wrap key slots).
    pub fn open(audit_dir: impl Into<PathBuf>, key_dir: impl Into<PathBuf>) -> Result<Self> {
        let audit_dir = audit_dir.into();
        let key_dir = key_dir.into();
        fs::create_dir_all(&audit_dir)?;
        fs::create_dir_all(&key_dir)?;
        restrict_dir_0700(&key_dir)?;
        Ok(Self {
            audit_dir,
            key_dir,
            state: Mutex::new(AuditRuntimeState::default()),
        })
    }

    /// Directory containing `<world>/<seq>.aseg` audit segments.
    #[must_use]
    pub fn audit_dir(&self) -> &Path {
        &self.audit_dir
    }

    /// Directory containing independent `0600` `<world>.key` master wrap key slots.
    #[must_use]
    pub fn key_dir(&self) -> &Path {
        &self.key_dir
    }

    /// Path of a world's independent `0600` key-slot file.
    #[must_use]
    pub fn key_slot_path(&self, world_id: WorldId) -> PathBuf {
        self.key_dir.join(format!("{}.key", world_id.to_base32()))
    }

    /// Directory holding a world's `.aseg` segment files (`audit/<world>/`).
    #[must_use]
    pub fn world_audit_dir(&self, world_id: WorldId) -> PathBuf {
        self.audit_dir.join(world_id.to_base32())
    }

    /// Path of a specific `.aseg` segment (`audit/<world>/<seq:08>.aseg`).
    #[must_use]
    pub fn segment_path(&self, world_id: WorldId, seq: u64) -> PathBuf {
        self.world_audit_dir(world_id)
            .join(format!("{seq:08}.aseg"))
    }

    /// Generate and durably persist a fresh 256-bit master wrap key in a `0600` key-slot file
    /// for `world_id`. Fails if the key slot already exists or if `world_id` was shredded.
    pub fn init_world(&self, world_id: WorldId) -> Result<PathBuf> {
        let mut rt = self.state.lock().expect("audit store lock poisoned");
        if rt.shredded.contains(&world_id) {
            return Err(GwError::AuditKeyMissing { world_id });
        }

        let key_path = self.key_slot_path(world_id);
        if fs::symlink_metadata(&key_path).is_ok() {
            return Err(GwError::InvalidPolicy(format!(
                "audit key slot already exists for world {world_id}"
            )));
        }

        let mut master_key = Zeroizing::new([0u8; KEY_LEN]);
        fill_random(&mut *master_key)?;
        write_key_slot_file(&key_path, world_id, &master_key)?;

        let world_dir = self.world_audit_dir(world_id);
        fs::create_dir_all(&world_dir)?;
        fsync_dir(&world_dir)?;

        rt.chains.insert(
            world_id,
            WorldChainState {
                next_seq: 1,
                prev_hash: [0u8; 32],
            },
        );
        Ok(key_path)
    }

    /// Ensure a world has an initialized key slot (idempotent for fresh worlds, NEVER resurrects
    /// a crypto-shredded world).
    pub fn ensure_world(&self, world_id: WorldId) -> Result<()> {
        let key_path = self.key_slot_path(world_id);
        {
            let rt = self.state.lock().expect("audit store lock poisoned");
            if rt.shredded.contains(&world_id) {
                return Err(GwError::AuditKeyMissing { world_id });
            }
            if rt.chains.contains_key(&world_id) && fs::symlink_metadata(&key_path).is_ok() {
                return Ok(());
            }
        }
        if fs::symlink_metadata(&key_path).is_ok() {
            // Existing key slot on disk (e.g. after daemon restart): verify chain to resume tip.
            let report = self.verify_chain(world_id)?;
            let mut rt = self.state.lock().expect("audit store lock poisoned");
            rt.chains.insert(
                world_id,
                WorldChainState {
                    next_seq: report.segment_count + 1,
                    prev_hash: report.tip_hash,
                },
            );
            Ok(())
        } else {
            self.init_world(world_id).map(|_| ())
        }
    }

    /// Append a batch of one or more sanitized audit records as a new atomic, AEAD-encrypted,
    /// hash-chained `.aseg` segment for `world_id`.
    pub fn append_segment(
        &self,
        world_id: WorldId,
        records: &[AuditRecord],
    ) -> Result<SegmentReceipt> {
        if records.is_empty() {
            return Err(GwError::InvalidPolicy(
                "cannot write empty audit segment".into(),
            ));
        }

        let mut rt = self.state.lock().expect("audit store lock poisoned");
        if rt.shredded.contains(&world_id) {
            return Err(GwError::AuditKeyMissing { world_id });
        }

        let key_path = self.key_slot_path(world_id);
        let master_key = load_key_slot_file(&key_path, world_id)?;

        // If runtime state isn't loaded yet (e.g. reopen after restart), verify existing chain.
        let chain = if let Some(c) = rt.chains.get(&world_id).cloned() {
            c
        } else {
            let report = verify_chain_unlocked(&self.world_audit_dir(world_id), world_id, &master_key)?;
            let c = WorldChainState {
                next_seq: report.segment_count + 1,
                prev_hash: report.tip_hash,
            };
            rt.chains.insert(world_id, c.clone());
            c
        };

        let world_dir = self.world_audit_dir(world_id);
        fs::create_dir_all(&world_dir)?;
        cleanup_stale_tmp_segments(&world_dir)?;

        let seq = chain.next_seq;
        let prev_hash = chain.prev_hash;

        // Serialize records to JSON plaintext.
        let plaintext = Zeroizing::new(serde_json::to_vec(records)?);

        // Generate fresh per-segment DEK + nonces.
        let mut dek = Zeroizing::new([0u8; KEY_LEN]);
        fill_random(&mut *dek)?;
        let mut wrap_nonce = [0u8; NONCE_LEN];
        fill_random(&mut wrap_nonce)?;
        let mut body_nonce = [0u8; NONCE_LEN];
        fill_random(&mut body_nonce)?;

        // Wrap DEK under master_key with AAD binding (magic || version || world_id || seq || prev_hash).
        let wrap_aad = build_wrap_aad(world_id, seq, &prev_hash);
        let wrap_cipher = XChaCha20Poly1305::new((&*master_key).into());
        let wrapped_dek_vec = wrap_cipher
            .encrypt(
                XNonce::from_slice(&wrap_nonce),
                Payload {
                    msg: dek.as_slice(),
                    aad: &wrap_aad,
                },
            )
            .map_err(|e| GwError::Crypto(format!("DEK wrap failed: {e}")))?;
        let wrapped_dek: [u8; WRAPPED_DEK_LEN] = wrapped_dek_vec
            .try_into()
            .map_err(|_| GwError::Crypto("unexpected wrapped DEK length".into()))?;

        // Build full 180-byte header first (ciphertext_len = plaintext.len() + AEAD_TAG_LEN).
        let ciphertext_len = (plaintext.len() + AEAD_TAG_LEN) as u64;
        let record_count = records.len() as u64;
        let header = encode_segment_header(
            world_id,
            seq,
            record_count,
            &prev_hash,
            &wrap_nonce,
            &wrapped_dek,
            &body_nonce,
            ciphertext_len,
        );

        // Encrypt segment payload with per-segment DEK, binding full 180-byte header as AAD.
        let body_cipher = XChaCha20Poly1305::new((&*dek).into());
        let ciphertext = body_cipher
            .encrypt(
                XNonce::from_slice(&body_nonce),
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &header,
                },
            )
            .map_err(|e| GwError::Crypto(format!("segment encryption failed: {e}")))?;
        debug_assert_eq!(ciphertext.len() as u64, ciphertext_len);

        // Compute blake3 hash over header || ciphertext.
        let segment_hash = compute_segment_hash(&header, &ciphertext);

        // Atomic write: <seq>.aseg.tmp -> fsync -> rename -> fsync(dir).
        let final_path = self.segment_path(world_id, seq);
        let tmp_path = world_dir.join(format!("{seq:08}.aseg.tmp"));
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)?;
            f.write_all(&header)?;
            f.write_all(&ciphertext)?;
            f.write_all(&segment_hash)?;
            f.sync_all()?;
        }
        fs::rename(&tmp_path, &final_path)?;
        fsync_dir(&world_dir)?;

        rt.chains.insert(
            world_id,
            WorldChainState {
                next_seq: seq + 1,
                prev_hash: segment_hash,
            },
        );

        Ok(SegmentReceipt {
            seq,
            record_count,
            segment_hash,
        })
    }

    /// Convenience helper appending a single audit record as a durable segment.
    pub fn append_record(&self, record: AuditRecord) -> Result<SegmentReceipt> {
        let world_id = record.world_id;
        self.append_segment(world_id, &[record])
    }

    /// Verify every segment in `audit/<world>/`:
    /// - contiguous sequence numbers `1..=N` (no gaps, no reordered segments),
    /// - `world_id` matches directory,
    /// - `prev_hash` forms an unbroken `blake3` hash chain from `[0; 32]`,
    /// - trailing `segment_hash` equals `blake3(header || ciphertext)`,
    /// - `wrapped_dek` authenticates and unwraps under the world's master wrap key,
    /// - `ciphertext` authenticates and decrypts under the segment DEK with full header AAD,
    /// - decrypted JSON record count matches header `record_count`.
    pub fn verify_chain(&self, world_id: WorldId) -> Result<ChainVerificationReport> {
        let key_path = self.key_slot_path(world_id);
        let master_key = load_key_slot_file(&key_path, world_id)?;
        verify_chain_unlocked(&self.world_audit_dir(world_id), world_id, &master_key)
    }

    /// Verify the chain AND confirm it matches an externally tracked `(expected_segments, expected_tip_hash)`
    /// to detect tail-truncation attacks.
    pub fn verify_chain_with_tip(
        &self,
        world_id: WorldId,
        expected_segments: u64,
        expected_tip_hash: [u8; 32],
    ) -> Result<ChainVerificationReport> {
        let report = self.verify_chain(world_id)?;
        if report.segment_count != expected_segments {
            return Err(GwError::AuditChainTampered {
                world_id,
                seq: expected_segments,
                reason: format!(
                    "segment count mismatch (truncation/injection): expected {expected_segments}, found {}",
                    report.segment_count
                ),
            });
        }
        if report.tip_hash != expected_tip_hash {
            return Err(GwError::AuditChainTampered {
                world_id,
                seq: report.segment_count,
                reason: "chain tip hash mismatch".into(),
            });
        }
        Ok(report)
    }

    /// Verify the full hash chain and decrypt/return all audit records for `world_id` in order.
    pub fn read_records(&self, world_id: WorldId) -> Result<Vec<AuditRecord>> {
        let key_path = self.key_slot_path(world_id);
        let master_key = load_key_slot_file(&key_path, world_id)?;
        let (_report, records) =
            verify_and_read_unlocked(&self.world_audit_dir(world_id), world_id, &master_key)?;
        Ok(records)
    }

    /// Crypto-shred `world_id`'s master wrap key slot:
    /// 1. Rejects symlinks (refuses to overwrite targets outside `key_dir`).
    /// 2. Overwrites full file length with CSPRNG random bytes + `fsync`.
    /// 3. Overwrites full file length with zeros + `fsync`.
    /// 4. Unlinks the key-slot file + `fsync(key_dir)`.
    /// 5. Marks `world_id` as shredded in memory so future appends/reads fail cleanly.
    ///
    /// Note: SSD flash wear-leveling physical remnants rely on full-disk LUKS encryption
    /// as documented in ARCHITECTURE_V2 §6.2.
    pub fn crypto_shred(&self, world_id: WorldId) -> Result<()> {
        let mut rt = self.state.lock().expect("audit store lock poisoned");
        rt.chains.remove(&world_id);
        rt.shredded.insert(world_id);

        let key_path = self.key_slot_path(world_id);
        let md = match fs::symlink_metadata(&key_path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(GwError::AuditKeyMissing { world_id });
            }
            Err(e) => return Err(GwError::Io(e)),
        };

        if md.file_type().is_symlink() || !md.file_type().is_file() {
            return Err(GwError::AuditKeyCorrupt {
                path: key_path,
                reason: "refusing to crypto-shred symlink or non-regular file".into(),
            });
        }

        let len = usize::try_from(md.len().max(KEY_SLOT_LEN as u64)).unwrap_or(KEY_SLOT_LEN);
        {
            let mut f = OpenOptions::new().read(true).write(true).open(&key_path)?;

            // Pass 1: overwrite with CSPRNG random bytes + fsync.
            let mut noise = Zeroizing::new(vec![0u8; len]);
            fill_random(&mut noise)?;
            f.seek(SeekFrom::Start(0))?;
            f.write_all(&noise)?;
            f.sync_all()?;

            // Pass 2: overwrite with zeros + fsync.
            let zeros = vec![0u8; len];
            f.seek(SeekFrom::Start(0))?;
            f.write_all(&zeros)?;
            f.sync_all()?;
        }

        fs::remove_file(&key_path)?;
        fsync_dir(&self.key_dir)?;
        Ok(())
    }
}

fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|e| GwError::Entropy(e.to_string()))
}

fn write_key_slot_file(path: &Path, world_id: WorldId, master_key: &[u8; KEY_LEN]) -> Result<()> {
    let mut blob = Zeroizing::new([0u8; KEY_SLOT_LEN]);
    blob[0..8].copy_from_slice(KEY_SLOT_MAGIC);
    blob[8..24].copy_from_slice(world_id.as_bytes());
    blob[24..56].copy_from_slice(master_key);
    let checksum = blake3::hash(&blob[0..56]);
    blob[56..88].copy_from_slice(checksum.as_bytes());

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let mut f = opts.open(path)?;
    f.write_all(&*blob)?;
    f.sync_all()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }

    if let Some(parent) = path.parent() {
        fsync_dir(parent)?;
    }
    Ok(())
}

fn load_key_slot_file(path: &Path, expected_world: WorldId) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let md = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(GwError::AuditKeyMissing {
                world_id: expected_world,
            });
        }
        Err(e) => return Err(GwError::Io(e)),
    };

    if md.file_type().is_symlink() || !md.file_type().is_file() {
        return Err(GwError::AuditKeyCorrupt {
            path: path.to_path_buf(),
            reason: "key slot must be a regular file, not a symlink".into(),
        });
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = md.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(GwError::AuditKeyCorrupt {
                path: path.to_path_buf(),
                reason: format!("key slot permissions must be 0600, found {mode:04o}"),
            });
        }
    }

    let mut f = File::open(path)?;
    let mut raw = Zeroizing::new(Vec::new());
    f.read_to_end(&mut raw)?;
    if raw.len() != KEY_SLOT_LEN {
        return Err(GwError::AuditKeyCorrupt {
            path: path.to_path_buf(),
            reason: format!("expected {KEY_SLOT_LEN} bytes, got {}", raw.len()),
        });
    }
    if &raw[0..8] != KEY_SLOT_MAGIC {
        return Err(GwError::AuditKeyCorrupt {
            path: path.to_path_buf(),
            reason: "invalid key slot magic".into(),
        });
    }
    if &raw[8..24] != expected_world.as_bytes() {
        return Err(GwError::AuditKeyCorrupt {
            path: path.to_path_buf(),
            reason: "key slot world_id mismatch".into(),
        });
    }
    let expected_checksum = blake3::hash(&raw[0..56]);
    if &raw[56..88] != expected_checksum.as_bytes() {
        return Err(GwError::AuditKeyCorrupt {
            path: path.to_path_buf(),
            reason: "key slot blake3 checksum mismatch".into(),
        });
    }

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(&raw[24..56]);
    Ok(key)
}

fn build_wrap_aad(world_id: WorldId, seq: u64, prev_hash: &[u8; 32]) -> [u8; 8 + 1 + 16 + 8 + 32] {
    let mut aad = [0u8; 65];
    aad[0..8].copy_from_slice(SEG_MAGIC);
    aad[8] = SEG_VERSION;
    aad[9..25].copy_from_slice(world_id.as_bytes());
    aad[25..33].copy_from_slice(&seq.to_be_bytes());
    aad[33..65].copy_from_slice(prev_hash);
    aad
}

#[allow(clippy::too_many_arguments)]
fn encode_segment_header(
    world_id: WorldId,
    seq: u64,
    record_count: u64,
    prev_hash: &[u8; 32],
    wrap_nonce: &[u8; NONCE_LEN],
    wrapped_dek: &[u8; WRAPPED_DEK_LEN],
    body_nonce: &[u8; NONCE_LEN],
    ciphertext_len: u64,
) -> [u8; SEG_HEADER_LEN] {
    let mut h = [0u8; SEG_HEADER_LEN];
    h[0..8].copy_from_slice(SEG_MAGIC);
    h[8] = SEG_VERSION;
    h[9] = SEG_COMPRESSION_NONE;
    h[10..12].copy_from_slice(&[0, 0]);
    h[12..28].copy_from_slice(world_id.as_bytes());
    h[28..36].copy_from_slice(&seq.to_be_bytes());
    h[36..44].copy_from_slice(&record_count.to_be_bytes());
    h[44..76].copy_from_slice(prev_hash);
    h[76..100].copy_from_slice(wrap_nonce);
    h[100..148].copy_from_slice(wrapped_dek);
    h[148..172].copy_from_slice(body_nonce);
    h[172..180].copy_from_slice(&ciphertext_len.to_be_bytes());
    h
}

fn compute_segment_hash(header: &[u8; SEG_HEADER_LEN], ciphertext: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(header);
    hasher.update(ciphertext);
    *hasher.finalize().as_bytes()
}

fn cleanup_stale_tmp_segments(world_dir: &Path) -> Result<()> {
    for entry in fs::read_dir(world_dir)? {
        let entry = entry?;
        if let Some(name) = entry.file_name().to_str()
            && name.ends_with(".aseg.tmp")
        {
            let _ = fs::remove_file(entry.path());
        }
    }
    Ok(())
}

fn verify_chain_unlocked(
    world_dir: &Path,
    world_id: WorldId,
    master_key: &[u8; KEY_LEN],
) -> Result<ChainVerificationReport> {
    let (report, _) = verify_and_read_unlocked(world_dir, world_id, master_key)?;
    Ok(report)
}

fn verify_and_read_unlocked(
    world_dir: &Path,
    world_id: WorldId,
    master_key: &[u8; KEY_LEN],
) -> Result<(ChainVerificationReport, Vec<AuditRecord>)> {
    if !world_dir.exists() {
        return Ok((
            ChainVerificationReport {
                segment_count: 0,
                total_records: 0,
                tip_hash: [0u8; 32],
            },
            Vec::new(),
        ));
    }

    let mut segments: Vec<(u64, PathBuf)> = Vec::new();
    for entry in fs::read_dir(world_dir)? {
        let entry = entry?;
        let fname = entry.file_name();
        let Some(name) = fname.to_str() else {
            return Err(GwError::AuditChainTampered {
                world_id,
                seq: 0,
                reason: "non-UTF8 filename inside audit directory".into(),
            });
        };
        if name.ends_with(".aseg.tmp") {
            // Uncommitted crash temp file: rollback-only semantics ignore/skip it.
            continue;
        }
        let Some(stem) = name.strip_suffix(".aseg") else {
            return Err(GwError::AuditChainTampered {
                world_id,
                seq: 0,
                reason: format!("unexpected file {name:?} in audit directory"),
            });
        };
        let seq: u64 = stem.parse().map_err(|_| GwError::AuditChainTampered {
            world_id,
            seq: 0,
            reason: format!("invalid segment filename {name:?}"),
        })?;
        if format!("{seq:08}.aseg") != name || seq == 0 {
            return Err(GwError::AuditChainTampered {
                world_id,
                seq,
                reason: format!("non-canonical segment filename {name:?}"),
            });
        }
        segments.push((seq, entry.path()));
    }

    segments.sort_by_key(|(seq, _)| *seq);

    let wrap_cipher = XChaCha20Poly1305::new(master_key.into());
    let mut expected_seq = 1u64;
    let mut expected_prev_hash = [0u8; 32];
    let mut total_records = 0u64;
    let mut all_records = Vec::new();

    for (file_seq, path) in segments {
        if file_seq != expected_seq {
            return Err(GwError::AuditChainTampered {
                world_id,
                seq: expected_seq,
                reason: format!(
                    "missing or out-of-order segment: expected seq {expected_seq}, found {file_seq}"
                ),
            });
        }

        let md = fs::symlink_metadata(&path)?;
        if md.file_type().is_symlink() || !md.file_type().is_file() {
            return Err(GwError::AuditChainTampered {
                world_id,
                seq: expected_seq,
                reason: "segment must be a regular file".into(),
            });
        }
        if md.len() > MAX_SEGMENT_BYTES {
            return Err(GwError::AuditChainTampered {
                world_id,
                seq: expected_seq,
                reason: "segment exceeds maximum allowed size".into(),
            });
        }

        let raw = fs::read(&path)?;
        let min_len = SEG_HEADER_LEN + AEAD_TAG_LEN + SEG_HASH_LEN;
        if raw.len() < min_len {
            return Err(GwError::AuditChainTampered {
                world_id,
                seq: expected_seq,
                reason: format!("truncated segment: {} bytes < {min_len}", raw.len()),
            });
        }

        let header: [u8; SEG_HEADER_LEN] = raw[0..SEG_HEADER_LEN]
            .try_into()
            .expect("header slice exact length");
        if &header[0..8] != SEG_MAGIC {
            return Err(GwError::AuditChainTampered {
                world_id,
                seq: expected_seq,
                reason: "invalid segment magic".into(),
            });
        }
        if header[8] != SEG_VERSION || header[9] != SEG_COMPRESSION_NONE {
            return Err(GwError::AuditChainTampered {
                world_id,
                seq: expected_seq,
                reason: "unsupported segment version or compression".into(),
            });
        }
        if &header[12..28] != world_id.as_bytes() {
            return Err(GwError::AuditChainTampered {
                world_id,
                seq: expected_seq,
                reason: "header world_id mismatch".into(),
            });
        }
        let header_seq = u64::from_be_bytes(header[28..36].try_into().unwrap());
        if header_seq != expected_seq {
            return Err(GwError::AuditChainTampered {
                world_id,
                seq: expected_seq,
                reason: format!("header seq {header_seq} != filename seq {expected_seq}"),
            });
        }
        let record_count = u64::from_be_bytes(header[36..44].try_into().unwrap());
        let prev_hash: [u8; 32] = header[44..76].try_into().unwrap();
        if prev_hash != expected_prev_hash {
            return Err(GwError::AuditChainTampered {
                world_id,
                seq: expected_seq,
                reason: "prev_hash chain link mismatch".into(),
            });
        }

        let wrap_nonce = &header[76..100];
        let wrapped_dek = &header[100..148];
        let body_nonce = &header[148..172];
        let ciphertext_len = u64::from_be_bytes(header[172..180].try_into().unwrap());

        let expected_total_len = (SEG_HEADER_LEN as u64)
            .checked_add(ciphertext_len)
            .and_then(|v| v.checked_add(SEG_HASH_LEN as u64))
            .ok_or_else(|| GwError::AuditChainTampered {
                world_id,
                seq: expected_seq,
                reason: "ciphertext length overflow".into(),
            })?;
        if raw.len() as u64 != expected_total_len {
            return Err(GwError::AuditChainTampered {
                world_id,
                seq: expected_seq,
                reason: format!(
                    "segment size mismatch: file has {} bytes, header implies {expected_total_len}",
                    raw.len()
                ),
            });
        }

        let ct_end = SEG_HEADER_LEN + usize::try_from(ciphertext_len).unwrap();
        let ciphertext = &raw[SEG_HEADER_LEN..ct_end];
        let stored_hash: [u8; 32] = raw[ct_end..ct_end + SEG_HASH_LEN].try_into().unwrap();

        let computed_hash = compute_segment_hash(&header, ciphertext);
        if stored_hash != computed_hash {
            return Err(GwError::AuditChainTampered {
                world_id,
                seq: expected_seq,
                reason: "blake3 segment hash mismatch".into(),
            });
        }

        // Unwrap DEK with AAD verification.
        let wrap_aad = build_wrap_aad(world_id, expected_seq, &prev_hash);
        let dek_vec = wrap_cipher
            .decrypt(
                XNonce::from_slice(wrap_nonce),
                Payload {
                    msg: wrapped_dek,
                    aad: &wrap_aad,
                },
            )
            .map_err(|_| GwError::AuditChainTampered {
                world_id,
                seq: expected_seq,
                reason: "DEK unwrap AEAD authentication failed".into(),
            })?;
        let dek_bytes: [u8; KEY_LEN] = dek_vec
            .try_into()
            .map_err(|_| GwError::AuditChainTampered {
                world_id,
                seq: expected_seq,
                reason: "unwrapped DEK has wrong length".into(),
            })?;
        let dek = Zeroizing::new(dek_bytes);

        // Decrypt segment payload with header AAD.
        let body_cipher = XChaCha20Poly1305::new((&*dek).into());
        let plaintext = Zeroizing::new(
            body_cipher
                .decrypt(
                    XNonce::from_slice(body_nonce),
                    Payload {
                        msg: ciphertext,
                        aad: &header,
                    },
                )
                .map_err(|_| GwError::AuditChainTampered {
                    world_id,
                    seq: expected_seq,
                    reason: "segment ciphertext AEAD authentication failed".into(),
                })?,
        );

        let records: Vec<AuditRecord> =
            serde_json::from_slice(&plaintext).map_err(|e| GwError::AuditChainTampered {
                world_id,
                seq: expected_seq,
                reason: format!("corrupt audit JSON payload: {e}"),
            })?;

        if records.len() as u64 != record_count {
            return Err(GwError::AuditChainTampered {
                world_id,
                seq: expected_seq,
                reason: format!(
                    "header record_count {record_count} != decrypted count {}",
                    records.len()
                ),
            });
        }

        total_records += record_count;
        all_records.extend(records);
        expected_prev_hash = computed_hash;
        expected_seq += 1;
    }

    Ok((
        ChainVerificationReport {
            segment_count: expected_seq - 1,
            total_records,
            tip_hash: expected_prev_hash,
        },
        all_records,
    ))
}

#[cfg(unix)]
fn restrict_dir_0700(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_dir_0700(_dir: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn fsync_dir(dir: &Path) -> Result<()> {
    let f = File::open(dir)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn fsync_dir(_dir: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record(world_id: WorldId, idx: u64) -> AuditRecord {
        AuditRecord {
            timestamp_ms: 1_700_000_000_000 + idx,
            world_id,
            epoch: EpochId::FIRST,
            slot_id: "slot-0".into(),
            method: "POST".into(),
            host: "api.example.com".into(),
            path: format!("/v1/chat/{idx}"),
            status_code: Some(200),
            outcome: AuditOutcome::Allowed,
            bytes_in: 128,
            bytes_out: 256,
            detail: None,
        }
    }

    fn temp_test_dir(tag: &str) -> PathBuf {
        let mut rand = [0u8; 8];
        getrandom::fill(&mut rand).unwrap();
        let hex: String = rand.iter().map(|b| format!("{b:02x}")).collect();
        let p = std::env::temp_dir().join(format!("aos-gw-audit-{tag}-{hex}"));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn encrypted_chain_roundtrip_tamper_detection_and_crypto_shred() {
        let root = temp_test_dir("roundtrip");
        let store = AuditStore::open(root.join("audit"), root.join("keys")).unwrap();
        let w = WorldId::random();

        let key_path = store.init_world(w).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "key slot must be 0600");
        }

        let r1 = store.append_record(sample_record(w, 1)).unwrap();
        let r2 = store.append_segment(w, &[sample_record(w, 2), sample_record(w, 3)]).unwrap();
        let r3 = store.append_record(sample_record(w, 4)).unwrap();
        assert_eq!(r1.seq, 1);
        assert_eq!(r2.seq, 2);
        assert_eq!(r3.seq, 3);

        // Plaintext path must NOT appear anywhere in raw encrypted .aseg file!
        let seg1_bytes = fs::read(store.segment_path(w, 1)).unwrap();
        assert!(
            !seg1_bytes
                .windows(b"/v1/chat/1".len())
                .any(|win| win == b"/v1/chat/1"),
            "audit plaintext leaked unencrypted on disk!"
        );

        // Full verification succeeds.
        let report = store.verify_chain_with_tip(w, 3, r3.segment_hash).unwrap();
        assert_eq!(report.segment_count, 3);
        assert_eq!(report.total_records, 4);
        let decoded = store.read_records(w).unwrap();
        assert_eq!(decoded.len(), 4);
        assert_eq!(decoded[0].path, "/v1/chat/1");
        assert_eq!(decoded[3].path, "/v1/chat/4");

        // Tamper test 1: flip a single bit in segment 2 ciphertext -> detected!
        let seg2_path = store.segment_path(w, 2);
        let orig_seg2 = fs::read(&seg2_path).unwrap();
        let mut tampered = orig_seg2.clone();
        tampered[SEG_HEADER_LEN + 5] ^= 0x01;
        fs::write(&seg2_path, &tampered).unwrap();
        assert!(matches!(
            store.verify_chain(w),
            Err(GwError::AuditChainTampered { seq: 2, .. })
        ));
        // Restore segment 2.
        fs::write(&seg2_path, &orig_seg2).unwrap();
        assert!(store.verify_chain(w).is_ok());

        // Tamper test 2: delete segment 2 (gap in hash chain) -> detected!
        fs::remove_file(&seg2_path).unwrap();
        assert!(matches!(
            store.verify_chain(w),
            Err(GwError::AuditChainTampered { seq: 2, .. })
        ));
        fs::write(&seg2_path, &orig_seg2).unwrap();
        assert!(store.verify_chain(w).is_ok());

        // Tamper test 3: swap segment 1 and segment 2 -> detected!
        let seg1_path = store.segment_path(w, 1);
        let orig_seg1 = fs::read(&seg1_path).unwrap();
        fs::write(&seg1_path, &orig_seg2).unwrap();
        fs::write(&seg2_path, &orig_seg1).unwrap();
        assert!(matches!(
            store.verify_chain(w),
            Err(GwError::AuditChainTampered { seq: 1, .. })
        ));
        fs::write(&seg1_path, &orig_seg1).unwrap();
        fs::write(&seg2_path, &orig_seg2).unwrap();
        assert!(store.verify_chain(w).is_ok());

        // Reopen AuditStore (simulating daemon restart) with a leftover `.aseg.tmp` crash file.
        let stale_tmp = store.world_audit_dir(w).join("00000004.aseg.tmp");
        fs::write(&stale_tmp, b"partial torn write").unwrap();
        let reopened = AuditStore::open(root.join("audit"), root.join("keys")).unwrap();
        // Rollback-only: verify_chain ignores torn .aseg.tmp and validates segments 1..=3.
        let re_report = reopened.verify_chain_with_tip(w, 3, r3.segment_hash).unwrap();
        assert_eq!(re_report.segment_count, 3);
        // Appending segment 4 cleans stale tmp and continues the hash chain cleanly.
        let r4 = reopened.append_record(sample_record(w, 5)).unwrap();
        assert_eq!(r4.seq, 4);
        assert!(!stale_tmp.exists());
        assert_eq!(reopened.verify_chain_with_tip(w, 4, r4.segment_hash).unwrap().total_records, 5);

        // Tail truncation test: deleting segment 4 is detected by verify_chain_with_tip.
        let seg4_path = reopened.segment_path(w, 4);
        let orig_seg4 = fs::read(&seg4_path).unwrap();
        fs::remove_file(&seg4_path).unwrap();
        assert!(matches!(
            reopened.verify_chain_with_tip(w, 4, r4.segment_hash),
            Err(GwError::AuditChainTampered { seq: 4, .. })
        ));
        fs::write(&seg4_path, &orig_seg4).unwrap();
        assert!(reopened.verify_chain_with_tip(w, 4, r4.segment_hash).is_ok());

        // Crypto-shred destroys key slot; segments become permanently unreadable.
        reopened.crypto_shred(w).unwrap();
        assert!(!key_path.exists());
        assert!(matches!(
            reopened.verify_chain(w),
            Err(GwError::AuditKeyMissing { .. })
        ));
        assert!(matches!(
            reopened.read_records(w),
            Err(GwError::AuditKeyMissing { .. })
        ));
        assert!(matches!(
            reopened.append_record(sample_record(w, 6)),
            Err(GwError::AuditKeyMissing { .. })
        ));

        let _ = fs::remove_dir_all(&root);
    }
}
