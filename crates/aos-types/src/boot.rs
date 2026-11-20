//! Kernel boot identity.
//!
//! `BootId` wraps `/proc/sys/kernel/random/boot_id`, a random UUID generated once per kernel
//! boot. Volatile (`Ephemeral`) state is bound to it so that anything left over from a previous
//! boot is detected and discarded instead of being trusted.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

/// Canonical location of the boot id on Linux.
pub const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

/// Errors reading or validating a boot id.
#[derive(Debug, Error)]
pub enum BootIdError {
    /// The boot id file could not be read.
    #[error("failed to read boot id from {path}: {source}")]
    Io {
        /// File that was read.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// The content is not a strict lowercase `8-4-4-4-12` UUID.
    #[error("malformed boot id {value:?}: {reason}")]
    Malformed {
        /// (Possibly truncated) offending value.
        value: String,
        /// Human readable reason.
        reason: &'static str,
    },
}

/// A kernel boot identifier (128-bit UUID).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct BootId([u8; 16]);

impl BootId {
    /// Strictly parse `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` (lowercase hex, no braces,
    /// no whitespace).
    pub fn parse(s: &str) -> Result<Self, BootIdError> {
        let malformed = |reason: &'static str| BootIdError::Malformed {
            value: s.chars().take(64).collect(),
            reason,
        };
        if s.len() != 36 {
            return Err(malformed("length must be exactly 36"));
        }
        let mut nibbles = Vec::with_capacity(32);
        for (i, b) in s.bytes().enumerate() {
            if matches!(i, 8 | 13 | 18 | 23) {
                if b != b'-' {
                    return Err(malformed("expected '-' at 8-4-4-4-12 boundary"));
                }
                continue;
            }
            match b {
                b'0'..=b'9' => nibbles.push(b - b'0'),
                b'a'..=b'f' => nibbles.push(b - b'a' + 10),
                _ => return Err(malformed("non lowercase-hex character")),
            }
        }
        debug_assert_eq!(nibbles.len(), 32);
        let mut out = [0u8; 16];
        for (i, o) in out.iter_mut().enumerate() {
            *o = (nibbles[2 * i] << 4) | nibbles[2 * i + 1];
        }
        Ok(Self(out))
    }

    /// Read and validate the boot id from an arbitrary file (a single trailing `\n` is allowed).
    pub fn read_from(path: &Path) -> Result<Self, BootIdError> {
        let raw = std::fs::read_to_string(path).map_err(|source| BootIdError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let trimmed = raw.strip_suffix('\n').unwrap_or(&raw);
        Self::parse(trimmed)
    }

    /// Read the current boot id from [`BOOT_ID_PATH`] (always re-read; procfs is cheap).
    pub fn current() -> Result<Self, BootIdError> {
        Self::read_from(Path::new(BOOT_ID_PATH))
    }

    /// Raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for BootId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12],
            b[13], b[14], b[15]
        )
    }
}

impl fmt::Debug for BootId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BootId({self})")
    }
}

/// Serialized as the canonical lowercase `8-4-4-4-12` string; deserialization is as strict as
/// [`BootId::parse`].
#[cfg(feature = "serde")]
impl serde::Serialize for BootId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for BootId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(d)?;
        BootId::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "0a1b2c3d-4e5f-6789-abcd-ef0123456789";

    #[test]
    fn parse_good_and_display_roundtrip() {
        let id = BootId::parse(GOOD).unwrap();
        assert_eq!(id.to_string(), GOOD);
        assert_eq!(id.as_bytes()[0], 0x0a);
        assert_eq!(id.as_bytes()[15], 0x89);
        assert_eq!(format!("{id:?}"), format!("BootId({GOOD})"));
    }

    #[test]
    fn parse_rejects_malformed() {
        let bad = [
            "",
            "0a1b2c3d4e5f6789abcdef0123456789",              // no dashes
            "0A1B2C3D-4E5F-6789-ABCD-EF0123456789",          // uppercase
            "0a1b2c3d-4e5f-6789-abcd-ef012345678",           // too short
            "0a1b2c3d-4e5f-6789-abcd-ef01234567890",         // too long
            "0a1b2c3d_4e5f-6789-abcd-ef0123456789",          // wrong separator
            "0a1b2c3d-4e5f-6789-abcd-ef012345678g",          // non hex
            " 0a1b2c3d-4e5f-6789-abcd-ef0123456789",         // leading space
            "{0a1b2c3d-4e5f-6789-abcd-ef0123456789}",        // braces
            "0a1b2c3d-4e5f-6789-abcd-ef0123456789\n",        // newline is only stripped by read_from
            "0a1b2c3-d4e5f-6789-abcd-ef0123456789",          // dash in wrong place
            "0a1b2c3d-4e5f-6789-abcd-ef01234567é9",          // non-ascii
        ];
        for b in bad {
            assert!(
                matches!(BootId::parse(b), Err(BootIdError::Malformed { .. })),
                "accepted {b:?}"
            );
        }
    }

    fn tmp_file(tag: &str, content: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("aos-types-boot-{}-{tag}", std::process::id()));
        std::fs::write(&p, content).unwrap();
        p
    }

    #[test]
    fn read_from_strips_single_trailing_newline_only() {
        let p = tmp_file("ok", &format!("{GOOD}\n"));
        assert_eq!(BootId::read_from(&p).unwrap().to_string(), GOOD);
        let p2 = tmp_file("nonl", GOOD);
        assert!(BootId::read_from(&p2).is_ok());
        let p3 = tmp_file("two", &format!("{GOOD}\n\n"));
        assert!(matches!(BootId::read_from(&p3), Err(BootIdError::Malformed { .. })));
        let p4 = tmp_file("crlf", &format!("{GOOD}\r\n"));
        assert!(matches!(BootId::read_from(&p4), Err(BootIdError::Malformed { .. })));
        let missing = std::env::temp_dir().join("aos-types-boot-definitely-missing");
        assert!(matches!(BootId::read_from(&missing), Err(BootIdError::Io { .. })));
        for p in [p, p2, p3, p4] {
            let _ = std::fs::remove_file(p);
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_roundtrip_is_canonical_and_strict() {
        let id = BootId::parse(GOOD).unwrap();
        let j = serde_json::to_string(&id).unwrap();
        assert_eq!(j, format!("\"{GOOD}\""));
        assert_eq!(serde_json::from_str::<BootId>(&j).unwrap(), id);
        for bad in [
            j.to_uppercase(),
            format!("\"{GOOD}\\n\""),
            "\"0a1b2c3d4e5f6789abcdef0123456789\"".to_owned(),
            "42".to_owned(),
        ] {
            assert!(serde_json::from_str::<BootId>(&bad).is_err(), "accepted {bad}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn current_boot_id_is_valid_and_stable() {
        let a = BootId::current().expect("/proc boot_id must be a valid UUID");
        let b = BootId::current().unwrap();
        assert_eq!(a, b);
        assert_eq!(a.to_string().len(), 36);
    }
}
