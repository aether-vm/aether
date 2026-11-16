//! Strongly typed identifiers.
//!
//! * [`WorldId`] / [`FrameId`]: 128-bit random identifiers generated from the OS CSPRNG.
//! * Canonical text encodings (and *only* those are accepted by the parsers, so one ID never
//!   has two names):
//!   * **Crockford Base32, lowercase, exactly 26 characters.** 26 * 5 = 130 bits, so the first
//!     character carries only 3 significant bits and MUST be `<= '7'`. Uppercase and the
//!     Crockford aliases (`i`, `l`, `o`, `u`) are rejected.
//!   * **Hex, lowercase, exactly 32 characters.**
//! * [`EpochId`]: monotonic, non-zero `u64` fencing token (maps to the `epoch-<n>` cgroup).

use std::fmt;
use std::num::NonZeroU64;
use std::str::FromStr;

use thiserror::Error;

/// Crockford Base32 alphabet, lowercase (no `i`, `l`, `o`, `u`).
const B32_ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// Number of raw bytes in a 128-bit identifier.
pub const ID_BYTES: usize = 16;
/// Length of the canonical Base32 text form.
pub const BASE32_LEN: usize = 26;
/// Length of the canonical hex text form.
pub const HEX_LEN: usize = 32;

/// Errors produced when parsing an identifier from text.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IdParseError {
    /// Text length is not the canonical length.
    #[error("invalid length: expected {expected} bytes, got {got}")]
    BadLength {
        /// Expected length in bytes.
        expected: usize,
        /// Observed length in bytes.
        got: usize,
    },
    /// Character outside the canonical (lowercase) alphabet.
    #[error("invalid character {ch:?} at byte offset {index}")]
    InvalidChar {
        /// Byte offset of the offending character.
        index: usize,
        /// The offending character.
        ch: char,
    },
    /// First Base32 character would overflow 128 bits (must be `<= '7'`).
    #[error("non-canonical base32: leading character {0:?} exceeds '7' (overflows 128 bits)")]
    NonCanonicalLeading(char),
}

/// Errors produced when generating a random identifier.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IdGenError {
    /// The OS CSPRNG failed.
    #[error("OS CSPRNG failure: {0}")]
    Entropy(String),
}

fn encode_base32(bytes: &[u8; ID_BYTES]) -> String {
    let v = u128::from_be_bytes(*bytes);
    let mut s = String::with_capacity(BASE32_LEN);
    for i in (0..BASE32_LEN).rev() {
        let idx = ((v >> (5 * i)) & 0x1f) as usize;
        s.push(B32_ALPHABET[idx] as char);
    }
    s
}

fn decode_base32(s: &str) -> Result<[u8; ID_BYTES], IdParseError> {
    if s.len() != BASE32_LEN {
        return Err(IdParseError::BadLength {
            expected: BASE32_LEN,
            got: s.len(),
        });
    }
    let mut v: u128 = 0;
    for (index, ch) in s.char_indices() {
        let digit = if ch.is_ascii() {
            B32_ALPHABET.iter().position(|&a| a as char == ch)
        } else {
            None
        };
        let Some(d) = digit else {
            return Err(IdParseError::InvalidChar { index, ch });
        };
        if index == 0 && d > 7 {
            return Err(IdParseError::NonCanonicalLeading(ch));
        }
        v = (v << 5) | d as u128;
    }
    Ok(v.to_be_bytes())
}

fn encode_hex(bytes: &[u8; ID_BYTES]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(HEX_LEN);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn decode_hex(s: &str) -> Result<[u8; ID_BYTES], IdParseError> {
    if s.len() != HEX_LEN {
        return Err(IdParseError::BadLength {
            expected: HEX_LEN,
            got: s.len(),
        });
    }
    let mut out = [0u8; ID_BYTES];
    let mut nibbles = [0u8; HEX_LEN];
    for (index, ch) in s.char_indices() {
        nibbles[index] = match ch {
            '0'..='9' => ch as u8 - b'0',
            'a'..='f' => ch as u8 - b'a' + 10,
            _ => return Err(IdParseError::InvalidChar { index, ch }),
        };
    }
    for (i, o) in out.iter_mut().enumerate() {
        *o = (nibbles[2 * i] << 4) | nibbles[2 * i + 1];
    }
    Ok(out)
}

macro_rules! define_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; ID_BYTES]);

        impl $name {
            /// Generate a fresh random identifier from the OS CSPRNG.
            pub fn try_random() -> Result<Self, IdGenError> {
                let mut b = [0u8; ID_BYTES];
                getrandom::fill(&mut b).map_err(|e| IdGenError::Entropy(e.to_string()))?;
                Ok(Self(b))
            }

            /// Like [`Self::try_random`] but panics if the OS CSPRNG is unavailable
            /// (which is unrecoverable for a security-sensitive runtime).
            #[must_use]
            pub fn random() -> Self {
                Self::try_random().expect("OS CSPRNG unavailable")
            }

            /// Construct from raw bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; ID_BYTES]) -> Self {
                Self(bytes)
            }

            /// Raw big-endian bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; ID_BYTES] {
                &self.0
            }

            /// Canonical lowercase 26-char Crockford Base32 form.
            #[must_use]
            pub fn to_base32(&self) -> String {
                encode_base32(&self.0)
            }

            /// Canonical lowercase 32-char hex form.
            #[must_use]
            pub fn to_hex(&self) -> String {
                encode_hex(&self.0)
            }

            /// Strictly parse the canonical Base32 form.
            pub fn from_base32(s: &str) -> Result<Self, IdParseError> {
                decode_base32(s).map(Self)
            }

            /// Strictly parse the canonical hex form.
            pub fn from_hex(s: &str) -> Result<Self, IdParseError> {
                decode_hex(s).map(Self)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_base32())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.to_base32())
            }
        }

        impl FromStr for $name {
            type Err = IdParseError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::from_base32(s)
            }
        }

        #[cfg(feature = "serde")]
        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.to_base32())
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = <String as serde::Deserialize>::deserialize(d)?;
                s.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

define_id!(
    /// Identifier of a world (an isolated agent workspace lineage).
    WorldId
);
define_id!(
    /// Identifier of a frame (an immutable checkpoint of a world).
    FrameId
);

/// Monotonic, non-zero epoch fencing token.
///
/// Each `agentd` incarnation takes a strictly larger epoch; all sandbox processes live in the
/// cgroup directory named by [`EpochId::cgroup_dir_name`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EpochId(NonZeroU64);

impl EpochId {
    /// The first valid epoch (`1`).
    pub const FIRST: EpochId = EpochId(NonZeroU64::MIN);

    /// Construct from a raw value; `0` is not a valid epoch.
    #[must_use]
    pub fn new(n: u64) -> Option<Self> {
        NonZeroU64::new(n).map(EpochId)
    }

    /// Raw numeric value (always `>= 1`).
    #[must_use]
    pub fn get(self) -> u64 {
        self.0.get()
    }

    /// The next epoch, or `None` on `u64` overflow (callers must treat that as fatal).
    #[must_use]
    pub fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(EpochId)
    }

    /// cgroup directory name, e.g. `epoch-7`.
    #[must_use]
    pub fn cgroup_dir_name(self) -> String {
        format!("epoch-{}", self.get())
    }

    /// Strictly parse a name produced by [`Self::cgroup_dir_name`]
    /// (no leading zeros, no sign, no whitespace).
    #[must_use]
    pub fn from_cgroup_dir_name(name: &str) -> Option<Self> {
        let rest = name.strip_prefix("epoch-")?;
        let n: u64 = rest.parse().ok()?;
        if n.to_string() != rest {
            return None;
        }
        Self::new(n)
    }
}

impl fmt::Display for EpochId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.get())
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for EpochId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(self.get())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for EpochId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let n = <u64 as serde::Deserialize>::deserialize(d)?;
        EpochId::new(n).ok_or_else(|| serde::de::Error::custom("epoch must be non-zero"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn base32_known_vectors() {
        assert_eq!(WorldId::from_bytes([0; 16]).to_base32(), "0".repeat(26));
        assert_eq!(
            WorldId::from_bytes([0xff; 16]).to_base32(),
            format!("7{}", "z".repeat(25))
        );
        let mut one = [0u8; 16];
        one[15] = 1;
        assert_eq!(FrameId::from_bytes(one).to_base32(), format!("{}1", "0".repeat(25)));
    }

    #[test]
    fn base32_and_hex_roundtrip_random() {
        for _ in 0..2000 {
            let w = WorldId::random();
            let b = w.to_base32();
            assert_eq!(b.len(), 26);
            assert!(b.bytes().all(|c| B32_ALPHABET.contains(&c)));
            assert!(b.as_bytes()[0] <= b'7', "first char must be <= '7': {b}");
            assert_eq!(WorldId::from_base32(&b).unwrap(), w);
            assert_eq!(b.parse::<WorldId>().unwrap(), w);
            assert_eq!(w.to_string(), b);

            let h = w.to_hex();
            assert_eq!(h.len(), 32);
            assert!(h.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
            assert_eq!(WorldId::from_hex(&h).unwrap(), w);
        }
    }

    #[test]
    fn rejects_every_non_canonical_base32_spelling() {
        let canon = WorldId::from_bytes([0x11; 16]).to_base32();
        assert!(WorldId::from_base32(&canon).is_ok());
        // uppercase
        assert!(matches!(
            WorldId::from_base32(&canon.to_uppercase().replace('0', "O")),
            Err(IdParseError::InvalidChar { .. })
        ));
        assert!(matches!(
            WorldId::from_base32(&canon.to_uppercase()),
            Err(IdParseError::InvalidChar { .. })
        ));
        // Crockford aliases are not accepted: i, l, o, u
        for bad in ['i', 'l', 'o', 'u', 'I', 'L', 'O', 'U', '-', ' ', '=', 'é'] {
            let mut s = canon.clone();
            s.replace_range(5..6, &bad.to_string());
            assert!(WorldId::from_base32(&s).is_err(), "accepted alias {bad:?}");
        }
        // wrong lengths
        assert!(matches!(
            WorldId::from_base32(&canon[..25]),
            Err(IdParseError::BadLength { expected: 26, got: 25 })
        ));
        assert!(matches!(
            WorldId::from_base32(&format!("{canon}0")),
            Err(IdParseError::BadLength { expected: 26, got: 27 })
        ));
        assert!(WorldId::from_base32("").is_err());
        // leading char > '7' would silently drop 2 bits => second spelling of the same ID
        for lead in ['8', '9', 'a', 'z'] {
            let s = format!("{lead}{}", "0".repeat(25));
            assert_eq!(
                WorldId::from_base32(&s),
                Err(IdParseError::NonCanonicalLeading(lead))
            );
        }
        assert!(WorldId::from_base32(&format!("7{}", "0".repeat(25))).is_ok());
    }

    #[test]
    fn rejects_non_canonical_hex() {
        let canon = FrameId::from_bytes([0xab; 16]).to_hex();
        assert_eq!(canon, "ab".repeat(16));
        assert!(FrameId::from_hex(&canon).is_ok());
        assert!(matches!(
            FrameId::from_hex(&canon.to_uppercase()),
            Err(IdParseError::InvalidChar { .. })
        ));
        assert!(FrameId::from_hex(&canon[..31]).is_err());
        assert!(FrameId::from_hex(&format!("{canon}0")).is_err());
        assert!(FrameId::from_hex(&format!("g{}", &canon[1..])).is_err());
        assert!(FrameId::from_hex(&format!("0x{}", &canon[2..])).is_err());
    }

    #[test]
    fn exactly_one_name_per_id() {
        // decode -> encode is the identity for every accepted string (no aliases survive).
        let mut seed = 0x1234_5678_9abc_def0u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut accepted = 0;
        for _ in 0..5000 {
            let s: String = (0..26)
                .map(|i| {
                    let r = (next() % 40) as usize; // sometimes out of alphabet
                    let r = if i == 0 { r % 10 } else { r };
                    B32_ALPHABET.get(r).map(|&b| b as char).unwrap_or('Z')
                })
                .collect();
            if let Ok(id) = WorldId::from_base32(&s) {
                accepted += 1;
                assert_eq!(id.to_base32(), s);
            }
        }
        assert!(accepted > 0);
    }

    #[test]
    fn ids_are_random_and_unique_and_ordered_like_text() {
        let mut seen = HashSet::new();
        let mut v = Vec::new();
        for _ in 0..1000 {
            let id = FrameId::random();
            assert!(seen.insert(id), "duplicate random id");
            v.push(id);
        }
        v.sort();
        let texts: Vec<String> = v.iter().map(|i| i.to_base32()).collect();
        let mut sorted = texts.clone();
        sorted.sort();
        assert_eq!(texts, sorted, "byte order must equal text order");
    }

    #[test]
    fn debug_shows_type_and_value() {
        let w = WorldId::from_bytes([0; 16]);
        assert_eq!(format!("{w:?}"), format!("WorldId({})", "0".repeat(26)));
    }

    #[test]
    fn epoch_basics() {
        assert!(EpochId::new(0).is_none());
        let e1 = EpochId::FIRST;
        assert_eq!(e1.get(), 1);
        let e2 = e1.next().unwrap();
        assert_eq!(e2.get(), 2);
        assert!(e2 > e1);
        assert_eq!(e2.to_string(), "2");
        let max = EpochId::new(u64::MAX).unwrap();
        assert!(max.next().is_none(), "overflow must be reported, not wrapped");
    }

    #[test]
    fn epoch_cgroup_dir_name_roundtrip_and_strictness() {
        let e = EpochId::new(42).unwrap();
        assert_eq!(e.cgroup_dir_name(), "epoch-42");
        assert_eq!(EpochId::from_cgroup_dir_name("epoch-42"), Some(e));
        for bad in [
            "epoch-0", "epoch-042", "epoch-+42", "epoch-", "epoch--1", "epoch-42 ", " epoch-42",
            "Epoch-42", "epoch-4_2", "epoch-18446744073709551616", "epoch42", "",
        ] {
            assert_eq!(EpochId::from_cgroup_dir_name(bad), None, "accepted {bad:?}");
        }
        assert!(EpochId::from_cgroup_dir_name(&format!("epoch-{}", u64::MAX)).is_some());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_roundtrip_uses_canonical_strings() {
        let w = WorldId::random();
        let j = serde_json::to_string(&w).unwrap();
        assert_eq!(j, format!("\"{}\"", w.to_base32()));
        assert_eq!(serde_json::from_str::<WorldId>(&j).unwrap(), w);
        assert!(serde_json::from_str::<WorldId>(&j.to_uppercase()).is_err());
        let e = EpochId::new(9).unwrap();
        assert_eq!(serde_json::to_string(&e).unwrap(), "9");
        assert!(serde_json::from_str::<EpochId>("0").is_err());
    }
}
