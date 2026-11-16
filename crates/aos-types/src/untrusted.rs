//! `Untrusted<T>`: data that crossed a trust boundary (sandbox output, network, guest disk).
//!
//! * No `Deref`, no `Clone`, no accessor: the inner value is private.
//! * `Debug` is redacted, so untrusted bytes never leak into logs by accident.
//! * The **only** way to obtain the inner data is [`Untrusted::validate`], which runs a
//!   [`Validator`] and returns whatever *validated* type that validator produces.
//!
//! ```compile_fail
//! use aos_types::Untrusted;
//! let u = Untrusted::new(String::from("x"));
//! let _inner = u.0; // private field: does not compile
//! ```

use std::fmt;

/// Turns raw untrusted input into a validated output (or an error).
pub trait Validator<T> {
    /// Validated representation.
    type Output;
    /// Validation failure.
    type Error;
    /// Validate (and take ownership of) `input`.
    fn validate(&self, input: T) -> Result<Self::Output, Self::Error>;
}

/// A value from an untrusted source that has not been validated yet.
#[must_use = "Untrusted<T> must be consumed via Untrusted::validate"]
pub struct Untrusted<T>(T);

impl<T> Untrusted<T> {
    /// Mark `value` as untrusted.
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// The only exit: validate with `validator`.
    pub fn validate<V>(self, validator: &V) -> Result<V::Output, V::Error>
    where
        V: Validator<T>,
    {
        validator.validate(self.0)
    }
}

impl<T> fmt::Debug for Untrusted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Untrusted(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NonEmptyAscii;
    impl Validator<String> for NonEmptyAscii {
        type Output = String;
        type Error = &'static str;
        fn validate(&self, input: String) -> Result<String, Self::Error> {
            if input.is_empty() {
                Err("empty")
            } else if !input.is_ascii() {
                Err("non-ascii")
            } else {
                Ok(input)
            }
        }
    }

    #[test]
    fn debug_is_redacted() {
        let u = Untrusted::new(String::from("super-secret-payload ../../etc/passwd"));
        let s = format!("{u:?}");
        assert_eq!(s, "Untrusted(<redacted>)");
        assert!(!s.contains("secret"));
        assert_eq!(format!("{u:#?}"), "Untrusted(<redacted>)");
        let _ = u.validate(&NonEmptyAscii);
    }

    #[test]
    fn validate_is_the_only_exit() {
        assert_eq!(
            Untrusted::new(String::from("ok")).validate(&NonEmptyAscii),
            Ok(String::from("ok"))
        );
        assert_eq!(
            Untrusted::new(String::new()).validate(&NonEmptyAscii),
            Err("empty")
        );
        assert_eq!(
            Untrusted::new(String::from("é")).validate(&NonEmptyAscii),
            Err("non-ascii")
        );
    }
}
