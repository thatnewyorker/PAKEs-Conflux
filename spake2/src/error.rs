//! Error types.
//!
//! Normalization guidance
//! - The public `Error` enum is intentionally small and suitable for embedding in network or API
//!   responses. When interacting with untrusted peers, prefer not to leak fine-grained failure
//!   information, as it can be used as an oracle.
//! - A common policy is to normalize all peer-facing parse/validation failures to a single error
//!   (e.g., `CorruptMessage`), while reserving `Rng` for internal errors that might be retried or
//!   surfaced to logs/metrics only.
//! - Use the helper `normalize_for_peer` below to apply this mapping where appropriate.

#![allow(dead_code)]
use core::fmt;

/// [`Result`][`core::result::Result`] type with `spake2`'s [`Error`] type.
pub type Result<T> = core::result::Result<T, Error>;

/// SPAKE2 errors.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Bad side
    BadSide,

    /// Corrupt message
    CorruptMessage,

    /// Wrong length
    WrongLength,

    /// Random number generator failure
    Rng,
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadSide => fmt.write_str("bad side"),
            Self::CorruptMessage => fmt.write_str("corrupt message"),
            Self::WrongLength => fmt.write_str("invalid length"),
            Self::Rng => fmt.write_str("random number generator failure"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Normalize errors for peer-facing exposure.
///
/// Rationale:
/// - Different error messages can act as oracles for adversaries probing your API.
/// - Mapping all parse/validation issues to a single error reduces information leakage,
///   while preserving `Rng` for operational handling and observability.
///
/// Policy:
/// - `BadSide`, `WrongLength`, and `CorruptMessage` -> `CorruptMessage`
/// - `Rng` -> `Rng`
///
/// Note: This does not alter the original error; it returns a mapped copy.
/// Callers can log the original error locally (with detail) and only expose
/// the normalized version over the network boundary.
#[inline]
pub fn normalize_for_peer(err: Error) -> Error {
    match err {
        Error::BadSide | Error::WrongLength | Error::CorruptMessage => Error::CorruptMessage,
        Error::Rng => Error::Rng,
    }
}
