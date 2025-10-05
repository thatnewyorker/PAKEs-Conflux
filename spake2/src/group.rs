//! Group trait.
//!
//! Security contract (must-read for implementers):
//! - `bytes_to_element` MUST reject:
//!   * Non-canonical encodings.
//!   * The identity element.
//!   * Any small-order/cofactor-related points (e.g., points P where the cofactor times P equals identity).
//!   Return `None` for all such cases; never panic on malformed input.
//! - `element_to_bytes` MUST return the canonical encoding for elements.
//!   Round-tripping via `element_to_bytes` -> `bytes_to_element` MUST succeed
//!   and recover an equivalent element.
//! - `element_length` MUST equal the length in bytes of the canonical encoding
//!   produced by `element_to_bytes` and accepted by `bytes_to_element`.
//! - `random_scalar` MUST be fallible and return `Error::Rng` on RNG failure.
//!   Implementations must not panic on RNG errors.
//!
//! These requirements ensure that protocol code can rely on backends to enforce
//! security-critical validation uniformly.

use crate::error::Error;
use alloc::vec::Vec;
use rand_core::{TryCryptoRng, TryRngCore};

/// Group trait.
// TODO(tarcieri): replace with `group` crate?
pub trait Group {
    /// Scalar element
    type Scalar;

    /// Base field element
    type Element;

    /// Transcript hash
    type TranscriptHash;

    /// Name
    fn name() -> &'static str;

    /// `m` constant
    fn const_m() -> Self::Element;

    /// `n` constant
    fn const_n() -> Self::Element;

    /// `s` constant
    fn const_s() -> Self::Element;

    /// Hash to scalar
    fn hash_to_scalar(s: &[u8]) -> Self::Scalar;

    /// Generate a random scalar
    fn random_scalar<T>(cspring: &mut T) -> Result<Self::Scalar, Error>
    where
        T: TryRngCore + TryCryptoRng;

    /// Scalar negation
    fn scalar_neg(s: &Self::Scalar) -> Self::Scalar;

    /// Convert base field element to canonical bytes
    /// The returned encoding must be canonical and round-trip with `bytes_to_element`.
    fn element_to_bytes(e: &Self::Element) -> Vec<u8>;

    /// Convert bytes to base field element with strict validation
    ///
    /// Implementations MUST:
    /// - Reject non-canonical encodings (return `None`).
    /// - Reject the identity element (return `None`).
    /// - Reject any small-order/cofactor-related points (return `None`).
    /// - Never panic on malformed inputs.
    fn bytes_to_element(b: &[u8]) -> Option<Self::Element>;

    /// Length in bytes of the canonical element encoding
    fn element_length() -> usize;

    /// Fixed-base scalar multiplication
    fn basepoint_mult(s: &Self::Scalar) -> Self::Element;

    /// Variable-base scalar multiplication
    fn scalarmult(e: &Self::Element, s: &Self::Scalar) -> Self::Element;

    /// Group operation
    fn add(a: &Self::Element, b: &Self::Element) -> Self::Element;
}
