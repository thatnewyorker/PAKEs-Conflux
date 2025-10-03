#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

//! Secret handling utilities for the PAKEs-Conflux workspace.
//!
//! This crate is intended to centralize secret-handling patterns across the
//! `aucpace`, `spake2`, and `srp` crates. It will provide:
//! - Typed wrappers for secret material (passwords, verifiers, scalars, derived keys).
//! - Reliable in-memory erasure via zeroization semantics.
//! - Clear API boundaries that prevent accidental exposure or cloning of secrets.
//! - Testing guidance and utilities to validate zeroization behavior where feasible.
//!
//! Design goals
//! - Minimize accidental copies of secret data.
//! - Ensure secrets are zeroized on drop and after critical transitions.
//! - Provide clear documentation and policies for secret lifecycles.
//! - Remain no_std-friendly with an `alloc`-based default.
//!
//! Scope (initial scaffolding)
//! - This initial version is documentation-only with module placeholders. There
//!   are no public APIs yet. Follow-up phases will introduce concrete wrappers,
//!   traits, and utilities, along with unit and integration tests.
//!
//! Feature flags
//! - `alloc` (default): Enables heap-backed containers to support secret buffers.
//! - `std`: Convenience alias that implies `alloc`. Intended for environments
//!   where the standard library is available.
//!
//! Usage policy (to be enforced in subsequent phases)
//! - All password bytes, ephemeral private scalars, long-lived verifiers, and
//!   derived session keys must be wrapped by secret types provided here.
//! - Public APIs must not expose raw secret bytes. Controlled exposure
//!   methods will be provided and documented.
//! - Conversions to/from public representations (e.g., serialized forms) will be
//!   centralized in audited helpers.
//!
//! Tests and CI (to be added in later phases)
//! - Unit tests to verify zeroization semantics and API boundaries.
//! - Integration tests to exercise protocol flows without leaking secrets.
//! - CI gates to help prevent regressions in secret-handling policies.

#[cfg(feature = "alloc")]
extern crate alloc;

/// Placeholder module for secret wrappers.
///
/// This module will host strongly-typed wrappers (e.g., secret byte buffers,
/// scalar wrappers) with drop-time zeroization and constrained exposure.
/// No items are defined yet; content will be added in subsequent phases.
pub mod wrappers {
    //! Zeroizing secret wrappers for byte-oriented secrets.
    //!
    //! Notes:
    //! - These wrappers are currently behind the `alloc` feature to remain
    //!   compatible with `no_std` builds where `alloc` is unavailable.
    //! - Introducing these types does not change any public API in dependent
    //!   crates yet. They are provided here for upcoming incremental adoption.
    //!
    //! Intended usage:
    //! - `SecretBytes`: for password bytes or other sensitive buffers provided by users.
    //! - `SecretKey`: for derived session keys or key material that must be cleared on drop.

    #[cfg(feature = "alloc")]
    use alloc::vec::Vec;
    #[cfg(feature = "alloc")]
    use core::ops::Deref;
    #[cfg(feature = "alloc")]
    use zeroize::{Zeroize, ZeroizeOnDrop};

    /// Zeroizing wrapper for secret byte buffers (e.g., passwords).
    #[cfg(feature = "alloc")]
    #[derive(Zeroize, ZeroizeOnDrop)]
    pub struct SecretBytes(Vec<u8>);

    #[cfg(feature = "alloc")]
    impl SecretBytes {
        /// Create a new `SecretBytes` from an owned byte vector.
        pub fn new(bytes: Vec<u8>) -> Self {
            Self(bytes)
        }

        /// Borrow the inner bytes without copying.
        pub fn expose(&self) -> &[u8] {
            &self.0
        }

        /// Consume and return the inner `Vec<u8>`.
        ///
        /// Note: this transfers ownership of the secret data to the caller.
        /// Prefer to keep secrets wrapped and scoped when possible.
        pub fn into_inner(mut self) -> Vec<u8> {
            let mut out = Vec::new();
            core::mem::swap(&mut out, &mut self.0);
            out
        }
    }

    #[cfg(feature = "alloc")]
    impl AsRef<[u8]> for SecretBytes {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    #[cfg(feature = "alloc")]
    impl Deref for SecretBytes {
        type Target = [u8];

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    #[cfg(feature = "alloc")]
    impl From<Vec<u8>> for SecretBytes {
        fn from(v: Vec<u8>) -> Self {
            Self(v)
        }
    }

    /// Zeroizing wrapper for derived session keys or other key material.
    #[cfg(feature = "alloc")]
    #[derive(Zeroize, ZeroizeOnDrop)]
    pub struct SecretKey(Vec<u8>);

    #[cfg(feature = "alloc")]
    impl SecretKey {
        /// Create a new `SecretKey` from an owned byte vector.
        pub fn new(bytes: Vec<u8>) -> Self {
            Self(bytes)
        }

        /// Borrow the inner key bytes without copying.
        pub fn expose(&self) -> &[u8] {
            &self.0
        }

        /// Consume and return the inner `Vec<u8>`.
        ///
        /// Note: this transfers ownership of the secret key to the caller.
        pub fn into_inner(mut self) -> Vec<u8> {
            let mut out = Vec::new();
            core::mem::swap(&mut out, &mut self.0);
            out
        }
    }

    #[cfg(feature = "alloc")]
    impl AsRef<[u8]> for SecretKey {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    #[cfg(feature = "alloc")]
    impl Deref for SecretKey {
        type Target = [u8];

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    #[cfg(feature = "alloc")]
    impl From<Vec<u8>> for SecretKey {
        fn from(v: Vec<u8>) -> Self {
            Self(v)
        }
    }
}

/// Placeholder module for secret-related traits and policies.
///
/// This module will define shared traits and policy helpers for secret lifecycles,
/// zeroization semantics, and conversion boundaries.
pub mod traits {
    //! Future contents:
    //! - Traits describing zeroization guarantees
    //! - Traits for controlled exposure and borrowing
    //! - Helpers for documenting and enforcing lifecycles
    //!
    //! Intentionally empty in this initial scaffold.
}

/// Placeholder module for internal test utilities.
///
/// This module will eventually include optional test-only helpers to validate
/// zeroization and to instrument secret lifecycles under controlled conditions.
#[cfg(any(test, doc))]
pub mod test_utils {
    //! Future contents:
    //! - Test-only helpers for memory inspections (where viable)
    //! - Utilities to construct scoped secrets for lifecycle tests
    //!
    //! Intentionally empty in this initial scaffold.
}
