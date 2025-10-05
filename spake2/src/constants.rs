//! Deterministic derivation of SPAKE2 distinguished constants (M, N, S) for Ed25519.
//!
//! This module provides library APIs to derive the compressed Edwards-Y encodings
//! of the SPAKE2 distinguished group elements M, N, and S using a deterministic,
//! reproducible procedure. The procedure is designed for auditability and to
//! ensure that no party knows the discrete logs of the derived points.
//!
//! Overview of the derivation procedure (deterministic):
//! - Suite identifier: `spake2-conflux/ed25519/v1`
//! - Derivation label: `spake2-conflux/derive-constant/v1`
//! - For each name in {"M","N","S"}:
//!   1) seed = HKDF-SHA256(salt = "", ikm = suite || 0x00 || name, info = label, L = 32)
//!   2) For counter in 0..=MAX_SEARCH_ITERS:
//!        candidate = SHA256(seed || counter_le)
//!        If CompressedEdwardsY(candidate).decompress() succeeds and the point
//!        is neither identity nor small-order (cofactor-related), accept it.
//!   3) The accepted point is returned as its canonical 32-byte compressed Edwards-Y encoding.
//!
//! Security checks enforced:
//! - Reject invalid encodings (failed decompression).
//! - Reject identity.
//! - Reject small-order points via cofactor multiplication check.
//!
//! Notes:
//! - The helper functions below return the canonical compressed encodings and
//!   the counter used. The canonical bytes are intended to be embedded in the
//!   crate and asserted by tests to enforce provenance.
//! - The public API is no_std-friendly and uses `alloc` where needed.
//!
//! Usage:
//! - Use `derive_m()`, `derive_n()`, and `derive_s()` to derive constants.
//! - Or use the generic `derive_constant("M"|"N"|"S")` to derive by name.

extern crate alloc;

use crate::error::{Error, Result};
use alloc::vec::Vec;
use curve25519_dalek::{edwards::CompressedEdwardsY, traits::IsIdentity};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

/// Suite label used as part of the IKM (input keying material).
pub const SUITE_LABEL: &[u8] = b"spake2-conflux/ed25519/v1";

/// HKDF info label for deterministic constant derivation.
pub const DERIVATION_LABEL: &[u8] = b"spake2-conflux/derive-constant/v1";

/// Maximum number of candidate attempts before giving up.
///
/// This is a safety bound to prevent infinite loops in pathological cases.
/// In practice, a valid point should be found quickly.
pub const MAX_SEARCH_ITERS: u32 = 1_000_000;

/// Derive the canonical 32-byte compressed Edwards-Y encoding for a named constant.
///
/// - `name` must be one of: `"M"`, `"N"`, `"S"`.
/// - Returns the compressed bytes and the counter value used to find them.
///
/// Errors:
/// - Returns `Error::CorruptMessage` if a constant cannot be derived within `MAX_SEARCH_ITERS`.
pub fn derive_constant(name: &str) -> Result<([u8; 32], u32)> {
    // Build IKM = SUITE_LABEL || 0x00 || name (ASCII).
    let mut ikm = Vec::with_capacity(SUITE_LABEL.len() + 1 + name.len());
    ikm.extend_from_slice(SUITE_LABEL);
    ikm.push(0x00);
    ikm.extend_from_slice(name.as_bytes());

    // HKDF-SHA256 with empty-salt to derive a 32-byte seed.
    let hk = Hkdf::<Sha256>::new(Some(b""), &ikm);
    let mut seed = [0u8; 32];
    hk.expand(DERIVATION_LABEL, &mut seed)
        .map_err(|_| Error::CorruptMessage)?;

    // Search for the first acceptable candidate.
    for counter in 0u32..=MAX_SEARCH_ITERS {
        let mut hasher = Sha256::new();
        hasher.update(&seed);
        hasher.update(counter.to_le_bytes());
        let digest = hasher.finalize();

        // Interpret as a compressed Edwards-Y encoding and attempt to decompress.
        let mut candidate = [0u8; 32];
        candidate.copy_from_slice(&digest);

        if let Some(p) = CompressedEdwardsY(candidate).decompress() {
            // Reject identity and small-order points.
            if bool::from(p.is_identity()) || bool::from(p.mul_by_cofactor().is_identity()) {
                continue;
            }

            // Canonical re-encoding.
            let out = p.compress().to_bytes();
            return Ok((out, counter));
        }
    }

    Err(Error::CorruptMessage)
}

/// Derive the M constant (compressed Edwards-Y) and its counter.
pub fn derive_m() -> Result<([u8; 32], u32)> {
    derive_constant("M")
}

/// Derive the N constant (compressed Edwards-Y) and its counter.
pub fn derive_n() -> Result<([u8; 32], u32)> {
    derive_constant("N")
}

/// Derive the S constant (compressed Edwards-Y) and its counter.
pub fn derive_s() -> Result<([u8; 32], u32)> {
    derive_constant("S")
}
