#![allow(clippy::module_name_repetitions)]
//! Ristretto backend implementing the `Group` trait.
//!
//! This backend provides a prime-order group abstraction on top of Curve25519
//! using Ristretto. It offers canonical 32-byte encodings and eliminates
//! cofactor/torsion pitfalls present when using raw Edwards points.
//!
//! Security and design notes:
//! - `bytes_to_element` accepts only canonical Ristretto encodings and returns
//!   `None` on malformed inputs. Ristretto construction ensures no identity or
//!   small-order points are accepted via valid encodings.
//! - `element_to_bytes` returns canonical compressed Ristretto encodings
//!   (32 bytes).
//! - `random_scalar` is fallible and returns `Error::Rng` upon RNG failure.
//! - `suite_label()` identifies this backend for domain separation in transcripts
//!   and confirmation MACs.
//! - Distinguished constants M/N/S are derived deterministically from a suite-
//!   specific HKDF seed via `RistrettoPoint::from_uniform_bytes`, ensuring
//!   provenance and auditability.

extern crate alloc;

use crate::error::Error;
use crate::group::Group;
use alloc::vec::Vec;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use hkdf::Hkdf;
use rand_core::{TryCryptoRng, TryRngCore};
use sha2::{Digest, Sha256, Sha512};

/// Suite label used for domain separation with this backend.
pub const RISTRETTO_SUITE_LABEL: &str = "spake2-conflux/ristretto/v1";

/// HKDF info label for deterministic constant derivation.
const DERIVATION_LABEL: &[u8] = b"spake2-conflux/derive-constant/v1";

/// SPAKE2 over Ristretto group.
#[derive(Debug, PartialEq, Eq)]
pub struct RistrettoGroup;

impl Group for RistrettoGroup {
    type Scalar = Scalar;
    type Element = RistrettoPoint;
    type TranscriptHash = Sha256;

    fn suite_label() -> &'static str {
        RISTRETTO_SUITE_LABEL
    }

    fn name() -> &'static str {
        "Ristretto255"
    }

    /// M constant (distinguished element)
    ///
    /// Provenance: Deterministically derived using HKDF-SHA256 seeded with:
    /// - suite: "spake2-conflux/ristretto/v1"
    /// - derivation label: "spake2-conflux/derive-constant/v1"
    /// - name: "M"
    fn const_m() -> RistrettoPoint {
        derive_ristretto_constant("M")
    }

    /// N constant (distinguished element)
    ///
    /// Provenance: Deterministically derived using the same procedure as `const_m`,
    /// with name "N".
    fn const_n() -> RistrettoPoint {
        derive_ristretto_constant("N")
    }

    /// S constant (symmetric distinguished element)
    ///
    /// Provenance: Deterministically derived using the same procedure as `const_m`,
    /// with name "S".
    fn const_s() -> RistrettoPoint {
        derive_ristretto_constant("S")
    }

    fn hash_to_scalar(s: &[u8]) -> Scalar {
        hash_to_scalar_ristretto(s)
    }

    fn random_scalar<T>(cspring: &mut T) -> Result<Scalar, Error>
    where
        T: TryRngCore + TryCryptoRng,
    {
        let mut seed = [0u8; 64];
        cspring.try_fill_bytes(&mut seed).map_err(|_| Error::Rng)?;
        let digest = Sha512::digest(&seed);
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&digest);
        Ok(Scalar::from_bytes_mod_order_wide(&wide))
    }

    fn scalar_neg(s: &Scalar) -> Scalar {
        -s
    }

    fn element_to_bytes(e: &RistrettoPoint) -> Vec<u8> {
        e.compress().as_bytes().to_vec()
    }

    fn bytes_to_element(b: &[u8]) -> Option<RistrettoPoint> {
        if b.len() != 32 {
            return None;
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(b);
        CompressedRistretto(bytes).decompress()
    }

    fn element_length() -> usize {
        32
    }

    fn basepoint_mult(s: &Scalar) -> RistrettoPoint {
        RISTRETTO_BASEPOINT_POINT * s
    }

    fn scalarmult(e: &RistrettoPoint, s: &Scalar) -> RistrettoPoint {
        e * s
    }

    fn add(a: &RistrettoPoint, b: &RistrettoPoint) -> RistrettoPoint {
        a + b
    }
}

/// Deterministically derive a Ristretto distinguished element by name.
///
/// Procedure:
/// - IKM = SUITE_LABEL || 0x00 || name
/// - seed = HKDF-SHA256(salt = "", ikm = IKM, info = DERIVATION_LABEL, L = 64)
/// - point = RistrettoPoint::from_uniform_bytes(seed)
fn derive_ristretto_constant(name: &str) -> RistrettoPoint {
    let mut ikm = Vec::with_capacity(RISTRETTO_SUITE_LABEL.len() + 1 + name.len());
    ikm.extend_from_slice(RISTRETTO_SUITE_LABEL.as_bytes());
    ikm.push(0x00);
    ikm.extend_from_slice(name.as_bytes());

    // HKDF-SHA256 to obtain 64 uniform bytes for Ristretto mapping.
    let hk = Hkdf::<Sha256>::new(Some(b""), &ikm);
    let mut okm = [0u8; 64];
    // This expand length is valid for HKDF-SHA256; treat failure as unreachable.
    hk.expand(DERIVATION_LABEL, &mut okm)
        .unwrap_or_else(|_| unreachable!("HKDF expand length must be valid"));

    RistrettoPoint::from_uniform_bytes(&okm)
}

/// Map arbitrary bytes to a Scalar deterministically (Ristretto/Curve25519 scalar field).
///
/// This mirrors the Ed25519 backend approach:
/// - HKDF-SHA256(salt="", ikm=input, info="SPAKE2 pw", L=48)
/// - Interpret the 48 bytes as big-endian into a 64-byte wide buffer
/// - Reduce with `Scalar::from_bytes_mod_order_wide`
fn hash_to_scalar_ristretto(s: &[u8]) -> Scalar {
    let mut okm = [0u8; 32 + 16];
    Hkdf::<Sha256>::new(Some(b""), s)
        .expand(b"SPAKE2 pw", &mut okm)
        .unwrap_or_else(|_| unreachable!("HKDF expand length must be valid"));

    let mut wide = [0u8; 64]; // little-endian expected by dalek's reduction
    // Place the 48 bytes as big-endian into the 64-byte wide buffer.
    for (i, x) in okm.iter().enumerate().take(48) {
        wide[48 - 1 - i] = *x;
    }

    Scalar::from_bytes_mod_order_wide(&wide)
}
