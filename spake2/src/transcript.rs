#![allow(clippy::module_name_repetitions)]
//! Suite-aware transcript hashing helpers for SPAKE2.
//!
//! This module provides helper functions to compute the transcript hash used
//! to derive the final session key in both the asymmetric (A/B) and symmetric
//! SPAKE2 flows. The hashing is "suite-aware": the selected group's suite label
//! must be included to domain-separate transcripts across groups (e.g.,
//! Ed25519 vs Ristretto), preventing cross-suite mix-ups.
//!
//! Design notes
//! - These helpers use SHA-256 and length-prefixed labeled components to avoid
//!   ambiguity and to provide explicit domain separation.
//! - The suite label MUST uniquely identify the group backend in use, for
//!   example: "spake2-conflux/ristretto/v1" or "spake2-conflux/ed25519/v1".
//! - The first and second messages are the canonical 32-byte encodings produced
//!   by the respective SPAKE2 start functions, with their leading side byte
//!   removed (i.e., only the 32-byte group element encoding).
//! - For the symmetric flow, the two messages are sorted lexicographically
//!   to obtain a canonical ordering in the transcript.
//!
//! Warning
//! - Callers must pass the correct suite label corresponding to the chosen
//!   backend (`Group::suite_label()`), or transcripts will not match across peers.

extern crate alloc;

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

/// Compute the suite-aware transcript hash for the asymmetric A/B flow.
///
/// Inputs:
/// - `suite_label`: group suite identifier (e.g., "spake2-conflux/ristretto/v1").
/// - `password_bytes`: raw password bytes used for SPAKE2 (pre-hash).
/// - `id_a`: identity string for side A (opaque bytes).
/// - `id_b`: identity string for side B (opaque bytes).
/// - `first_msg`: 32-byte canonical encoding of the first message (X or Y).
/// - `second_msg`: 32-byte canonical encoding of the second message (Y or X).
/// - `key_bytes`: derived group element bytes used in the final transcript.
///
/// Output:
/// - 32-byte SHA-256 digest of the canonical transcript.
pub fn hash_ab_suited(
    suite_label: &str,
    password_bytes: &[u8],
    id_a: &[u8],
    id_b: &[u8],
    first_msg: &[u8],
    second_msg: &[u8],
    key_bytes: &[u8],
) -> Vec<u8> {
    assert_eq!(first_msg.len(), 32, "first_msg must be 32 bytes");
    assert_eq!(second_msg.len(), 32, "second_msg must be 32 bytes");

    // Compute component digests.
    let mut pw_hasher = Sha256::new();
    pw_hasher.update(password_bytes);
    let pw_digest = pw_hasher.finalize();

    let mut ida_hasher = Sha256::new();
    ida_hasher.update(id_a);
    let ida_digest = ida_hasher.finalize();

    let mut idb_hasher = Sha256::new();
    idb_hasher.update(id_b);
    let idb_digest = idb_hasher.finalize();

    // Build labeled, length-prefixed transcript with suite-aware domain separation.
    let mut hash = Sha256::new();
    update_transcript_label(&mut hash, suite_label, b"ab");

    // Helper to absorb label || len_le || value
    let mut absorb = |label: &[u8], value: &[u8]| {
        hash.update(label);
        let len = (value.len() as u32).to_le_bytes();
        hash.update(&len);
        hash.update(value);
    };

    absorb(b"pw_hash", &pw_digest);
    absorb(b"id_a_hash", &ida_digest);
    absorb(b"id_b_hash", &idb_digest);
    absorb(b"X", first_msg);
    absorb(b"Y", second_msg);
    absorb(b"K", key_bytes);

    hash.finalize().to_vec()
}

/// Compute the suite-aware transcript hash for the symmetric flow.
///
/// Inputs:
/// - `suite_label`: group suite identifier (e.g., "spake2-conflux/ristretto/v1").
/// - `password_bytes`: raw password bytes used for SPAKE2 (pre-hash).
/// - `id_s`: symmetric identity string (opaque bytes).
/// - `msg_u`: one of the two 32-byte canonical messages.
/// - `msg_v`: the other 32-byte canonical message.
/// - `key_bytes`: derived group element bytes used in the final transcript.
///
/// Behavior:
/// - Lexicographically sorts `msg_u` and `msg_v` to obtain canonical order.
///
/// Output:
/// - 32-byte SHA-256 digest of the canonical transcript.
pub fn hash_symmetric_suited(
    suite_label: &str,
    password_bytes: &[u8],
    id_s: &[u8],
    msg_u: &[u8],
    msg_v: &[u8],
    key_bytes: &[u8],
) -> Vec<u8> {
    assert_eq!(msg_u.len(), 32, "msg_u must be 32 bytes");
    assert_eq!(msg_v.len(), 32, "msg_v must be 32 bytes");

    // Compute component digests.
    let mut pw_hasher = Sha256::new();
    pw_hasher.update(password_bytes);
    let pw_digest = pw_hasher.finalize();

    let mut ids_hasher = Sha256::new();
    ids_hasher.update(id_s);
    let ids_digest = ids_hasher.finalize();

    // Canonical order for the two messages.
    let (first, second) = if msg_u < msg_v {
        (msg_u, msg_v)
    } else {
        (msg_v, msg_u)
    };

    // Build labeled, length-prefixed transcript with suite-aware domain separation.
    let mut hash = Sha256::new();
    update_transcript_label(&mut hash, suite_label, b"symmetric");

    // Helper to absorb label || len_le || value
    let mut absorb = |label: &[u8], value: &[u8]| {
        hash.update(label);
        let len = (value.len() as u32).to_le_bytes();
        hash.update(&len);
        hash.update(value);
    };

    absorb(b"pw_hash", &pw_digest);
    absorb(b"id_s_hash", &ids_digest);
    absorb(b"msg_first", first);
    absorb(b"msg_second", second);
    absorb(b"K", key_bytes);

    hash.finalize().to_vec()
}

/// Update the transcript hasher with a suite-aware domain separation label.
///
/// The label format is:
///     suite_label || "/transcript/" || flow || "/v1"
///
/// Examples:
/// - "spake2-conflux/ristretto/v1/transcript/ab/v1"
/// - "spake2-conflux/ed25519/v1/transcript/symmetric/v1"
fn update_transcript_label(hasher: &mut Sha256, suite_label: &str, flow: &[u8]) {
    hasher.update(suite_label.as_bytes());
    hasher.update(b"/transcript/");
    hasher.update(flow);
    hasher.update(b"/v1");
}
