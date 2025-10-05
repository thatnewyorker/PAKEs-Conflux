#![allow(clippy::module_name_repetitions)]
//! Key-confirmation helpers for SPAKE2 using HMAC-SHA256.
//!
//! Overview
//! - These helpers compute and verify explicit confirmation tags that prove
//!   both parties derived the same session key.
//! - The confirmation MAC is computed as:
//!     HMAC-SHA256(K, suite_label || "/confirm/v1" || role || transcript_parts)
//! - Role is one of: 'A', 'B', or 'S' (symmetric sub-roles 'U'/'V' are encoded in the body).
//! - Transcript parts are constructed from the SPAKE2 exchange messages:
//!     - For asymmetric A/B: X_msg || Y_msg (32 bytes each, compressed points).
//!     - For symmetric: min(M1, M2) || max(M1, M2) (32 bytes each), plus a sender role marker.
//!
//! API surface
//! - A/B flows:
//!     - make_confirm_a / verify_confirm_a
//!     - make_confirm_b / verify_confirm_b
//! - Symmetric flow:
//!     - make_confirm_s / verify_confirm_s with an explicit SymmetricRole
//!
//! Notes
//! - These helpers operate on the 32-byte compressed point encodings (X and Y).
//!   They deliberately avoid re-deriving the SPAKE2 transcript to keep the
//!   confirmation step simple and side-channel minimized.
//! - All verification is performed using a constant-time comparison.
//! - The caller should send the output of `make_confirm_*` to the peer and
//!   verify the peer's response with the respective `verify_confirm_*` function.

use crate::error::Error;
use core::cmp::Ordering;
use secret_utils::wrappers::SecretKey;
use sha2::{Digest, Sha256};
#[cfg(feature = "constant-time")]
use subtle::ConstantTimeEq;

/// Length in bytes of the HMAC-SHA256 confirmation tag.
pub const CONFIRM_TAG_LEN: usize = 32;

/// Confirmation tag type alias (HMAC-SHA256 output).
pub type ConfirmationTag = [u8; CONFIRM_TAG_LEN];

/// Suite label used for domain separation (default when a specific suite is not provided).
const SUITE_LABEL_DEFAULT: &[u8] = b"spake2-conflux/ed25519/v1";
/// Suffix appended to the suite label for confirmation MAC domain separation.
const CONFIRM_SUFFIX: &[u8] = b"/confirm/v1";

/// Role markers for asymmetric exchanges.
const ROLE_A: u8 = b'A';
const ROLE_B: u8 = b'B';

/// Role marker for symmetric exchanges (outer role), with inner sender sub-role.
const ROLE_S: u8 = b'S';

/// Sender sub-roles for symmetric exchange confirmation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SymmetricRole {
    /// The sender whose message is the lexicographically smaller 32-byte encoding.
    U,
    /// The sender whose message is the lexicographically larger 32-byte encoding.
    V,
}

impl SymmetricRole {
    fn as_byte(self) -> u8 {
        match self {
            SymmetricRole::U => b'U',
            SymmetricRole::V => b'V',
        }
    }
}

/// Compute confirmation tag for side A.
///
/// Inputs:
/// - `session_key`: the 32-byte session key derived from SPAKE2 (or any-length key material).
/// - `x_msg`: the 32-byte compressed point sent by A (X).
/// - `y_msg`: the 32-byte compressed point sent by B (Y).
///
/// Output:
/// - 32-byte HMAC-SHA256 confirmation tag to send to B.
pub fn make_confirm_a_with_suite(
    session_key: &SecretKey,
    suite_label: &str,
    x_msg: &[u8],
    y_msg: &[u8],
) -> Result<ConfirmationTag, Error> {
    ensure_len_32(x_msg)?;
    ensure_len_32(y_msg)?;
    Ok(hmac_sha256_multi(
        session_key.as_ref(),
        &[
            suite_label.as_bytes(),
            CONFIRM_SUFFIX,
            &[ROLE_A],
            x_msg,
            y_msg,
        ],
    ))
}

/// Convenience wrapper that computes the A->B confirmation tag using the crate’s
/// default suite label. For explicit control over the suite label, use
/// [`make_confirm_a_with_suite`].
pub fn make_confirm_a(
    session_key: &SecretKey,
    x_msg: &[u8],
    y_msg: &[u8],
) -> Result<ConfirmationTag, Error> {
    make_confirm_a_with_suite(
        session_key,
        core::str::from_utf8(SUITE_LABEL_DEFAULT).unwrap_or("spake2-conflux/ed25519/v1"),
        x_msg,
        y_msg,
    )
}

/// Verify confirmation tag purportedly created by side A.
///
/// Inputs:
/// - `session_key`: the session key K.
/// - `x_msg`: X (sent by A).
/// - `y_msg`: Y (sent by B).
/// - `received`: 32-byte tag received from A.
///
/// Returns:
/// - Ok(()) if valid, Error::WrongLength or Error::CorruptMessage otherwise.
pub fn verify_confirm_a_with_suite(
    session_key: &SecretKey,
    suite_label: &str,
    x_msg: &[u8],
    y_msg: &[u8],
    received: &[u8],
) -> Result<(), Error> {
    ensure_len_32(x_msg)?;
    ensure_len_32(y_msg)?;
    ensure_len_32(received)?;
    let expected = make_confirm_a_with_suite(session_key, suite_label, x_msg, y_msg)?;
    if ct_eq(&expected, received) {
        Ok(())
    } else {
        Err(Error::CorruptMessage)
    }
}

/// Convenience wrapper that verifies the A->B confirmation tag using the crate’s
/// default suite label. For explicit control over the suite label, use
/// [`verify_confirm_a_with_suite`].
pub fn verify_confirm_a(
    session_key: &SecretKey,
    x_msg: &[u8],
    y_msg: &[u8],
    received: &[u8],
) -> Result<(), Error> {
    verify_confirm_a_with_suite(
        session_key,
        core::str::from_utf8(SUITE_LABEL_DEFAULT).unwrap_or("spake2-conflux/ed25519/v1"),
        x_msg,
        y_msg,
        received,
    )
}

/// Compute confirmation tag for side B.
///
/// Inputs:
/// - `session_key`: the session key K.
/// - `x_msg`: X (sent by A).
/// - `y_msg`: Y (sent by B).
///
/// Output:
/// - 32-byte HMAC-SHA256 confirmation tag to send to A.
pub fn make_confirm_b_with_suite(
    session_key: &SecretKey,
    suite_label: &str,
    x_msg: &[u8],
    y_msg: &[u8],
) -> Result<ConfirmationTag, Error> {
    ensure_len_32(x_msg)?;
    ensure_len_32(y_msg)?;
    Ok(hmac_sha256_multi(
        session_key.as_ref(),
        &[
            suite_label.as_bytes(),
            CONFIRM_SUFFIX,
            &[ROLE_B],
            x_msg,
            y_msg,
        ],
    ))
}

/// Convenience wrapper that computes the B->A confirmation tag using the crate’s
/// default suite label. For explicit control over the suite label, use
/// [`make_confirm_b_with_suite`].
pub fn make_confirm_b(
    session_key: &SecretKey,
    x_msg: &[u8],
    y_msg: &[u8],
) -> Result<ConfirmationTag, Error> {
    make_confirm_b_with_suite(
        session_key,
        core::str::from_utf8(SUITE_LABEL_DEFAULT).unwrap_or("spake2-conflux/ed25519/v1"),
        x_msg,
        y_msg,
    )
}

/// Verify confirmation tag purportedly created by side B.
///
/// Inputs:
/// - `session_key`: the session key K.
/// - `x_msg`: X (sent by A).
/// - `y_msg`: Y (sent by B).
/// - `received`: 32-byte tag received from B.
///
/// Returns:
/// - Ok(()) if valid, Error::WrongLength or Error::CorruptMessage otherwise.
pub fn verify_confirm_b_with_suite(
    session_key: &SecretKey,
    suite_label: &str,
    x_msg: &[u8],
    y_msg: &[u8],
    received: &[u8],
) -> Result<(), Error> {
    ensure_len_32(x_msg)?;
    ensure_len_32(y_msg)?;
    ensure_len_32(received)?;
    let expected = make_confirm_b_with_suite(session_key, suite_label, x_msg, y_msg)?;
    if ct_eq(&expected, received) {
        Ok(())
    } else {
        Err(Error::CorruptMessage)
    }
}

/// Convenience wrapper that verifies the B->A confirmation tag using the crate’s
/// default suite label. For explicit control over the suite label, use
/// [`verify_confirm_b_with_suite`].
pub fn verify_confirm_b(
    session_key: &SecretKey,
    x_msg: &[u8],
    y_msg: &[u8],
    received: &[u8],
) -> Result<(), Error> {
    verify_confirm_b_with_suite(
        session_key,
        core::str::from_utf8(SUITE_LABEL_DEFAULT).unwrap_or("spake2-conflux/ed25519/v1"),
        x_msg,
        y_msg,
        received,
    )
}

/// Compute confirmation tag for the symmetric exchange.
///
/// The symmetric exchange uses the two 32-byte messages (call them `msg_u` and `msg_v`),
/// sorts them lexicographically to match the transcript convention, and includes an
/// explicit sub-role marker indicating which sender produced the tag (U or V).
///
/// Inputs:
/// - `session_key`: the session key K.
/// - `msg_u`: one of the two 32-byte compressed points.
/// - `msg_v`: the other 32-byte compressed point.
/// - `sender_role`: which symmetric participant is sending the tag (U or V).
///
/// Output:
/// - 32-byte HMAC-SHA256 confirmation tag.
pub fn make_confirm_s_with_suite(
    session_key: &SecretKey,
    suite_label: &str,
    msg_u: &[u8],
    msg_v: &[u8],
    sender_role: SymmetricRole,
) -> Result<ConfirmationTag, Error> {
    ensure_len_32(msg_u)?;
    ensure_len_32(msg_v)?;
    let (first, second) = sort_pair(msg_u, msg_v);
    Ok(hmac_sha256_multi(
        session_key.as_ref(),
        &[
            suite_label.as_bytes(),
            CONFIRM_SUFFIX,
            &[ROLE_S],
            first,
            second,
            &[sender_role.as_byte()],
        ],
    ))
}

/// Convenience wrapper that computes a symmetric confirmation tag using the
/// crate’s default suite label. For explicit control over the suite label, use
/// [`make_confirm_s_with_suite`].
pub fn make_confirm_s(
    session_key: &SecretKey,
    msg_u: &[u8],
    msg_v: &[u8],
    sender_role: SymmetricRole,
) -> Result<ConfirmationTag, Error> {
    make_confirm_s_with_suite(
        session_key,
        core::str::from_utf8(SUITE_LABEL_DEFAULT).unwrap_or("spake2-conflux/ed25519/v1"),
        msg_u,
        msg_v,
        sender_role,
    )
}

/// Verify confirmation tag for the symmetric exchange.
///
/// Inputs:
/// - `session_key`: the session key K.
/// - `msg_u`, `msg_v`: the two 32-byte messages from the symmetric exchange.
/// - `sender_role`: which symmetric participant purportedly created the tag (U or V).
/// - `received`: 32-byte tag received.
///
/// Returns:
/// - Ok(()) if valid, Error::WrongLength or Error::CorruptMessage otherwise.
pub fn verify_confirm_s_with_suite(
    session_key: &SecretKey,
    suite_label: &str,
    msg_u: &[u8],
    msg_v: &[u8],
    sender_role: SymmetricRole,
    received: &[u8],
) -> Result<(), Error> {
    ensure_len_32(msg_u)?;
    ensure_len_32(msg_v)?;
    ensure_len_32(received)?;
    let expected = make_confirm_s_with_suite(session_key, suite_label, msg_u, msg_v, sender_role)?;
    if ct_eq(&expected, received) {
        Ok(())
    } else {
        Err(Error::CorruptMessage)
    }
}

/// Convenience wrapper that verifies a symmetric confirmation tag using the
/// crate’s default suite label. For explicit control over the suite label, use
/// [`verify_confirm_s_with_suite`].
pub fn verify_confirm_s(
    session_key: &SecretKey,
    msg_u: &[u8],
    msg_v: &[u8],
    sender_role: SymmetricRole,
    received: &[u8],
) -> Result<(), Error> {
    verify_confirm_s_with_suite(
        session_key,
        core::str::from_utf8(SUITE_LABEL_DEFAULT).unwrap_or("spake2-conflux/ed25519/v1"),
        msg_u,
        msg_v,
        sender_role,
        received,
    )
}

/// Constant-time equality of two byte slices.
/// Returns true if equal, false otherwise.
/// If the `constant-time` feature is enabled and both inputs are 32 bytes,
/// use `subtle::ConstantTimeEq` for comparison.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    #[cfg(feature = "constant-time")]
    {
        if a.len() == 32 && b.len() == 32 {
            let mut ea = [0u8; 32];
            let mut eb = [0u8; 32];
            ea.copy_from_slice(&a[..32]);
            eb.copy_from_slice(&b[..32]);
            return ea.ct_eq(&eb).unwrap_u8() == 1;
        }
    }

    // Generic fallback (works for any length).
    let max_len = if a.len() > b.len() { a.len() } else { b.len() };
    let mut acc: u8 = (a.len() ^ b.len()) as u8;
    let mut i = 0;
    while i < max_len {
        let av = a.get(i).copied().unwrap_or(0);
        let bv = b.get(i).copied().unwrap_or(0);
        acc |= av ^ bv;
        i += 1;
    }
    acc == 0
}

/// Ensure the provided slice is exactly 32 bytes long.
fn ensure_len_32(s: &[u8]) -> Result<(), Error> {
    if s.len() == 32 {
        Ok(())
    } else {
        Err(Error::WrongLength)
    }
}

/// Return a pair (min, max) according to lexicographic order.
fn sort_pair<'a>(a: &'a [u8], b: &'a [u8]) -> (&'a [u8], &'a [u8]) {
    match a.cmp(b) {
        Ordering::Less => (a, b),
        Ordering::Equal | Ordering::Greater => (b, a),
    }
}

/// Minimal no-alloc HMAC-SHA256 over multiple input parts.
///
/// This function implements HMAC as specified in RFC 2104/4868 using `Sha256`.
/// It accepts an arbitrary-length key and a slice of message parts, avoiding
/// intermediate allocations.
fn hmac_sha256_multi(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    const BLOCK: usize = 64; // SHA-256 block size in bytes

    // Step 1: Normalize key to block size: if longer => hash; if shorter => right-pad with zeros.
    let mut k0 = [0u8; BLOCK];
    if key.len() > BLOCK {
        let mut h = Sha256::new();
        h.update(key);
        let digest = h.finalize();
        k0[..digest.len()].copy_from_slice(&digest);
    } else {
        k0[..key.len()].copy_from_slice(key);
    }

    // Step 2: Compute inner hash = H((k0 ^ ipad) || message)
    let mut inner_pad = [0u8; BLOCK];
    let mut outer_pad = [0u8; BLOCK];
    for i in 0..BLOCK {
        inner_pad[i] = k0[i] ^ 0x36;
        outer_pad[i] = k0[i] ^ 0x5c;
    }

    let mut inner = Sha256::new();
    inner.update(&inner_pad);
    for p in parts {
        inner.update(p);
    }
    let inner_digest = inner.finalize();

    // Step 3: Compute outer hash = H((k0 ^ opad) || inner_digest)
    let mut outer = Sha256::new();
    outer.update(&outer_pad);
    outer.update(&inner_digest);

    let mut out = [0u8; 32];
    out.copy_from_slice(&outer.finalize());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn ct_eq_basic() {
        assert!(ct_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!ct_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!ct_eq(&[1, 2], &[1, 2, 0]));
    }

    #[test]
    fn hmac_matches_known_vector() {
        // RFC 4231 test case 1 for HMAC-SHA256:
        // key = 20 bytes of 0x0b, data = "Hi There"
        let key = vec![0x0b; 20];
        let data = b"Hi There";
        let mac = hmac_sha256_multi(&key, &[data]);
        let expected = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(mac, expected);
    }

    #[test]
    fn confirm_a_b_roundtrip() {
        let key = SecretKey::new(vec![42u8; 32]);
        let x = [1u8; 32];
        let y = [2u8; 32];

        let a_tag = make_confirm_a(&key, &x, &y).unwrap();
        assert!(verify_confirm_a(&key, &x, &y, &a_tag).is_ok());

        let b_tag = make_confirm_b(&key, &x, &y).unwrap();
        assert!(verify_confirm_b(&key, &x, &y, &b_tag).is_ok());

        // Cross-verify mismatches fail
        assert!(verify_confirm_a(&key, &x, &y, &b_tag).is_err());
        assert!(verify_confirm_b(&key, &x, &y, &a_tag).is_err());
    }

    #[test]
    fn confirm_s_roundtrip() {
        let key = SecretKey::new(vec![9u8; 32]);
        let m1 = [0xAAu8; 32];
        let m2 = [0xBBu8; 32];

        let tag_u = make_confirm_s(&key, &m1, &m2, SymmetricRole::U).unwrap();
        let tag_v = make_confirm_s(&key, &m1, &m2, SymmetricRole::V).unwrap();

        assert!(verify_confirm_s(&key, &m1, &m2, SymmetricRole::U, &tag_u).is_ok());
        assert!(verify_confirm_s(&key, &m1, &m2, SymmetricRole::V, &tag_v).is_ok());

        // Mismatched roles should fail
        assert!(verify_confirm_s(&key, &m1, &m2, SymmetricRole::U, &tag_v).is_err());
        assert!(verify_confirm_s(&key, &m1, &m2, SymmetricRole::V, &tag_u).is_err());
    }
}
