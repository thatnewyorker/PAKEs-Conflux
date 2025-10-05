#![allow(clippy::unwrap_used)]

use curve25519_dalek::{
    constants::EIGHT_TORSION,
    edwards::EdwardsPoint,
    traits::{Identity, IsIdentity},
};
use spake2_conflux::confirm::{
    SymmetricRole, make_confirm_a, make_confirm_b, make_confirm_s, verify_confirm_a,
    verify_confirm_b, verify_confirm_s,
};
use spake2_conflux::{Ed25519Group, Error, Identity as SpakeIdentity, Password, Spake2};

fn identity_compressed() -> [u8; 32] {
    EdwardsPoint::identity().compress().to_bytes()
}

fn small_order_compressed_non_identity() -> [u8; 32] {
    // Use a known, non-identity point from the 8-torsion subgroup.
    // This should decompress but have small order, which we must reject.
    // EIGHT_TORSION[0] is identity; pick a different index.
    let p = EIGHT_TORSION[1];
    debug_assert!(bool::from(!p.is_identity()));
    debug_assert!(bool::from(p.mul_by_cofactor().is_identity()));
    p.compress().to_bytes()
}

#[test]
fn finish_rejects_identity_point_for_a_side() {
    // Prepare A-side state
    let (s_a, _msg1) = Spake2::<Ed25519Group>::start_a(
        &Password::new(b"password"),
        &SpakeIdentity::new(b"idA"),
        &SpakeIdentity::new(b"idB"),
    )
    .unwrap();

    // Craft a msg2 from "B" containing the identity element encoding
    let mut bad_msg2 = Vec::with_capacity(1 + 32);
    bad_msg2.push(b'B'); // side marker for B
    bad_msg2.extend_from_slice(&identity_compressed());

    let res = s_a.finish(&bad_msg2);
    assert_eq!(res.unwrap_err(), Error::CorruptMessage);
}

#[test]
fn finish_rejects_small_order_point_for_b_side() {
    // Prepare B-side state
    let (s_b, _msg2) = Spake2::<Ed25519Group>::start_b(
        &Password::new(b"password"),
        &SpakeIdentity::new(b"idA"),
        &SpakeIdentity::new(b"idB"),
    )
    .unwrap();

    // Craft a msg1 from "A" containing a small-order (but non-identity) point
    let mut bad_msg1 = Vec::with_capacity(1 + 32);
    bad_msg1.push(b'A'); // side marker for A
    bad_msg1.extend_from_slice(&small_order_compressed_non_identity());

    let res = s_b.finish(&bad_msg1);
    assert_eq!(res.unwrap_err(), Error::CorruptMessage);
}

#[test]
fn confirm_roundtrip_asymmetric_a_b() {
    // Standard A/B flow with matching passwords
    let (s_a, msg_a) = Spake2::<Ed25519Group>::start_a(
        &Password::new(b"password"),
        &SpakeIdentity::new(b"idA"),
        &SpakeIdentity::new(b"idB"),
    )
    .unwrap();
    let (s_b, msg_b) = Spake2::<Ed25519Group>::start_b(
        &Password::new(b"password"),
        &SpakeIdentity::new(b"idA"),
        &SpakeIdentity::new(b"idB"),
    )
    .unwrap();

    let key_a = s_a.finish(&msg_b).unwrap();
    let key_b = s_b.finish(&msg_a).unwrap();

    // X and Y are the 32-byte payloads following the side marker
    let x = &msg_a[1..]; // A's message
    let y = &msg_b[1..]; // B's message
    assert_eq!(x.len(), 32);
    assert_eq!(y.len(), 32);

    // A generates a tag; B verifies it.
    let tag_a = make_confirm_a(&key_a, x, y).unwrap();
    verify_confirm_a(&key_b, x, y, &tag_a).unwrap();

    // B generates a tag; A verifies it.
    let tag_b = make_confirm_b(&key_b, x, y).unwrap();
    verify_confirm_b(&key_a, x, y, &tag_b).unwrap();

    // Negative checks
    // 1) Mismatched role verification should fail (A's tag verified as B's).
    assert!(verify_confirm_b(&key_a, x, y, &tag_a).is_err());
    // 2) Mismatched transcript (swapped X/Y) should fail.
    assert!(verify_confirm_a(&key_b, y, x, &tag_a).is_err());
    assert!(verify_confirm_b(&key_a, y, x, &tag_b).is_err());
}

#[test]
fn confirm_roundtrip_symmetric() {
    // Symmetric flow with two peers using the same identity and password
    let (s_u, msg_u) = Spake2::<Ed25519Group>::start_symmetric(
        &Password::new(b"password"),
        &SpakeIdentity::new(b"idS"),
    )
    .unwrap();
    let (s_v, msg_v) = Spake2::<Ed25519Group>::start_symmetric(
        &Password::new(b"password"),
        &SpakeIdentity::new(b"idS"),
    )
    .unwrap();

    let key_u = s_u.finish(&msg_v).unwrap();
    let key_v = s_v.finish(&msg_u).unwrap();

    let mu = &msg_u[1..];
    let mv = &msg_v[1..];
    assert_eq!(mu.len(), 32);
    assert_eq!(mv.len(), 32);

    // Each side produces a confirmation tag with its sender role.
    let tag_u = make_confirm_s(&key_u, mu, mv, SymmetricRole::U).unwrap();
    let tag_v = make_confirm_s(&key_v, mu, mv, SymmetricRole::V).unwrap();

    // Verify with the correct roles.
    verify_confirm_s(&key_v, mu, mv, SymmetricRole::U, &tag_u).unwrap();
    verify_confirm_s(&key_u, mu, mv, SymmetricRole::V, &tag_v).unwrap();

    // Negative checks
    // Wrong sender role should fail verification.
    assert!(verify_confirm_s(&key_v, mu, mv, SymmetricRole::V, &tag_u).is_err());
    assert!(verify_confirm_s(&key_u, mu, mv, SymmetricRole::U, &tag_v).is_err());
}
