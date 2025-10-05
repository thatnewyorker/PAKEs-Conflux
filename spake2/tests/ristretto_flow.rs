#![allow(clippy::unwrap_used)]

use spake2_conflux::confirm::{make_confirm_a, make_confirm_b, verify_confirm_a, verify_confirm_b};
use spake2_conflux::{Group, Identity, Password, RistrettoGroup, Spake2};

fn derive_ab_keys_ristretto() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let pw = Password::new(b"correct horse battery staple");
    let id_a = Identity::new(b"client@example.com");
    let id_b = Identity::new(b"server.example.com");

    let (s_a, msg_a) = Spake2::<RistrettoGroup>::start_a(&pw, &id_a, &id_b).unwrap();
    let (s_b, msg_b) = Spake2::<RistrettoGroup>::start_b(&pw, &id_a, &id_b).unwrap();

    let key_a = s_a.finish(&msg_b).unwrap();
    let key_b = s_b.finish(&msg_a).unwrap();

    (
        key_a.as_ref().to_vec(),
        key_b.as_ref().to_vec(),
        msg_a,
        msg_b,
    )
}

#[test]
fn ristretto_ab_roundtrip_keys_equal() {
    let (key_a_bytes, key_b_bytes, _msg_a, _msg_b) = derive_ab_keys_ristretto();
    assert_eq!(
        key_a_bytes, key_b_bytes,
        "A/B keys must match for same password and identities"
    );
}

#[test]
fn ristretto_ab_mismatch_passwords_keys_differ() {
    let pw_a = Password::new(b"password-1");
    let pw_b = Password::new(b"password-2");
    let id_a = Identity::new(b"alice@example.com");
    let id_b = Identity::new(b"service.example.com");

    let (s_a, msg_a) = Spake2::<RistrettoGroup>::start_a(&pw_a, &id_a, &id_b).unwrap();
    let (s_b, msg_b) = Spake2::<RistrettoGroup>::start_b(&pw_b, &id_a, &id_b).unwrap();

    let key_a = s_a.finish(&msg_b).unwrap();
    let key_b = s_b.finish(&msg_a).unwrap();

    assert_ne!(
        key_a.as_ref(),
        key_b.as_ref(),
        "Keys must differ when passwords are not the same"
    );
}

#[test]
fn ristretto_symmetric_roundtrip_keys_equal() {
    let pw = Password::new(b"pa$$w0rd");
    let id_s = Identity::new(b"shared@domain");

    let (s_u, msg_u) = Spake2::<RistrettoGroup>::start_symmetric(&pw, &id_s).unwrap();
    let (s_v, msg_v) = Spake2::<RistrettoGroup>::start_symmetric(&pw, &id_s).unwrap();

    let key_u = s_u.finish(&msg_v).unwrap();
    let key_v = s_v.finish(&msg_u).unwrap();

    assert_eq!(
        key_u.as_ref(),
        key_v.as_ref(),
        "Symmetric keys must match for same password and identity"
    );
}

#[test]
fn ristretto_confirm_roundtrip_ab() {
    // Recompute a fresh handshake to obtain SecretKey types for confirmation helpers.
    let pw = Password::new(b"correct horse battery staple");
    let id_a = Identity::new(b"client@example.com");
    let id_b = Identity::new(b"server.example.com");
    let (s_a, msg_a) = Spake2::<RistrettoGroup>::start_a(&pw, &id_a, &id_b).unwrap();
    let (s_b, msg_b) = Spake2::<RistrettoGroup>::start_b(&pw, &id_a, &id_b).unwrap();
    let key_a = s_a.finish(&msg_b).unwrap();
    let key_b = s_b.finish(&msg_a).unwrap();

    // Canonical transcript bytes: strip the 1-byte side markers.
    let x = &msg_a[1..];
    let y = &msg_b[1..];

    // A -> B
    let tag_a = make_confirm_a(&key_a, x, y).expect("make_confirm_a failed");
    verify_confirm_a(&key_b, x, y, &tag_a).expect("verify_confirm_a failed");

    // B -> A
    let tag_b = make_confirm_b(&key_b, x, y).expect("make_confirm_b failed");
    verify_confirm_b(&key_a, x, y, &tag_b).expect("verify_confirm_b failed");
}

#[test]
fn ristretto_confirm_negative_tampered_tag() {
    // Recompute a fresh handshake to obtain SecretKey types for confirmation helpers.
    let pw = Password::new(b"correct horse battery staple");
    let id_a = Identity::new(b"client@example.com");
    let id_b = Identity::new(b"server.example.com");
    let (s_a, msg_a) = Spake2::<RistrettoGroup>::start_a(&pw, &id_a, &id_b).unwrap();
    let (s_b, msg_b) = Spake2::<RistrettoGroup>::start_b(&pw, &id_a, &id_b).unwrap();
    let key_a = s_a.finish(&msg_b).unwrap();
    let key_b = s_b.finish(&msg_a).unwrap();
    let x = &msg_a[1..];
    let y = &msg_b[1..];

    let mut tag_a = make_confirm_a(&key_a, x, y).expect("make_confirm_a failed");
    // Tamper one byte of the tag to force verification failure.
    if let Some(byte) = tag_a.get_mut(0) {
        *byte ^= 0x01;
    }
    let err = verify_confirm_a(&key_b, x, y, &tag_a)
        .expect_err("verify_confirm_a should fail on tampered tag");
    // Do not assert on exact error variant to avoid coupling; any error is acceptable here.
    let _ = err;
}

#[test]
fn ristretto_confirm_negative_wrong_transcript() {
    // Recompute a fresh handshake to obtain SecretKey types for confirmation helpers.
    let pw = Password::new(b"correct horse battery staple");
    let id_a = Identity::new(b"client@example.com");
    let id_b = Identity::new(b"server.example.com");
    let (s_a, msg_a) = Spake2::<RistrettoGroup>::start_a(&pw, &id_a, &id_b).unwrap();
    let (s_b, msg_b) = Spake2::<RistrettoGroup>::start_b(&pw, &id_a, &id_b).unwrap();
    let key_a = s_a.finish(&msg_b).unwrap();
    let key_b = s_b.finish(&msg_a).unwrap();
    let x = &msg_a[1..];
    let y = &msg_b[1..];

    let tag_a = make_confirm_a(&key_a, x, y).expect("make_confirm_a failed");

    // Tamper transcript: flip one bit of X
    let mut x_tampered = x.to_vec();
    if let Some(byte) = x_tampered.get_mut(0) {
        *byte ^= 0x80;
    }

    let err = verify_confirm_a(&key_b, &x_tampered, y, &tag_a)
        .expect_err("verify_confirm_a should fail on tampered transcript");
    let _ = err;
}

#[test]
fn ristretto_bytes_to_element_rejects_non_32_lengths() {
    // Too short
    assert!(
        <RistrettoGroup as Group>::bytes_to_element(&[]).is_none(),
        "must reject empty input"
    );
    assert!(
        <RistrettoGroup as Group>::bytes_to_element(&[0u8; 31]).is_none(),
        "must reject <32 bytes"
    );

    // Too long
    assert!(
        <RistrettoGroup as Group>::bytes_to_element(&[0u8; 33]).is_none(),
        "must reject >32 bytes"
    );
    assert!(
        <RistrettoGroup as Group>::bytes_to_element(&[0u8; 64]).is_none(),
        "must reject >32 bytes (64)"
    );
}

#[test]
fn ristretto_bytes_to_element_accepts_valid_element_from_handshake() {
    // Use a valid element from a real handshake message to ensure acceptance.
    let (_key_a, _key_b, msg_a, _msg_b) = derive_ab_keys_ristretto();
    let x = &msg_a[1..]; // 32-byte group element

    let parsed = <RistrettoGroup as Group>::bytes_to_element(x);
    assert!(parsed.is_some(), "expected a valid Ristretto element");
}
