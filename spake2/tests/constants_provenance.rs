#![cfg(feature = "constants-provenance")]
use hex::encode;
use spake2_conflux::{
    Ed25519Group, Group,
    constants::{derive_m, derive_n, derive_s},
};

fn embedded_const_bytes_m() -> Vec<u8> {
    <Ed25519Group as Group>::element_to_bytes(&Ed25519Group::const_m())
}

fn embedded_const_bytes_n() -> Vec<u8> {
    <Ed25519Group as Group>::element_to_bytes(&Ed25519Group::const_n())
}

fn embedded_const_bytes_s() -> Vec<u8> {
    <Ed25519Group as Group>::element_to_bytes(&Ed25519Group::const_s())
}

#[test]
fn test_derive_m_matches_embedded() {
    let (derived, counter) = derive_m().expect("failed to derive M");
    let embedded = embedded_const_bytes_m();

    assert_eq!(
        embedded.as_slice(),
        &derived,
        "M mismatch: derived={} embedded={} counter={}",
        encode(derived),
        encode(&embedded),
        counter
    );
}

#[test]
fn test_derive_n_matches_embedded() {
    let (derived, counter) = derive_n().expect("failed to derive N");
    let embedded = embedded_const_bytes_n();

    assert_eq!(
        embedded.as_slice(),
        &derived,
        "N mismatch: derived={} embedded={} counter={}",
        encode(derived),
        encode(&embedded),
        counter
    );
}

#[test]
fn test_derive_s_matches_embedded() {
    let (derived, counter) = derive_s().expect("failed to derive S");
    let embedded = embedded_const_bytes_s();

    assert_eq!(
        embedded.as_slice(),
        &derived,
        "S mismatch: derived={} embedded={} counter={}",
        encode(derived),
        encode(&embedded),
        counter
    );
}
