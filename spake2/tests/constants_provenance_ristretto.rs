#![allow(clippy::unwrap_used)]

use hex::encode;
use spake2_conflux::{
    Group, RistrettoGroup,
    constants::{derive_m_ristretto, derive_n_ristretto, derive_s_ristretto},
};

fn embedded_const_bytes_m() -> Vec<u8> {
    <RistrettoGroup as Group>::element_to_bytes(&<RistrettoGroup as Group>::const_m())
}

fn embedded_const_bytes_n() -> Vec<u8> {
    <RistrettoGroup as Group>::element_to_bytes(&<RistrettoGroup as Group>::const_n())
}

fn embedded_const_bytes_s_() -> Vec<u8> {
    <RistrettoGroup as Group>::element_to_bytes(&<RistrettoGroup as Group>::const_s())
}

#[test]
fn test_derive_m_ristretto_matches_embedded() {
    let (derived, counter) = derive_m_ristretto().expect("failed to derive M (ristretto)");
    let embedded = embedded_const_bytes_m();

    assert_eq!(
        embedded.as_slice(),
        &derived,
        "M(ristretto) mismatch: derived={} embedded={} counter={}",
        encode(derived),
        encode(&embedded),
        counter
    );
    assert_eq!(counter, 0, "Ristretto derivation should use counter=0");
}

#[test]
fn test_derive_n_ristretto_matches_embedded() {
    let (derived, counter) = derive_n_ristretto().expect("failed to derive N (ristretto)");
    let embedded = embedded_const_bytes_n();

    assert_eq!(
        embedded.as_slice(),
        &derived,
        "N(ristretto) mismatch: derived={} embedded={} counter={}",
        encode(derived),
        encode(&embedded),
        counter
    );
    assert_eq!(counter, 0, "Ristretto derivation should use counter=0");
}

#[test]
fn test_derive_s_ristretto_matches_embedded() {
    let (derived, counter) = derive_s_ristretto().expect("failed to derive S (ristretto)");
    let embedded = embedded_const_bytes_s_();

    assert_eq!(
        embedded.as_slice(),
        &derived,
        "S(ristretto) mismatch: derived={} embedded={} counter={}",
        encode(derived),
        encode(&embedded),
        counter
    );
    assert_eq!(counter, 0, "Ristretto derivation should use counter=0");
}
