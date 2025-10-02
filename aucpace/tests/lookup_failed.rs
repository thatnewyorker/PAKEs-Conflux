#![cfg(test)]

use aucpace_conflux::{Database, Server, ServerMessage};
use curve25519_dalek::ristretto::RistrettoPoint;
use password_hash::{ParamsString, SaltString};
use rand::rngs::OsRng;

struct NoneDb;

impl Database for NoneDb {
    type PasswordVerifier = RistrettoPoint;

    fn lookup_verifier(
        &self,
        _username: &[u8],
    ) -> Option<(Self::PasswordVerifier, SaltString, ParamsString)> {
        None
    }

    fn store_verifier(
        &mut self,
        _username: &[u8],
        _salt: SaltString,
        _uad: Option<&[u8]>,
        _verifier: Self::PasswordVerifier,
        _params: ParamsString,
    ) {
        unimplemented!()
    }
}

#[test]
#[cfg(all(feature = "sha2", feature = "getrandom"))]
fn test_lookup_failed_aug_returns_ok() {
    // Prepare a server and pre-established SSID (length >= MIN_SSID_LEN)
    let mut server = Server::new(OsRng).expect("failed to initialize server RNG");
    let aug_layer = server
        .begin_prestablished_ssid(b"0123456789abcdef")
        .expect("failed to begin prestablished ssid");

    // Database with no entries to force lookup_failed path
    let db = NoneDb;

    // Generate client info; this should take the lookup_failed path and still succeed
    let result = aug_layer.generate_client_info(b"nonexistent-user", &db, OsRng);

    assert!(
        result.is_ok(),
        "lookup_failed path should not panic or error"
    );
    let (_next_step, message) = result.unwrap();

    // Should receive AugmentationInfo with default PBKDF params
    match message {
        ServerMessage::AugmentationInfo {
            group,
            x_pub: _,
            salt: _,
            pbkdf_params,
        } => {
            assert_eq!(group, "ristretto255");
            assert_eq!(pbkdf_params, ParamsString::default());
        }
        other => panic!("Expected AugmentationInfo, got: {:?}", other),
    }
}

#[cfg(all(feature = "strong_aucpace", feature = "sha2", feature = "getrandom"))]
mod strong_lookup_failed_tests {
    use super::*;
    use aucpace_conflux::StrongDatabase;
    use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, traits::IsIdentity};

    struct NoneStrongDb;

    impl StrongDatabase for NoneStrongDb {
        type PasswordVerifier = RistrettoPoint;
        type Exponent = curve25519_dalek::scalar::Scalar;

        fn lookup_verifier_strong(
            &self,
            _username: &[u8],
        ) -> Option<(Self::PasswordVerifier, Self::Exponent, ParamsString)> {
            None
        }

        fn store_verifier_strong(
            &mut self,
            _username: &[u8],
            _uad: Option<&[u8]>,
            _verifier: Self::PasswordVerifier,
            _secret_exponent: Self::Exponent,
            _params: ParamsString,
        ) {
            unimplemented!()
        }
    }

    #[test]
    fn test_lookup_failed_strong_returns_ok() {
        let mut server = Server::new(OsRng).expect("failed to initialize server RNG");
        let aug_layer = server
            .begin_prestablished_ssid(b"0123456789abcdef")
            .expect("failed to begin prestablished ssid");

        // Strong DB with no entries to force lookup_failed_strong path
        let db = NoneStrongDb;

        // Use a non-identity blinded point to avoid IllegalPointError
        let blinded = RISTRETTO_BASEPOINT_POINT;

        let result =
            aug_layer.generate_client_info_strong(b"nonexistent-user", blinded, &db, OsRng);

        assert!(
            result.is_ok(),
            "lookup_failed_strong path should not panic or error"
        );

        let (_next_step, message) = result.unwrap();

        match message {
            ServerMessage::StrongAugmentationInfo {
                group,
                x_pub: _,
                blinded_salt,
                pbkdf_params,
            } => {
                assert_eq!(group, "ristretto255");
                assert_eq!(pbkdf_params, ParamsString::default());
                assert!(
                    !blinded_salt.is_identity(),
                    "fallback blinded_salt must not be identity"
                );
            }
            other => panic!("Expected StrongAugmentationInfo, got: {:?}", other),
        }
    }
}
