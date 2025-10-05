#![allow(clippy::unwrap_used)]

use proptest::prelude::*;
use spake2_conflux::{Ed25519Group, Error, Group, Identity, Password, Spake2};

fn arb_non32_len_vec() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        // lengths 0..=31
        (0usize..=31).prop_flat_map(|len| proptest::collection::vec(any::<u8>(), len)),
        // lengths 33..=64
        (33usize..=64).prop_flat_map(|len| proptest::collection::vec(any::<u8>(), len)),
    ]
}

proptest! {
    // bytes_to_element must reject any length != 32
    #[test]
    fn bytes_to_element_rejects_non_32_lengths(b in arb_non32_len_vec()) {
        let parsed = <Ed25519Group as Group>::bytes_to_element(&b);
        prop_assert!(parsed.is_none());
    }

    // For any 32-byte input that parses successfully, re-encoding must be canonical:
    // element_to_bytes must be 32 bytes and parse back to the same element.
    #[test]
    fn bytes_to_element_roundtrip_is_canonical(b in prop::array::uniform32(any::<u8>())) {
        if let Some(p) = <Ed25519Group as Group>::bytes_to_element(&b) {
            let enc = <Ed25519Group as Group>::element_to_bytes(&p);
            prop_assert_eq!(enc.len(), <Ed25519Group as Group>::element_length());
            let reparsed = <Ed25519Group as Group>::bytes_to_element(&enc);
            prop_assert!(reparsed.is_some());
            // EdwardsPoint implements PartialEq; equality is well-defined here.
            prop_assert_eq!(reparsed.unwrap(), p);
        } else {
            // Not all 32-byte strings are valid encodings; this is fine.
            prop_assert!(true);
        }
    }

    // finish() must return WrongLength for messages that do not match 1 + element_length()
    #[test]
    fn finish_rejects_wrong_lengths_for_side_a(msg_len in 0usize..=128) {
        // Create a valid A-side session state
        let (s_a, _msg1) = Spake2::<Ed25519Group>::start_a(
            &Password::new(b"password"),
            &Identity::new(b"idA"),
            &Identity::new(b"idB"),
        ).unwrap();

        // Build an arbitrary message with the correct 'B' side marker but arbitrary length
        let mut msg = vec![b'B'];
        if msg_len > 0 {
            // We already placed one byte, so compensate to reach msg_len total (best-effort).
            let extra = msg_len.saturating_sub(1);
            msg.extend(core::iter::repeat(0u8).take(extra));
        }

        let res = s_a.finish(&msg);
        if msg.len() != 1 + <Ed25519Group as Group>::element_length() {
            prop_assert_eq!(res.unwrap_err(), Error::WrongLength);
        } else {
            // If the length is correct, result may be Ok or Err depending on content.
            prop_assert!(true);
        }
    }

    // finish() must return BadSide when the side marker is incorrect for A and B.
    #[test]
    fn finish_rejects_wrong_side_marker_for_a(side in any::<u8>(), payload in prop::array::uniform32(any::<u8>())) {
        // Skip the valid marker for A's peer (B).
        prop_assume!(side != b'B');

        let (s_a, _msg1) = Spake2::<Ed25519Group>::start_a(
            &Password::new(b"password"),
            &Identity::new(b"idA"),
            &Identity::new(b"idB"),
        ).unwrap();

        let mut msg = Vec::with_capacity(1 + payload.len());
        msg.push(side);
        msg.extend_from_slice(&payload);

        let res = s_a.finish(&msg);
        prop_assert_eq!(res.unwrap_err(), Error::BadSide);
    }

    #[test]
    fn finish_rejects_wrong_side_marker_for_b(side in any::<u8>(), payload in prop::array::uniform32(any::<u8>())) {
        // Skip the valid marker for B's peer (A).
        prop_assume!(side != b'A');

        let (s_b, _msg2) = Spake2::<Ed25519Group>::start_b(
            &Password::new(b"password"),
            &Identity::new(b"idA"),
            &Identity::new(b"idB"),
        ).unwrap();

        let mut msg = Vec::with_capacity(1 + payload.len());
        msg.push(side);
        msg.extend_from_slice(&payload);

        let res = s_b.finish(&msg);
        prop_assert_eq!(res.unwrap_err(), Error::BadSide);
    }

    // If the point bytes are invalid (don't decode), finish() must return CorruptMessage
    // when the side marker is correct and length is correct.
    #[test]
    fn finish_rejects_invalid_point_for_a(payload in prop::array::uniform32(any::<u8>())) {
        // Only test when decoding fails; otherwise finish may succeed (valid but adversarial).
        prop_assume!(<Ed25519Group as Group>::bytes_to_element(&payload).is_none());

        let (s_a, _msg1) = Spake2::<Ed25519Group>::start_a(
            &Password::new(b"password"),
            &Identity::new(b"idA"),
            &Identity::new(b"idB"),
        ).unwrap();

        let mut msg = Vec::with_capacity(33);
        msg.push(b'B'); // correct side marker for A's peer
        msg.extend_from_slice(&payload);

        let res = s_a.finish(&msg);
        prop_assert_eq!(res.unwrap_err(), Error::CorruptMessage);
    }

    #[test]
    fn finish_rejects_invalid_point_for_b(payload in prop::array::uniform32(any::<u8>())) {
        // Only test when decoding fails; otherwise finish may succeed (valid but adversarial).
        prop_assume!(<Ed25519Group as Group>::bytes_to_element(&payload).is_none());

        let (s_b, _msg2) = Spake2::<Ed25519Group>::start_b(
            &Password::new(b"password"),
            &Identity::new(b"idA"),
            &Identity::new(b"idB"),
        ).unwrap();

        let mut msg = Vec::with_capacity(33);
        msg.push(b'A'); // correct side marker for B's peer
        msg.extend_from_slice(&payload);

        let res = s_b.finish(&msg);
        prop_assert_eq!(res.unwrap_err(), Error::CorruptMessage);
    }
}
