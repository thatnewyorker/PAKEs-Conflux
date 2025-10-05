/*!
A/B key-confirmation example for SPAKE2 (Ed25519).

This example demonstrates:
- Running the SPAKE2 handshake for roles A and B.
- Computing and exchanging explicit key-confirmation tags using HMAC-SHA256.
- Verifying tags to detect MITM or key mismatches.

Run:
  cargo run --example confirm_example
*/

use spake2_conflux::confirm::{make_confirm_a, make_confirm_b, verify_confirm_a, verify_confirm_b};
use spake2_conflux::{Ed25519Group, Identity, Password, Spake2};

fn main() {
    // Shared password and identity strings agreed by both sides in advance.
    let pw = Password::new(b"correct horse battery staple");
    let id_a = Identity::new(b"client@example.com");
    let id_b = Identity::new(b"server.example.com");

    // A-side: create first message (X)
    let (s_a, msg_a) =
        Spake2::<Ed25519Group>::start_a(&pw, &id_a, &id_b).expect("A-side start failed");

    // B-side: create second message (Y)
    let (s_b, msg_b) =
        Spake2::<Ed25519Group>::start_b(&pw, &id_a, &id_b).expect("B-side start failed");

    // Each side "receives" the peer message and finishes to derive its session key.
    // In a real application, msg_a and msg_b would be exchanged over the network.
    let key_a = s_a.finish(&msg_b).expect("A-side finish failed");
    let key_b = s_b.finish(&msg_a).expect("B-side finish failed");

    // Extract the 32-byte SPAKE2 messages (remove the first 'side' byte).
    // X := msg_a[1..], Y := msg_b[1..]
    let x = &msg_a[1..];
    let y = &msg_b[1..];

    // Side A computes confirmation tag and sends to B.
    let tag_a = make_confirm_a(&key_a, x, y).expect("make_confirm_a failed");

    // Side B verifies A's tag with its own session key and the same transcript bytes.
    verify_confirm_a(&key_b, x, y, &tag_a).expect("verify_confirm_a failed");

    // Side B computes confirmation tag and sends to A.
    let tag_b = make_confirm_b(&key_b, x, y).expect("make_confirm_b failed");

    // Side A verifies B's tag.
    verify_confirm_b(&key_a, x, y, &tag_b).expect("verify_confirm_b failed");

    println!("SPAKE2 handshake complete and keys confirmed in both directions.");

    // Notes:
    // - Do not print or log session keys in real applications.
    // - The confirmation tags are 32-byte MACs; you may transmit them as-is or encode as hex/base64.
    // - If any verify_* step fails, treat the session as unauthenticated and abort.
}
