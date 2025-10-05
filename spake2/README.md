# [RustCrypto]: SPAKE2

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the [SPAKE2] password-authenticated key-exchange algorithm. Maintained as part of the PAKEs-Conflux workspace.

[Documentation][docs-link]

Compatibility note: As of 0.6.0, this crate’s docs and examples use RistrettoGroup by default. If you must remain on Ed25519 for wire-compatibility with legacy peers, see [MIGRATION.md](MIGRATION.md) for step-by-step instructions to explicitly select `Ed25519Group` and coordinate upgrades.

## About

This library implements the SPAKE2 password-authenticated key exchange
("PAKE") algorithm. This allows two parties, who share a weak password, to
safely derive a strong shared secret (and therefore build an
encrypted+authenticated channel).

A passive attacker who eavesdrops on the connection learns no information
about the password or the generated secret. An active attacker
(man-in-the-middle) gets exactly one guess at the password, and unless they
get it right, they learn no information about the password or the generated
secret. Each execution of the protocol enables one guess. The use of a weak
password is made safer by the rate-limiting of guesses: no off-line
dictionary attack is available to the network-level attacker, and the
protocol does not depend upon having previously-established confidentiality
of the network (unlike e.g. sending a plaintext password over TLS).

The protocol requires the exchange of one pair of messages, so only one round
trip is necessary to establish the session key. If key-confirmation is
necessary, that will require a second round trip.

All messages are bytestrings. Message sizes depend on the selected suite; for the provided Ed25519 and Ristretto suites they are 33 bytes (1 role byte + 32-byte element).

This implementation is generic over a `Group`, which defines the cyclic
group to use, the functions which convert group elements and scalars to
and from bytestrings, and the three distinctive group elements used in
the blinding process. Two groups are implemented:
`RistrettoGroup` (recommended default for new deployments) and `Ed25519Group` (available for explicit, legacy interoperability). Note that suites have different encodings and constants and are not wire-compatible.

## SecretKey usage (session key handling)

SPAKE2 returns the derived session key as `secret_utils::wrappers::SecretKey`. This wrapper:
- Zeroizes its contents on drop (`ZeroizeOnDrop`)
- Redacts `Debug` output to avoid accidental leaks
- Is not `Clone`, reducing accidental copies
- Allows borrowing bytes via `as_ref()` or deref to `&[u8]`

Examples:

- Compare two session keys (equality)

```/dev/null/usage.rs#L1-11
use secret_utils::wrappers::SecretKey;

fn equal_keys(k1: &SecretKey, k2: &SecretKey) -> bool {
    // Standard equality; do not rely on constant-time properties here.
    k1 == k2
}
```

- Hex encode a session key (only when necessary)

```/dev/null/usage.rs#L12-29
use secret_utils::wrappers::SecretKey;

// Requires the `hex` crate when you actually use this pattern.
fn key_as_hex(key: &SecretKey) -> String {
    // Borrow without copying the underlying bytes
    let bytes: &[u8] = key.as_ref();
    hex::encode(bytes)
}

// Even though Debug is redacted, avoid logging secrets altogether.
```

- Drop semantics (automatic zeroization when leaving scope)

```/dev/null/usage.rs#L30-44
use secret_utils::wrappers::SecretKey;

fn ephemeral_use() {
    {
        // SPAKE2 APIs return `SecretKey` directly; constructed here for demo.
        let key = SecretKey::from(vec![0u8; 32]);
        // use `key.as_ref()` to access bytes
        let _first_byte = key.as_ref().get(0).copied();
    } // key is zeroized here on drop
}
```

Notes:
- Prefer borrowing (`&[u8]`) instead of taking ownership.
- Do not print or log keys; use authenticated encryption if you must serialize.

# What Is It Good For?

PAKE can be used in a pairing protocol, like the initial version of Firefox
Sync (the one with J-PAKE), to introduce one device to another and help them
share secrets. In this mode, one device creates a random code, the user
copies that code to the second device, then both devices use the code as a
one-time password and run the PAKE protocol. Once both devices have a shared
strong key, they can exchange other secrets safely.

PAKE can also be used (carefully) in a login protocol, where SRP is perhaps
the best-known approach. Traditional non-PAKE login consists of sending a
plaintext password through a TLS-encrypted channel, to a server which then
checks it (by hashing/stretching and comparing against a stored verifier). In
a PAKE login, both sides put the password into their PAKE protocol, and then
confirm that their generated key is the same. This nominally does not require
the initial TLS-protected channel. However note that it requires other,
deeper design considerations (the PAKE protocol must be bound to whatever
protected channel you end up using, else the attacker can wait for PAKE to
complete normally and then steal the channel), and is not simply a drop-in
replacement. In addition, the server cannot hash/stretch the password very
much (see the note on "Augmented PAKE" below), so unless the client is
willing to perform key-stretching before running PAKE, the server's stored
verifier will be vulnerable to a low-cost dictionary attack.

## ⚠️ Security Warning

This crate has never received an independent third party audit for security and
correctness.

USE AT YOUR OWN RISK!

## Minimum Supported Rust Version

Rust **1.60** or higher.

Minimum supported Rust version can be changed in the future, but it will be
done with a minor version bump.

## License

Licensed under either of:

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/spake2-conflux.svg
[crate-link]: https://crates.io/crates/spake2-conflux
[docs-image]: https://docs.rs/spake2-conflux/badge.svg
[docs-link]: https://docs.rs/spake2-conflux/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.60+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260045-PAKEs
[build-image]: https://github.com/thatnewyorker/PAKEs-Conflux/actions/workflows/spake2.yml/badge.svg
[build-link]: https://github.com/thatnewyorker/PAKEs-Conflux/actions/workflows/spake2.yml

[//]: # (general links)

[RustCrypto]: https://github.com/RustCrypto
[SPAKE2]: https://tools.ietf.org/id/draft-irtf-cfrg-spake2-10.html

## Key Confirmation

To detect MITM and key mismatches, perform an explicit, authenticated key-confirmation exchange after both sides call `finish()`.

Recommended flow:
1) Run SPAKE2 handshake (A/B or symmetric) and call `finish()` to derive the session key on each side.
2) Exchange confirmation tags computed over the canonical transcript bytes (the 32-byte SPAKE2 messages).
3) Only mark the session as authenticated if both confirmation verifications succeed.

Asymmetric A/B example:

```rust
use spake2_conflux::{Identity, Password, RistrettoGroup, Spake2};
use spake2_conflux::confirm::{make_confirm_a, make_confirm_b, verify_confirm_a, verify_confirm_b};

let pw = Password::new(b"correct horse battery staple");
let id_a = Identity::new(b"client@example.com");
let id_b = Identity::new(b"server.example.com");

// A creates X
let (s_a, msg_a) = Spake2::<RistrettoGroup>::start_a(&pw, &id_a, &id_b).unwrap();

// B creates Y
let (s_b, msg_b) = Spake2::<RistrettoGroup>::start_b(&pw, &id_a, &id_b).unwrap();

// Each side derives its session key
let key_a = s_a.finish(&msg_b).unwrap();
let key_b = s_b.finish(&msg_a).unwrap();

// Canonical transcript parts (strip the first 'side' byte)
let x = &msg_a[1..]; // 32 bytes
let y = &msg_b[1..]; // 32 bytes

// A -> B confirmation
let tag_a = make_confirm_a(&key_a, x, y).unwrap();
verify_confirm_a(&key_b, x, y, &tag_a).unwrap();

// B -> A confirmation
let tag_b = make_confirm_b(&key_b, x, y).unwrap();
verify_confirm_b(&key_a, x, y, &tag_b).unwrap();

// Both verifications succeeded: session is authenticated.
```

Notes:
- The confirmation helpers compute HMAC-SHA256 over a domain-separated label and the transcript bytes to bind the returned tag to the exact SPAKE2 exchange.
- Verification uses a constant-time comparison to avoid timing oracles on MAC tags.
- If any verification fails, treat the session as unauthenticated and abort.

Symmetric roles are supported via `make_confirm_s` / `verify_confirm_s` with an explicit sender role marker.

## Threat Model and Constant-Time

Attacker capabilities:
- Remote network attacker: can observe, replay, and inject messages but cannot measure fine-grained local timing with precision.
- Local/co-resident attacker: may be able to measure microarchitectural timing or cache effects.

What this crate does:
- Group validation: the Ed25519 backend rejects invalid encodings, identity, and small-order points to prevent degenerate shared secrets.
- Key confirmation: explicit confirmation tags are provided to detect MITM and accidental misconfigurations.
- Constant-time options: critical comparisons in confirmation verification are performed without early returns, and when the `constant-time` feature is enabled, 32-byte comparisons use constant-time primitives.
- RNG handling: public constructors are fallible; RNG failures return `Error::Rng` instead of panicking.

Out of scope:
- Hardware side-channels and speculative-execution leaks.
- Full constant-timeness of all operations in all environments.

Guidance:
- Enable the `constant-time` feature when attackers can perform fine-grained timing (e.g., co-resident adversaries) or when you want to minimize timing channels at the cost of some performance.
- Always perform the key-confirmation step in production to defend against undetected MITM and mismatched keys.
- Normalize peer-facing errors (e.g., map parse/validation failures to a single error) to avoid providing oracle information in network protocols.

## Group Validation

- The `Group` trait contract requires strict validation in `bytes_to_element`: reject non-canonical encodings, the identity element, and any small-order/cofactor points. Implementations must never panic on malformed input.
- The Ed25519 backend enforces these checks and `Spake2::finish` performs a canonical round-trip re-encoding as defense-in-depth.
- These validations are always enabled; no feature flag is required.
- Negative tests under `spake2/tests/security.rs` exercise identity and small-order encodings and expect `Error::CorruptMessage`.

## Deterministic Constants and Provenance

This crate includes a deterministic, auditable procedure to derive SPAKE2 distinguished elements (M, N, S) for Ed25519:

- Suite: "spake2-conflux/ed25519/v1"
- Label: "spake2-conflux/derive-constant/v1"
- Procedure: HKDF-SHA256(seed from suite||0x00||name) → iterate SHA-256(seed||counter_le) until a decompressible, non-identity, non-small-order point is found; use its canonical compressed Edwards-Y bytes.

Tooling and features:
- CLI: `cargo run --bin derive_constants` prints bytes and counters for selected names.
- Provenance tests (optional): `cargo test --features constants-provenance` asserts that embedded constants match the derivation output. Enable this feature when you intend to standardize on deterministic constants and want CI/audit checks.
- Migration note: embedded constants are historically sourced for compatibility; the deterministic derivation may yield different values. If you plan to migrate, coordinate a protocol versioning strategy and update peers accordingly.
