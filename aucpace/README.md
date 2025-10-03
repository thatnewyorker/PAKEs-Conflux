# [RustCrypto]: AuCPace

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the [AuCPace] password-authenticated key-exchange algorithm. Maintained as part of the PAKEs-Conflux workspace.

[Documentation][docs-link]

## About

This library is an implementation of the AuCPace (Augmented Composable Password Authenticated Connection Establishment)
protocol. AuCPace is an efficient verifier-based PAKE protocol designed for Industrial IOT applications.
It allows two parties, who share a weak password, to safely derive a strong shared secret (and therefore build 
an encrypted+authenticated channel).

A passive attacker who eavesdrops on the connection learns no information
about the password or the generated secret. An active attacker
(machine-in-the-middle) gets exactly one guess at the password, and unless they
get it right, they learn no information about the password or the generated
secret. Each execution of the protocol enables one guess. The use of a weak
password is made safer by the rate-limiting of guesses: no offline
dictionary attack is available to the network-level attacker.

The protocol requires a previous "registration" of a user over a secure channel.
Without this it is unsafe to perform a registration.

The `ClientMessage` and `ServerMessage` structs compromise all the data that is sent in messages between the
client and the server. Optionally the `serde` feature can be enabled to allow serde to serialise and deserialise
these messages.

Currently this implementation uses the "Ristretto255" group, though this is subject to change.

## SecretKey usage (session key handling)

AuCPace returns the derived session key as `secret_utils::wrappers::SecretKey`. This wrapper:
- Zeroizes its contents on drop (`ZeroizeOnDrop`)
- Avoids accidental exposure (redacted `Debug`)
- Is not `Clone` to reduce accidental copies
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

- Hex encode a session key (only when absolutely necessary)

```/dev/null/usage.rs#L12-29
use secret_utils::wrappers::SecretKey;

// Requires the `hex` crate when you actually use this pattern.
fn key_as_hex(key: &SecretKey) -> String {
    // Borrow without copying the underlying bytes
    let bytes: &[u8] = key.as_ref();
    hex::encode(bytes)
}

// Alternatively, for logging-sensitive contexts, prefer not to print secrets.
// Debug is redacted, but it's still best to avoid logging secrets altogether.
```

- Drop semantics (automatic zeroization when leaving scope)

```/dev/null/usage.rs#L30-44
use secret_utils::wrappers::SecretKey;

fn ephemeral_use() {
    {
        // Constructed for demonstration; AuCPace APIs return `SecretKey` directly.
        let key = SecretKey::from(vec![0u8; 32]);
        // use `key.as_ref()` to access bytes
        let _first_byte = key.as_ref().get(0).copied();
    } // key is zeroized here on drop
}
```

Notes:
- Prefer borrowing (`&[u8]`) over taking ownership.
- Avoid persisting secrets in logs or long-lived buffers.
- If you must serialize for transport/storage, consider authenticated encryption; hex/base64 only encodes bytes and does not provide secrecy.

# What Is It Good For?
AuCPace is designed for Industrial IOT settings, specifically where you have many low-power servers and a single
client which is assumed to be more powerful. This protocol is specifically designed for situations with limited
Public Key Infrastructure (PKI), where using a V-PAKE protocol provides a significant security improvement by
preventing phishing and offline dictionary attacks.

Additionally a variant of the protocol - StrongAuCPace - is also implemented, this provides resistance to
pre-computation attacks by blinding sensitive values in transit.

The partially augmented version of the protocol allows for even less computational burden on the server by utilising
a long term key-pair for each user on the server, instead of generating a fresh one each time.

## ⚠️ Security Warning

This crate has never received an independent third party audit for security and
correctness.

USE AT YOUR OWN RISK!

## Minimum Supported Rust Version

Rust **1.61** or higher.

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

[crate-image]: https://img.shields.io/crates/v/aucpace-conflux.svg
[crate-link]: https://crates.io/crates/aucpace-conflux
[docs-image]: https://docs.rs/aucpace-conflux/badge.svg
[docs-link]: https://docs.rs/aucpace-conflux/
[build-image]: https://github.com/thatnewyorker/PAKEs-Conflux/actions/workflows/aucpace.yml/badge.svg
[build-link]: https://github.com/thatnewyorker/PAKEs-Conflux/actions/workflows/aucpace.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.60+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260045-PAKEs

[//]: # (general links)

[RustCrypto]: https://github.com/RustCrypto
[AuCPace]: https://eprint.iacr.org/2018/286
