# [RustCrypto]: SRP

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the [Secure Remote Password] password-authenticated
key-exchange algorithm. Maintained as part of the PAKEs-Conflux workspace.

[Documentation][docs-link]

## About

This implementation is generic over hash functions using the [`Digest`] trait,
so you will need to choose a hash  function, e.g. `Sha256` from [`sha2`] crate.

Additionally this crate allows to use a specialized password hashing
algorithm for private key computation instead of method described in the
SRP literature.

Compatibility with other implementations has not yet been tested.

## SecretKey usage (session key handling)

SRP verifier types hold the derived session key as `secret_utils::wrappers::SecretKey`. Where available, prefer using accessor methods that return `&SecretKey` (e.g., `SrpClientVerifier::key_secret()`), then borrow bytes with `as_ref()`.

This wrapper:
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
        // SRP verifier types hold `SecretKey`; constructed here for demo.
        let key = SecretKey::from(vec![0u8; 32]);
        // use `key.as_ref()` to access bytes
        let _first_byte = key.as_ref().get(0).copied();
    } // key is zeroized here on drop
}
```

Notes:
- Prefer borrowing (`&[u8]`) instead of taking ownership.
- Do not print or log keys; use authenticated encryption if you must serialize.

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

[crate-image]: https://img.shields.io/crates/v/srp-conflux.svg
[crate-link]: https://crates.io/crates/srp-conflux
[docs-image]: https://docs.rs/srp-conflux/badge.svg
[docs-link]: https://docs.rs/srp-conflux/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.60+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260045-PAKEs
[build-image]: https://github.com/thatnewyorker/PAKEs-Conflux/actions/workflows/srp.yml/badge.svg
[build-link]: https://github.com/thatnewyorker/PAKEs-Conflux/actions/workflows/srp.yml

[//]: # (general links)

[RustCrypto]: https://github.com/RustCrypto
[Secure Remote Password]: https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol
[`Digest`]: https://docs.rs/digest
[`sha2`]: https://crates.io/crates/sha2
