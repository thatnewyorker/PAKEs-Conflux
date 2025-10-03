# PAKEs-Conflux [![dependency status][deps-image]][deps-link]
[Password-Authenticated Key Agreement][1] protocols implementation.

## Warnings

Crates in this repository have not yet received any formal cryptographic and
security reviews.

Blinding is not yet implemented. Secrets are wrapped and zeroized in memory (via
`secret-utils`); passwords, ephemeral scalars, and session keys are cleared on drop.

**USE AT YOUR OWN RISK.**

## Secret handling and `SecretKey`

- The workspace uses zeroizing wrappers from the `secret-utils` crate to handle sensitive data.
- Session keys are returned as `secret_utils::wrappers::SecretKey` in `aucpace`, `spake2`, and `srp`.
- `SecretKey`:
  - Zeroizes on drop
  - Redacts `Debug` output
  - Is not `Clone` (to reduce accidental copies)
  - Implements `AsRef<[u8]>` and deref to `&[u8]` for compatibility
- Usage notes:
  - Compare two keys with `==` when needed.
  - To hex-encode, borrow bytes via `key.as_ref()` and pass to your hex/base64 encoder. Avoid logging secrets.
  - Zeroization is best-effort and does not defend against all attack vectors (e.g., certain hardware/OS-level attacks).

## Supported algorithms

| Name      | Crates.io  | Documentation  |
| --------- |:----------:| :-----:|
| [SRP][2]  | [![crates.io](https://img.shields.io/crates/v/srp-conflux.svg)](https://crates.io/crates/srp-conflux) | [![Documentation](https://docs.rs/srp-conflux/badge.svg)](https://docs.rs/srp-conflux) |
| [spake2][4]  | [![crates.io](https://img.shields.io/crates/v/spake2-conflux.svg)](https://crates.io/crates/spake2-conflux) | [![Documentation](https://docs.rs/spake2-conflux/badge.svg)](https://docs.rs/spake2-conflux) |
| [aucpace][5]  | [![crates.io](https://img.shields.io/crates/v/aucpace-conflux.svg)](https://crates.io/crates/aucpace-conflux) | [![Documentation](https://docs.rs/aucpace-conflux/badge.svg)](https://docs.rs/aucpace-conflux) |


## License

All crates are licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[deps-image]: https://deps.rs/repo/github/thatnewyorker/PAKEs-Conflux/status.svg
[deps-link]: https://deps.rs/repo/github/thatnewyorker/PAKEs-Conflux

[//]: # (footnotes)

[1]: https://en.wikipedia.org/wiki/Password-authenticated_key_agreement
[2]: https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol
[3]: https://en.wikipedia.org/wiki/Blinding_(cryptography)
[4]: https://www.di.ens.fr/~mabdalla/papers/AbPo05a-letter.pdf
[5]: https://eprint.iacr.org/2018/286
