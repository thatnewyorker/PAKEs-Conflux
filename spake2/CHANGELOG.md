# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0/).

## Unreleased
### Changed
- Session key handling: session keys are now returned as `secret_utils::wrappers::SecretKey` with zeroization-on-drop and redacted Debug. Borrow bytes via `AsRef<[u8]>`/deref.
- Dependencies: bumped `secret-utils` to `0.2.x` and removed the unused `secrecy` dependency from this crate.
- Make RNG usage fallible: cryptographic RNG entry points that previously assumed infallible generation are now fallible and return `Result`. In particular, group RNG entry points such as `random_scalar` and any constructors or helpers that obtain randomness will propagate RNG failures rather than panicking. Callers must handle or propagate RNG-related errors (for example with `?`), or explicitly match the returned `Result`.
- Examples and tests updated to demonstrate handling fallible RNG APIs (propagate with `?` or match on the `Result` and handle the error case).
- Removed panic-prone invariant-based unwraps in workspace crates where applicable; conversions now return errors instead of panicking. For `spake2`, the primary change is RNG fallibility and error propagation.
- Improved workspace test coverage: added integration tests (in `aucpace`) for handshake variants and lookup-failure paths to ensure stable, non-panicking behavior across the workspace.

### Breaking Changes
- Several public APIs changed their signatures to return `Result` where they previously were infallible. This is a breaking change for downstream code: update call sites to handle the new fallible signatures.
- Equality removed for secrets: `SecretKey` no longer implements `PartialEq`. Use `SecretKey::ct_eq(&other)` for explicit comparison.

### Migration notes
- Replace any uses of `==`/`!=` on `SecretKey` with `SecretKey::ct_eq(&other)`.
- Update Cargo.toml for release: set `secret-utils = "0.2"` (remove any local `path` dependency when publishing).
- Update call sites to handle the new `Result` signatures:
  - Use the `?` operator in fallible contexts to propagate RNG failures.
  - Or explicitly match on the returned `Result` and handle RNG failures gracefully.
- Examples that previously assumed infallible RNG now show patterns such as:
  - Propagate: `let s = Spake2::<...>::start_a_with_rng(..., &mut rng)?;`
  - Match: `match Group::random_scalar(&mut rng) { Ok(s) => ..., Err(e) => ... }`
- When publishing, consider a version bump and add a short migration guide for downstream users.

## 0.4.0 (2023-07-23)
### Changed
- Move IDs to relevant `Side` enum variants ([#114])
- MSRV 1.60 ([#115])
- Bump `curve25519-dalek` to v4.0 release ([#138])

[#114]: https://github.com/RustCrypto/PAKEs/pull/114
[#115]: https://github.com/RustCrypto/PAKEs/pull/115
[#138]: https://github.com/RustCrypto/PAKEs/pull/138

## 0.3.1 (2022-01-22)
### Changed
- Refactor internals ([#91])

[#91]: https://github.com/RustCrypto/PAKEs/pull/91

## 0.3.0 (2022-01-22) [YANKED]
### Added
- Initial `no_std` support ([#87])
- `getrandom` feature ([#88])

### Changed
- 2021 edition upgrade; MSRV 1.56 ([#80])
- Bump `curve25519-dalek` to v3.0  ([#85])
- Replace `rand` with `rand_core` v0.5 ([#85])
- Bump `hkdf` to v0.12 ([#86])
- Bump `sha2` to v0.10 ([#86])
- Renamed `SPAKE2` => `Spake2` ([#89])
- Renamed `SPAKEErr` => `Error` ([#89])

[#80]: https://github.com/RustCrypto/PAKEs/pull/80
[#85]: https://github.com/RustCrypto/PAKEs/pull/85
[#86]: https://github.com/RustCrypto/PAKEs/pull/86
[#87]: https://github.com/RustCrypto/PAKEs/pull/87
[#88]: https://github.com/RustCrypto/PAKEs/pull/88
[#89]: https://github.com/RustCrypto/PAKEs/pull/89

## 0.2.0 (2018-12-20)

## 0.1.1 (2018-10-16)

## 0.1.0 (2018-08-21)

## 0.0.9 (2018-08-21)

## 0.0.8 (2018-05-26)

## 0.0.7 (2018-05-25)

## 0.0.6 (2018-05-23)

## 0.0.5 (2018-04-29)

## 0.0.4 (2018-01-28)

## 0.0.3 (2017-11-29)

## 0.0.2 (2017-09-21)

## 0.0.1 (2017-08-01)

## 0.4.0 (2023-07-23)
### Changed
- Move IDs to relevant `Side` enum variants ([#114])
- MSRV 1.60 ([#115])
- Bump `curve25519-dalek` to v4.0 release ([#138])

[#114]: https://github.com/RustCrypto/PAKEs/pull/114
[#115]: https://github.com/RustCrypto/PAKEs/pull/115
[#138]: https://github.com/RustCrypto/PAKEs/pull/138

## 0.3.1 (2022-01-22)
### Changed
- Refactor internals ([#91])

[#91]: https://github.com/RustCrypto/PAKEs/pull/91

## 0.3.0 (2022-01-22) [YANKED]
### Added
- Initial `no_std` support ([#87])
- `getrandom` feature ([#88])

### Changed
- 2021 edition upgrade; MSRV 1.56 ([#80])
- Bump `curve25519-dalek` to v3.0  ([#85])
- Replace `rand` with `rand_core` v0.5 ([#85])
- Bump `hkdf` to v0.12 ([#86])
- Bump `sha2` to v0.10 ([#86])
- Renamed `SPAKE2` => `Spake2` ([#89])
- Renamed `SPAKEErr` => `Error` ([#89])

[#80]: https://github.com/RustCrypto/PAKEs/pull/80
[#85]: https://github.com/RustCrypto/PAKEs/pull/85
[#86]: https://github.com/RustCrypto/PAKEs/pull/86
[#87]: https://github.com/RustCrypto/PAKEs/pull/87
[#88]: https://github.com/RustCrypto/PAKEs/pull/88
[#89]: https://github.com/RustCrypto/PAKEs/pull/89

## 0.2.0 (2018-12-20)

## 0.1.1 (2018-10-16)

## 0.1.0 (2018-08-21)

## 0.0.9 (2018-08-21)

## 0.0.8 (2018-05-26)

## 0.0.7 (2018-05-25)

## 0.0.6 (2018-05-23)

## 0.0.5 (2018-04-29)

## 0.0.4 (2018-01-28)

## 0.0.3 (2017-11-29)

## 0.0.2 (2017-09-21)

## 0.0.1 (2017-08-01)
