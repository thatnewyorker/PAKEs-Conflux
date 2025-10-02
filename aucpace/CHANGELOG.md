# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0/).

## Unreleased
### Changed
- Make RNG usage fully fallible: all cryptographically secure RNG calls that could previously panic now return `Result` and surface RNG failures as `Err(Error::Rng)`.
  - Notable affected APIs: `aucpace::utils::generate_nonce`, `generate_keypair`, `generate_server_keypair` now return `Result`.
  - Higher-level constructors and protocol entry points that obtain randomness (for example `AuCPaceServer::new`, `AuCPaceServer::begin`, and CPace substep helpers) were updated to propagate RNG errors.
  - `spake2` group RNG entry points (e.g. `random_scalar`) are fallible and return `Result`.
- Updated examples and tests to demonstrate and handle the fallible RNG APIs (using `?` or explicit `match`), and added doc examples that show patterns such as:
  - Propagating errors: `let kv = generate_keypair(&mut rng, ...)?;`
  - Explicit handling: `match generate_nonce(&mut rng) { Ok(n) => ..., Err(Error::Rng) => ... }`

### Breaking Changes
- Several public functions changed their signatures to return `Result` where they previously were infallible. This is a breaking change for downstream users — callers must now handle or propagate RNG-related errors (e.g., `Error::Rng`).

### Migration notes
- Update call sites to handle the new `Result` signatures:
  - Use the `?` operator in fallible contexts to propagate RNG failures.
  - Or explicitly match on the returned `Result` and handle `Error::Rng`.
- Update examples and integration code to construct and pass RNGs as before (e.g., `OsRng`), but now treat RNG calls as fallible.
- When publishing, consider a version bump (semver: minor or major depending on current versioning policy) and add a short migration guide linking to the updated examples.

## 0.1.1 (2023-07-27)
### Changed
- Bump `curve25519-dalek` to v4.0 release ([#138])

[#138]: https://github.com/RustCrypto/PAKEs/pull/138

## 0.1.0 (2023-05-14)
- Initial release
