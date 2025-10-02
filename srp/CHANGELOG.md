# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0/).

## Unreleased
### Changed
- No RNG-specific API changes were necessary for `srp` as part of the workspace-wide RNG hardening. The recent work focused on making RNG usage fallible in `aucpace` and `spake2`. `srp` maintainers should still audit any direct RNG usage in their integration code and handle RNG errors if they surface from underlying RNG crates.
- Clarified documentation to note that `srp` has no API changes or breaking changes as part of these workspace updates.

### Added
- Clarifications in this changelog regarding workspace-wide RNG hardening and tests. Integration tests were expanded in the `aucpace` crate; there are no `srp`-specific test changes in this release.

### Migration notes
- Downstream users of the workspace should review call sites that obtain randomness. If you call RNG-taking APIs from `aucpace` or `spake2`, update your code to handle the new `Result`-returning APIs (use `?` to propagate or match on `Err` and handle `Error::Rng`).
- For `srp` consumers: no changes are required unless you have code that directly used infallible RNG patterns; in that case, replace any `unwrap()`/`expect()` on RNG results with proper error handling.


## 0.6.0 (2022-01-22)
### Changed
- Use `modpow` for constant time modular exponentiation ([#78])
- Rebuild library ([#79])

[#78]: https://github.com/RustCrypto/PAKEs/pull/78
[#79]: https://github.com/RustCrypto/PAKEs/pull/79

## 0.5.0 (2020-10-07)

## 0.4.3 (2019-11-07)

## 0.4.2 (2019-11-06)

## 0.4.1 (2019-11-07)

## 0.4.0 (2018-12-20)

## 0.3.0 (2018-10-22)

## 0.2.5 (2018-04-14)

## 0.2.4 (2017-11-01)

## 0.2.3 (2017-08-17)

## 0.2.2 (2017-08-14)

## 0.2.1 (2017-08-14)

## 0.2.0 (2017-08-14)

## 0.1.1 (2017-08-13)

## 0.1.0 (2017-08-13)
