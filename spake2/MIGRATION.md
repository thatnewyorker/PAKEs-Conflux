# SPAKE2-Conflux Migration Guide (0.6.0)

This guide explains how to upgrade to `spake2-conflux` 0.6.0, where the documented and example “default” is now Ristretto. It also shows how to explicitly keep Ed25519 behavior if you need wire compatibility with legacy peers.

Audience: downstream consumers of the `spake2-conflux` crate.


## What changed

- Ristretto is now the recommended suite and is used in all top-level docs and examples (`RistrettoGroup`).
- Ed25519 remains available as `Ed25519Group` for explicit selection.
- Wire encodings and distinguished constants are suite-dependent; Ristretto and Ed25519 are not interoperable on the wire.
- New Ristretto-focused tests were added and run by default in CI. Provenance checks for Ristretto constants run by default; Ed25519 provenance is optional/gated.


## TL;DR: Quick checklist

1) Update dependency:
- `spake2-conflux = "^0.6.0"`

2) Pick your suite:
- Recommended: Use `RistrettoGroup` explicitly in imports and type parameters.
- Legacy: To retain Ed25519, use `Ed25519Group` explicitly.

3) Coordinate with peers:
- Ensure both sides select the same suite (Ristretto vs Ed25519). Wire formats are not compatible.

4) Run tests and docs:
- `RUST_BACKTRACE=full cargo nextest run --workspace --all-targets --no-fail-fast`
- `cargo test -p spake2-conflux --doc`
- `cargo run -p spake2-conflux --example confirm_example`

5) Optional provenance checks:
- `RUST_BACKTRACE=full cargo nextest run -p spake2-conflux --features constants-provenance`


## Upgrading to 0.6.0

- Update your Cargo.toml to use `spake2-conflux = "^0.6.0"`.
- If you previously copied examples from this crate, note they now use Ristretto. Your code may still compile if it imported `Ed25519Group` explicitly; otherwise, update imports and generic parameters to select your intended suite.

Minimum Supported Rust Version (MSRV): match the `rust-version` declared by the crate. Ensure your toolchain meets or exceeds it.


## Adopting Ristretto (recommended)

- Import and select `RistrettoGroup` in your code.
- Use `Spake2::<RistrettoGroup>` for A/B or symmetric flows.
- Key confirmation APIs and transcript handling are unchanged; they remain suite-aware internally.
- Message sizes remain 33 bytes for both suites (1 role byte + 32-byte element). Encodings and constants differ.

Rationale:
- Ristretto provides a prime-order group with canonical encodings and eliminates cofactor/torsion pitfalls present in raw Edwards encodings. It reduces validation complexity and hardens protocols by default.


## Keeping Ed25519 behavior (legacy/explicit)

- Import and select `Ed25519Group` explicitly.
- Use `Spake2::<Ed25519Group>` where you previously relied on implicit Ed25519 examples.
- This preserves the legacy wire format and semantics for deployments that must interoperate with Ed25519-only peers.

Trade-offs:
- Ed25519 requires careful validation to avoid pitfalls (identity/small-order points). The crate enforces checks, but Ristretto remains the safer default moving forward.


## Interoperability guidance

- All participants in a protocol run must select the same suite. Ristretto and Ed25519 encodings and constants are not wire-compatible.
- When coordinating upgrades across services, plan a migration window to move both sides to Ristretto. If you cannot do that immediately, explicitly select `Ed25519Group` on both sides.
- Persisted or logged transcripts must not be mixed across suites. Domain separation strings differ, and confirmation MACs are suite-aware.


## Test and CI guidance

Local testing
- Full workspace tests: `RUST_BACKTRACE=full cargo nextest run --workspace --all-targets --no-fail-fast`
- Doctests for spake2: `cargo test -p spake2-conflux --doc`
- Example smoke test: `cargo run -p spake2-conflux --example confirm_example`
- Optional provenance checks:
  - Ristretto is validated by default.
  - Ed25519 provenance (optional): `RUST_BACKTRACE=full cargo nextest run -p spake2-conflux --features constants-provenance`
- Optional constant-time focused run: `RUST_BACKTRACE=full cargo nextest run --workspace --all-targets --no-fail-fast --features constant-time`

CI suggestions
- Keep PR jobs fast by running Ristretto flows and default tests with nextest.
- Run `constants-provenance` in a scheduled or manual audit job if you want to keep PR times minimal.
- Ensure at least one job compiles and runs tests that reference `Ed25519Group` (this crate still includes tests referencing it).


## Common pitfalls and how to avoid them

- Mismatched suites:
  - Symptom: `finish()` errors (e.g., wrong side marker, corrupt message) or confirmation verification failures between peers.
  - Fix: Ensure both sides explicitly use the same group (`RistrettoGroup` or `Ed25519Group`).

- Copy/pasted legacy examples:
  - Symptom: Examples use Ed25519 unintentionally, leading to interop issues with services expecting Ristretto.
  - Fix: Update imports and generics to `RistrettoGroup`.

- Hidden dependencies on Ed25519 wire format:
  - Symptom: Persisted messages or protocol parsers assume Ed25519 encodings.
  - Fix: Retain Ed25519 explicitly until you can migrate stored data and peers, or add a protocol version/suite negotiation mechanism.


## Feature flags overview

- `getrandom` (default): enables OS RNG support.
- `constant-time`: enables constant-time comparison helpers in confirmation verification paths.
- `constants-provenance`: enables Ed25519 provenance tests (Ristretto provenance is tested by default).

Ensure your CI runs the combinations you care about. For provenance checks, you can run Ristretto by default and Ed25519 under `constants-provenance` in scheduled jobs.


## FAQ

Q: Does switching to Ristretto change performance?
- Performance is broadly comparable for most use cases. The main consideration is correctness and safety—Ristretto provides canonical encodings and avoids cofactor pitfalls.

Q: Are the message sizes the same?
- Yes, both suites use 33 bytes on the wire (1 role byte + 32-byte element). However, the encodings and constants differ, so messages are not interoperable.

Q: Do I need to change how I do key confirmation?
- No. The confirm helpers are suite-aware and unchanged at the API level. Just ensure both sides use the same suite for the handshake.

Q: How do I pin the old behavior?
- Keep using `Ed25519Group` explicitly and stay on `^0.5` if you don’t want to opt into 0.6.x. To upgrade to 0.6.0 while keeping Ed25519 wire behavior, import and use `Ed25519Group` explicitly everywhere you construct `Spake2<...>` instances.


## Appendix: migration steps in detail

1) Decide your target suite:
- Prefer Ristretto for new deployments.
- Keep Ed25519 if you must interoperate with legacy peers immediately.

2) Update dependency:
- `spake2-conflux = "^0.6.0"`

3) Update imports and type parameters:
- Ristretto path: import `RistrettoGroup` and use `Spake2::<RistrettoGroup>`.
- Ed25519 path: import `Ed25519Group` and use `Spake2::<Ed25519Group>`.

4) Coordinate peers and services:
- Confirm all participants select the same suite.
- If rolling upgrades are required, consider a short-term negotiation/versioning mechanism or pin Ed25519 until all peers can move.

5) Validate locally:
- `RUST_BACKTRACE=full cargo nextest run --workspace --all-targets --no-fail-fast`
- `cargo test -p spake2-conflux --doc`
- `cargo run -p spake2-conflux --example confirm_example`

6) Optional: enable provenance and CT checks:
- `RUST_BACKTRACE=full cargo nextest run -p spake2-conflux --features constants-provenance`
- `RUST_BACKTRACE=full cargo nextest run --workspace --all-targets --no-fail-fast --features constant-time`

7) Update your CI:
- Ensure nextest is used for PRs.
- Add an audit/nightly job for `constants-provenance` if PR runtime is a concern.

By following this guide, you can adopt Ristretto as the safer default or explicitly retain Ed25519 behavior while coordinating upgrades across your ecosystem.