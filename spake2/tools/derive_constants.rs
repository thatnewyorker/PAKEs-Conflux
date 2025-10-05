/*! Derivation script scaffold for SPAKE2 M/N/S constants provenance.

This file documents a deterministic, reproducible procedure to generate the
distinguished group elements M, N, and S for the SPAKE2 construction over
Edwards25519. It is documentation-first: an outline with rationale and strict
rules, so auditors and contributors can reproduce or regenerate constants.

Status
- This is an outline: it prioritizes clarity and provenance over executable code.
- If you want an executable derivation utility, follow the "Implementation
  outline" section below and integrate it as a standalone binary (e.g.,
  `cargo run --package spake2-conflux --bin derive-constants`) or a small
  throwaway crate under `tools/`.

Background and goals
- SPAKE2 requires distinguished group elements M and N (and optionally S for
  the symmetric variant). Their discrete logs with respect to the base point
  must be unknown.
- We will derive M, N, S deterministically from public, human-readable labels,
  with explicit domain separation and rejection criteria that ensure the points
  are valid and not of small order.
- The procedure MUST be fully reproducible across platforms and time. The
  derived constants are the canonical values to embed and test against.

Group and encoding assumptions
- Group: Edwards25519 (curve25519-dalek)
- Encoding: 32-byte compressed Edwards-Y
- Rejection criteria:
  - Non-canonical encodings are rejected (decompression must succeed).
  - The identity element is rejected.
  - Any point whose cofactor-multiplication yields identity (i.e., in a
    small-order subgroup) is rejected.

High-level derivation procedure (deterministic)
1) Parameters and domain separation
   - Suite identifier: "spake2-conflux/ed25519/v1"
   - Derivation label: "spake2-conflux/derive-constant/v1"
   - Constant-specific labels:
     - "M"
     - "N"
     - "S"
   - Counter: 32-bit unsigned, little-endian, starting at 0.

2) Byte generator (expand) function
   - Use HKDF-SHA256 to derive a 32-byte seed for each constant:
     seed = HKDF_SHA256(salt = "", ikm = suite || 0x00 || name, info = derivation_label, L = 32)
     where:
     - suite = "spake2-conflux/ed25519/v1"
     - name ∈ {"M", "N", "S"}
     - The 0x00 separator is to prevent accidental concatenation ambiguity.
   - From that seed, derive candidate encodings with:
     candidate = SHA256(seed || counter_le)
     where:
     - counter_le = u32::to_le_bytes(counter)
     - counter starts at 0 and is incremented by 1 for each trial (0, 1, 2, ...).

3) Candidate acceptance
   - Attempt to interpret `candidate` as an Edwards25519 compressed point:
     p = CompressedEdwardsY(candidate).decompress()
     - If decompression fails, increment the counter and retry.
   - Reject if p.is_identity() is true.
   - Reject if (p.mul_by_cofactor().is_identity()) is true.
   - The first candidate that passes all checks is accepted as the constant.

4) Output format
   - The canonical output is the 32-byte compressed Edwards-Y encoding of `p`,
     i.e., `p.compress().to_bytes()`. (This should be identical to `candidate`,
     but enforce a canonical re-encode to guard against non-canonical inputs.)
   - Emit the bytes as hex as well as a Rust array literal for easy embedding.
   - For provenance, record:
     - suite
     - derivation_label
     - constant name
     - counter selected
     - final 32-byte hex encoding
     - (optional) the final EdwardsPoint’s debug information if available

5) Reproducibility notes
   - All inputs are ASCII strings (no trailing nulls).
   - HKDF uses an empty-string salt (i.e., no salt).
   - Endianness for the counter is little-endian (u32).
   - The SHA256 and HKDF versions are the standard ones from RFC 2104/5869/6234.

Rationale for security and unknown discrete logs
- This process does NOT rely on selecting a scalar and multiplying a known
  generator (which would produce a known discrete log to whoever computes the
  scalar). Instead, it takes the compressed Edwards-Y encoding space as a
  search space, selecting uniformly via HKDF/SHA256 outputs. Because Edwards
  compressed encodings are not linear in the basepoint scalar, the discrete log
  of the chosen point relative to the base point remains unknown to the
  derivation process.
- Rejection of identity and small-order points prevents degenerate cases.

Interoperability and migration
- The current crate embeds specific hard-coded compressed points for M, N, S
  that trace back to a historical Python implementation. If this procedure
  yields different values than currently embedded constants:
  - Option A: Document old constants were legacy and deprecate them (breaking
    change).
  - Option B: Keep legacy as default for backward compatibility and provide an
    opt-in feature (e.g., "deterministic-constants-v1") for the new constants.
  - Option C: Bump crate MAJOR version to switch to the deterministic constants.
- In any case, the provenance and full derivation procedure should be
  documented and the outputs published in the README/CHANGELOG.

Test coverage and CI recommendations
- Implement a test which re-runs the derivation steps and asserts that the
  generated constants match the embedded bytes. This safeguards accidental edits.
- Negative tests:
  - Ensure the procedure rejects identity/small-order points by synthetic
    injection (e.g., pre-set the candidate to a known 8-torsion encoding).
- CI should run the derivation tests by default.

Implementation outline (if/when converting this into executable code)
- Dependencies
  - curve25519-dalek = { version = "4", default-features = false, features = ["digest"] }
  - hkdf = "0.12"
  - sha2 = "0.10"
- Pseudocode structure
  - const SUITE: &[u8] = b"spake2-conflux/ed25519/v1";
  - const LABEL: &[u8] = b"spake2-conflux/derive-constant/v1";
  - fn derive_seed(name: &[u8]) -> [u8; 32] {
      // hkdf with ikm = suite || 0x00 || name
    }
  - fn find_point(seed: [u8; 32]) -> [u8; 32] {
      for counter in 0u32.. {
        candidate = SHA256(seed || counter_le)
        if let Some(p) = CompressedEdwardsY(candidate).decompress() {
          if !p.is_identity() && !p.mul_by_cofactor().is_identity() {
            return p.compress().to_bytes()
          }
        }
      }
    }
  - fn derive_constant(name: &str) -> (bytes: [u8; 32], counter: u32) { ... }
  - fn main() {
      for name in ["M", "N", "S"] {
        (bytes, counter) = derive_constant(name)
        print details and a Rust array literal
      }
    }

Expected outputs to record when finalizing constants
- For each constant (M, N, S):
  - name: "M" | "N" | "S"
  - suite: "spake2-conflux/ed25519/v1"
  - derivation_label: "spake2-conflux/derive-constant/v1"
  - counter: decimal value used
  - bytes_hex: 64 hex chars (compressed Edwards-Y)
  - rust_literal: [0x.., 0x.., ..., 0x..] (32 entries)

Editorial note on Ristretto (future option)
- If the crate migrates to Ristretto for SPAKE2 (preferred for cofactor safety),
  we recommend deriving M/N/S using `RistrettoPoint::hash_from_bytes::<Sha256>`:
  - Use the same suite/label scheme and domain separation.
  - `RistrettoPoint` does not have small-order points; the hash construction is
    a one-way map to the prime-order group.
  - Output the compressed Ristretto encodings.
- Migration would be a breaking change unless gated behind a feature flag.

Copyright
- This derivation procedure is provided to ensure transparency and auditability.
- License: same as crate (MIT OR Apache-2.0).

*/

#![allow(dead_code, unused_variables)]

/// Documentation-only scaffold. This binary is not intended to be compiled
/// or executed as-is. See the module-level comment for the derivation process.
fn main() {
    println!("This file documents the derivation process for M/N/S constants.");
    println!("See the module-level comments for the full reproducible procedure.");
}
