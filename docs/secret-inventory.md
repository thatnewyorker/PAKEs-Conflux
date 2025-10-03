# Secret Inventory (Initial)

Status: draft (initial pass)
Scope: PAKEs-Conflux workspace (aucpace, spake2, srp)
Revision: v0

This document inventories secret-bearing material in the workspace, summarizes current protections, and outlines remediation steps to ensure proper zeroization and controlled exposure. It is intended to guide implementation, testing, and reviews.

Goals
- Identify all secret values and their lifecycles (where created, how used, when dropped).
- Record current protections (zeroization status, wrappers) and gaps.
- Provide actionable next steps to harden secret handling across crates.

Threat model assumptions (summary)
- We aim to reduce exposure from:
  - Process memory snapshots, core dumps, swap/paging, and post-mortem analysis.
  - Accidental logging or debug printing.
  - Transient intermediate variables that linger after use.
- Not addressed here: stronger OS/hardware protection (mlock/mprotect), or powerful attackers with ongoing read access before zeroization.

---

## Workspace overview

- Shared utilities: secret-utils crate scaffolding added (no public wrappers yet). This will centralize wrappers and policies in a follow-up phase.
- Zeroization dependencies added to crates:
  - aucpace: zeroize dependency present, curve25519-dalek has an optional zeroize feature but is not enabled by default.
  - spake2: zeroize dependency added and used for password wrapper; curve25519-dalek’s zeroize feature is not enabled.
  - srp: zeroize dependency added and used for key material in verifiers; BigUint-based secrets remain non-zeroized.

---

## Crate: spake2

Key locations and secrets
- Struct: Spake2<G>
  - xy_scalar: G::Scalar (ephemeral secret; private scalar)
  - password_vec: Password (user password bytes)
  - password_scalar: G::Scalar (secret derived from password)
  - msg1: Vec<u8> (public transcript component)
- Derived key (session key): returned from finish() as Vec<u8> (secret)
- Group implementation (ed25519.rs)
  - HKDF output, transcript hashing inputs (transient, should be treated as sensitive where derived from secret inputs)

Lifecycles (high level)
- password bytes: created from user input during start_*; live through the Spake2 state until finish() or drop.
- scalars (xy_scalar, password_scalar): created during start and used for computing messages and shared secret; live through the Spake2 state until drop.
- key (finish result): computed at finish() and returned to caller; lifetime controlled by caller.

Current protections
- Password: wrapped in a struct that derives Zeroize and ZeroizeOnDrop; clears on drop.
- Scalars: stored as curve25519-dalek scalar type (c2_Scalar); the crate currently does not enable curve25519-dalek’s zeroize feature in spake2, so scalars are not guaranteed to zeroize on drop.
- Derived key (Vec<u8>): returned to caller; not zeroized by default.

Gaps
- xy_scalar and password_scalar not guaranteed to zeroize on drop (missing curve25519-dalek/zeroize feature).
- Return value (session key) is not wrapped/zeroized by default.
- No consistent secret wrapper usage for derived key material at API boundaries.

Action items
- Enable curve25519-dalek’s zeroize feature in spake2 to ensure scalar zeroization on drop.
- Wrap returned session key in a zeroizing type (or document requirement for callers and provide a helper wrapper in the shared secret-utils crate).
- Add tests to validate zeroization of password and scalar fields when Spake2 drops.

---

## Crate: aucpace

Key locations and secrets (from client/server flow)
- Client augmentation layer (client.rs)
  - username: &[u8] (sensitive but not strictly secret; may be considered PII)
  - password: &[u8] (secret; input to password hashing)
  - w: scalar derived from password hashing (secret)
  - PRS: password-related string (derived using w and x_pub); consider sensitive
- CPace substep (client/server)
  - ya/yb: ephemeral secret scalars (secrets)
  - Ya/Yb: public points
  - K: shared secret point (secret input to key derivation)
  - sk1/sk: derived session keys (secret)
- Server augmentation layer (server.rs and database.rs)
  - W (verifier), salt (W considered sensitive; salt is public)
  - x: server secret exponent (secret; ephemeral)
- Nonces (ssid agreement s, t): nonces are non-secret but must be unpredictable

Lifecycles (high level)
- password input: lives through hashing; should be short-lived.
- w and ephemeral scalars: used to compute PRS and CPace; should be short-lived; drop immediately after use.
- K, sk1, sk: derived; live until session teardown; drop ASAP after consumption.
- server verifier W: may be long-lived (persisted in DB) but should not linger in process memory longer than necessary.

Current protections
- Crate depends on curve25519-dalek; a “zeroize” cargo feature is defined to enable curve25519-dalek/zeroize.
- Default feature set does not enable “zeroize”; thus scalars/points are not guaranteed to zeroize on drop in default builds.
- Passwords are passed as &[u8] from callers; no secret wrappers at API boundary.
- No explicit zeroization of PRS, w, sk1/sk in the current state.

Gaps
- No enforced zeroization for ephemeral scalars, w, PRS, K, sk1/sk under default features.
- Password and username are passed as slices, which increases the risk of accidental copying/leaks.
- No consistent secret wrappers for derived keys or password inputs.
- No tests asserting zeroization lifecycles.

Action items
- Enable “zeroize” feature by default or document security feature set for release builds (preferred: include zeroize in defaults for production profiles).
- Introduce secret wrappers for password input (and any owned buffers).
- Add scoped wrappers or patterns for w, PRS, K, and session keys to ensure prompt drop and zeroization (e.g., via zeroizing wrappers).
- Add tests to validate zeroization and absence of accidental copies.
- Document sensitive vs non-sensitive values (e.g., salt and public points are non-secret; PRS and K are sensitive).

---

## Crate: srp

Key locations and secrets (client.rs)
- Identity hash inputs: username (sensitive), password (secret)
- x (private key): BigUint
- a (client secret exponent): BigUint
- u, k (protocol parameters): BigUint; derived from secrets and public values; treat as sensitive
- Premaster secret S: BigUint
- m1, m2: proofs (not keys; sensitive but not secret keys)
- key: Vec<u8> (shared secret key; secret)

Key locations and secrets (server.rs)
- v (verifier): BigUint (sensitive)
- b (server secret exponent): BigUint
- a_pub, b_pub: public values
- u, k (protocol parameters): BigUint; treat as sensitive
- Premaster secret S: BigUint
- m1, m2: proofs (sensitive)
- key: Vec<u8> (shared secret key; secret)

Lifecycles (high level)
- BigUint intermediates (x, a, b, u, k, S, v) are created during compute phases; drop after use.
- key: derived and lives in verifier structs until caller consumes or struct is dropped.

Current protections
- SrpClientVerifier and SrpServerVerifier derive Zeroize and ZeroizeOnDrop for the key field (Vec<u8>); proof fields are skipped (Output<D>).
- BigUint intermediates are not zeroized on drop (num-bigint does not provide zeroize by default).
- Input password is accepted as &[u8]; no secret wrapper at API boundary.

Gaps
- BigUint secrets (x, a, b, S, v, u, k) are not zeroized; might linger in memory until allocator reuse.
- No secret wrappers for password inputs; risk of accidental copies in callers.
- No tests asserting zeroization for key material after drop or absence of secret exposure.

Action items
- Introduce zeroizing wrappers for byte buffers used to hold secret material where feasible.
- Consider minimizing BigUint heap allocations or scoping BigUint variables tightly; evaluate feasibility of manual zeroization of internal buffers (challenging without library support).
- Provide guidance and helpers for callers to pass password as a secret wrapper type.
- Add tests validating the zeroization of key material (already present for verifiers) and absence of accidental logging.

---

## Cross-cutting items

Secret categories to standardize
- Inputs: passwords (secret), usernames (sensitive), salts (non-secret), nonces (non-secret).
- Ephemeral secrets: private scalars/exponents; should be zeroized on drop.
- Derived secrets: PRS, K, session keys; should be zeroized on drop and scoped tightly.
- Long-lived sensitive data: verifiers (server-side W or v). Memory copies in-process should be minimized and dropped/zeroized as soon as possible; persistent storage requires separate controls.

API boundary expectations
- Avoid returning raw secret buffers; prefer secret wrappers or document caller obligations.
- Provide controlled exposure methods only where necessary (e.g., for KDF consumption).
- Avoid Clone for secret types by default.

RNG hygiene
- Ensure all places that require randomness are using vetted RNGs.
- Audit random scalar generation and blinding randomness paths.
- Handle RNG errors explicitly and fail closed.

Logging and serialization
- Avoid logging secret values or including them in debug formats.
- Guard serde with care: do not serialize secrets unless explicitly designed for ephemeral transport; zeroize temporary buffers after serialization.

---

## Implementation checklist (near-term)

- spake2
  - [ ] Enable curve25519-dalek/zeroize feature and verify scalar zeroization on drop.
  - [ ] Wrap returned session key with zeroizing type or provide helper and document expectations.
  - [ ] Add zeroization tests for Spake2 state drop and for finish() key handling.

- aucpace
  - [ ] Enable zeroize feature in default features or document required build features for production.
  - [ ] Introduce secret wrappers for password input (owned variants) and for derived keys (sk1/sk).
  - [ ] Ensure ephemeral scalars, w, PRS, K are tightly scoped and zeroized.
  - [ ] Add tests validating zeroization and absence of accidental copies or logs.

- srp
  - [ ] Maintain zeroization of key Vec<u8> (client/server verifiers).
  - [ ] Minimize BigUint secret lifetimes; investigate practical zeroization approaches or containment strategies.
  - [ ] Add documentation for callers to pass password with secret wrappers and avoid accidental copies.
  - [ ] Add tests ensuring no secret leakage via debug or serialization.

- secret-utils (shared)
  - [ ] Define and implement secret wrappers for byte buffers (passwords, derived session keys).
  - [ ] Provide traits/utilities for controlled exposure and conversions.
  - [ ] Add test utilities to validate zeroization in unit tests.

---

## Testing and CI (roadmap)

- Unit tests
  - Validate zeroization of password wrappers on drop.
  - Validate zeroization of session key wrappers on drop.
  - When feasible, assert that secret-carrying structs do not implement Clone.

- Integration tests
  - Run standard protocol flows and ensure secret state is dropped promptly post-handshake.
  - Panic-path tests to ensure Drop-based zeroization still triggers.

- CI gates
  - Build with zeroize features enabled in release profiles.
  - Lint for accidental uses of String/Vec<u8> where secret wrappers are expected.

---

## Notes and caveats

- BigUint zeroization: current ecosystem support is limited. Prefer short lifetimes and avoid unnecessary heap copies. Consider future investigation into bigint types with zeroization support or custom big-integer wrappers if justified.
- Returning secret keys: returning raw Vec<u8> is convenient but leaks responsibility to callers. Prefer a consistent strategy (wrappers with explicit extraction or documented caller obligations plus helper utilities).

---

This is a living document. Please update entries as protections are added, wrappers are introduced, and tests/CI checks are implemented.
