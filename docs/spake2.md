# SPAKE2

A high-level guide to the SPAKE2 (Simple Password Authenticated Key Exchange) protocol and how it fits into the PAKEs-Conflux workspace.

SPAKE2 is a balanced PAKE: both sides contribute a shared password and derive a high-entropy session key with strong resistance to offline dictionary attacks and active attackers. It is simple, efficient, and well-suited for pairing flows and some login-style use cases (with care).

References:
- Draft spec: https://tools.ietf.org/id/draft-irtf-cfrg-spake2-10.html
- Crate docs: https://docs.rs/spake2
- Crate on crates.io: https://crates.io/crates/spake2

---

## When to use SPAKE2

Use SPAKE2 when you need:
- A simple, efficient PAKE with one round trip (plus an optional second for key confirmation).
- Mutual authentication based on a password that both parties know.
- Protection against offline dictionary attacks by a passive or active network attacker.
- A balanced PAKE where both sides have the same role (no server-stored verifier required).

Consider alternatives:
- If you need a verifier-based server deployment (i.e., the server stores a password-derived verifier rather than the raw password), see AuCPace.
- If you need a widely deployed login PAKE with mature interop and a verifier-based approach, see SRP.

---

## Protocol at a glance

- Both parties share the same password (or a derivation of it).
- Each party computes an ephemeral public value that is blinded by password-derived elements.
- They exchange a single message pair (one round trip).
- Both parties derive the same high-entropy session key if and only if they used the same password.
- Optionally, both parties perform key confirmation (a second exchange) to ensure they derived the same key and bind the transcript.

Messages:
- For the default security level (using the Ed25519 group), each side’s single message is 33 bytes.
- All messages are byte strings and can be sent over any transport.

---

## Groups and implementation notes

- The implementation is generic over a `Group`.
- The default provided group is `Ed25519Group`, which offers strong security and performance.
- Group choice affects message sizes and performance. The Ed25519-based group is a widely used and robust default.

---

## Features and crate setup

Minimal setup in `Cargo.toml`:
- Add `spake2` from crates.io.
- Choose optional features if/when the crate exposes them (see docs.rs for up-to-date feature flags).

Example dependency snippet (replace `x.y` with the desired version):
- `spake2 = "x.y"`

---

## High-level integration guide

1) Preliminaries
- Decide how you will obtain the shared password. For pairing, this might be a short code that the user copies between devices. For login-like flows, it might be the user’s long-term password.
- Consider doing client-side key stretching/normalization to mitigate low-entropy passwords, especially in login scenarios.

2) Key exchange (1 round trip)
- Each side (call them A and B) uses the same password to produce an ephemeral message `msg_A` and `msg_B`.
- A sends `msg_A` to B; B sends `msg_B` to A.
- Each side computes the same session key from its own ephemeral secret and the other side’s message.

3) Key confirmation (optional, 2nd round trip)
- Each side derives a confirmation tag (e.g., a MAC) from the session key and transcript.
- They exchange confirmation tags. If they match, both sides are assured they share the same key.

4) Channel binding and application usage
- Bind your higher-level channel or application protocol to the SPAKE2 transcript (e.g., by including channel identifiers or context in the key derivation and confirmation).
- Use the derived session key with an AEAD to protect subsequent messages.
- Maintain replay protection and integrity across the full handshake transcript.

---

## Security considerations

- SPAKE2 resists passive and active attackers but does not, by itself, provide channel security beyond the derived session key. You must use the derived key properly (e.g., AEAD) and perform key confirmation to avoid unknown key-share issues.
- SPAKE2 is not “drop-in” for password login without careful design. In a login setting:
  - The server typically needs a verifier-based scheme (or ensure the client does key stretching before SPAKE2).
  - Ensure the final secure channel is bound to the PAKE to prevent an attacker from completing the PAKE normally and then hijacking the channel.
- Rate-limit failed attempts to reduce online guessing.
- Normalize and process passwords carefully (consistent encoding, normalization, salting where appropriate in your KDF).
- Keep dependencies updated and monitor for security advisories.

---

## Interoperability and serialization

- SPAKE2 messages are raw bytes; you can transport them over any medium (HTTP, QUIC, BLE, custom transports).
- If you define a custom envelope (like JSON), include versioning and clear field definitions.
- Ensure both sides agree on the same group parameters and transcript-binding strategy.

---

## Performance notes

- SPAKE2 is fast and requires just one round trip (plus optional confirmation).
- Ed25519-based groups provide a good balance of security and performance for most applications.
- Message sizes are small (33 bytes per side for Ed25519-based parameters), making it suitable for constrained links.

---

## MSRV and licensing

- Minimum Supported Rust Version (MSRV): 1.60 or higher (subject to change per crate’s release notes).
- Dual-licensed:
  - Apache-2.0: http://www.apache.org/licenses/LICENSE-2.0
  - MIT: http://opensource.org/licenses/MIT

---

## Troubleshooting checklist

- Did both sides use the exact same password (including normalization and encoding)?
- Are you performing key confirmation and rejecting the session if it fails?
- Is your transcript/channel binding complete and unambiguous?
- Are messages serialized and transported consistently on both sides?
- Are you rate-limiting failed attempts in login-style flows?

---

## See also

- AuCPace (verifier-based PAKE with strong options): see `docs/aucpace.md`
- SRP (verifier-based login PAKE with broad adoption): see `docs/srp.md`
