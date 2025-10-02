# AuCPace

A high-level guide to the AuCPace (Augmented Composable Password Authenticated Connection Establishment) protocol and how it fits into the PAKEs-Conflux workspace.

AuCPace is a modern verifier-based PAKE designed for low-power and constrained environments. It enables two parties that share a low-entropy secret (a password) to derive a high-entropy shared session key, while providing strong resistance to offline dictionary attacks and active attackers.

References:
- Paper: https://eprint.iacr.org/2018/286
- Crate docs: https://docs.rs/aucpace-conflux
- Crate on crates.io: https://crates.io/crates/aucpace-conflux

---

## When to use AuCPace

Use AuCPace when you need:
- Mutual authentication based on a shared password, with a derived high-entropy session key.
- Protection against offline dictionary attacks.
- A verifier-based design (server stores a verifier instead of a raw password).
- Efficient performance suitable for Industrial IoT or embedded contexts.
- Optional stronger precomputation resistance via the StrongAuCPace variant.

If you’re looking for a simpler PAKE without server-side verifiers, consider `spake2`. If you need a widely deployed login PAKE with mature interop, consider `srp`. AuCPace is a strong choice when you want a V-PAKE with a clear upgrade path for stronger defenses (e.g., blinding).

---

## Protocol at a glance

AuCPace consists of two phases:

1) Registration (out-of-band, over a secure channel)
- The client provisions credentials to the server.
- The server derives and stores a password verifier (not the password itself).
- This step must be done over a secure channel; doing registration insecurely defeats the security properties of the protocol.

2) Authentication (over an insecure network)
- Client and server exchange ephemeral messages.
- Both parties derive the same session key if and only if they share the correct password/verifier relationship.
- An active attacker gets at most one online guess per protocol run and gains no useful information from failures.

---

## Variants

- Base AuCPace
  - Efficient verifier-based PAKE suitable for many deployments.

- StrongAuCPace
  - Hardens against precomputation attacks by blinding sensitive values in transit.
  - Recommended if you expect powerful adversaries who may invest in precomputation.

- Partially Augmented AuCPace
  - Reduces computational burden on the server by using a long-term key-pair per user on the server side.
  - Useful in deployments with many low-power servers and a more capable client.

---

## Features

- Default group: Ristretto255 (subject to change in the future).
- Optional `serde` feature:
  - Enables `serde` serialization for protocol message types (e.g., `ClientMessage`, `ServerMessage`).
  - Useful for transporting messages over your own chosen channel (HTTP, QUIC, BLE, custom radio, etc).

Example `Cargo.toml` snippet enabling `serde`:
    [dependencies]
    aucpace-conflux = { version = "x.y", features = ["serde"] }
    serde = { version = "1", features = ["derive"] }

Replace `x.y` with the desired crate version (see crates.io).

---

## High-level integration guide

1) Registration flow (secure channel)
- Client and server agree on the username and password (or a salted/password-derived value).
- Server constructs and stores a password verifier for the user.
- The verifier must be protected at rest; compromise enables online guessing but not direct password disclosure.

2) Authentication flow (insecure channel)
- Client begins a login attempt by generating an ephemeral message and sending it to the server.
- Server processes the message, uses the stored verifier, and responds with its own ephemeral message.
- Both sides compute the shared session key.
- Optionally, both sides exchange key confirmation MACs to ensure they derived the same key and bind the transcript.

3) Channel binding and application usage
- Bind your application protocol/channel to the PAKE transcript (e.g., include channel identifiers in the transcript or the key confirmation step).
- Use the derived session key with an AEAD (or hand it to your secure channel implementation) to protect subsequent traffic.
- Ensure replay-protection and integrity for the full transcript.

---

## Security considerations

- Registration must be done over a secure channel.
- Treat verifiers as sensitive: they are stronger than plaintext passwords, but leaks can still enable online guessing.
- Always include explicit key confirmation and consider channel binding.
- Use unique salts and user identifiers to avoid cross-user leakage.
- Rate-limit failed authentications to reduce the impact of online guesses.
- Keep dependencies updated and monitor for advisories.

---

## Interoperability and message serialization

- All protocol messages are binary-safe and can be sent over any transport.
- Enabling the `serde` feature allows you to serialize `ClientMessage` and `ServerMessage` to formats like `bincode`, `cbor`, or `json` (depending on your use case).
- Include versioning in your envelope/transport layer if you expect to evolve message formats.

---

## Performance notes

- AuCPace is optimized for constrained environments.
- StrongAuCPace adds additional blinding steps, trading some performance for precomputation resistance.
- The partially augmented variant can shift work away from the server by using long-term key material.

---

## MSRV and licensing

- Minimum Supported Rust Version (MSRV): 1.61 or higher.
- Dual-licensed:
  - Apache-2.0: http://www.apache.org/licenses/LICENSE-2.0
  - MIT: http://opensource.org/licenses/MIT

---

## Troubleshooting checklist

- Are you performing registration over a secure channel?
- Are you storing only verifiers server-side (not plaintext passwords)?
- Did both sides run key confirmation and verify it before using the derived key?
- Are messages serialized consistently on both sides (if using `serde`)?
- Have you enabled and enforced rate-limits for failed attempts?

---

## See also

- SPAKE2 (balanced PAKE): docs in `docs/spake2.md`
- SRP (login PAKE with broad adoption): docs in `docs/srp.md`
