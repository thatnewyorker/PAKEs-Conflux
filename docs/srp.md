# SRP

A high-level guide to the SRP (Secure Remote Password) protocol and how it fits into the PAKEs-Conflux workspace.

SRP is a verifier-based PAKE designed primarily for password login flows. It allows a client and a server that share a low-entropy password to establish a high-entropy session key without ever sending the password to the server. The server stores only a password-derived verifier, not the plaintext password, reducing the impact of server compromise.

References:
- Overview: https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol
- RFC 5054 (TLS-SRP groups and usage): https://datatracker.ietf.org/doc/html/rfc5054
- Crate docs: https://docs.rs/srp
- Crate on crates.io: https://crates.io/crates/srp

---

## When to use SRP

Use SRP when you need:
- A password-backed login protocol where the server stores a verifier instead of a password.
- Resistance to offline dictionary attacks against intercepted traffic.
- Mutual authentication with key confirmation (client and server prove they derived the same key).
- Mature, widely referenced parameters and deployment patterns (e.g., RFC 5054 groups).

Consider alternatives:
- AuCPace: a modern V-PAKE with variants for stronger precomputation resistance and constrained environments.
- SPAKE2: a simple, balanced PAKE (both sides share the same password) that is well-suited for pairing flows.

---

## Protocol at a glance

SRP (most commonly SRP-6a) has two phases:

1) Registration (secure channel, one-time)
- The client picks a username I and password P.
- The server generates a random salt s.
- The client computes x = H(s, H(I ":" P)) and v = g^x mod N, where N is a large safe prime and g is a generator.
- The client sends (I, s, v) to the server over a secure channel (or the server computes v itself if it learns x).
- The server stores (I, s, v). It never stores P.

2) Authentication (insecure channel)
- Client selects random a and computes A = g^a mod N. Sends (I, A) to server.
- Server selects random b and computes B = k*v + g^b mod N (k is a multiplier derived from parameters). Sends (s, B) to client.
- Both sides compute u = H(A, B) and then the shared secret S (formulas depend on the SRP variant):
  - Client: x = H(s, H(I ":" P)), S_c = (B - k*g^x)^(a + u*x) mod N
  - Server: S_s = (A * v^u)^b mod N
- Both derive K = H(S).
- Both exchange and verify key-confirmation proofs (e.g., M1 and M2) to mutually authenticate and bind the transcript.
- If verification succeeds, use K to protect the application channel (e.g., via an AEAD).

Notes:
- A and B must be validated (e.g., A ≠ 0 mod N, B ≠ 0 mod N).
- u must be non-zero.
- Use the SRP-6a variant for interoperability and well-understood security properties.

---

## Parameters and configuration

- Group (N, g): Use well-known safe-prime groups from RFC 5054 (e.g., 2048-bit with g = 2) for robust security and interop.
- Hash function H: The `srp` crate is generic over the `Digest` trait. Choose a modern hash (e.g., SHA-256) and use it consistently across clients and servers.
- Multiplier k: Defined per SRP-6a; typically derived from H and the group parameters (e.g., k = H(N, g) with a defined encoding).
- Salt s: A per-user, randomly generated value. Store alongside the verifier.
- Randomness: a and b must be uniformly random and never reused.

The `srp` crate also supports using a specialized password hashing/KDF for the private key computation (x), which can raise the cost of offline guessing if the verifier is stolen.

---

## Features and crate setup

- Generic over hash functions via the `Digest` trait (e.g., `sha2::Sha256`).
- Supports using a dedicated password hashing function when computing x, allowing you to integrate memory-hard KDFs.
- See docs.rs for the current API, features, and examples.

Example dependency snippet (replace x.y with the desired version):
- srp = "x.y"
- sha2 = "0.10"

---

## High-level integration guide

1) Registration (over a secure channel)
- Generate a unique random salt s per user.
- Compute x = H(s, H(I ":" P)) (or with a dedicated PHF/KDF).
- Compute verifier v = g^x mod N.
- Store (I, s, v). Do not store P or x. Protect the verifier in your database.

2) Authentication (over an insecure channel)
- Client sends (I, A), where A = g^a mod N, a random a.
- Server loads (s, v), picks random b, computes B = k*v + g^b mod N, returns (s, B).
- Both compute u = H(A, B) (verify u != 0).
- Client recomputes x from s and P, then S_c = (B - k*g^x)^(a + u*x) mod N.
- Server computes S_s = (A * v^u)^b mod N.
- Both derive K = H(S).
- Exchange and verify key confirmation (e.g., M1 from client to server, M2 from server to client).
- On success, start using K within an AEAD or pass it to your secure channel.

3) Channel binding and application usage
- Bind your application/channel context (identities, channel IDs, protocol version) into the transcript or confirmation step.
- Use K only after successful confirmation.
- Ensure replay protection and integrity for the handshake messages.

---

## Security considerations

- Use SRP-6a and standardized parameter encodings to avoid subtle interop and security bugs.
- Validate parameters:
  - A mod N != 0, B mod N != 0, u != 0.
  - N is a safe prime and g is a valid generator for the group you chose.
- Never reuse a or b (ephemeral exponents). Ensure strong randomness.
- Use memory-hard password hashing for x (e.g., Argon2, scrypt) where possible to improve resistance if verifiers leak.
- Rate-limit failed authentication attempts to reduce online guessing.
- Perform and strictly verify key confirmation (M1/M2) before using K.
- Keep all big-integer operations constant-time where possible and avoid side-channel leaks.
- Store and handle verifiers and salts as sensitive data. Even though verifiers are safer than plaintext passwords, a leak can still enable online guessing.
- Keep dependencies up to date and monitor for advisories.

---

## Interoperability and serialization

- SRP variants differ subtly (e.g., SRP-6 vs SRP-6a). Choose SRP-6a and stick to it across all participants.
- Define consistent encodings for N, g, A, B, s, and the hash inputs (big-endian byte strings are common).
- Pad big integers to the byte length of N where required by the chosen spec/variant.
- Ensure both sides use the same hash, group, and multiplier definition (k) and agree on M1/M2 formulas.
- Include versioning in any higher-level message envelope to allow future evolution.

---

## Performance notes

- SRP uses modular exponentiation over large integers (e.g., 2048-bit), which is fast enough for typical login flows.
- Message sizes are moderate and suitable for most network environments.
- For higher performance with similar security goals in constrained devices, consider comparing with AuCPace.

---

## MSRV and licensing

- Minimum Supported Rust Version (MSRV): 1.61 or higher (per this workspace’s SRP crate).
- Dual-licensed:
  - Apache-2.0: http://www.apache.org/licenses/LICENSE-2.0
  - MIT: http://opensource.org/licenses/MIT

---

## Troubleshooting checklist

- Are both client and server using the same SRP variant (SRP-6a), hash function, and parameter encodings?
- Are A and B validated (non-zero modulo N)? Is u non-zero?
- Are you performing key confirmation (M1/M2) and rejecting sessions if it fails?
- Are salts unique per user and generated with a secure RNG?
- Are you using a memory-hard KDF for x (recommended) and rate-limiting failed attempts?
- Are integers padded and serialized consistently (e.g., to the byte length of N)?
- Are you binding the secure channel or application protocol to the SRP transcript?

---

## See also

- AuCPace (verifier-based PAKE with strong options): see docs/aucpace.md
- SPAKE2 (balanced PAKE, great for pairing flows): see docs/spake2.md