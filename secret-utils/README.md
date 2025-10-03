# secret-utils

Zeroizing secret wrappers and utilities used across the PAKEs-Conflux workspace.

This crate provides lightweight, no-unsafe wrappers for secret material (passwords, session keys, etc.) with:
- Best-effort in-memory erasure via zeroization on drop.
- Redacted Debug output to avoid accidental leaks in logs.
- Borrow-first ergonomics (`AsRef<[u8]>`, deref to `&[u8]`) to minimize copies.
- Explicit, best-effort constant-time equality for keys (`ct_eq`).

It is designed to be small, straightforward, and compatible with `no_std + alloc`.

## Status and MSRV

- Edition: 2024
- MSRV: 1.90
- No `unsafe` code

## Feature flags

- `alloc` (default): Enables heap-backed wrappers (required for `SecretBytes` and `SecretKey`).
- `std`: Convenience alias; implies `alloc`.

If you disable default features, the wrappers will be unavailable (docs-only build).

## Installation

Basic (default features include `alloc`):
```toml
[dependencies]
secret-utils = "0.2"
```

no_std with alloc:
```toml
[dependencies]
secret-utils = { version = "0.2", default-features = false, features = ["alloc"] }
```

no_std docs-only (wrappers disabled):
```toml
[dependencies]
secret-utils = { version = "0.2", default-features = false }
```

## Types

### `SecretBytes`
- Use for password-like or otherwise sensitive byte buffers.
- Zeroizes memory on drop.
- Redacted `Debug`: prints `[redacted]` and length.
- `AsRef<[u8]>` and deref to `&[u8]` for borrow-first access.
- Not `Clone`.
- Constructors and conversions:
  - `SecretBytes::new(Vec<u8>) -> Self`
  - `From<Vec<u8>> for SecretBytes`
  - `into_inner(self) -> Vec<u8>` (explicit escape hatch; see Security Notes)

### `SecretKey`
- Use for derived session keys or other key material.
- Zeroizes memory on drop.
- Redacted `Debug`: prints `[redacted]` and length.
- `AsRef<[u8]>` and deref to `&[u8]` for borrow-first access.
- Not `Clone`.
- DOES NOT implement `PartialEq`. Use `ct_eq(&other)` for explicit, best-effort constant-time equality.
- Constructors and conversions:
  - `SecretKey::new(Vec<u8>) -> Self`
  - `From<Vec<u8>> for SecretKey`
  - `into_inner(self) -> Vec<u8>` (explicit escape hatch; see Security Notes)

## Usage

Borrow-first access (avoid copying):
```rust
use secret_utils::wrappers::SecretKey;

fn use_key_material(key: &SecretKey) {
    // Borrow key bytes without copying
    let key_bytes: &[u8] = key.as_ref();

    // Use with your AEAD/KDF/HKDF, etc.
    // For example:
    // aead.init(key_bytes, nonce, associated_data);
}
```

Compare keys with explicit equality:
```rust
use secret_utils::wrappers::SecretKey;

fn keys_equal(a: &SecretKey, b: &SecretKey) -> bool {
    // Best-effort constant-time comparison
    a.ct_eq(b)
}
```

Hex-encode (only when necessary):
```rust
use hex;
use secret_utils::wrappers::SecretKey;

fn key_hex(key: &SecretKey) -> String {
    hex::encode(key.as_ref())
}
```

Passwords with `SecretBytes`:
```rust
use secret_utils::wrappers::SecretBytes;

fn authenticate(password: &SecretBytes) {
    // Borrow password bytes without copying
    let pw = password.as_ref();
    // Use pw in your password hashing / verifier logic
}
```

Explicit extraction when absolutely required:
```rust
use secret_utils::wrappers::SecretKey;

// Prefer borrowing via `as_ref()`; extraction should be rare and deliberate.
fn export_for_storage(mut key: SecretKey) -> Vec<u8> {
    // Transfers ownership of the sensitive bytes to the caller
    // Caller is responsible for careful handling post-extraction
    key.into_inner()
}
```

## Design decisions

- Zeroization: both wrappers implement `Zeroize` and `ZeroizeOnDrop` so memory is cleared when dropped and when explicitly zeroized.
- Debug redaction: `Debug` never includes raw bytes; only `[redacted]` with length.
- No `PartialEq` for `SecretKey`: comparing secrets should be explicit; `ct_eq` avoids accidental timing leaks that could arise with naive equality.
- Borrow-first ergonomics: `AsRef<[u8]>`/deref encourage minimal copies when interfacing with crypto APIs that accept `&[u8]`.

## Security notes and limitations

- Zeroization is best-effort:
  - It clears heap memory upon drop or explicit zeroize.
  - It cannot protect against all OS/hardware attacks (e.g., swapping, DMA, side channels, register spills).
- Equality timing:
  - `ct_eq` is a best-effort constant-time comparison for byte arrays. Compiler optimizations, CPU details, and surrounding logic can still influence timing; design higher-level protocols to minimize the need to compare secrets directly.
- Logging:
  - Do not log secret data. Redacted `Debug` is a safety net, not a license to print secrets.
- Copies and persistence:
  - Prefer borrowing `&[u8]` over taking ownership. Avoid cloning or persisting raw secret bytes.
  - `into_inner` is an explicit escape hatch that transfers secret ownership. Use rarely and deliberately.
- Serialization:
  - Hex/Base64 encode only when absolutely required and be aware this does not provide secrecy. Use authenticated encryption for storage/transport of secrets.

## Version notes

- `0.2`:
  - `SecretKey`: removed `PartialEq`; added `ct_eq(&Self) -> bool`.
  - Redacted `Debug` for `SecretBytes` for consistent behavior with `SecretKey`.
  - Fixed `cfg` gating for `Debug` impls to match `alloc` feature.
  - `into_inner` now uses `core::mem::take` for clarity.

## License

Licensed under either of:
- Apache License, Version 2.0
- MIT License

at your option.