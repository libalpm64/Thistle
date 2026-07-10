---
title: Security Notes
nav_order: 8
---

# Security Notes

## Constant-time

X25519 Ed25519 P-256 P-384 use mask-select ladders with branchless field arithmetic. ML-KEM uses branchless message encoding and constant-time implicit rejection. ML-DSA uses flag-accumulated rejection sampling.

Camellia and KCipher-2 are constant-time on every path. With hardware AES
(ARM crypto or AES-NI) their S-boxes run on AES round instructions with
register-resident affine fixups; without it they fall back to bitsliced
S-box circuits. No secret-indexed table lookups remain in either cipher.

Not constant-time: software AES. Table-based S-boxes are cache observable. Use AES-NI or ChaCha20 for secret-key material on shared hardware.

Source-level constant-time is not a compiler guarantee. Crypto entry
points are `@no_inline` to keep codegen stable. For a formal claim inspect emitted assembly or run a dudect-style harness.

## Validation

Every public entry point validates length and range then raises. P-256/P-384 are the exception. They return `Bool` instead of raising. Check it.

## Zeroization

Key schedules and hash contexts that absorbed secrets and signing scratch are wiped with volatile stores. This is `.wipe()` methods and internal cleanup on drop.
This is best-effort. There is no guarantee against register or stack-spill copies.

## Out of scope

No protocol layer (TLS/Noise/session management) and no key storage. ECDH/KEM outputs need a KDF pass before use as a key. ChaCha20 has no built-in authentication. Pair it with HMAC.

Not independently audited. Test coverage is 20,000+ NIST CAVP/ACVP and Wycheproof vectors.
