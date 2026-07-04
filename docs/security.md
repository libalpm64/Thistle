---
title: Security Notes
nav_order: 8
---

# Security Notes

## Constant-time

X25519, Ed25519, P-256, P-384: mask-select ladders, branchless field
arithmetic. ML-KEM: branchless message encoding, constant-time implicit
rejection. ML-DSA: flag-accumulated rejection sampling.

Not constant-time: software AES, Camellia (table-based S-boxes, cache
observable). Use AES-NI or ChaCha20 for secret-key material on shared
hardware.

Source-level constant-time is not a compiler guarantee. Crypto entry
points are `@no_inline` to keep codegen stable. For a formal claim, inspect
emitted assembly or run a dudect-style harness.

## Validation

Every public entry point validates length/range and raises. Exceptions:
P-256/P-384 return `Bool` instead of raising — check it.

## Zeroization

Key schedules, hash contexts that absorbed secrets, and signing scratch are
wiped with volatile stores (`.wipe()` methods, internal cleanup on drop).
This is best-effort — no guarantee against register/stack-spill copies.

## Out of scope

No protocol layer (TLS/Noise/session management), no key storage. ECDH/KEM
outputs need a KDF pass before use as a key. ChaCha20 has no built-in
authentication — pair with HMAC.

Not independently audited. Test coverage: 20,000+ NIST CAVP/ACVP and
Wycheproof vectors.
