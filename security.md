---
title: Security Notes
nav_order: 8
---

# Security Notes

What Thistle does for you, and what it expects from you.

## Constant-time behavior

Secret-handling paths avoid secret-dependent branches and table indices at
the source level:

- X25519 / Ed25519 / P-256 / P-384 scalar multiplication: always
  double-add-select ladders with mask-based conditional swaps.
- Field arithmetic under those curves: branchless carries, borrows, and
  conditional reductions.
- ML-KEM: branchless message encoding, constant-time implicit rejection.
- ML-DSA: flag-accumulated rejection bounds, branchless reductions.

Known exceptions, disclosed in the source: software AES and Camellia use
lookup tables that are observable through cache timing. Prefer the AES-NI
path on shared hardware.

Source-level constant-time is not a formal guarantee — a compiler can
reintroduce branches. Crypto entry points are marked `@no_inline` to keep
codegen stable. For a formal evaluation, inspect the emitted assembly or run
a dudect-style harness.

## Input validation

Every public entry point validates its inputs and raises on violation:
key/point/block lengths, RFC 9106 Argon2 bounds, PBKDF2 iteration minimums,
BLAKE2b digest bounds, ChaCha20 counter exhaustion, SEC 1 point validation,
ML-DSA/ML-KEM encoding checks. A `Bool`-returning API (P-256/P-384) must
have its result checked.

## Zeroization

Key schedules, hash contexts that absorbed secrets, signing scratch, and
secret intermediates are wiped with volatile stores after use (`wipe()`
methods and internal cleanup). This is best-effort: Mojo gives no formal
guarantee that copies never exist elsewhere (registers, spills).

## What Thistle does not do

- No protocol layer: no TLS, no Noise, no session management.
- No key management or storage.
- Raw ECDH outputs and KEM secrets should pass through a KDF before use.
- ChaCha20 has no built-in authentication.
- Not independently audited.
