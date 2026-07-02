---
title: Security Notes
nav_order: 8
---

# Security Notes

What Thistle takes care of, and what remains your job.

## What Thistle does for you

**Tested against the world's test suites.** 20,000+ vectors from NIST
(CAVP/ACVP), Google's Wycheproof (which specifically probes edge cases and
known implementation bugs), and the RFCs, run continuously for over four
months.

**Timing-attack resistance.** Code that touches secret keys runs in the
same amount of time regardless of what the secret is, so attackers can't
learn key bits with a stopwatch. This holds for X25519, Ed25519,
P-256/P-384, ML-KEM, and ML-DSA. Two documented exceptions: software AES
and Camellia use lookup tables that a co-tenant on shared hardware could
observe through the CPU cache — use the AES-NI path (`has_aes_ni()`) or
ChaCha20 there.

**Input checking.** Wrong key lengths, out-of-range parameters, undersized
buffers, cipher limits — public functions validate and raise. The
`True`/`False` APIs (P-256/P-384) must have their result checked.

**Key cleanup.** Key schedules, secret scratch, and hash state that
absorbed secrets are erased from memory after use.

## What's still your job

- **Keep private keys private.** Thistle has no key storage; where keys
  live is up to you.
- **Fresh nonces.** Stream ciphers break if a (key, nonce) pair is ever
  reused. Thistle catches counter overflow, but it can't know you used the
  same nonce twice across runs.
- **Hash shared secrets before using them as keys** (one `sha256_hash`
  call).
- **Authenticate your ciphertext.** ChaCha20 hides data but doesn't detect
  tampering — add an [HMAC](mac-kdf).
- **Compare secrets in constant time.** Checking an HMAC tag with `==`
  leaks through timing; compare all bytes unconditionally.

## Honest limits

- No protocol layer: Thistle is primitives, not TLS/Noise/sessions.
- Memory erasure is best-effort — the language gives no guarantee that no
  copy of a secret ever existed in a register or spilled to the stack.
- Not yet independently audited. The test coverage is extensive; an audit
  is a different kind of assurance.
