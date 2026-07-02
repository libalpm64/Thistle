---
title: Home
nav_order: 1
---

# Thistle

Thistle is a cryptography library written in pure Mojo — no Python or C
on any path. It covers hashing, password hashing, HMAC/KDFs, symmetric
ciphers, elliptic-curve signatures and key exchange, and the NIST
post-quantum standards (ML-KEM, ML-DSA), validated against 20,000+ NIST
and Wycheproof test vectors.

Hardware acceleration is compile-time dispatched: SHA-NI on x86 and the
ARMv8 SHA2 crypto extension (Apple Silicon), AES-NI on x86 and ARM, and
GPU AES kernels for bulk ECB/CTR/GCM. All intrinsics lower directly
through LLVM — no FFI.

## Install

```sh
git clone https://github.com/libalpm64/Thistle
cd Thistle
pixi run test
```

To use it in your own project, add `-I path/to/Thistle/src` to your `mojo`
command and import from `thistle`.

## Sanity check

```mojo
from thistle import sha256_hash

def main() raises:
    var message = String("abc").as_bytes()
    var digest = sha256_hash(message)   # 32 bytes
```

That digest is always `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`
— the same answer every SHA-256 implementation in the world gives for "abc".

## Which page do I need?

| I want to... | Go to |
|---|---|
| Fingerprint or checksum data | [Hashing](hashing) |
| Store user passwords safely | [Passwords & Keys](mac-kdf) |
| Encrypt data with a key I have | [Encryption](symmetric) |
| Sign messages / agree on a key with someone | [Signatures & Key Exchange](curves) |
| Be safe against future quantum computers | [Post-Quantum](post-quantum) |
| Generate random keys | [Random Numbers](random) |
| Understand the safety guarantees | [Security Notes](security) |

## Conventions

- Invalid inputs raise `Error` — wrong key sizes, out-of-range parameters,
  cipher limits. The `Bool`-returning APIs (P-256/P-384) must be checked.
- Everything documented here is exported from `thistle`; lower-level pieces
  stay importable from the submodules (`thistle.aes`, `thistle.sha2`, ...).
- Every example on this site was run against the library before publishing.
