---
title: Home
nav_order: 1
---

# Thistle

Thistle is a cryptography library written in pure Mojo. It gives you the
building blocks every application eventually needs — hashing data, checking
passwords, encrypting files, signing messages, agreeing on keys — without
calling out to Python or C.

It has been tested continuously for over four months against more than
20,000 official test vectors (NIST, Wycheproof, RFC), and uses hardware
acceleration (SHA extensions, AES-NI, GPU kernels) wherever your CPU offers
it.

## Install

```sh
git clone https://github.com/libalpm64/Thistle
cd Thistle
pixi run test        # run the full test suite yourself
```

To use it in your own project, add `-I path/to/Thistle/src` to your `mojo`
command and import from `thistle`.

## Your first hash

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

## Three things to know

1. **Mistakes raise errors.** Wrong key size, bad parameters, using a cipher
   past its limits — Thistle raises an `Error` instead of silently producing
   something broken.
2. **One import.** Everything on these pages comes from `from thistle import ...`.
3. **Every example on this site is real.** Each one was run against the
   library before being published.
