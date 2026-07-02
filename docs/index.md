---
title: Home
nav_order: 1
---

# Thistle

Thistle is a high-performance cryptography library written in pure Mojo. No
Python interop on any hot path, hardware acceleration where the CPU offers it
(SHA extensions on x86 and ARM, AES-NI, GPU AES kernels), and constant-time
implementations for the secret-handling primitives.

> Thistle is an experimental library. It has extensive test coverage
> (Wycheproof, NIST CAVP/ACVP vectors, RFC test vectors — 20,000+ vectors in
> CI) but has not been independently audited.

## Install

Thistle uses [pixi](https://pixi.sh) and the Mojo nightly toolchain:

```sh
git clone https://github.com/libalpm64/Thistle
cd Thistle
pixi run test        # run the full vector suite
```

To use it from your own project, add `-I path/to/Thistle/src` to your `mojo`
invocation and import from `thistle`.

## Quick start

```mojo
from thistle import (
    sha256_hash, blake3_hash,
    ed25519_generate_public_key, ed25519_sign, ed25519_verify,
    mlkem768_keygen, mlkem768_encaps, mlkem768_decaps,
    random_bytes,
)

def main() raises:
    var msg = random_bytes(64)
    var digest = sha256_hash(Span[UInt8, ...](msg))

    # Ed25519 sign / verify
    var sk = random_bytes(32)
    var pk = InlineArray[UInt8, 32](uninitialized=True)
    var sig = InlineArray[UInt8, 64](uninitialized=True)
    ed25519_generate_public_key(Span[UInt8, ...](sk), pk.unsafe_ptr())
    ed25519_sign(Span[UInt8, ...](sk), Span[UInt8, ...](msg), sig.unsafe_ptr())
    var ok = ed25519_verify(
        Span[UInt8, ...](ptr=pk.unsafe_ptr(), length=32),
        Span[UInt8, ...](msg),
        Span[UInt8, ...](ptr=sig.unsafe_ptr(), length=64),
    )

    # Post-quantum KEM
    var keys = mlkem768_keygen()                          # (public, secret)
    var enc = mlkem768_encaps(Span[UInt8, ...](keys[0]))  # (ct, shared, ok)
    var dec = mlkem768_decaps(Span[UInt8, ...](keys[1]), Span[UInt8, ...](enc[0]))
```

## Design rules

- **Errors raise.** Wrong key sizes, invalid parameters, counter exhaustion —
  everything raises `Error` instead of silently continuing.
- **One import.** Everything documented here is exported from `thistle`.
  Low-level building blocks stay importable from the submodules
  (`thistle.aes`, `thistle.curve25519`, ...).
- **Secrets get wiped.** Key schedules, hash contexts that absorbed secrets,
  and signing scratch are zeroized with volatile stores.
