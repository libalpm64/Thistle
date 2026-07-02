---
title: Hashing
nav_order: 2
---

# Hashing

All one-shot hash functions take a `Span[UInt8, ...]` and return a
`List[UInt8]` digest.

## SHA-2 / SHA-3

```mojo
from thistle import sha224_hash, sha256_hash, sha384_hash, sha512_hash
from thistle import sha3_224, sha3_256, sha3_384, sha3_512, shake128, shake256

var digest = sha256_hash(data)          # 32 bytes
var wide = sha512_hash(data)            # 64 bytes
var xof = shake256(data, 100)           # arbitrary output length
```

Streaming SHA-2 via contexts:

```mojo
from thistle import SHA256Context
from thistle.sha2 import sha256_update, sha256_final_to_buffer

var ctx = SHA256Context()
sha256_update(ctx, part1)
sha256_update(ctx, part2)
var out = InlineArray[UInt8, 32](uninitialized=True)
sha256_final_to_buffer(ctx, out.unsafe_ptr())
```

`SHA512Context.wipe()` volatile-clears the context if it absorbed secret
input.

## Hardware SHA-256

`sha256ni_hash` uses the SHA extensions on x86 (SHA-NI) and ARMv8 (Apple
Silicon and other ARM crypto-extension CPUs), roughly 4-5x the scalar
throughput. On CPUs without the extension it transparently falls back to the
scalar transform, so it is always correct:

```mojo
from thistle import sha256ni_hash, has_sha_ni

var digest = sha256ni_hash(data)   # same output as sha256_hash, faster
```

## BLAKE2b / BLAKE3

```mojo
from thistle import blake2b_hash, blake2b_hash_keyed, blake3_hash, blake3_parallel_hash

var d = blake2b_hash(data)                 # out_len 1..64, default 64; raises otherwise
var mac = blake2b_hash_keyed(data, key)    # key up to 64 bytes
var b3 = blake3_hash(data)                 # out_len default 32, any length
var big = blake3_parallel_hash(data)       # multi-threaded for large inputs (~10 GB/s)
```

Streaming BLAKE3 uses the `Hasher` struct from `thistle`.
