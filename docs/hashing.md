---
title: Hashing
nav_order: 2
---

# Hashing

A hash turns any amount of data into a short, fixed-size fingerprint. The
same input always gives the same fingerprint, and no two different inputs
should ever share one. Use it to check files for corruption, deduplicate
data, or build integrity checks.

**Which one?**
**BLAKE3** Incredibly fast parallel hashing algorithim.
**SHA-256** when you need compatibility with older systems.

## Hash a string

```mojo
from thistle import sha256_hash, sha3_256, blake3_hash, blake2b_hash

def main() raises:
    var message = String("abc").as_bytes()

    var a = sha256_hash(message)    # 32 bytes
    var b = sha3_256(message)       # 32 bytes
    var c = blake3_hash(message)    # 32 bytes
    var d = blake2b_hash(message)   # 64 bytes
```

For `"abc"` these produce (in hex):

| Function | Result |
|---|---|
| `sha256_hash` | `ba7816bf8f01cfea...b410ff61f20015ad` |
| `sha3_256` | `3a985da74fe225b2...5b46bfe24511431532` |
| `blake3_hash` | `6437b3ac38465133...fd359c6cd5bd9d85` |

If your output matches these, everything is working.

## Hash a large file fast

`blake3_parallel_hash` splits the work across CPU cores — around 10 GB/s on
a modern laptop:

```mojo
from thistle import blake3_parallel_hash

var digest = blake3_parallel_hash(big_data)   # same result as blake3_hash
```

`sha256ni_hash` compiles to the dedicated SHA instructions — `sha256rnds2`
/ `sha256msg1/2` on x86 (SHA-NI), `sha256h/h2/su0/su1` on ARMv8 (Apple
Silicon and other CPUs with the crypto extension) — via LLVM intrinsics,
selected at compile time. Roughly 4-5x scalar throughput, byte-identical
output, and a scalar fallback on CPUs without the extension:

```mojo
from thistle import sha256ni_hash

var digest = sha256ni_hash(data)
```

## Hash data that arrives in pieces

If you can't hold everything in memory at once, feed it in chunks:

```mojo
from thistle import SHA256Context
from thistle.sha2 import sha256_update, sha256_final_to_buffer

var ctx = SHA256Context()
sha256_update(ctx, chunk1)
sha256_update(ctx, chunk2)
var digest = InlineArray[UInt8, 32](uninitialized=True)
sha256_final_to_buffer(ctx, digest.unsafe_ptr())
```

## Variable-length output

SHAKE lets you ask for as many output bytes as you want:

```mojo
from thistle import shake256

var out = shake256(data, 100)   # any length you like
```

## Common mistakes

- **Don't hash passwords with these.** Plain hashes are fast — which means
  attackers can guess billions of passwords per second. Use
  [Argon2id](mac-kdf) instead.
- **A hash is not a signature.** Anyone can compute a hash of tampered data.
  If you need to prove *who* produced data, you want an
  [HMAC](mac-kdf) or a [signature](curves).
