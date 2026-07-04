---
title: Hashing
nav_order: 2
---

# Hashing

Default: **BLAKE3** (`blake3_hash`). Use SHA-256 for interop, `sha256ni_hash`
if you want it hardware-accelerated (immune to cache timing — no table
lookups, register-only).

## `thistle.sha256_hash`

```mojo
def sha256_hash(data: Span[UInt8, ...]) -> List[UInt8]
```

```mojo
var d = sha256_hash(String("abc").as_bytes())
# hex(d) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
```

## `thistle.sha256ni_hash`

```mojo
def sha256ni_hash(data: Span[UInt8, ...]) -> List[UInt8]
```

Same output as `sha256_hash`. Dispatches to SHA-NI / ARMv8 crypto ext at
compile time; falls back to scalar transform if neither is present.

- Gotcha: none — output is always correct, this is a pure perf switch.

## `thistle.sha3_256` / `sha3_512`

```mojo
def sha3_256(data: Span[UInt8, ...]) -> List[UInt8]
def sha3_512(data: Span[UInt8, ...]) -> List[UInt8]
```

```mojo
var d = sha3_256(data)
# hex(d) == "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532" for "abc"
```

## `thistle.shake128` / `shake256`

```mojo
def shake256(data: Span[UInt8, ...], output_len_bytes: Int) -> List[UInt8]
```

```mojo
var out = shake256(data, 100)   # arbitrary output length
```

## `thistle.blake3_hash` / `blake3_parallel_hash`

```mojo
def blake3_hash(input: Span[UInt8, ...], out_len: Int = 32) -> List[UInt8]
def blake3_parallel_hash(input: Span[UInt8, ...], out_len: Int = 32) -> List[UInt8]
```

```mojo
var d = blake3_hash(data)
# hex(d) == "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85" for "abc"

var d2 = blake3_parallel_hash(large_data)   # ~10 GB/s, multi-threaded, same output as blake3_hash
```

## `thistle.blake2b_hash` / `blake2b_hash_keyed`

```mojo
def blake2b_hash(data: Span[UInt8, ...], out_len: Int = 64) raises -> List[UInt8]
def blake2b_hash_keyed(data: Span[UInt8, ...], key: Span[UInt8, ...], out_len: Int = 64) raises -> List[UInt8]
```

```mojo
var d = blake2b_hash(data, out_len=32)
var mac = blake2b_hash_keyed(data, key)
```

- Gotcha: raises if `out_len` not in `1..64`, or `key` longer than 64 bytes.

## Streaming SHA-256

```mojo
from thistle import SHA256Context
from thistle.sha2 import sha256_update, sha256_final_to_buffer

var ctx = SHA256Context()
sha256_update(ctx, chunk1)
sha256_update(ctx, chunk2)
var out = InlineArray[UInt8, 32](uninitialized=True)
sha256_final_to_buffer(ctx, out.unsafe_ptr())
```

- `SHA256Context`/`SHA512Context` have `.wipe()` — call it if the context
  absorbed secret input.
