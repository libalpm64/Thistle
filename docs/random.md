---
title: Random
nav_order: 7
---

# Random

## `thistle.random_bytes` / `random_fill`

```mojo
def random_bytes(n: Int) raises -> List[UInt8]
def random_fill(buf: UnsafePointer[UInt8, MutAnyOrigin], length: Int) raises
```

```mojo
var key = random_bytes(32)
random_fill(existing_buf.unsafe_ptr(), 64)
```

Direct syscalls: `getrandom(2)` (Linux, EINTR-retried), `getentropy(2)`
(macOS, chunked at 256 bytes). No `/dev/urandom` fd. Platforms without a
secure source fail to compile — no weak fallback path exists.

- Gotcha: raises on kernel failure — always in a `raises` context.
- Gotcha: this is not a PRNG. For bulk non-secret randomness where
  throughput/reproducibility matters (sims, fuzzing, shuffling), use
  `std.random` instead — this module is syscall-bound and orders of
  magnitude slower for that use case.
