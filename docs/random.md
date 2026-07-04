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

Uses direct syscalls. `getrandom(2)` on Linux with EINTR retry. `getentropy(2)` on macOS chunked at 256 bytes. No `/dev/urandom` fd. Platforms without a secure source fail to compile. There is no weak fallback path.

- Note: raises on kernel failure. Always call it in a `raises` context.
- Note: this is not a PRNG. For bulk non-secret randomness where throughput or reproducibility matters use `std.random` instead. This module is syscall-bound and much slower for that use case.
