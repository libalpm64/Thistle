---
title: Randomness
nav_order: 7
---

# Randomness

`thistle.random` goes straight to the kernel CSPRNG with raw syscalls — no
userspace RNG state to seed, leak, or fork-corrupt.

```mojo
from thistle import random_bytes, random_fill

var key = random_bytes(32)          # List[UInt8]
random_fill(buf_ptr, length)        # fill caller-owned memory
```

- Linux x86-64 / aarch64: `getrandom(2)`, with EINTR retry
- macOS arm64: `getentropy(2)`, chunked at its 256-byte limit
- Anything else: **compile error**, never a weak fallback

Both functions raise if the kernel reports failure. There is no way to get
non-cryptographic randomness from this module — use `std.random` for
simulations.
