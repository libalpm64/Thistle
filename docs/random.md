---
title: Random Numbers
nav_order: 7
---

# Random Numbers

`thistle.random` is the CSPRNG interface: it pulls entropy straight from
the kernel, which fuses hardware sources (RDRAND/RNDR), interrupt timing,
and other OS-collected input.

```mojo
from thistle import random_bytes, random_fill

def main() raises:
    var key = random_bytes(32)
    var nonce = random_bytes(12)

    # or fill a buffer you already own
    random_fill(buf.unsafe_ptr(), 64)
```

Implementation details that matter:

- Raw syscalls — `getrandom(2)` on Linux, `getentropy(2)` on macOS. No
  `/dev/urandom` file descriptor to exhaust, race, or have redirected in a
  sandbox.
- Failures raise; short reads are retried; platforms without a secure
  source fail at **compile time** rather than falling back to something
  weak.

**When to use what:** for keys, nonces, salts, and anything an attacker
must not predict, use this module. For bulk non-secret randomness where
throughput matters (simulations, fuzzing, shuffling), use a PRNG like
`std.random` — it's orders of magnitude faster and reproducibility is a
feature there, not a bug.
