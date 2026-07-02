---
title: Random Numbers
nav_order: 7
---

# Random Numbers

Every key on this site starts as random bytes. Cryptographic randomness has
to come from the operating system's secure generator — not from timestamps,
not from `rand()`.

```mojo
from thistle import random_bytes, random_fill

def main() raises:
    var key = random_bytes(32)      # a fresh 32-byte key
    var nonce = random_bytes(12)    # a fresh nonce

    # or fill a buffer you already own
    random_fill(buf.unsafe_ptr(), 64)
```

That's the whole API. Under the hood it calls the kernel directly
(`getrandom` on Linux, `getentropy` on macOS) and raises if the kernel
reports a failure. On platforms without a secure source, the code refuses
to compile rather than substitute something weak.

If you need reproducible "randomness" for simulations or tests, that's a
different tool — use `std.random`, never this module, and never the other
way around.
