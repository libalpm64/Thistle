---
title: Elliptic Curves
nav_order: 5
---

# Elliptic Curves

All scalar multiplication over secret data runs constant-time ladders
(mask-selects, no secret-dependent branches), and the entry points are
validated against the full Wycheproof suites.

## X25519 (key exchange)

```mojo
from thistle import x25519
from thistle import random_bytes

var my_secret = random_bytes(32)
var shared = InlineArray[UInt8, 32](uninitialized=True)
x25519(Span[UInt8, ...](my_secret), their_public_span, shared.unsafe_ptr())
```

Raises if either input is shorter than 32 bytes. Clamping per RFC 7748 is
applied internally. The shared secret should go through a KDF (HKDF-style
HMAC or BLAKE3-derive) before use as a key.

## Ed25519 (signatures)

Strict RFC 8032 verification: canonical point encodings required, `S < L`
enforced, not ZIP-215 compatible.

```mojo
from thistle import ed25519_generate_public_key, ed25519_sign, ed25519_verify

var sk = random_bytes(32)                       # the 32-byte seed
var pk = InlineArray[UInt8, 32](uninitialized=True)
var sig = InlineArray[UInt8, 64](uninitialized=True)

ed25519_generate_public_key(Span[UInt8, ...](sk), pk.unsafe_ptr())
ed25519_sign(Span[UInt8, ...](sk), message, sig.unsafe_ptr())
var ok = ed25519_verify(pk_span, message, sig_span)
```

The private key must be **exactly** 32 bytes; anything else raises. Secret
intermediates (the SHA-512 of the seed, nonces, scalars) are wiped after
use.

## NIST P-256 / P-384 (ECDH)

SEC 1 style APIs over byte buffers. Points are uncompressed `04 || X || Y`
(65 / 97 bytes); compressed `02/03 || X` is accepted on decode. Public keys
are fully validated (on-curve, in-range) before use.

```mojo
from thistle import p256_public_key, p256_ecdh, P256_POINT_SIZE

var d = random_bytes(32)                        # must be in [1, n-1]
var q = InlineArray[UInt8, P256_POINT_SIZE](uninitialized=True)
if not p256_public_key(Span[UInt8, ...](d), q.unsafe_ptr()):
    raise Error("bad private key")

var shared = InlineArray[UInt8, 32](uninitialized=True)
if not p256_ecdh(Span[UInt8, ...](d), their_point_span, shared.unsafe_ptr()):
    raise Error("ECDH failed")                  # invalid point or infinity
```

`p384_public_key` / `p384_ecdh` are identical with 48-byte scalars and
97-byte points. Both return `Bool` — always check it. The output is the raw
x-coordinate; run it through a KDF.
