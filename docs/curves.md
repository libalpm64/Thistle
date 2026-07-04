---
title: Curves
nav_order: 5
---

# Curves

Default: **X25519** (exchange), **Ed25519** (signatures). Constant-time
scalar mult (mask-select ladder, no secret-dependent branches). Use
P-256/P-384 only where NIST curves are mandated.

## `thistle.x25519`

```mojo
def x25519(scalar_in: Span[UInt8, ...], point: Span[UInt8, ...],
           output: UnsafePointer[UInt8, MutAnyOrigin]) raises
```

RFC 7748 clamping applied internally. Basepoint is `9` followed by 31
zero bytes.

```mojo
var shared = InlineArray[UInt8, 32](uninitialized=True)
x25519(my_secret_span, their_public_span, shared.unsafe_ptr())
```

- Gotcha: raises if either input span is shorter than 32 bytes.
- Gotcha: hash the shared secret before using it as a key
  (`sha256_hash(shared)`), don't use it raw.

## `thistle.ed25519_generate_public_key` / `ed25519_sign` / `ed25519_verify`

```mojo
def ed25519_generate_public_key(private_key: Span[UInt8, ...], output: UnsafePointer[UInt8, MutAnyOrigin]) raises
def ed25519_sign(private_key: Span[UInt8, ...], message: Span[UInt8, ...], output: UnsafePointer[UInt8, MutAnyOrigin]) raises
def ed25519_verify(public_key: Span[UInt8, ...], message: Span[UInt8, ...], signature: Span[UInt8, ...]) -> Bool
```

```mojo
ed25519_generate_public_key(sk_span, pk.unsafe_ptr())
ed25519_sign(sk_span, msg, sig.unsafe_ptr())
var ok = ed25519_verify(pk_span, msg, sig_span)
```

- Gotcha: `private_key` must be exactly 32 bytes, or it raises (not `>=`).
- Gotcha: strict RFC 8032 verify — non-canonical `A`/`R`, `S >= L`, or
  small-order components are rejected. Not ZIP-215 compatible.

## `thistle.p256_public_key` / `p256_ecdh` (also `p384_*`)

```mojo
def p256_public_key(private_key: Span[UInt8, ...], output: UnsafePointer[UInt8, MutAnyOrigin]) -> Bool
def p256_ecdh(private_key: Span[UInt8, ...], public_key: Span[UInt8, ...], output: UnsafePointer[UInt8, MutAnyOrigin]) -> Bool
```

Points are uncompressed `04 || X || Y` — `P256_POINT_SIZE` (65) /
`P384_POINT_SIZE` (97) bytes. Compressed `02/03 || X` accepted on decode.

```mojo
var pub = InlineArray[UInt8, P256_POINT_SIZE](uninitialized=True)
if not p256_public_key(sk_span, pub.unsafe_ptr()):
    raise Error("bad private key")

var shared = InlineArray[UInt8, 32](uninitialized=True)
if not p256_ecdh(sk_span, their_point_span, shared.unsafe_ptr()):
    raise Error("invalid peer point")
```

- Gotcha: these return `Bool`, they do not raise. Check the result —
  `False` means invalid key/point/infinity, silently ignoring it is a bug.
- `p384_public_key` / `p384_ecdh`: identical shape, 48-byte scalars.
