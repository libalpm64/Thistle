---
title: Symmetric
nav_order: 4
---

# Symmetric

Default: **ChaCha20**. ARX (add/rotate/xor) — no lookup tables, immune to
cache-timing by construction, and faster than software AES on CPU. Use AES
only where a spec requires it, and prefer `has_aes_ni()` when you do (the
software S-box path is table-based, not cache-timing safe).

## `thistle.ChaCha20`

```mojo
def __init__(out self, key_bytes: SIMD[DType.uint8, 32],
             nonce_bytes: SIMD[DType.uint8, 12], counter: UInt32 = 1)

def encrypt_inplace[origin: Origin[mut=True]](mut self, mut data: Span[mut=True, UInt8, origin]) raises
def encrypt_into[origin: Origin[mut=True]](mut self, plaintext: Span[UInt8, ...], mut ciphertext: Span[mut=True, UInt8, origin]) raises
def decrypt_into[origin: Origin[mut=True]](mut self, ciphertext: Span[UInt8, ...], mut plaintext: Span[mut=True, UInt8, origin]) raises
```

```mojo
var enc = ChaCha20(key, nonce)
enc.encrypt_inplace(buffer_span)   # buffer_span is Span[mut=True, UInt8]

var dec = ChaCha20(key, nonce)     # same key + nonce
dec.encrypt_inplace(buffer_span)   # decrypt == encrypt
```

- Gotcha: never reuse a (key, nonce) pair across two different plaintexts.
- Gotcha: raises past ~256 GiB encrypted under one nonce (counter wrap
  guard) instead of reusing keystream.
- Gotcha: `encrypt_into` raises if `ciphertext` is shorter than `plaintext`.
- Gotcha: no authentication. Pair with `hmac_sha256` over the ciphertext if
  you need tamper detection.

## `thistle.CamelliaCipher`

```mojo
def __init__(out self, key: Span[UInt8, ...]) raises   # 16, 24, or 32 bytes
def encrypt(self, block: SIMD[DType.uint8, 16]) -> SIMD[DType.uint8, 16]
def decrypt(self, block: SIMD[DType.uint8, 16]) -> SIMD[DType.uint8, 16]
def wipe(mut self)
```

`Span[UInt8, ...]` overloads of `encrypt`/`decrypt` also exist (raise if
not exactly 16 bytes).

```mojo
var cipher = CamelliaCipher(key)
var ct = cipher.encrypt(block)
var pt = cipher.decrypt(ct)
cipher.wipe()
```

- Gotcha: constructor raises on any key length other than 16/24/32.
- Gotcha: S-box lookups are table-based, not cache-timing constant-time.

## AES

`thistle.aes` — software (table-based, not cache-timing safe).
`thistle.aes_ni` — hardware, x86 + ARM; check `has_aes_ni()`.
`thistle.aes_gpu` — `aes_gpu_kernel_ecb/ctr/gcm` for bulk data.

## `thistle.KCipher2`

ISO/IEC 18033-4 stream cipher. Fixed-width SIMD key/IV constructor. No
reason to use it unless a spec requires it.
