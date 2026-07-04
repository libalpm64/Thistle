---
title: Symmetric
nav_order: 4
---

# Symmetric

Default: **ChaCha20**. It's ARX (add/rotate/xor) with no lookup tables so it's immune to cache-timing by construction. It's also faster than software AES on CPU. Use AES only where a spec requires it. Prefer `has_aes_ni()` when you do since the software S-box path is table-based and not cache-timing safe.

## `thistle.ChaCha20`

```python
def __init__(out self, key_bytes: SIMD[DType.uint8, 32],
             nonce_bytes: SIMD[DType.uint8, 12], counter: UInt32 = 1)

def encrypt_inplace[origin: Origin[mut=True]](mut self, mut data: Span[mut=True, UInt8, origin]) raises
def encrypt_into[origin: Origin[mut=True]](mut self, plaintext: Span[UInt8, ...], mut ciphertext: Span[mut=True, UInt8, origin]) raises
def decrypt_into[origin: Origin[mut=True]](mut self, ciphertext: Span[UInt8, ...], mut plaintext: Span[mut=True, UInt8, origin]) raises
```

```python
var enc = ChaCha20(key, nonce)
enc.encrypt_inplace(buffer_span)   # buffer_span is Span[mut=True, UInt8]

var dec = ChaCha20(key, nonce)     # same key + nonce
dec.encrypt_inplace(buffer_span)   # decrypt == encrypt
```

- Note: never reuse a (key, nonce) pair across two different plaintexts.
- Note: raises past ~256 GiB encrypted under one nonce instead of reusing keystream.
- Note: `encrypt_into` raises if `ciphertext` is shorter than `plaintext`.
- Note: no authentication. Pair with `hmac_sha256` over the ciphertext for tamper detection.

## `thistle.CamelliaCipher`

```python
def __init__(out self, key: Span[UInt8, ...]) raises   # 16, 24, or 32 bytes
def encrypt(self, block: SIMD[DType.uint8, 16]) -> SIMD[DType.uint8, 16]
def decrypt(self, block: SIMD[DType.uint8, 16]) -> SIMD[DType.uint8, 16]
def wipe(mut self)
```

`Span[UInt8, ...]` overloads of `encrypt`/`decrypt` also exist (raise if
not exactly 16 bytes).

```python
var cipher = CamelliaCipher(key)
var ct = cipher.encrypt(block)
var pt = cipher.decrypt(ct)
cipher.wipe()
```

- Note: constructor raises on any key length other than 16/24/32.
- Note: S-box lookups are table-based. Not cache-timing constant-time.

## AES

`thistle.aes` is software. Table-based and not cache-timing safe.
`thistle.aes_ni` is hardware for x86 and ARM. Check `has_aes_ni()` first.
`thistle.aes_gpu` has `aes_gpu_kernel_ecb/ctr/gcm` for bulk data.

## `thistle.KCipher2`

ISO/IEC 18033-4 stream cipher. Fixed-width SIMD key/IV constructor. No
reason to use it unless a spec requires it.
