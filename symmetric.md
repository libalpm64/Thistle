---
title: Symmetric Ciphers
nav_order: 4
---

# Symmetric Ciphers

## ChaCha20

RFC 8439 stream cipher. The struct tracks the block counter for you and
**refuses to wrap it** — encrypting past 256 GiB under one nonce raises
instead of silently reusing keystream.

```mojo
from thistle import ChaCha20

var cipher = ChaCha20(key_bytes, nonce_bytes)   # SIMD[UInt8, 32], SIMD[UInt8, 12]
cipher.encrypt_into(plaintext, ciphertext)      # raises if ciphertext buffer too small
cipher.encrypt_inplace(buffer)                  # encrypt/decrypt in place
```

Decryption is the same operation (`decrypt_into` is an alias). Never reuse a
(key, nonce) pair across messages.

ChaCha20 alone provides no integrity — pair it with an HMAC or use it only
where authentication happens elsewhere.

## AES

Software AES (table-based), AES-NI hardware paths for x86 and ARM, and GPU
kernels for bulk ECB/CTR/GCM. Key expansion and the `AESKey` struct are
exported from `thistle`; the mode implementations live in `thistle.aes`,
`thistle.aes_ni`, and `thistle.aes_gpu`.

```mojo
from thistle import has_aes_ni
from thistle import aes_gpu_kernel_ecb, aes_gpu_kernel_ctr, aes_gpu_kernel_gcm
```

The software fallback's table lookups are not constant-time against
cache-timing observers; prefer the AES-NI path (`has_aes_ni()`) for secret
keys on shared hardware.

## Camellia

RFC 3713 block cipher, 128/192/256-bit keys. The constructor raises on any
other key length.

```mojo
from thistle import CamelliaCipher

var cipher = CamelliaCipher(key)     # 16, 24, or 32 bytes
var ct = cipher.encrypt(block)       # 16-byte block (SIMD or Span)
var pt = cipher.decrypt(ct)
cipher.wipe()                        # volatile-clear the key schedule
```

Like AES software mode, the S-box tables are not cache-timing resistant.

## KCipher-2

ISO/IEC 18033-4 stream cipher, exported as `KCipher2` with a fixed-width
SIMD key/IV constructor. Niche; prefer ChaCha20 unless you specifically need
it.
