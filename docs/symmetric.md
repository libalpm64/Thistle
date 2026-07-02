---
title: Encryption
nav_order: 4
---

# Encryption

Symmetric encryption scrambles data with a key; the same key unscrambles
it. Both sides must already share the key — see
[Signatures & Key Exchange](curves) for how two parties get one.

**Which one?** Use **ChaCha20** unless you have a specific reason not to.
It's fast everywhere, and its implementation has no timing side channels.

## Encrypt and decrypt with ChaCha20

The key is 32 bytes, the nonce is 12 bytes. Decryption is literally the same
operation as encryption.

```mojo
from thistle import ChaCha20

def main() raises:
    var key = SIMD[DType.uint8, 32](7)      # use random_bytes(32) in real code!
    var nonce = SIMD[DType.uint8, 12](9)    # unique per message, never reused

    var secret_note = String("meet me at noon").as_bytes()
    var buffer = List[UInt8](capacity=len(secret_note))
    for i in range(len(secret_note)):
        buffer.append(secret_note[i])
    var buffer_span = Span[mut=True, UInt8](buffer)

    var enc = ChaCha20(key, nonce)
    enc.encrypt_inplace(buffer_span)        # buffer is now ciphertext

    var dec = ChaCha20(key, nonce)          # same key + nonce
    dec.encrypt_inplace(buffer_span)        # buffer is plaintext again
```

There's also `encrypt_into(plaintext, ciphertext)` when you want the output
in a separate buffer (it raises if the output buffer is too small).

**The one rule of ChaCha20:** never encrypt two different messages with the
same key *and* the same nonce. Give every message a fresh nonce (a counter
or `random_bytes(12)` both work). Thistle also refuses to encrypt more than
256 GiB under one nonce — it raises rather than repeat itself.

**Encryption alone doesn't detect tampering.** An attacker can flip bits in
the ciphertext without knowing the key. Send an
[HMAC](mac-kdf) of the ciphertext along with it, and check the HMAC before
decrypting.

## Camellia (16-byte block cipher)

An ISO/NESSIE-approved cipher used in some Japanese and European systems.
It encrypts exactly 16 bytes at a time:

```mojo
from thistle import CamelliaCipher, random_bytes

def main() raises:
    var key = random_bytes(16)              # 16, 24, or 32 bytes; anything else raises
    var cipher = CamelliaCipher(Span[UInt8, ...](key))

    var block = SIMD[DType.uint8, 16](42)
    var encrypted = cipher.encrypt(block)
    var decrypted = cipher.decrypt(encrypted)   # == block

    cipher.wipe()                           # erase the key schedule when done
```

## AES

Thistle ships three AES tiers: hardware AES-NI (x86 and ARM), GPU kernels
for bulk data (`aes_gpu_kernel_ecb/ctr/gcm`), and a software fallback. Check
`has_aes_ni()` and prefer hardware — the software table implementation can
leak key information through CPU cache timing on shared machines. The mode
implementations live in `thistle.aes`, `thistle.aes_ni`, and
`thistle.aes_gpu`.

## KCipher-2

A stream cipher standardized in Japan (ISO/IEC 18033-4), exported as
`KCipher2`. Unless a spec requires it, use ChaCha20.
