---
title: Signatures & Key Exchange
nav_order: 5
---

# Signatures & Key Exchange

Public-key cryptography solves two problems symmetric keys can't:

- **Signatures** — prove a message came from you. You sign with a private
  key only you hold; anyone can verify with your public key.
- **Key exchange** — two people who have never met agree on a shared secret
  key over a public channel. That key then feeds [encryption](symmetric).

**Which one?** Ed25519 for signatures, X25519 for key exchange. P-256/P-384
exist for systems that require NIST curves (many government and enterprise
standards do).

## Sign a message (Ed25519)

Your private key is just 32 random bytes. Everything else derives from it.

```mojo
from thistle import ed25519_generate_public_key, ed25519_sign, ed25519_verify
from thistle import random_bytes

def main() raises:
    var message = String("abc").as_bytes()

    # you do this once and keep signing_key safe
    var signing_key = random_bytes(32)
    var verify_key = InlineArray[UInt8, 32](uninitialized=True)
    ed25519_generate_public_key(Span[UInt8, ...](signing_key), verify_key.unsafe_ptr())

    # sign
    var signature = InlineArray[UInt8, 64](uninitialized=True)
    ed25519_sign(Span[UInt8, ...](signing_key), message, signature.unsafe_ptr())

    # anyone with verify_key can check it
    var ok = ed25519_verify(
        Span[UInt8, ...](ptr=verify_key.unsafe_ptr(), length=32),
        message,
        Span[UInt8, ...](ptr=signature.unsafe_ptr(), length=64),
    )
    # ok == True; flip any byte of message or signature and it's False
```

The key must be exactly 32 bytes — anything else raises. Verification is
strict (RFC 8032): malformed or non-canonical signatures are rejected, and
a signature can't be tweaked into a second "different" valid signature.

## Agree on a secret key (X25519)

Alice and Bob each make a key pair, swap public keys in the open, and both
arrive at the same 32-byte secret. An eavesdropper who saw both public keys
cannot compute it.

```mojo
from thistle import x25519, random_bytes

def main() raises:
    # the standard starting point ("base point"): 9 followed by zeros
    var basepoint = InlineArray[UInt8, 32](fill=0)
    basepoint[0] = 9
    var base = Span[UInt8, ...](ptr=basepoint.unsafe_ptr(), length=32)

    # each side: secret key + public key
    var alice_secret = random_bytes(32)
    var alice_public = InlineArray[UInt8, 32](uninitialized=True)
    x25519(Span[UInt8, ...](alice_secret), base, alice_public.unsafe_ptr())

    var bob_secret = random_bytes(32)
    var bob_public = InlineArray[UInt8, 32](uninitialized=True)
    x25519(Span[UInt8, ...](bob_secret), base, bob_public.unsafe_ptr())

    # they swap publics, then each computes the shared secret
    var alice_shared = InlineArray[UInt8, 32](uninitialized=True)
    x25519(Span[UInt8, ...](alice_secret),
           Span[UInt8, ...](ptr=bob_public.unsafe_ptr(), length=32),
           alice_shared.unsafe_ptr())

    var bob_shared = InlineArray[UInt8, 32](uninitialized=True)
    x25519(Span[UInt8, ...](bob_secret),
           Span[UInt8, ...](ptr=alice_public.unsafe_ptr(), length=32),
           bob_shared.unsafe_ptr())

    # alice_shared == bob_shared
```

Don't use the shared bytes directly as an encryption key — hash them first
(`sha256_hash` or `hmac_sha256` with a label). That's standard practice and
costs one line.

## NIST curves (P-256 / P-384)

Same key-exchange idea, different curves, byte-oriented API. Public keys
are 65-byte (P-256) or 97-byte (P-384) "points". These functions return
`True`/`False` instead of raising — **always check the result**, because
`False` means the other side's key was invalid.

```mojo
from thistle import p256_public_key, p256_ecdh, P256_POINT_SIZE
from thistle import random_bytes

def main() raises:
    var my_secret = random_bytes(32)
    var my_public = InlineArray[UInt8, P256_POINT_SIZE](uninitialized=True)
    if not p256_public_key(Span[UInt8, ...](my_secret), my_public.unsafe_ptr()):
        raise Error("bad private key, generate a new one")

    # after swapping publics:
    var shared = InlineArray[UInt8, 32](uninitialized=True)
    if not p256_ecdh(Span[UInt8, ...](my_secret), their_public, shared.unsafe_ptr()):
        raise Error("their public key was invalid")
```

`p384_public_key` / `p384_ecdh` work identically with 48-byte secrets.
Incoming public keys are fully validated (on the curve, in range) before
any secret math touches them.
