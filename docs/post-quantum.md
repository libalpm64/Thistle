---
title: Post-Quantum
nav_order: 6
---

# Post-Quantum

A large quantum computer would break the [curve-based](curves) algorithms.
Nobody has one yet, but data recorded today can be decrypted later —
so anything that must stay secret for decades should start using
quantum-resistant algorithms now. These are the two NIST picked as
standards in 2024.

**Which sizes?** `768` for ML-KEM and `65` for ML-DSA are the recommended
middle settings. The smaller ones trade safety margin for speed, the bigger
ones the reverse.

## Quantum-safe key exchange (ML-KEM)

Works like a locked mailbox rather than a handshake: the receiver publishes
a public key, the sender uses it to produce a ciphertext plus a shared
secret, and only the receiver can open the ciphertext to get the same
secret.

```mojo
from thistle import mlkem768_keygen, mlkem768_encaps, mlkem768_decaps

def main() raises:
    # receiver: make a key pair, publish public_key
    var keys = mlkem768_keygen()
    var public_key = keys[0]
    var secret_key = keys[1]

    # sender: lock a fresh secret to the public key
    var enc = mlkem768_encaps(Span[UInt8, ...](public_key))
    var ciphertext = enc[0]      # send this to the receiver
    var sender_secret = enc[1]   # keep this — it's your shared key
    # enc[2] is True on success

    # receiver: unlock
    var dec = mlkem768_decaps(Span[UInt8, ...](secret_key), Span[UInt8, ...](ciphertext))
    var receiver_secret = dec[0]
    # dec[1] is True on success; sender_secret == receiver_secret
```

Check the success flags. A corrupted ciphertext doesn't produce an error —
by design it decapsulates to a *different* random-looking secret, so
attackers can't probe why handshakes fail.

Belt and suspenders: many deployments run X25519 **and** ML-KEM and hash the
two secrets together, so both would have to fall.

## Quantum-safe signatures (ML-DSA)

Same sign/verify shape as Ed25519, bigger keys and signatures (an ML-DSA-65
signature is ~3.3 KB versus Ed25519's 64 bytes).

```mojo
from thistle import mldsa65_keygen, mldsa_sign_hedged, mldsa_verify

def main() raises:
    var message = String("abc").as_bytes()
    var empty = Span[UInt8, ...](ptr=message.unsafe_ptr(), length=0)

    var private_key = mldsa65_keygen()

    var signature = mldsa_sign_hedged(private_key, message, empty)
    var ok = mldsa_verify(private_key.pub, message, Span[UInt8, ...](signature), empty)
```

The third argument is an optional "context" — a label (up to 255 bytes)
that binds signatures to a purpose, so a signature made for one system
can't be replayed in another. Pass an empty span if you don't need it, but
sign and verify must use the same one.

- `mldsa_sign_hedged` — the default. Use this.
- `mldsa_sign_deterministic` — same signature every time for the same
  message; only for devices without a random number generator.

Key and signature sizes are exported as constants
(`MLDSA65_PUBLICKEYBYTES`, `MLDSA65_BYTES`, ...), and encoded public keys
load with `mldsa65_public_key(bytes)`.
