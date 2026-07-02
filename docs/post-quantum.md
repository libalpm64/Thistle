---
title: Post-Quantum
nav_order: 6
---

# Post-Quantum

FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA), validated against the NIST ACVP
vector sets.

## ML-KEM (key encapsulation)

Three parameter sets: 512, 768 (recommended), 1024. All keys, ciphertexts,
and shared secrets are plain `List[UInt8]`.

```mojo
from thistle import mlkem768_keygen, mlkem768_encaps, mlkem768_decaps
from thistle import MLKEM768_PUBLICKEYBYTES, MLKEM_BYTES

# receiver
var keys = mlkem768_keygen()                  # (encaps_key, decaps_key)

# sender
var enc = mlkem768_encaps(Span[UInt8, ...](keys[0]))
# enc = (ciphertext, shared_secret, ok)

# receiver
var dec = mlkem768_decaps(Span[UInt8, ...](keys[1]), Span[UInt8, ...](enc[0]))
# dec = (shared_secret, ok)
```

Always check the `ok` flags. Decapsulation of an invalid ciphertext performs
FIPS 203 implicit rejection in constant time — it returns a
pseudorandom secret rather than an error, so protocols never learn *why* a
handshake failed.

For hybrid deployments, combine an ML-KEM shared secret with an X25519
shared secret through a KDF.

## ML-DSA (signatures)

Parameter sets 44, 65 (recommended), 87.

```mojo
from thistle import mldsa65_keygen, mldsa_sign_hedged, mldsa_verify

var priv = mldsa65_keygen()
var context = Span[UInt8, ...](ptr=..., length=0)   # optional domain separator, <= 255 bytes

var sig = mldsa_sign_hedged(priv, message, context)  # FIPS 204 default (randomized)
var ok = mldsa_verify(priv.pub, message, Span[UInt8, ...](sig), context)
```

- `mldsa_sign_hedged` — the FIPS 204 default; mixes fresh randomness into
  each signature. Use this unless you have a reason not to.
- `mldsa_sign_deterministic` — reproducible signatures (rnd = 0). Only for
  environments without an RNG.
- `mldsa_sign(priv, msg, context, random)` — bring your own 32 bytes of
  randomness.

Public keys can be loaded from encoded bytes with
`mldsa44_public_key` / `mldsa65_public_key` / `mldsa87_public_key`.
Encoded sizes are exported as `MLDSA*_PUBLICKEYBYTES` / `_SECRETKEYBYTES` /
`_BYTES` (signature size).
