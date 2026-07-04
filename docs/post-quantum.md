---
title: Post-Quantum
nav_order: 6
---

# Post-Quantum

FIPS 203 (ML-KEM) / FIPS 204 (ML-DSA). Default parameter set: **768** /
**65**.

## `thistle.mlkem768_keygen` / `mlkem768_encaps` / `mlkem768_decaps`

```mojo
def mlkem768_keygen() raises -> Tuple[List[UInt8], List[UInt8]]                                   # (ek, dk)
def mlkem768_encaps(ek_bytes: Span[UInt8, ...]) raises -> Tuple[List[UInt8], List[UInt8], Bool]   # (ct, ss, ok)
def mlkem768_decaps(dk_bytes: Span[UInt8, ...], ciphertext: Span[UInt8, ...]) raises -> Tuple[List[UInt8], Bool]  # (ss, ok)
```

```mojo
var keys = mlkem768_keygen()
var enc = mlkem768_encaps(keys[0])
var dec = mlkem768_decaps(keys[1], enc[0])
# enc[1] == dec[0] when enc[2] and dec[1] are True
```

- Gotcha: check `ok`. An invalid ciphertext does not raise or return a
  distinguishable failure — decapsulation returns a pseudorandom secret
  (FIPS 203 implicit rejection). Don't branch protocol behavior on
  "decaps failed"; there's no such signal.
- 512/1024 variants: `mlkem512_*`, `mlkem1024_*`, identical shape.

## `thistle.mldsa65_keygen` / `mldsa_sign_hedged` / `mldsa_verify`

```mojo
def mldsa65_keygen() raises -> MLDSAPrivateKey
def mldsa_sign_hedged(priv: MLDSAPrivateKey, msg: Span[UInt8, ...], context: Span[UInt8, ...]) raises -> List[UInt8]
def mldsa_verify(pub: MLDSAPublicKey, msg: Span[UInt8, ...], sig: Span[UInt8, ...], context: Span[UInt8, ...]) raises -> Bool
```

```mojo
var priv = mldsa65_keygen()
var ctx = Span[UInt8, ...](ptr=p, length=0)   # empty context if unused
var sig = mldsa_sign_hedged(priv, msg, ctx)
var ok = mldsa_verify(priv.pub, msg, sig, ctx)
```

- Gotcha: `context` max 255 bytes; sign and verify must use the same one.
- `mldsa_sign_deterministic`: same signature every call for the same
  message — only for environments without an RNG.
- Load a public key from bytes: `mldsa65_public_key(pk_bytes)`.
- Sizes: `MLDSA65_PUBLICKEYBYTES`, `MLDSA65_SECRETKEYBYTES`, `MLDSA65_BYTES`
  (signature size). 44/87 variants follow the same naming.
