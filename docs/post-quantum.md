---
title: Post-Quantum
nav_order: 6
---

# Post-Quantum

FIPS 203 for ML-KEM and FIPS 204 for ML-DSA. Default parameter set is **768** for ML-KEM and **65** for ML-DSA.

## `thistle.mlkem768_keygen` / `mlkem768_encaps` / `mlkem768_decaps`

```python
def mlkem768_keygen() raises -> Tuple[List[UInt8], List[UInt8]]                                   # (ek, dk)
def mlkem768_encaps(ek_bytes: Span[UInt8, ...]) raises -> Tuple[List[UInt8], List[UInt8], Bool]   # (ct, ss, ok)
def mlkem768_decaps(dk_bytes: Span[UInt8, ...], ciphertext: Span[UInt8, ...]) raises -> Tuple[List[UInt8], Bool]  # (ss, ok)
```

```python
var keys = mlkem768_keygen()
var enc = mlkem768_encaps(keys[0])
var dec = mlkem768_decaps(keys[1], enc[0])
# enc[1] == dec[0] when enc[2] and dec[1] are True
```

- Note: check `ok`. An invalid ciphertext does not raise. Decapsulation returns a pseudorandom secret instead (FIPS 203 implicit rejection). Don't branch protocol behavior on "decaps failed" since there's no such signal.
- 512/1024 variants are `mlkem512_*` and `mlkem1024_*` with an identical shape.

## `thistle.mldsa65_keygen` / `mldsa_sign_hedged` / `mldsa_verify`

```python
def mldsa65_keygen() raises -> MLDSAPrivateKey
def mldsa_sign_hedged(priv: MLDSAPrivateKey, msg: Span[UInt8, ...], context: Span[UInt8, ...]) raises -> List[UInt8]
def mldsa_verify(pub: MLDSAPublicKey, msg: Span[UInt8, ...], sig: Span[UInt8, ...], context: Span[UInt8, ...]) raises -> Bool
```

```python
var priv = mldsa65_keygen()
var ctx = Span[UInt8, ...](ptr=p, length=0)   # empty context if unused
var sig = mldsa_sign_hedged(priv, msg, ctx)
var ok = mldsa_verify(priv.pub, msg, sig, ctx)
```

- Note: `context` max is 255 bytes. Sign and verify must use the same one.
- `mldsa_sign_deterministic` gives the same signature every call for the same message. Only use it in environments without an RNG.
- Load a public key from bytes with `mldsa65_public_key(pk_bytes)`.
- Sizes are `MLDSA65_PUBLICKEYBYTES`, `MLDSA65_SECRETKEYBYTES`, `MLDSA65_BYTES` for the signature size. 44/87 variants follow the same naming.
