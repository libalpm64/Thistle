---
title: Home
nav_order: 1
---

# Thistle

Pure Mojo crypto library. No Python/C FFI on any path. Validated against
20,000+ NIST CAVP/ACVP and Wycheproof vectors.

Hardware paths (compile-time dispatched, no runtime branch):

- SHA-NI (`sha256rnds2`/`msg1`/`msg2`) on x86, ARMv8 crypto ext
  (`sha256h`/`h2`/`su0`/`su1`) on ARM — `sha256ni_hash`
- AES-NI on x86 and ARM — `thistle.aes_ni`
- GPU AES ECB/CTR/GCM kernels — `thistle.aes_gpu`

## Install

```sh
git clone https://github.com/libalpm64/Thistle
cd Thistle
pixi run test
```

Add `-I path/to/Thistle/src` to your `mojo` invocation. Import from
`thistle`; submodules (`thistle.aes`, `thistle.sha2`, ...) stay directly
importable for lower-level access.

## Conventions

- Invalid input raises `Error`. `Bool`-returning APIs (P-256/P-384) must be
  checked — they don't raise.
- ML-KEM decapsulation failure is not an error: invalid ciphertexts
  decapsulate to a pseudorandom secret (FIPS 203 implicit rejection).

## Pages

- [Hashing](hashing)
- [MAC / KDF](mac-kdf)
- [Symmetric](symmetric)
- [Curves](curves)
- [Post-Quantum](post-quantum)
- [Random](random)
- [Security Notes](security)
