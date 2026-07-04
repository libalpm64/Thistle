---
title: Home
nav_order: 1
---

# Thistle

Pure Mojo crypto library. No Python/C FFI on any path. Validated against 20,000+ NIST CAVP/ACVP and Wycheproof vectors.

Hardware paths are compile-time dispatched with no runtime branch:

- SHA-NI (`sha256rnds2`/`msg1`/`msg2`) on x86 and ARMv8 crypto ext (`sha256h`/`h2`/`su0`/`su1`) on ARM via `sha256ni_hash`
- AES-NI on x86 and ARM via `thistle.aes_ni`
- GPU AES ECB/CTR/GCM kernels in `thistle.aes_gpu`

## Install

```sh
git clone https://github.com/libalpm64/Thistle
cd Thistle
pixi run test
```

Add `-I path/to/Thistle/src` to your `mojo` invocation. Import from `thistle`. Submodules like `thistle.aes` and `thistle.sha2` stay directly importable for lower-level access.

## Conventions

- Invalid input raises `Error`. `Bool`-returning APIs (P-256/P-384) don't raise. Check the return value.
- ML-KEM decapsulation failure is not an error. Invalid ciphertexts decapsulate to a pseudorandom secret (FIPS 203 implicit rejection).

## Pages

- [Hashing](hashing)
- [MAC / KDF](mac-kdf)
- [Symmetric](symmetric)
- [Curves](curves)
- [Post-Quantum](post-quantum)
- [Random](random)
- [Security Notes](security)
