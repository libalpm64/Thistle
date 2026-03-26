# Thistle

Thistle is a high-performance Crypto Library written in Mojo.

Thistle was written to avoid the **150x performance drops** when Mojo has to call Python Objects.

> [!IMPORTANT]
> Currently, Thistle is an experimental library.
> MacOS broken for Argon2, SHA, Blake3 (Compiler/Runtime Issue)
---

### Currently supported Algorithms:

* **Argon2** (Parity)
* **Blake2b** (Parity)
* **Blake3** (Parity)
* **Camellia** (Parity, very slow)
* **Pbkdf2** (Parity/Close)
* **SHA2** (Much slower ~5x slower lacks NI)
* **SHA3** (Parity/Close)
* **ChaCha20** (Parity)
* **KCipher-2** (Faster than Native C)
* **ML-KEM / ML-DSA** (FFI Linked Post-Quantum Crypto)
* **AES-GPU** (XTS/CBC/ECB/CTR/GCM/ECB/CTR)
* **AES-NI** (XTS/CBC/ECB/CTR/GCM/ECB/CTR)
* **AES-Software** (XTS/CBC/ECB/CTR/GCM/ECB/CTR)

### Build:

ML-KEM/ML-DSA/Random require native libraries built from source:

```bash
pixi install
pixi run build-pq
```

Platforms supported: Linux, macOS

---

### Current Roadmap:
* **SHA-NI**
* **ECDSA / ECDH** (NIST P-256, P-384)
* **RSA** (PSS only)

---

### Future Roadmap:

* **Camellia** (Use AES-NI)
---

### What is not on the roadmap:

* **Windows support.** Due to System V and Windows' poor architectural choices, we will not support them at the moment. It is technically infeasible for us to try, as Mojo doesn't even support Windows yet. Update: It does appear that Windows is now emulating instructions (System V for ARM in 26H1); however, it has high overhead ~ 30%).
* **Below AVX2 support on X86 / Non ARM systems.**
