# Thistle

Thistle is a high-performance Crypto Library written in Mojo.

Thistle was written to avoid the **150x performance drops** when Mojo has to call Python Objects.

> [!IMPORTANT]
> Currently, Thistle is an experimental library.

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

---

### Build:

ML-KEM/ML-DSA/Random require native libraries built from source:

```bash
pixi install
pixi run build-pq
```

Platforms supported: Linux, macOS

---

### Current Roadmap:

* **ECDSA / ECDH** (NIST P-256, P-384)
* **RSA** (PSS only)

---

### Future Roadmap:

* **AES-NI / SHA-NI** (~5x increase in speed, also CPU cache immune)
* **Camellia** (Use AES-NI)
---

### Detailed:

Currently AES-NI/RSA PSS (The one that is immune to sidechannels)/Camellia (Using the Linux Kernels AES-NI optimizations) are difficult to implement in Mojo.

---

### What is not on the roadmap:

* **Windows support.** Due to System V and Windows' poor architectural choices, we will not support them at the moment. It is technically infeasible for us to try, as Mojo doesn't even support Windows yet. Update: It does appear that Windows is now emulating instructions (System V for ARM in 26H1); however, it has high overhead ~ 30%).
* **Below AVX2 support on X86 / Non ARM systems.**
