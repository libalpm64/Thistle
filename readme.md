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
---

### Current Roadmap:

* **Post Quantum Crypto** (ML-KEM / ML-DSA)
* **ECDSA / ECDH** (NIST P-256, P-384)
* **RSA** (PSS only)

---

### Future Roadmap:

* **AES-NI / SHA-NI** (~5x increase in speed, also CPU cache immune)
* **Camellia** (Use AES-NI)
* **Target Multiple Architectures** (SVE / NEON / AVX512)
* **Unify Library** (make it easy to use for the public)

---

### Detailed:

Currently AES-NI/RSA PSS (The one that is immune to sidechannels)/Camellia (Using the Linux Kernels AES-NI optimizations) are extremely difficult to implement in Mojo currently due to inlined assembly lacking opcode format recognization and only executing 1 instruction. Additonally the target system in Mojo needs a lot of work interop between Multiple architectures, Multiple OS's is currently impossible without having to use other languages.

The goal is to be simillar to Golangs approach to their standard library they have a module that interops GO and assembly directly which is really awesome. (If you are unware of GO's standard library [https://github.com/golang/go/tree/master/src/crypto/internal/fips140/sha256]() this is very impressive). Additonally, if this is possible in Mojo we can also do GPU Crypto which can make matrix multplication instant making the hash rate *millions of times faster (in some operations) with GPU acceleration.

---

### What is not on the roadmap:

* **Windows support.** Due to System V and Windows' poor architectural choices, we will not support them at the moment. It is technically infeasible for us to try, as Mojo doesn't even support Windows yet. Update: It does appear that Windows is now emulating instructions (System V for ARM in 26H1); however, it has high overhead ~ 30%).
* **Below AVX2 support on X86 / Non ARM systems.**
