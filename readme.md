# Thistle

Thistle is a high-performance Crypto Library written in Mojo.

Thistle was written to avoid the **150x performance drops** when Mojo has to call Python Objects.

> [!IMPORTANT]
> Currently, Thistle is an experimental library.
> 
> MacOS broken for Argon2, SHA, Blake3 (Compiler/Runtime Issue)
---

### Currently supported Algorithms:

* **Argon2** (Parity)
* **Blake2b** (Parity)
* **Blake3** (Parity)
* **Camellia** (Parity)
* **Pbkdf2** (Parity/Close)
* **SHA2** (Parity)
* **SHA-NI** (Parity)
* **SHA3** (Parity/Close)
* **ChaCha20** (Parity)
* **KCipher-2** (Faster than C)
* **ML-KEM / ML-DSA** (FFI PQC, too complex to implement 80k line C/ASM codebase)
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
* **ECDSA / ECDH** (NIST P-256, P-384)
* **RSA** (PSS only)