# Thistle

Thistle is a high-performance cryptography library written in Mojo.

### Supported algorithms

* **Argon2id**
* **BLAKE2b**
* **BLAKE3**
* **Camellia**
* **PBKDF2-HMAC** (SHA-256/SHA-512)
* **HMAC** (SHA-256/SHA-384/SHA-512)
* **HKDF** (SHA-256 extract/expand)
* **SHA-2**
* **SHA-NI**
* **SHA-3**
* **ChaCha20-Poly1305 / XChaCha20-Poly1305**
* **KCipher-2**
* **ML-KEM / ML-DSA**
* **AES-NI** (ECB/CBC/CTR/XTS/GCM)
* **AES software** (ECB/CBC/CTR/XTS/GCM)
* **AES GPU** (ECB/CTR; GCM counter stage only)
* **Ed25519 / X25519** (including ephemeral key generation)
* **P-256 / P-384** (ECDH, ECDSA, ephemeral key generation)
* **RSA-PSS** signing and verification (SHA-256/SHA-384/SHA-512)
* **RSA PKCS#1 v1.5** signing and verification (SHA-256 signing; SHA-256/SHA-384/SHA-512 verification)
* **TLS 1.2 PRF** (SHA-256/SHA-384)

[Thistle documentation website](https://libalpm64.github.io/Thistle/)

Platforms supported: Linux, macOS
