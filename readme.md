# Thistle

Thistle is a high-performance Crypto Library written in Mojo.

Thistle was written to avoid the **150x performance drops** when Mojo has to call Python Objects.

> [!IMPORTANT]
> Currently, Thistle is an experimental library.

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
* **ML-KEM / ML-DSA**
* **AES-GPU** (XTS/CBC/ECB/CTR/GCM/ECB/CTR)
* **AES-NI** (XTS/CBC/ECB/CTR/GCM/ECB/CTR)
* **AES-Software** (XTS/CBC/ECB/CTR/GCM/ECB/CTR)
* **ECDSA** (ED25519/X25519)
* **ECDH** (NIST P-256, P-384)

### Current Roadmap:
* **RSA** (PSS only)
* Replace External SSL libraries and use Thistle for TLS 1.3 Crypto operations.
* Embeded like ascon, mpi, etc will be added as more hardware targets are added to Mojo compiler.

Platforms supported: Linux, macOS
