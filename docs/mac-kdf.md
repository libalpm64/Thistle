---
title: MACs & Key Derivation
nav_order: 3
---

# MACs & Key Derivation

## HMAC

```mojo
from thistle import hmac_sha256, hmac_sha512

var tag = hmac_sha256(key, message)   # 32 bytes
var tag2 = hmac_sha512(key, message)  # 64 bytes
```

Keys longer than the block size are hashed first, per RFC 2104. When
comparing tags, use a constant-time comparison — never `==` on the raw lists.

## PBKDF2

```mojo
from thistle import pbkdf2_hmac_sha256, pbkdf2_hmac_sha512

var dk = pbkdf2_hmac_sha256(password, salt, 600_000, 32)
```

Raises if `iterations < 1` or `dkLen < 1`. Pick iteration counts from the
current OWASP guidance (600k+ for SHA-256).

## Argon2id

The recommended password hash. Parameters are validated against RFC 9106 and
raise on violation (parallelism in [1, 2^24), tag length >= 4, memory >= 8 x
parallelism KiB, iterations >= 1).

```mojo
from thistle import Argon2id, argon2id_hash_string

# full control
var ctx = Argon2id(salt, parallelism=4, tag_length=32,
                   memory_size_kb=65536, iterations=3)
var hash = ctx.hash(password)

# one-liner with defaults, hex output
var hex = argon2id_hash_string("hunter2", "somesalt16bytes!")
```

A second constructor accepts `secret` (pepper) and `ad` (associated data)
spans before the keyword parameters.
