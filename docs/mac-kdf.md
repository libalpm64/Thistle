---
title: Passwords & Keys
nav_order: 3
---

# Passwords & Keys

Two everyday jobs live here: storing passwords so a database leak doesn't
expose them, and proving a message wasn't tampered with by someone who
doesn't know your key.

## Store a password (Argon2id)

Never store passwords, and never store plain hashes of them either. Argon2id
is deliberately slow and memory-hungry, so guessing attacks cost real money.
It's the current best practice.

```mojo
from thistle import argon2id_hash_string

def main() raises:
    # store this string in your database instead of the password
    var stored = argon2id_hash_string("hunter2", "somesalt16bytes!")

    # at login: recompute with the same salt and compare
    var attempt = argon2id_hash_string("hunter2", "somesalt16bytes!")
    var ok = attempt == stored
```

The salt should be random and unique per user — 16 bytes from
[`random_bytes`](random) is right. Store it next to the hash; it is not a
secret.

Need more control (memory cost, iterations, output length)?

```mojo
from thistle import Argon2id

var ctx = Argon2id(salt, parallelism=4, tag_length=32,
                   memory_size_kb=65536, iterations=3)
var hash = ctx.hash(password)
```

Out-of-range parameters raise an error instead of quietly weakening the
hash.

## Prove a message wasn't tampered with (HMAC)

An HMAC is a hash that only someone holding the key can compute. Send the
tag along with the message; the receiver recomputes it with the shared key
and compares.

```mojo
from thistle import hmac_sha256

def main() raises:
    var key = String("my secret key").as_bytes()
    var message = String("abc").as_bytes()

    var tag = hmac_sha256(key, message)   # 32 bytes, send with the message
```

When comparing a received tag with your own, compare **every byte** rather
than stopping at the first difference, so timing doesn't leak how close a
forgery got.

## Turn a password into an encryption key (PBKDF2)

Encryption needs a random-looking key, and "hunter2" isn't one. PBKDF2
stretches a password into key material:

```mojo
from thistle import pbkdf2_hmac_sha256

def main() raises:
    var password = String("correct horse battery staple").as_bytes()
    var salt = random_bytes(16)

    var key = pbkdf2_hmac_sha256(password, Span[UInt8, ...](salt), 600_000, 32)
```

600,000 iterations is the current OWASP recommendation. Fewer than 1 raises
an error. If you're choosing fresh today and don't need PBKDF2
compatibility, prefer Argon2id for this job too.
