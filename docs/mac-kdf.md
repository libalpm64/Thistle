---
title: MAC / KDF
nav_order: 3
---

# MAC / KDF

Default: **Argon2id** for password hashing.

## `thistle.hmac_sha256` / `hmac_sha512`

```mojo
def hmac_sha256(key: Span[UInt8, ...], data: Span[UInt8, ...]) -> List[UInt8]
def hmac_sha512(key: Span[UInt8, ...], data: Span[UInt8, ...]) -> List[UInt8]
```

```mojo
var tag = hmac_sha256(key, message)   # 32 bytes
```

- Note: compare tags in constant time. `==` on `List[UInt8]` is not guaranteed constant-time. Do a manual all-bytes XOR-accumulate compare.

## `thistle.pbkdf2_hmac_sha256` / `pbkdf2_hmac_sha512`

```mojo
def pbkdf2_hmac_sha256(password: Span[UInt8, ...], salt: Span[UInt8, ...], iterations: Int, dkLen: Int) raises -> List[UInt8]
def pbkdf2_hmac_sha512(password: Span[UInt8, ...], salt: Span[UInt8, ...], iterations: Int, dkLen: Int) raises -> List[UInt8]
```

```mojo
var key = pbkdf2_hmac_sha256(password, salt, 600_000, 32)
```

- Note: raises if `iterations < 1` or `dkLen < 1`.

## `thistle.Argon2id`

```mojo
def __init__(out self, salt: Span[UInt8, ...],
             parallelism: Int = 4, tag_length: Int = 32,
             memory_size_kb: Int = 65536, iterations: Int = 3,
             version: Int = 0x13) raises

def hash(self, password: Span[UInt8, ...]) -> List[UInt8]
```

Second constructor overload adds `secret: Span[UInt8, ...]` (pepper) and
`ad: Span[UInt8, ...]` before the keyword params.

```mojo
var ctx = Argon2id(salt, memory_size_kb=65536, iterations=3, parallelism=4)
var tag = ctx.hash(password)
```

- Note: raises if `parallelism` is not in `[1, 2^24)`.
- Note: raises if `tag_length < 4`.
- Note: raises if `memory_size_kb < 8 * parallelism`.
- Note: raises if `iterations < 1`.

## `thistle.argon2id_hash_string`

```mojo
def argon2id_hash_string(password: String, salt: String) raises -> String
```

```mojo
var hex = argon2id_hash_string("hunter2", "somesalt16bytes!")
```

Fixed defaults are parallelism=4 tag_length=32 memory=64MB iterations=3. Use `Argon2id` directly for custom parameters.
