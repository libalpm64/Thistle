# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Libalpm64, Lostlab Technologies.

"""
PBKDF2 (Password-Based Key Derivation Function 2) Implementation in Mojo
SP 800-132 / FIPS 140-2 / RFC 8018
By Libalpm64, Attribute not required.
"""
from std.collections import List
from std.memory import memset_zero
from std.builtin.simd import SIMD
from std.builtin.dtype import DType
from .utils import StackBuffer
from .sha2 import (
    SHA256Context,
    SHA512Context,
    sha256_hash,
    sha256_update,
    sha256_final_to_buffer,
    sha512_hash,
    sha512_update,
    sha512_final_to_buffer,
)

@always_inline
def encode_counter_be(counter: UInt32) -> SIMD[DType.uint8, 4]:
    return SIMD[DType.uint8, 4](
        UInt8((counter >> 24) & 0xFF),
        UInt8((counter >> 16) & 0xFF),
        UInt8((counter >> 8) & 0xFF),
        UInt8(counter & 0xFF),
    )

struct PBKDF2SHA256(Movable):
    var ipad: StackBuffer[UInt8, 64]
    var opad: StackBuffer[UInt8, 64]
    var inner_hash: StackBuffer[UInt8, 32]
    var u_block: StackBuffer[UInt8, 32]
    var f_block: StackBuffer[UInt8, 32]
    var counter_bytes: StackBuffer[UInt8, 4]
    var inner_ctx: SHA256Context
    var outer_ctx: SHA256Context

    def __init__(out self, password: Span[UInt8, ...]):
        self.ipad = StackBuffer[UInt8, 64](fill=0)
        self.opad = StackBuffer[UInt8, 64](fill=0)
        self.inner_hash = StackBuffer[UInt8, 32](fill=0)
        self.u_block = StackBuffer[UInt8, 32](fill=0)
        self.f_block = StackBuffer[UInt8, 32](fill=0)
        self.counter_bytes = StackBuffer[UInt8, 4](fill=0)
        self.inner_ctx = SHA256Context()
        self.outer_ctx = SHA256Context()

        var k = StackBuffer[UInt8, 64](fill=0)

        if len(password) > 64:
            var ctx = SHA256Context()
            sha256_update(ctx, password)
            sha256_final_to_buffer(ctx, k.ptr())
        else:
            for i in range(len(password)):
                k[i] = password[i]

        for i in range(64):
            self.ipad[i] = k[i] ^ 0x36
            self.opad[i] = k[i] ^ 0x5C
        memset_zero(k.ptr(), 64)

    @always_inline
    def hmac(mut self, data: Span[UInt8, ...]):
        self.inner_ctx.reset()
        sha256_update(self.inner_ctx, Span[UInt8, ...](ptr=self.ipad.ptr(), length=64))
        sha256_update(self.inner_ctx, data)
        sha256_final_to_buffer(self.inner_ctx, self.inner_hash.ptr())

        self.outer_ctx.reset()
        sha256_update(self.outer_ctx, Span[UInt8, ...](ptr=self.opad.ptr(), length=64))
        sha256_update(self.outer_ctx, Span[UInt8, ...](ptr=self.inner_hash.ptr(), length=32))
        sha256_final_to_buffer(self.outer_ctx, self.u_block.ptr())

    @always_inline
    def hmac_with_counter(mut self, data: Span[UInt8, ...], counter: UInt32):
        self.counter_bytes[0] = UInt8((counter >> 24) & 0xFF)
        self.counter_bytes[1] = UInt8((counter >> 16) & 0xFF)
        self.counter_bytes[2] = UInt8((counter >> 8) & 0xFF)
        self.counter_bytes[3] = UInt8(counter & 0xFF)

        self.inner_ctx.reset()
        sha256_update(self.inner_ctx, Span[UInt8, ...](ptr=self.ipad.ptr(), length=64))
        sha256_update(self.inner_ctx, data)
        sha256_update(self.inner_ctx, Span[UInt8, ...](ptr=self.counter_bytes.ptr(), length=4))
        sha256_final_to_buffer(self.inner_ctx, self.inner_hash.ptr())

        self.outer_ctx.reset()
        sha256_update(self.outer_ctx, Span[UInt8, ...](ptr=self.opad.ptr(), length=64))
        sha256_update(self.outer_ctx, Span[UInt8, ...](ptr=self.inner_hash.ptr(), length=32))
        sha256_final_to_buffer(self.outer_ctx, self.u_block.ptr())

    @always_inline
    def derive(mut self, salt: Span[UInt8, ...], iterations: Int, dklen: Int) -> List[UInt8]:
        var hLen = 32
        var num_blocks = (dklen + hLen - 1) // hLen

        var derived_key = List[UInt8](capacity=dklen)
        var t_block = StackBuffer[UInt8, 32](fill=0)

        for block_idx in range(1, num_blocks + 1):
            self.hmac_with_counter(salt, UInt32(block_idx))
            for b in range(32):
                t_block[b] = self.u_block[b]

            for _ in range(1, iterations):
                self.hmac(Span[UInt8, ...](ptr=self.u_block.ptr(), length=32))
                for b in range(32):
                    t_block[b] ^= self.u_block[b]

            var remaining = dklen - len(derived_key)
            var to_copy = 32 if remaining > 32 else remaining
            for b in range(to_copy):
                derived_key.append(t_block[b])

        return derived_key^

def pbkdf2_hmac_sha256(
    password: Span[UInt8, ...], salt: Span[UInt8, ...], iterations: Int, dkLen: Int
) -> List[UInt8]:
    var hLen = 32
    var num_blocks = (dkLen + hLen - 1) // hLen
    var derived_key = List[UInt8](capacity=dkLen)
    var salt_len = len(salt)

    for block_idx in range(1, num_blocks + 1):
        var salt_counter = List[UInt8](capacity=salt_len + 4)
        for i in range(salt_len):
            salt_counter.append(salt[i])
        salt_counter.append(UInt8((UInt32(block_idx) >> 24) & 0xFF))
        salt_counter.append(UInt8((UInt32(block_idx) >> 16) & 0xFF))
        salt_counter.append(UInt8((UInt32(block_idx) >> 8) & 0xFF))
        salt_counter.append(UInt8(UInt32(block_idx) & 0xFF))

        var u = hmac_sha256(password, Span[UInt8, ...](salt_counter))
        var t = u.copy()
        for _ in range(1, iterations):
            var prev_u = u.copy()
            u = hmac_sha256(password, Span[UInt8, ...](prev_u))
            for i in range(hLen):
                t[i] ^= u[i]

        var remaining = dkLen - len(derived_key)
        var to_copy = 32 if remaining > 32 else remaining
        for i in range(to_copy):
            derived_key.append(t[i])

    return derived_key^

struct PBKDF2SHA512(Movable):
    var ipad: StackBuffer[UInt8, 128]
    var opad: StackBuffer[UInt8, 128]
    var inner_hash: StackBuffer[UInt8, 64]
    var u_block: StackBuffer[UInt8, 64]
    var f_block: StackBuffer[UInt8, 64]
    var counter_bytes: StackBuffer[UInt8, 4]
    var inner_ctx: SHA512Context
    var outer_ctx: SHA512Context

    def __init__(out self, password: Span[UInt8, ...]):
        self.ipad = StackBuffer[UInt8, 128](fill=0)
        self.opad = StackBuffer[UInt8, 128](fill=0)
        self.inner_hash = StackBuffer[UInt8, 64](fill=0)
        self.u_block = StackBuffer[UInt8, 64](fill=0)
        self.f_block = StackBuffer[UInt8, 64](fill=0)
        self.counter_bytes = StackBuffer[UInt8, 4](fill=0)
        self.inner_ctx = SHA512Context()
        self.outer_ctx = SHA512Context()

        var k = StackBuffer[UInt8, 128](fill=0)

        if len(password) > 128:
            var ctx = SHA512Context()
            sha512_update(ctx, password)
            sha512_final_to_buffer(ctx, k.ptr())
        else:
            for i in range(len(password)):
                k[i] = password[i]

        for i in range(128):
            self.ipad[i] = k[i] ^ 0x36
            self.opad[i] = k[i] ^ 0x5C
        memset_zero(k.ptr(), 128)

    @always_inline
    def hmac(mut self, data: Span[UInt8, ...]):
        self.inner_ctx.reset()
        sha512_update(self.inner_ctx, Span[UInt8, ...](ptr=self.ipad.ptr(), length=128))
        sha512_update(self.inner_ctx, data)
        sha512_final_to_buffer(self.inner_ctx, self.inner_hash.ptr())

        self.outer_ctx.reset()
        sha512_update(self.outer_ctx, Span[UInt8, ...](ptr=self.opad.ptr(), length=128))
        sha512_update(self.outer_ctx, Span[UInt8, ...](ptr=self.inner_hash.ptr(), length=64))
        sha512_final_to_buffer(self.outer_ctx, self.u_block.ptr())

    @always_inline
    def hmac_with_counter(mut self, data: Span[UInt8, ...], counter: UInt32):
        self.counter_bytes[0] = UInt8((counter >> 24) & 0xFF)
        self.counter_bytes[1] = UInt8((counter >> 16) & 0xFF)
        self.counter_bytes[2] = UInt8((counter >> 8) & 0xFF)
        self.counter_bytes[3] = UInt8(counter & 0xFF)

        self.inner_ctx.reset()
        sha512_update(self.inner_ctx, Span[UInt8, ...](ptr=self.ipad.ptr(), length=128))
        sha512_update(self.inner_ctx, data)
        sha512_update(self.inner_ctx, Span[UInt8, ...](ptr=self.counter_bytes.ptr(), length=4))
        sha512_final_to_buffer(self.inner_ctx, self.inner_hash.ptr())

        self.outer_ctx.reset()
        sha512_update(self.outer_ctx, Span[UInt8, ...](ptr=self.opad.ptr(), length=128))
        sha512_update(self.outer_ctx, Span[UInt8, ...](ptr=self.inner_hash.ptr(), length=64))
        sha512_final_to_buffer(self.outer_ctx, self.u_block.ptr())

    @always_inline
    def derive(mut self, salt: Span[UInt8, ...], iterations: Int, dklen: Int) -> List[UInt8]:
        var hLen = 64
        var num_blocks = (dklen + hLen - 1) // hLen

        var derived_key = List[UInt8](capacity=dklen)
        var t_block = StackBuffer[UInt8, 64](fill=0)

        for block_idx in range(1, num_blocks + 1):
            self.hmac_with_counter(salt, UInt32(block_idx))
            for b in range(64):
                t_block[b] = self.u_block[b]

            for _ in range(1, iterations):
                self.hmac(Span[UInt8, ...](ptr=self.u_block.ptr(), length=64))
                for b in range(64):
                    t_block[b] ^= self.u_block[b]

            var remaining = dklen - len(derived_key)
            var to_copy = 64 if remaining > 64 else remaining
            for b in range(to_copy):
                derived_key.append(t_block[b])

        return derived_key^

def pbkdf2_hmac_sha512(
    password: Span[UInt8, ...], salt: Span[UInt8, ...], iterations: Int, dkLen: Int
) -> List[UInt8]:
    var hLen = 64
    var num_blocks = (dkLen + hLen - 1) // hLen
    var derived_key = List[UInt8](capacity=dkLen)
    var salt_len = len(salt)

    for block_idx in range(1, num_blocks + 1):
        var salt_counter = List[UInt8](capacity=salt_len + 4)
        for i in range(salt_len):
            salt_counter.append(salt[i])
        salt_counter.append(UInt8((UInt32(block_idx) >> 24) & 0xFF))
        salt_counter.append(UInt8((UInt32(block_idx) >> 16) & 0xFF))
        salt_counter.append(UInt8((UInt32(block_idx) >> 8) & 0xFF))
        salt_counter.append(UInt8(UInt32(block_idx) & 0xFF))

        var u = hmac_sha512(password, Span[UInt8, ...](salt_counter))
        var t = u.copy()
        for _ in range(1, iterations):
            var prev_u = u.copy()
            u = hmac_sha512(password, Span[UInt8, ...](prev_u))
            for i in range(hLen):
                t[i] ^= u[i]

        var remaining = dkLen - len(derived_key)
        var to_copy = 64 if remaining > 64 else remaining
        for i in range(to_copy):
            derived_key.append(t[i])

    return derived_key^

def hmac_sha256(key: Span[UInt8, ...], data: Span[UInt8, ...]) -> List[UInt8]:
    var k = StackBuffer[UInt8, 64](fill=0)
    if len(key) > 64:
        var key_hash = sha256_hash(key)
        for i in range(32):
            k[i] = key_hash[i]
    else:
        for i in range(len(key)):
            k[i] = key[i]

    var ipad = StackBuffer[UInt8, 64](fill=0)
    var opad = StackBuffer[UInt8, 64](fill=0)
    for i in range(64):
        ipad[i] = k[i] ^ 0x36
        opad[i] = k[i] ^ 0x5C

    var inner_input = List[UInt8](capacity=64 + len(data))
    for i in range(64):
        inner_input.append(ipad[i])
    inner_input.extend(data)
    var inner_hash = sha256_hash(Span[UInt8, ...](inner_input))

    var outer_input = List[UInt8](capacity=64 + 32)
    for i in range(64):
        outer_input.append(opad[i])
    outer_input.extend(inner_hash.copy())
    var outer_hash = sha256_hash(Span[UInt8, ...](outer_input))

    var result = List[UInt8](capacity=32)
    for i in range(32):
        result.append(outer_hash[i])
    return result^

def hmac_sha512(key: Span[UInt8, ...], data: Span[UInt8, ...]) -> List[UInt8]:
    var k = StackBuffer[UInt8, 128](fill=0)
    if len(key) > 128:
        var key_hash = sha512_hash(key)
        for i in range(64):
            k[i] = key_hash[i]
    else:
        for i in range(len(key)):
            k[i] = key[i]

    var ipad = StackBuffer[UInt8, 128](fill=0)
    var opad = StackBuffer[UInt8, 128](fill=0)
    for i in range(128):
        ipad[i] = k[i] ^ 0x36
        opad[i] = k[i] ^ 0x5C

    var inner_input = List[UInt8](capacity=128 + len(data))
    for i in range(128):
        inner_input.append(ipad[i])
    inner_input.extend(data)
    var inner_hash = sha512_hash(Span[UInt8, ...](inner_input))

    var outer_input = List[UInt8](capacity=128 + 64)
    for i in range(128):
        outer_input.append(opad[i])
    outer_input.extend(inner_hash.copy())
    var outer_hash = sha512_hash(Span[UInt8, ...](outer_input))

    var result = List[UInt8](capacity=64)
    for i in range(64):
        result.append(outer_hash[i])
    return result^