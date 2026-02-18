# SPDX-License-Identifier: MIT
#
# Copyright (c) 2026 Libalpm64, Lostlab Technologies.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
PBKDF2 (Password-Based Key Derivation Function 2) Implementation in Mojo
SP 800-132 / FIPS 140-2 / RFC 8018
By Libalpm64, Attribute not required.
"""

from collections import List
from memory import UnsafePointer, alloc, memcpy
from .sha2 import (
    SHA256Context,
    SHA512Context,
    sha256_update,
    sha256_final_to_buffer,
    sha512_update,
    sha512_final_to_buffer,
)


struct PBKDF2SHA256:
    var ipad: UnsafePointer[UInt8, MutAnyOrigin]
    var opad: UnsafePointer[UInt8, MutAnyOrigin]
    var inner_hash: UnsafePointer[UInt8, MutAnyOrigin]
    var u_block: UnsafePointer[UInt8, MutAnyOrigin]
    var f_block: UnsafePointer[UInt8, MutAnyOrigin]
    var counter_bytes: UnsafePointer[UInt8, MutAnyOrigin]
    var inner_ctx: SHA256Context
    var outer_ctx: SHA256Context

    fn __init__(out self, password: Span[UInt8]):
        self.ipad = alloc[UInt8](64)
        self.opad = alloc[UInt8](64)
        self.inner_hash = alloc[UInt8](32)
        self.u_block = alloc[UInt8](32)
        self.f_block = alloc[UInt8](32)
        self.counter_bytes = alloc[UInt8](4)
        self.inner_ctx = SHA256Context()
        self.outer_ctx = SHA256Context()

        var k = alloc[UInt8](64)
        for i in range(64):
            k[i] = 0

        if len(password) > 64:
            var ctx = SHA256Context()
            sha256_update(ctx, password)
            sha256_final_to_buffer(ctx, k)
        else:
            for i in range(len(password)):
                k[i] = password[i]

        for i in range(64):
            self.ipad[i] = k[i] ^ 0x36
            self.opad[i] = k[i] ^ 0x5C

        for i in range(64):
            k[i] = 0
        k.free()

    fn __del__(deinit self):
        self.ipad.free()
        self.opad.free()
        self.inner_hash.free()
        self.u_block.free()
        self.f_block.free()
        self.counter_bytes.free()

    @always_inline
    fn hmac(mut self, data: Span[UInt8]):
        self.inner_ctx.reset()
        sha256_update(self.inner_ctx, Span[UInt8](ptr=self.ipad, length=64))
        sha256_update(self.inner_ctx, data)
        sha256_final_to_buffer(self.inner_ctx, self.inner_hash)

        self.outer_ctx.reset()
        sha256_update(self.outer_ctx, Span[UInt8](ptr=self.opad, length=64))
        sha256_update(self.outer_ctx, Span[UInt8](ptr=self.inner_hash, length=32))
        sha256_final_to_buffer(self.outer_ctx, self.u_block)

    @always_inline
    fn hmac_with_counter(mut self, data: Span[UInt8], counter: UInt32):
        self.counter_bytes[0] = UInt8((counter >> 24) & 0xFF)
        self.counter_bytes[1] = UInt8((counter >> 16) & 0xFF)
        self.counter_bytes[2] = UInt8((counter >> 8) & 0xFF)
        self.counter_bytes[3] = UInt8(counter & 0xFF)

        self.inner_ctx.reset()
        sha256_update(self.inner_ctx, Span[UInt8](ptr=self.ipad, length=64))
        sha256_update(self.inner_ctx, data)
        sha256_update(self.inner_ctx, Span[UInt8](ptr=self.counter_bytes, length=4))
        sha256_final_to_buffer(self.inner_ctx, self.inner_hash)

        self.outer_ctx.reset()
        sha256_update(self.outer_ctx, Span[UInt8](ptr=self.opad, length=64))
        sha256_update(self.outer_ctx, Span[UInt8](ptr=self.inner_hash, length=32))
        sha256_final_to_buffer(self.outer_ctx, self.u_block)

    fn derive(mut self, salt: Span[UInt8], iterations: Int, dklen: Int) -> List[UInt8]:
        var hLen = 32
        var num_blocks = (dklen + hLen - 1) // hLen

        var derived_key = List[UInt8](capacity=dklen)
        var f_u64 = self.f_block.bitcast[UInt64]()
        var u_u64 = self.u_block.bitcast[UInt64]()

        for block_idx in range(1, num_blocks + 1):
            self.hmac_with_counter(salt, UInt32(block_idx))
            for b in range(4):
                f_u64[b] = u_u64[b]

            for _ in range(1, iterations):
                self.hmac(Span[UInt8](ptr=self.u_block, length=32))
                for b in range(4):
                    f_u64[b] ^= u_u64[b]

            var remaining = dklen - len(derived_key)
            var to_copy = 32 if remaining > 32 else remaining
            for b in range(to_copy):
                derived_key.append(self.f_block[b])

        return derived_key^


fn pbkdf2_hmac_sha256(
    password: Span[UInt8], salt: Span[UInt8], iterations: Int, dkLen: Int
) -> List[UInt8]:
    var pbkdf2 = PBKDF2SHA256(password)
    return pbkdf2.derive(salt, iterations, dkLen)


struct PBKDF2SHA512:
    var ipad: UnsafePointer[UInt8, MutAnyOrigin]
    var opad: UnsafePointer[UInt8, MutAnyOrigin]
    var inner_hash: UnsafePointer[UInt8, MutAnyOrigin]
    var u_block: UnsafePointer[UInt8, MutAnyOrigin]
    var f_block: UnsafePointer[UInt8, MutAnyOrigin]
    var counter_bytes: UnsafePointer[UInt8, MutAnyOrigin]
    var inner_ctx: SHA512Context
    var outer_ctx: SHA512Context

    fn __init__(out self, password: Span[UInt8]):
        self.ipad = alloc[UInt8](128)
        self.opad = alloc[UInt8](128)
        self.inner_hash = alloc[UInt8](64)
        self.u_block = alloc[UInt8](64)
        self.f_block = alloc[UInt8](64)
        self.counter_bytes = alloc[UInt8](4)
        self.inner_ctx = SHA512Context()
        self.outer_ctx = SHA512Context()

        var k = alloc[UInt8](128)
        for i in range(128):
            k[i] = 0

        if len(password) > 128:
            var ctx = SHA512Context()
            sha512_update(ctx, password)
            sha512_final_to_buffer(ctx, k)
        else:
            for i in range(len(password)):
                k[i] = password[i]

        for i in range(128):
            self.ipad[i] = k[i] ^ 0x36
            self.opad[i] = k[i] ^ 0x5C

        for i in range(128):
            k[i] = 0
        k.free()

    fn __del__(deinit self):
        self.ipad.free()
        self.opad.free()
        self.inner_hash.free()
        self.u_block.free()
        self.f_block.free()
        self.counter_bytes.free()

    @always_inline
    fn hmac(mut self, data: Span[UInt8]):
        self.inner_ctx.reset()
        sha512_update(self.inner_ctx, Span[UInt8](ptr=self.ipad, length=128))
        sha512_update(self.inner_ctx, data)
        sha512_final_to_buffer(self.inner_ctx, self.inner_hash)

        self.outer_ctx.reset()
        sha512_update(self.outer_ctx, Span[UInt8](ptr=self.opad, length=128))
        sha512_update(self.outer_ctx, Span[UInt8](ptr=self.inner_hash, length=64))
        sha512_final_to_buffer(self.outer_ctx, self.u_block)

    @always_inline
    fn hmac_with_counter(mut self, data: Span[UInt8], counter: UInt32):
        self.counter_bytes[0] = UInt8((counter >> 24) & 0xFF)
        self.counter_bytes[1] = UInt8((counter >> 16) & 0xFF)
        self.counter_bytes[2] = UInt8((counter >> 8) & 0xFF)
        self.counter_bytes[3] = UInt8(counter & 0xFF)

        self.inner_ctx.reset()
        sha512_update(self.inner_ctx, Span[UInt8](ptr=self.ipad, length=128))
        sha512_update(self.inner_ctx, data)
        sha512_update(self.inner_ctx, Span[UInt8](ptr=self.counter_bytes, length=4))
        sha512_final_to_buffer(self.inner_ctx, self.inner_hash)

        self.outer_ctx.reset()
        sha512_update(self.outer_ctx, Span[UInt8](ptr=self.opad, length=128))
        sha512_update(self.outer_ctx, Span[UInt8](ptr=self.inner_hash, length=64))
        sha512_final_to_buffer(self.outer_ctx, self.u_block)

    fn derive(mut self, salt: Span[UInt8], iterations: Int, dklen: Int) -> List[UInt8]:
        var hLen = 64
        var num_blocks = (dklen + hLen - 1) // hLen

        var derived_key = List[UInt8](capacity=dklen)
        var f_u64 = self.f_block.bitcast[UInt64]()
        var u_u64 = self.u_block.bitcast[UInt64]()

        for block_idx in range(1, num_blocks + 1):
            self.hmac_with_counter(salt, UInt32(block_idx))
            for b in range(8):
                f_u64[b] = u_u64[b]

            for _ in range(1, iterations):
                self.hmac(Span[UInt8](ptr=self.u_block, length=64))
                for b in range(8):
                    f_u64[b] ^= u_u64[b]

            var remaining = dklen - len(derived_key)
            var to_copy = 64 if remaining > 64 else remaining
            for b in range(to_copy):
                derived_key.append(self.f_block[b])

        return derived_key^


fn pbkdf2_hmac_sha512(
    password: Span[UInt8], salt: Span[UInt8], iterations: Int, dkLen: Int
) -> List[UInt8]:
    var pbkdf2 = PBKDF2SHA512(password)
    return pbkdf2.derive(salt, iterations, dkLen)


fn hmac_sha256(key: Span[UInt8], data: Span[UInt8]) -> List[UInt8]:
    var pbkdf2 = PBKDF2SHA256(key)
    pbkdf2.hmac(data)
    var result = List[UInt8](capacity=32)
    for i in range(32):
        result.append(pbkdf2.u_block[i])
    return result^


fn hmac_sha512(key: Span[UInt8], data: Span[UInt8]) -> List[UInt8]:
    var pbkdf2 = PBKDF2SHA512(key)
    pbkdf2.hmac(data)
    var result = List[UInt8](capacity=64)
    for i in range(64):
        result.append(pbkdf2.u_block[i])
    return result^
