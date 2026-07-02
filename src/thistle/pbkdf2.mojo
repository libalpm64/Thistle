"""
PBKDF2 (Password-Based Key Derivation Function 2) Implementation in Mojo
SP 800-132 / FIPS 140-2 / RFC 8018
"""
from std.collections import List
from std.memory import memset_zero, memcpy, UnsafePointer
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
def _xor_block_32(dst: UnsafePointer[UInt8, MutAnyOrigin], src: UnsafePointer[UInt8, MutAnyOrigin]):
    var d = dst.bitcast[UInt64]().load[width=4, alignment=1]()
    var s = src.bitcast[UInt64]().load[width=4, alignment=1]()
    dst.bitcast[UInt64]().store[width=4, alignment=1](0, d ^ s)

@always_inline
def _xor_block_64(dst: UnsafePointer[UInt8, MutAnyOrigin], src: UnsafePointer[UInt8, MutAnyOrigin]):
    var d = dst.bitcast[UInt64]().load[width=8, alignment=1]()
    var s = src.bitcast[UInt64]().load[width=8, alignment=1]()
    dst.bitcast[UInt64]().store[width=8, alignment=1](0, d ^ s)

struct PBKDF2SHA256(Movable):
    var ipad: StackBuffer[UInt8, 64]
    var opad: StackBuffer[UInt8, 64]
    var inner_hash: StackBuffer[UInt8, 32]
    var u_block: StackBuffer[UInt8, 32]
    var counter_bytes: StackBuffer[UInt8, 4]
    var inner_ctx: SHA256Context
    var outer_ctx: SHA256Context

    def __init__(out self, password: Span[UInt8, ...]):
        self.ipad = StackBuffer[UInt8, 64](fill=0)
        self.opad = StackBuffer[UInt8, 64](fill=0)
        self.inner_hash = StackBuffer[UInt8, 32](fill=0)
        self.u_block = StackBuffer[UInt8, 32](fill=0)
        self.counter_bytes = StackBuffer[UInt8, 4](fill=0)
        self.inner_ctx = SHA256Context()
        self.outer_ctx = SHA256Context()

        var k = StackBuffer[UInt8, 64](fill=0)

        if len(password) > 64:
            var ctx = SHA256Context()
            sha256_update(ctx, password)
            sha256_final_to_buffer(ctx, k.ptr())
        else:
            memcpy(dest=k.ptr(), src=password.unsafe_ptr(), count=len(password))

        for i in range(64):
            self.ipad[i] = k[i] ^ 0x36
            self.opad[i] = k[i] ^ 0x5C
        memset_zero(k.ptr(), 64)

    def __del__(deinit self):
        memset_zero(self.ipad.ptr(), 64)
        memset_zero(self.opad.ptr(), 64)
        memset_zero(self.inner_hash.ptr(), 32)
        memset_zero(self.u_block.ptr(), 32)
        memset_zero(self.counter_bytes.ptr(), 4)

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
            memcpy(dest=t_block.ptr(), src=self.u_block.ptr(), count=32)

            for _ in range(1, iterations):
                self.hmac(Span[UInt8, ...](ptr=self.u_block.ptr(), length=32))
                _xor_block_32(t_block.ptr(), self.u_block.ptr())

            var remaining = dklen - len(derived_key)
            var to_copy = 32 if remaining > 32 else remaining
            for b in range(to_copy):
                derived_key.append(t_block[b])

        return derived_key^

def pbkdf2_hmac_sha256(
    password: Span[UInt8, ...], salt: Span[UInt8, ...], iterations: Int, dkLen: Int
) raises -> List[UInt8]:
    if iterations < 1:
        raise Error("PBKDF2 iterations must be at least 1")
    if dkLen < 1:
        raise Error("PBKDF2 dkLen must be at least 1")
    var ctx = PBKDF2SHA256(password)
    return ctx.derive(salt, iterations, dkLen)

struct PBKDF2SHA512(Movable):
    var ipad: StackBuffer[UInt8, 128]
    var opad: StackBuffer[UInt8, 128]
    var inner_hash: StackBuffer[UInt8, 64]
    var u_block: StackBuffer[UInt8, 64]
    var counter_bytes: StackBuffer[UInt8, 4]
    var inner_ctx: SHA512Context
    var outer_ctx: SHA512Context

    def __init__(out self, password: Span[UInt8, ...]):
        self.ipad = StackBuffer[UInt8, 128](fill=0)
        self.opad = StackBuffer[UInt8, 128](fill=0)
        self.inner_hash = StackBuffer[UInt8, 64](fill=0)
        self.u_block = StackBuffer[UInt8, 64](fill=0)
        self.counter_bytes = StackBuffer[UInt8, 4](fill=0)
        self.inner_ctx = SHA512Context()
        self.outer_ctx = SHA512Context()

        var k = StackBuffer[UInt8, 128](fill=0)

        if len(password) > 128:
            var ctx = SHA512Context()
            sha512_update(ctx, password)
            sha512_final_to_buffer(ctx, k.ptr())
        else:
            memcpy(dest=k.ptr(), src=password.unsafe_ptr(), count=len(password))

        for i in range(128):
            self.ipad[i] = k[i] ^ 0x36
            self.opad[i] = k[i] ^ 0x5C
        memset_zero(k.ptr(), 128)

    def __del__(deinit self):
        memset_zero(self.ipad.ptr(), 128)
        memset_zero(self.opad.ptr(), 128)
        memset_zero(self.inner_hash.ptr(), 64)
        memset_zero(self.u_block.ptr(), 64)
        memset_zero(self.counter_bytes.ptr(), 4)

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
            memcpy(dest=t_block.ptr(), src=self.u_block.ptr(), count=64)

            for _ in range(1, iterations):
                self.hmac(Span[UInt8, ...](ptr=self.u_block.ptr(), length=64))
                _xor_block_64(t_block.ptr(), self.u_block.ptr())

            var remaining = dklen - len(derived_key)
            var to_copy = 64 if remaining > 64 else remaining
            for b in range(to_copy):
                derived_key.append(t_block[b])

        return derived_key^

def pbkdf2_hmac_sha512(
    password: Span[UInt8, ...], salt: Span[UInt8, ...], iterations: Int, dkLen: Int
) raises -> List[UInt8]:
    if iterations < 1:
        raise Error("PBKDF2 iterations must be at least 1")
    if dkLen < 1:
        raise Error("PBKDF2 dkLen must be at least 1")
    var ctx = PBKDF2SHA512(password)
    return ctx.derive(salt, iterations, dkLen)

def hmac_sha256(key: Span[UInt8, ...], data: Span[UInt8, ...]) -> List[UInt8]:
    var ctx = PBKDF2SHA256(key)
    ctx.hmac(data)
    var result = List[UInt8](capacity=32)
    for i in range(32):
        result.append(ctx.u_block[i])
    return result^

def hmac_sha512(key: Span[UInt8, ...], data: Span[UInt8, ...]) -> List[UInt8]:
    var ctx = PBKDF2SHA512(key)
    ctx.hmac(data)
    var result = List[UInt8](capacity=64)
    for i in range(64):
        result.append(ctx.u_block[i])
    return result^