# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Libalpm64, Lostlab Technologies.

"""
SHA-3 (Keccak) + shake128/shake256 Implementation in Mojo
FIPS 202
By Libalpm64, Attribute not required.
"""

from std.collections import List
from std.memory import UnsafePointer, memcpy, memset_zero
from .utils import StackBuffer
from std.bit import rotate_bits_left
from std.builtin.simd import SIMD
from std.builtin.dtype import DType

comptime KECCAK_RC = SIMD[DType.uint64, 24](
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B,
    0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080,
    0x0000000080000001, 0x8000000080008008,
)

comptime HEX_CHARS = SIMD[DType.uint8, 16](
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
)


@always_inline
def rotl64[n: Int](x: UInt64) -> UInt64:
    return rotate_bits_left[n](x)


def keccak_f1600(state: UnsafePointer[UInt64, MutAnyOrigin]):
    var a0 = state[0]
    var a1 = state[1]
    var a2 = state[2]
    var a3 = state[3]
    var a4 = state[4]
    var a5 = state[5]
    var a6 = state[6]
    var a7 = state[7]
    var a8 = state[8]
    var a9 = state[9]
    var a10 = state[10]
    var a11 = state[11]
    var a12 = state[12]
    var a13 = state[13]
    var a14 = state[14]
    var a15 = state[15]
    var a16 = state[16]
    var a17 = state[17]
    var a18 = state[18]
    var a19 = state[19]
    var a20 = state[20]
    var a21 = state[21]
    var a22 = state[22]
    var a23 = state[23]
    var a24 = state[24]

    comptime for round in range(24):
        var c0 = a0 ^ a5 ^ a10 ^ a15 ^ a20
        var c1 = a1 ^ a6 ^ a11 ^ a16 ^ a21
        var c2 = a2 ^ a7 ^ a12 ^ a17 ^ a22
        var c3 = a3 ^ a8 ^ a13 ^ a18 ^ a23
        var c4 = a4 ^ a9 ^ a14 ^ a19 ^ a24

        var d0 = c4 ^ rotl64[1](c1)
        var d1 = c0 ^ rotl64[1](c2)
        var d2 = c1 ^ rotl64[1](c3)
        var d3 = c2 ^ rotl64[1](c4)
        var d4 = c3 ^ rotl64[1](c0)

        a0 ^= d0
        a1 ^= d1
        a2 ^= d2
        a3 ^= d3
        a4 ^= d4
        a5 ^= d0
        a6 ^= d1
        a7 ^= d2
        a8 ^= d3
        a9 ^= d4
        a10 ^= d0
        a11 ^= d1
        a12 ^= d2
        a13 ^= d3
        a14 ^= d4
        a15 ^= d0
        a16 ^= d1
        a17 ^= d2
        a18 ^= d3
        a19 ^= d4
        a20 ^= d0
        a21 ^= d1
        a22 ^= d2
        a23 ^= d3
        a24 ^= d4

        var b0 = a0
        var b1 = rotl64[44](a6)
        var b2 = rotl64[43](a12)
        var b3 = rotl64[21](a18)
        var b4 = rotl64[14](a24)
        var b5 = rotl64[28](a3)
        var b6 = rotl64[20](a9)
        var b7 = rotl64[3](a10)
        var b8 = rotl64[45](a16)
        var b9 = rotl64[61](a22)
        var b10 = rotl64[1](a1)
        var b11 = rotl64[6](a7)
        var b12 = rotl64[25](a13)
        var b13 = rotl64[8](a19)
        var b14 = rotl64[18](a20)
        var b15 = rotl64[27](a4)
        var b16 = rotl64[36](a5)
        var b17 = rotl64[10](a11)
        var b18 = rotl64[15](a17)
        var b19 = rotl64[56](a23)
        var b20 = rotl64[62](a2)
        var b21 = rotl64[55](a8)
        var b22 = rotl64[39](a14)
        var b23 = rotl64[41](a15)
        var b24 = rotl64[2](a21)

        a0 = b0 ^ (~b1 & b2)
        a1 = b1 ^ (~b2 & b3)
        a2 = b2 ^ (~b3 & b4)
        a3 = b3 ^ (~b4 & b0)
        a4 = b4 ^ (~b0 & b1)
        a5 = b5 ^ (~b6 & b7)
        a6 = b6 ^ (~b7 & b8)
        a7 = b7 ^ (~b8 & b9)
        a8 = b8 ^ (~b9 & b5)
        a9 = b9 ^ (~b5 & b6)
        a10 = b10 ^ (~b11 & b12)
        a11 = b11 ^ (~b12 & b13)
        a12 = b12 ^ (~b13 & b14)
        a13 = b13 ^ (~b14 & b10)
        a14 = b14 ^ (~b10 & b11)
        a15 = b15 ^ (~b16 & b17)
        a16 = b16 ^ (~b17 & b18)
        a17 = b17 ^ (~b18 & b19)
        a18 = b18 ^ (~b19 & b15)
        a19 = b19 ^ (~b15 & b16)
        a20 = b20 ^ (~b21 & b22)
        a21 = b21 ^ (~b22 & b23)
        a22 = b22 ^ (~b23 & b24)
        a23 = b23 ^ (~b24 & b20)
        a24 = b24 ^ (~b20 & b21)

        a0 ^= KECCAK_RC[round]

    state[0] = a0
    state[1] = a1
    state[2] = a2
    state[3] = a3
    state[4] = a4
    state[5] = a5
    state[6] = a6
    state[7] = a7
    state[8] = a8
    state[9] = a9
    state[10] = a10
    state[11] = a11
    state[12] = a12
    state[13] = a13
    state[14] = a14
    state[15] = a15
    state[16] = a16
    state[17] = a17
    state[18] = a18
    state[19] = a19
    state[20] = a20
    state[21] = a21
    state[22] = a22
    state[23] = a23
    state[24] = a24


@always_inline
def nibble_to_hex_char(nibble: UInt8) -> UInt8:
    if nibble < 10:
        return nibble + 0x30
    else:
        return nibble - 10 + 0x61


@always_inline
def bytes_to_hex_simd(data: UnsafePointer[UInt8, ImmutAnyOrigin], len: Int) -> String:
    var result = String(capacity=len * 2)
    for i in range(len):
        var b = data[i]
        result += chr(Int(nibble_to_hex_char((b >> 4) & 0x0F)))
        result += chr(Int(nibble_to_hex_char(b & 0x0F)))
    return result


def bytes_to_hex(data: List[UInt8]) -> String:
    return bytes_to_hex_simd(data.unsafe_ptr(), len(data))


def string_to_bytes(s: String) -> List[UInt8]:
    var bytes = s.as_bytes()
    var data = List[UInt8](capacity=len(bytes))
    for i in range(len(bytes)):
        data.append(bytes[i])
    return data^


struct SHA3Context(Movable):
    var state: StackBuffer[UInt64, 25]
    var rate_bytes: Int
    var buffer: StackBuffer[UInt8, 168]
    var buffer_len: Int

    def __init__(out self, rate_bits: Int):
        self.state = StackBuffer[UInt64, 25](fill=0)
        self.rate_bytes = rate_bits // 8
        self.buffer = StackBuffer[UInt8, 168](fill=0)
        self.buffer_len = 0

    def __init__(out self, *, deinit take: Self):
        self.state = take.state^
        self.rate_bytes = take.rate_bytes
        self.buffer = take.buffer^
        self.buffer_len = take.buffer_len

    def __del__(deinit self):
        pass


@always_inline
def sha3_absorb_block(state: UnsafePointer[UInt64, MutAnyOrigin], block: UnsafePointer[UInt8, ImmutAnyOrigin], rate_bytes: Int):
    var full_lanes = rate_bytes // 8
    for i in range(full_lanes):
        state[i] ^= (block + i * 8).bitcast[UInt64]().load[width=1, alignment=1]()
    keccak_f1600(state)


def sha3_update(mut ctx: SHA3Context, data: Span[UInt8, ...]):
    var i = 0
    var total_len = len(data)

    if ctx.buffer_len > 0:
        var available = ctx.rate_bytes - ctx.buffer_len
        if total_len >= available:
            memcpy(
                dest=ctx.buffer.ptr() + ctx.buffer_len,
                src=data.unsafe_ptr(),
                count=available,
            )
            sha3_absorb_block(ctx.state.ptr(), ctx.buffer.ptr(), ctx.rate_bytes)
            ctx.buffer_len = 0
            i += available
        else:
            memcpy(
                dest=ctx.buffer.ptr() + ctx.buffer_len,
                src=data.unsafe_ptr(),
                count=total_len,
            )
            ctx.buffer_len += total_len
            return

    while i + ctx.rate_bytes <= total_len:
        sha3_absorb_block(ctx.state.ptr(), data.unsafe_ptr() + i, ctx.rate_bytes)
        i += ctx.rate_bytes

    if i < total_len:
        var remaining = total_len - i
        memcpy(
            dest=ctx.buffer.ptr(),
            src=data.unsafe_ptr() + i,
            count=remaining,
        )
        ctx.buffer_len = remaining


def sha3_final(mut ctx: SHA3Context, output_len_bytes: Int) -> List[UInt8]:
    ctx.buffer[ctx.buffer_len] = 0x06
    ctx.buffer_len += 1

    var pad_len = ctx.rate_bytes - ctx.buffer_len
    if pad_len > 0:
        memset_zero(ctx.buffer.ptr() + ctx.buffer_len, pad_len)
        ctx.buffer_len = ctx.rate_bytes

    ctx.buffer[ctx.rate_bytes - 1] |= 0x80
    sha3_absorb_block(ctx.state.ptr(), ctx.buffer.ptr(), ctx.rate_bytes)

    var output = List[UInt8](capacity=output_len_bytes)
    for _ in range(output_len_bytes):
        output.append(0)

    var offset = 0
    while offset < output_len_bytes:
        var limit = ctx.rate_bytes
        if output_len_bytes - offset < limit:
            limit = output_len_bytes - offset

        memcpy(
            dest=output.unsafe_ptr() + offset,
            src=ctx.state.ptr().bitcast[UInt8](),
            count=limit,
        )

        offset += limit
        if offset < output_len_bytes:
            keccak_f1600(ctx.state.ptr())

    return output^


@always_inline
def sha3_final_into(mut ctx: SHA3Context, mut output: StackBuffer[UInt8, ...], output_len_bytes: Int):
    output.clear()
    ctx.buffer[ctx.buffer_len] = 0x06
    ctx.buffer_len += 1

    var pad_len = ctx.rate_bytes - ctx.buffer_len
    if pad_len > 0:
        memset_zero(ctx.buffer.ptr() + ctx.buffer_len, pad_len)
        ctx.buffer_len = ctx.rate_bytes

    ctx.buffer[ctx.rate_bytes - 1] |= 0x80
    sha3_absorb_block(ctx.state.ptr(), ctx.buffer.ptr(), ctx.rate_bytes)

    output.set_len_unchecked(output_len_bytes)

    var offset = 0
    while offset < output_len_bytes:
        var limit = ctx.rate_bytes
        if output_len_bytes - offset < limit:
            limit = output_len_bytes - offset

        memcpy(
            dest=output.ptr() + offset,
            src=ctx.state.ptr().bitcast[UInt8](),
            count=limit,
        )

        offset += limit
        if offset < output_len_bytes:
            keccak_f1600(ctx.state.ptr())


@always_inline
def sha3_hash(rate_bits: Int, data: Span[UInt8, ...], output_len: Int) -> List[UInt8]:
    var ctx = SHA3Context(rate_bits)
    sha3_update(ctx, data)
    return sha3_final(ctx, output_len)


@always_inline
def sha3_hash_into(mut output: StackBuffer[UInt8, ...], rate_bits: Int, data: Span[UInt8, ...], output_len: Int):
    var ctx = SHA3Context(rate_bits)
    sha3_update(ctx, data)
    sha3_final_into(ctx, output, output_len)


def sha3_224(data: Span[UInt8, ...]) -> List[UInt8]:
    return sha3_hash(1152, data, 28)


def sha3_256(data: Span[UInt8, ...]) -> List[UInt8]:
    return sha3_hash(1088, data, 32)


def sha3_384(data: Span[UInt8, ...]) -> List[UInt8]:
    return sha3_hash(832, data, 48)


def sha3_512(data: Span[UInt8, ...]) -> List[UInt8]:
    return sha3_hash(576, data, 64)


@always_inline
def sha3_256_into(mut output: StackBuffer[UInt8, ...], data: Span[UInt8, ...]):
    sha3_hash_into(output, 1088, data, 32)


@always_inline
def sha3_512_into(mut output: StackBuffer[UInt8, ...], data: Span[UInt8, ...]):
    sha3_hash_into(output, 576, data, 64)


def sha3_224_hash_string(s: String) -> String:
    var data = string_to_bytes(s)
    var hash = sha3_224(Span[UInt8, ...](data))
    return bytes_to_hex(hash)


def sha3_256_hash_string(s: String) -> String:
    var data = string_to_bytes(s)
    var hash = sha3_256(Span[UInt8, ...](data))
    return bytes_to_hex(hash)


def sha3_384_hash_string(s: String) -> String:
    var data = string_to_bytes(s)
    var hash = sha3_384(Span[UInt8, ...](data))
    return bytes_to_hex(hash)


def sha3_512_hash_string(s: String) -> String:
    var data = string_to_bytes(s)
    var hash = sha3_512(Span[UInt8, ...](data))
    return bytes_to_hex(hash)


@always_inline
def shake_finalize(mut ctx: SHA3Context):
    ctx.buffer[ctx.buffer_len] = 0x1F
    ctx.buffer_len += 1

    var pad_len = ctx.rate_bytes - ctx.buffer_len
    if pad_len > 0:
        memset_zero(ctx.buffer.ptr() + ctx.buffer_len, pad_len)
        ctx.buffer_len = ctx.rate_bytes

    ctx.buffer[ctx.rate_bytes - 1] |= 0x80
    sha3_absorb_block(ctx.state.ptr(), ctx.buffer.ptr(), ctx.rate_bytes)
    ctx.buffer_len = 0


@always_inline
def shake_squeeze_block_into(mut ctx: SHA3Context, mut output: StackBuffer[UInt8, ...]):
    output.clear()
    output.set_len_unchecked(ctx.rate_bytes)
    memcpy(
        dest=output.ptr(),
        src=ctx.state.ptr().bitcast[UInt8](),
        count=ctx.rate_bytes,
    )
    keccak_f1600(ctx.state.ptr())


@always_inline
def shake_squeeze_into(mut ctx: SHA3Context, mut output: StackBuffer[UInt8, ...], output_len: Int):
    output.clear()
    output.set_len_unchecked(output_len)

    var offset = 0
    while offset < output_len:
        var limit = ctx.rate_bytes
        if output_len - offset < limit:
            limit = output_len - offset

        memcpy(
            dest=output.ptr() + offset,
            src=ctx.state.ptr().bitcast[UInt8](),
            count=limit,
        )

        offset += limit
        keccak_f1600(ctx.state.ptr())


@always_inline
def shake_squeeze_prefix_into(mut ctx: SHA3Context, mut output: StackBuffer[UInt8, ...], output_len: Int):
    output.clear()
    output.set_len_unchecked(output_len)

    var offset = 0
    while offset < output_len:
        var limit = ctx.rate_bytes
        if output_len - offset < limit:
            limit = output_len - offset

        memcpy(
            dest=output.ptr() + offset,
            src=ctx.state.ptr().bitcast[UInt8](),
            count=limit,
        )

        offset += limit
        if offset < output_len:
            keccak_f1600(ctx.state.ptr())


@always_inline
def shake_advance(mut ctx: SHA3Context):
    keccak_f1600(ctx.state.ptr())



@always_inline
def shake_final(mut ctx: SHA3Context, output_len: Int) -> List[UInt8]:
    shake_finalize(ctx)

    var output = List[UInt8](capacity=output_len)
    for _ in range(output_len):
        output.append(0)

    var offset = 0
    while offset < output_len:
        var limit = ctx.rate_bytes
        if output_len - offset < limit:
            limit = output_len - offset

        memcpy(
            dest=output.unsafe_ptr() + offset,
            src=ctx.state.ptr().bitcast[UInt8](),
            count=limit,
        )

        offset += limit
        if offset < output_len:
            keccak_f1600(ctx.state.ptr())

    return output^


@always_inline
def shake_final_into(mut ctx: SHA3Context, mut output: StackBuffer[UInt8, ...], output_len: Int):
    output.clear()
    shake_finalize(ctx)

    output.set_len_unchecked(output_len)

    var offset = 0
    while offset < output_len:
        var limit = ctx.rate_bytes
        if output_len - offset < limit:
            limit = output_len - offset

        memcpy(
            dest=output.ptr() + offset,
            src=ctx.state.ptr().bitcast[UInt8](),
            count=limit,
        )

        offset += limit
        if offset < output_len:
            keccak_f1600(ctx.state.ptr())


@always_inline
def shake_hash(rate_bits: Int, data: Span[UInt8, ...], output_len: Int) -> List[UInt8]:
    var ctx = SHA3Context(rate_bits)
    sha3_update(ctx, data)
    return shake_final(ctx, output_len)


@always_inline
def shake_hash_into(mut output: StackBuffer[UInt8, ...], rate_bits: Int, data: Span[UInt8, ...], output_len: Int):
    var ctx = SHA3Context(rate_bits)
    sha3_update(ctx, data)
    shake_final_into(ctx, output, output_len)



def shake128(data: Span[UInt8, ...], output_len_bytes: Int) -> List[UInt8]:
    return shake_hash(1344, data, output_len_bytes)


def shake256(data: Span[UInt8, ...], output_len_bytes: Int) -> List[UInt8]:
    return shake_hash(1088, data, output_len_bytes)


@always_inline
def shake128_into(mut output: StackBuffer[UInt8, ...], data: Span[UInt8, ...], output_len_bytes: Int):
    shake_hash_into(output, 1344, data, output_len_bytes)


@always_inline
def shake256_into(mut output: StackBuffer[UInt8, ...], data: Span[UInt8, ...], output_len_bytes: Int):
    shake_hash_into(output, 1088, data, output_len_bytes)
