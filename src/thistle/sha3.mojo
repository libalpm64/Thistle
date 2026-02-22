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
SHA-3 (Keccak) + shake128/shake256 Implementation in Mojo
FIPS 202
By Libalpm64, Attribute not required.
"""

from collections import List
from memory import UnsafePointer, alloc, memcpy
from bit import rotate_bits_left

comptime KECCAK_RC = SIMD[DType.uint64, 24](
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)


@always_inline
fn rotl64[n: Int](x: UInt64) -> UInt64:
    """Rotate left 64-bit using compile-time intrinsic."""
    return rotate_bits_left[n](x)


@always_inline
fn zero_buffer(ptr: UnsafePointer[UInt8, MutAnyOrigin], len: Int):
    for i in range(len):
        ptr[i] = 0


@always_inline
fn zero_and_free(ptr: UnsafePointer[UInt8, MutAnyOrigin], len: Int):
    zero_buffer(ptr, len)
    ptr.free()


@always_inline
fn zero_and_free_u64(ptr: UnsafePointer[UInt64, MutAnyOrigin], len: Int):
    for i in range(len):
        ptr[i] = 0
    ptr.free()


fn keccak_f1600(mut state: UnsafePointer[UInt64, MutAnyOrigin]):
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

    for round in range(24):
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
fn nibble_to_hex_char(nibble: UInt8) -> UInt8:
    """Convert 4-bit nibble to hex character."""
    if nibble < 10:
        return nibble + 0x30
    else:
        return nibble - 10 + 0x61


fn bytes_to_hex(data: List[UInt8]) -> String:
    """Convert byte list to hex string."""
    var result = String()
    for i in range(len(data)):
        var b = data[i]
        var high = (b >> 4) & 0x0F
        var low = b & 0x0F
        result += chr(Int(nibble_to_hex_char(high)))
        result += chr(Int(nibble_to_hex_char(low)))
    return result


fn string_to_bytes(s: String) -> List[UInt8]:
    """Convert string to byte list."""
    var data = List[UInt8]()
    var bytes = s.as_bytes()
    for i in range(len(bytes)):
        data.append(bytes[i])
    return data^


struct SHA3Context(Movable):
    """SHA-3 hashing context."""
    var state: UnsafePointer[UInt64, MutAnyOrigin]
    var rate_bytes: Int
    var buffer: UnsafePointer[UInt8, MutAnyOrigin]
    var buffer_len: Int

    fn __init__(out self, rate_bits: Int):
        self.state = alloc[UInt64](25)
        for i in range(25):
            self.state[i] = 0
        self.rate_bytes = rate_bits // 8
        self.buffer = alloc[UInt8](168)
        for i in range(168):
            self.buffer[i] = 0
        self.buffer_len = 0

    fn __moveinit__(out self, deinit other: Self):
        self.state = other.state
        self.rate_bytes = other.rate_bytes
        self.buffer = other.buffer
        self.buffer_len = other.buffer_len

    fn __del__(deinit self):
        zero_and_free_u64(self.state, 25)
        zero_and_free(self.buffer, 168)


@always_inline
fn sha3_absorb_block(mut state: UnsafePointer[UInt64, MutAnyOrigin], block: UnsafePointer[UInt8, ImmutAnyOrigin], rate_bytes: Int):
    var block_u64 = block.bitcast[UInt64]()
    var full_lanes = rate_bytes // 8
    for i in range(full_lanes):
        state[i] ^= block_u64[i]
    keccak_f1600(state)


fn sha3_update(mut ctx: SHA3Context, data: Span[UInt8]):
    var i = 0
    var total_len = len(data)

    if ctx.buffer_len > 0:
        var available = ctx.rate_bytes - ctx.buffer_len
        if total_len >= available:
            memcpy(
                dest=ctx.buffer + ctx.buffer_len,
                src=data.unsafe_ptr(),
                count=available,
            )
            sha3_absorb_block(ctx.state, ctx.buffer, ctx.rate_bytes)
            ctx.buffer_len = 0
            i += available
        else:
            memcpy(
                dest=ctx.buffer + ctx.buffer_len,
                src=data.unsafe_ptr(),
                count=total_len,
            )
            ctx.buffer_len += total_len
            return

    while i + ctx.rate_bytes <= total_len:
        sha3_absorb_block(ctx.state, data.unsafe_ptr() + i, ctx.rate_bytes)
        i += ctx.rate_bytes

    if i < total_len:
        var remaining = total_len - i
        memcpy(
            dest=ctx.buffer,
            src=data.unsafe_ptr() + i,
            count=remaining,
        )
        ctx.buffer_len = remaining


fn sha3_final(mut ctx: SHA3Context, output_len_bytes: Int) -> List[UInt8]:
    ctx.buffer[ctx.buffer_len] = 0x06
    ctx.buffer_len += 1

    while ctx.buffer_len < ctx.rate_bytes:
        ctx.buffer[ctx.buffer_len] = 0
        ctx.buffer_len += 1

    ctx.buffer[ctx.rate_bytes - 1] |= 0x80

    sha3_absorb_block(ctx.state, ctx.buffer, ctx.rate_bytes)

    var output = List[UInt8](capacity=output_len_bytes)
    var offset = 0

    while offset < output_len_bytes:
        var limit = ctx.rate_bytes
        if output_len_bytes - offset < limit:
            limit = output_len_bytes - offset

        var state_bytes = ctx.state.bitcast[UInt8]()
        for i in range(limit):
            output.append(state_bytes[i])

        offset += limit

        if offset < output_len_bytes:
            keccak_f1600(ctx.state)

    return output^

fn sha3_224(data: Span[UInt8]) -> List[UInt8]:
    """SHA3-224 hash (28 bytes output)."""
    var ctx = SHA3Context(1152)
    sha3_update(ctx, data)
    return sha3_final(ctx, 28)


fn sha3_256(data: Span[UInt8]) -> List[UInt8]:
    """SHA3-256 hash (32 bytes output)."""
    var ctx = SHA3Context(1088)
    sha3_update(ctx, data)
    return sha3_final(ctx, 32)


fn sha3_384(data: Span[UInt8]) -> List[UInt8]:
    """SHA3-384 hash (48 bytes output)."""
    var ctx = SHA3Context(832)
    sha3_update(ctx, data)
    return sha3_final(ctx, 48)


fn sha3_512(data: Span[UInt8]) -> List[UInt8]:
    """SHA3-512 hash (64 bytes output)."""
    var ctx = SHA3Context(576)
    sha3_update(ctx, data)
    return sha3_final(ctx, 64)


fn sha3_224_hash_string(s: String) -> String:
    """SHA3-224 hash of string, returned as hex."""
    var data = string_to_bytes(s)
    var hash = sha3_224(Span[UInt8](data))
    return bytes_to_hex(hash)


fn sha3_256_hash_string(s: String) -> String:
    """SHA3-256 hash of string, returned as hex."""
    var data = string_to_bytes(s)
    var hash = sha3_256(Span[UInt8](data))
    return bytes_to_hex(hash)


fn sha3_384_hash_string(s: String) -> String:
    """SHA3-384 hash of string, returned as hex."""
    var data = string_to_bytes(s)
    var hash = sha3_384(Span[UInt8](data))
    return bytes_to_hex(hash)


fn sha3_512_hash_string(s: String) -> String:
    """SHA3-512 hash of string, returned as hex."""
    var data = string_to_bytes(s)
    var hash = sha3_512(Span[UInt8](data))
    return bytes_to_hex(hash)


fn shake128(data: Span[UInt8], output_len_bytes: Int) -> List[UInt8]:
    """SHAKE128 XOF (capacity=256 bits, rate=1344 bits)."""
    var ctx = SHA3Context(1344)
    sha3_update(ctx, data)
    ctx.buffer[ctx.buffer_len] = 0x1F
    ctx.buffer_len += 1
    while ctx.buffer_len < ctx.rate_bytes:
        ctx.buffer[ctx.buffer_len] = 0
        ctx.buffer_len += 1
    ctx.buffer[ctx.rate_bytes - 1] |= 0x80
    sha3_absorb_block(ctx.state, ctx.buffer, ctx.rate_bytes)
    
    var output = List[UInt8](capacity=output_len_bytes)
    var offset = 0
    while offset < output_len_bytes:
        var limit = ctx.rate_bytes
        if output_len_bytes - offset < limit:
            limit = output_len_bytes - offset
        var state_bytes = ctx.state.bitcast[UInt8]()
        for i in range(limit):
            output.append(state_bytes[i])
        offset += limit
        if offset < output_len_bytes:
            keccak_f1600(ctx.state)
    return output^


fn shake256(data: Span[UInt8], output_len_bytes: Int) -> List[UInt8]:
    """SHAKE256 XOF (capacity=512 bits, rate=1088 bits)."""
    var ctx = SHA3Context(1088)
    sha3_update(ctx, data)
    ctx.buffer[ctx.buffer_len] = 0x1F
    ctx.buffer_len += 1
    while ctx.buffer_len < ctx.rate_bytes:
        ctx.buffer[ctx.buffer_len] = 0
        ctx.buffer_len += 1
    ctx.buffer[ctx.rate_bytes - 1] |= 0x80
    sha3_absorb_block(ctx.state, ctx.buffer, ctx.rate_bytes)
    
    var output = List[UInt8](capacity=output_len_bytes)
    var offset = 0
    while offset < output_len_bytes:
        var limit = ctx.rate_bytes
        if output_len_bytes - offset < limit:
            limit = output_len_bytes - offset
        var state_bytes = ctx.state.bitcast[UInt8]()
        for i in range(limit):
            output.append(state_bytes[i])
        offset += limit
        if offset < output_len_bytes:
            keccak_f1600(ctx.state)
    return output^
