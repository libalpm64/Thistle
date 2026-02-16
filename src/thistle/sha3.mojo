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
SHA-3 (Keccak) Implementation in Mojo
FIPS 202
By Libalpm64, Attribute not required.
"""

from collections import List
from memory import UnsafePointer
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

# Rho rotation offsets: state[x][y] rotates by ROTATIONS[x][y]
# x=0  1  2  3  4
# y=0  0  1 62 28 27
# y=1 36 44  6 55 20
# y=2  3 10 43 25 39
# y=3 41 45 15 21  8
# y=4 18  2 61 56 14

@always_inline
fn rotl64[n: Int](x: UInt64) -> UInt64:
    """Rotate left 64-bit using compile-time intrinsic."""
    return rotate_bits_left[n](x)


fn keccak_f1600(mut state: InlineArray[UInt64, 25]):
    """Keccak-f[1600] permutation with 24 rounds.
    
    State is organized as 5x5 lanes of 64-bit words.
    Uses SIMD vectors for efficient parallel processing.
    """
    var r0 = SIMD[DType.uint64, 8](
        state[0], state[1], state[2], state[3], state[4], 0, 0, 0
    )
    var r1 = SIMD[DType.uint64, 8](
        state[5], state[6], state[7], state[8], state[9], 0, 0, 0
    )
    var r2 = SIMD[DType.uint64, 8](
        state[10], state[11], state[12], state[13], state[14], 0, 0, 0
    )
    var r3 = SIMD[DType.uint64, 8](
        state[15], state[16], state[17], state[18], state[19], 0, 0, 0
    )
    var r4 = SIMD[DType.uint64, 8](
        state[20], state[21], state[22], state[23], state[24], 0, 0, 0
    )

    @parameter
    for round in range(24):
        # Theta step
        var C = r0 ^ r1 ^ r2 ^ r3 ^ r4
        var C40123 = SIMD[DType.uint64, 8](
            C[4], C[0], C[1], C[2], C[3], 0, 0, 0
        )
        var C12340 = SIMD[DType.uint64, 8](
            C[1], C[2], C[3], C[4], C[0], 0, 0, 0
        )
        var D = C40123 ^ ((C12340 << 1) | (C12340 >> 63))
        r0 ^= D
        r1 ^= D
        r2 ^= D
        r3 ^= D
        r4 ^= D
        # Rho and Pi steps
        var b0 = SIMD[DType.uint64, 8](
            r0[0],
            rotl64[44](r1[1]),
            rotl64[43](r2[2]),
            rotl64[21](r3[3]),
            rotl64[14](r4[4]),
            0,
            0,
            0,
        )
        var b1 = SIMD[DType.uint64, 8](
            rotl64[28](r0[3]),
            rotl64[20](r1[4]),
            rotl64[3](r2[0]),
            rotl64[45](r3[1]),
            rotl64[61](r4[2]),
            0,
            0,
            0,
        )
        var b2 = SIMD[DType.uint64, 8](
            rotl64[1](r0[1]),
            rotl64[6](r1[2]),
            rotl64[25](r2[3]),
            rotl64[8](r3[4]),
            rotl64[18](r4[0]),
            0,
            0,
            0,
        )
        var b3 = SIMD[DType.uint64, 8](
            rotl64[27](r0[4]),
            rotl64[36](r1[0]),
            rotl64[10](r2[1]),
            rotl64[15](r3[2]),
            rotl64[56](r4[3]),
            0,
            0,
            0,
        )
        var b4 = SIMD[DType.uint64, 8](
            rotl64[62](r0[2]),
            rotl64[55](r1[3]),
            rotl64[39](r2[4]),
            rotl64[41](r3[0]),
            rotl64[2](r4[1]),
            0,
            0,
            0,
        )
        # Chi step: A[x,y] = B[x,y] ^ ((~B[x+1,y]) & B[x+2,y])
        r0 = b0 ^ (
            ~SIMD[DType.uint64, 8](b0[1], b0[2], b0[3], b0[4], b0[0], 0, 0, 0)
            & SIMD[DType.uint64, 8](b0[2], b0[3], b0[4], b0[0], b0[1], 0, 0, 0)
        )
        r1 = b1 ^ (
            ~SIMD[DType.uint64, 8](b1[1], b1[2], b1[3], b1[4], b1[0], 0, 0, 0)
            & SIMD[DType.uint64, 8](b1[2], b1[3], b1[4], b1[0], b1[1], 0, 0, 0)
        )
        r2 = b2 ^ (
            ~SIMD[DType.uint64, 8](b2[1], b2[2], b2[3], b2[4], b2[0], 0, 0, 0)
            & SIMD[DType.uint64, 8](b2[2], b2[3], b2[4], b2[0], b2[1], 0, 0, 0)
        )
        r3 = b3 ^ (
            ~SIMD[DType.uint64, 8](b3[1], b3[2], b3[3], b3[4], b3[0], 0, 0, 0)
            & SIMD[DType.uint64, 8](b3[2], b3[3], b3[4], b3[0], b3[1], 0, 0, 0)
        )
        r4 = b4 ^ (
            ~SIMD[DType.uint64, 8](b4[1], b4[2], b4[3], b4[4], b4[0], 0, 0, 0)
            & SIMD[DType.uint64, 8](b4[2], b4[3], b4[4], b4[0], b4[1], 0, 0, 0)
        )
        # Iota step
        r0[0] = r0[0] ^ KECCAK_RC[round]

    for x in range(5):
        state[x] = r0[x]
        state[x + 5] = r1[x]
        state[x + 10] = r2[x]
        state[x + 15] = r3[x]
        state[x + 20] = r4[x]


@always_inline
fn rotl64_simd(v: SIMD[DType.uint64, 8], s: Int) -> SIMD[DType.uint64, 8]:
    """Rotate left for SIMD vector."""
    return (v << s) | (v >> (64 - s))


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
    var state: InlineArray[UInt64, 25]
    var rate_bytes: Int
    var buffer: InlineArray[UInt8, 168]
    var buffer_len: Int

    fn __init__(out self, rate_bits: Int):
        self.state = InlineArray[UInt64, 25](fill=0)
        self.rate_bytes = rate_bits // 8
        self.buffer = InlineArray[UInt8, 168](fill=0)
        self.buffer_len = 0

    fn __moveinit__(out self, deinit other: Self):
        self.state = other.state^
        self.rate_bytes = other.rate_bytes
        self.buffer = other.buffer^
        self.buffer_len = other.buffer_len


fn sha3_absorb_block(mut state: InlineArray[UInt64, 25], block: Span[UInt8]):
    """XOR block into state and apply permutation."""
    var block_ptr = block.unsafe_ptr().bitcast[UInt64]()
    for i in range(len(block) // 8):
        state[i] ^= block_ptr[i]
    keccak_f1600(state)


fn sha3_update(mut ctx: SHA3Context, data: Span[UInt8]):
    """Update context with input data."""
    var i = 0
    var total_len = len(data)
    
    if ctx.buffer_len > 0:
        var available = ctx.rate_bytes - ctx.buffer_len
        if total_len >= available:
            for j in range(available):
                ctx.buffer[ctx.buffer_len + j] = data[i + j]
            sha3_absorb_block(
                ctx.state,
                Span[UInt8](ptr=ctx.buffer.unsafe_ptr(), length=ctx.rate_bytes),
            )
            ctx.buffer_len = 0
            i += available
        else:
            for j in range(len(data)):
                ctx.buffer[ctx.buffer_len + j] = data[i + j]
            ctx.buffer_len += len(data)
            return

    while i + ctx.rate_bytes <= len(data):
        sha3_absorb_block(ctx.state, data[i : i + ctx.rate_bytes])
        i += ctx.rate_bytes

    if i < len(data):
        for j in range(len(data) - i):
            ctx.buffer[ctx.buffer_len + j] = data[i + j]
        ctx.buffer_len += len(data) - i


fn sha3_final(mut ctx: SHA3Context, output_len_bytes: Int) -> List[UInt8]:
    """Finalize and return hash output.
    
    Applies SHA-3 padding (domain separation 0x06, pad10*1).
    """
    ctx.buffer[ctx.buffer_len] = 0x06
    ctx.buffer_len += 1

    while ctx.buffer_len < ctx.rate_bytes:
        ctx.buffer[ctx.buffer_len] = 0
        ctx.buffer_len += 1

    ctx.buffer[ctx.rate_bytes - 1] |= 0x80

    sha3_absorb_block(
        ctx.state,
        Span[UInt8](ptr=ctx.buffer.unsafe_ptr(), length=ctx.rate_bytes),
    )

    var output = List[UInt8](capacity=output_len_bytes)
    var output_offset = 0

    while output_offset < output_len_bytes:
        var limit = ctx.rate_bytes
        if output_len_bytes - output_offset < limit:
            limit = output_len_bytes - output_offset

        for i in range(limit // 8):
            var lane = ctx.state[i]
            output.append(UInt8(lane & 0xFF))
            output.append(UInt8((lane >> 8) & 0xFF))
            output.append(UInt8((lane >> 16) & 0xFF))
            output.append(UInt8((lane >> 24) & 0xFF))
            output.append(UInt8((lane >> 32) & 0xFF))
            output.append(UInt8((lane >> 40) & 0xFF))
            output.append(UInt8((lane >> 48) & 0xFF))
            output.append(UInt8((lane >> 56) & 0xFF))

        var remaining = limit % 8
        if remaining > 0:
            var lane = ctx.state[limit // 8]
            for k in range(remaining):
                output.append(UInt8((lane >> (k * 8)) & 0xFF))

        output_offset += limit

        if output_offset < output_len_bytes:
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
