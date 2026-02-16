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
SHA-2 (SHA-256/SHA-512) Implementation in Mojo
RFC 6234 / FIPS 180-4 / CAVP validated
By Libalpm64, Attribute not required.

Todo:
- Add NI support for SHA-NI Hardware acceleration (~5x speedup, currently Mojo lacks proper inline assembly support)
- Note: It's limited to SHA-1 and SHA-256
"""

from collections import List
from memory import UnsafePointer
from bit import rotate_bits_left, rotate_bits_right, byte_swap


@always_inline
fn sha256_init_h0() -> UInt32:
    return 0x6A09E667


@always_inline
fn sha256_init_h1() -> UInt32:
    return 0xBB67AE85


@always_inline
fn sha256_init_h2() -> UInt32:
    return 0x3C6EF372


@always_inline
fn sha256_init_h3() -> UInt32:
    return 0xA54FF53A


@always_inline
fn sha256_init_h4() -> UInt32:
    return 0x510E527F


@always_inline
fn sha256_init_h5() -> UInt32:
    return 0x9B05688C


@always_inline
fn sha256_init_h6() -> UInt32:
    return 0x1F83D9AB


@always_inline
fn sha256_init_h7() -> UInt32:
    return 0x5BE0CD19


# SHA-256 constants K[0..63]
comptime SHA256_K = SIMD[DType.uint32, 64](
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
)

# SHA-512 Constants (64-bit words)
@always_inline
fn sha512_init_h0() -> UInt64:
    return 0x6A09E667F3BCC908


@always_inline
fn sha512_init_h1() -> UInt64:
    return 0xBB67AE8584CAA73B


@always_inline
fn sha512_init_h2() -> UInt64:
    return 0x3C6EF372FE94F82B


@always_inline
fn sha512_init_h3() -> UInt64:
    return 0xA54FF53A5F1D36F1


@always_inline
fn sha512_init_h4() -> UInt64:
    return 0x510E527FADE682D1


@always_inline
fn sha512_init_h5() -> UInt64:
    return 0x9B05688C2B3E6C1F


@always_inline
fn sha512_init_h6() -> UInt64:
    return 0x1F83D9ABFB41BD6B


@always_inline
fn sha512_init_h7() -> UInt64:
    return 0x5BE0CD19137E2179


# SHA-512 constants K[0..79]
comptime SHA512_K = SIMD[DType.uint64, 80](
    0x428A2F98D728AE22,
    0x7137449123EF65CD,
    0xB5C0FBCFEC4D3B2F,
    0xE9B5DBA58189DBBC,
    0x3956C25BF348B538,
    0x59F111F1B605D019,
    0x923F82A4AF194F9B,
    0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242,
    0x12835B0145706FBE,
    0x243185BE4EE4B28C,
    0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F,
    0x80DEB1FE3B1696B1,
    0x9BDC06A725C71235,
    0xC19BF174CF692694,
    0xE49B69C19EF14AD2,
    0xEFBE4786384F25E3,
    0x0FC19DC68B8CD5B5,
    0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275,
    0x4A7484AA6EA6E483,
    0x5CB0A9DCBD41FBD4,
    0x76F988DA831153B5,
    0x983E5152EE66DFAB,
    0xA831C66D2DB43210,
    0xB00327C898FB213F,
    0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2,
    0xD5A79147930AA725,
    0x06CA6351E003826F,
    0x142929670A0E6E70,
    0x27B70A8546D22FFC,
    0x2E1B21385C26C926,
    0x4D2C6DFC5AC42AED,
    0x53380D139D95B3DF,
    0x650A73548BAF63DE,
    0x766A0ABB3C77B2A8,
    0x81C2C92E47EDAEE6,
    0x92722C851482353B,
    0xA2BFE8A14CF10364,
    0xA81A664BBC423001,
    0xC24B8B70D0F89791,
    0xC76C51A30654BE30,
    0xD192E819D6EF5218,
    0xD69906245565A910,
    0xF40E35855771202A,
    0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8,
    0x1E376C085141AB53,
    0x2748774CDF8EEB99,
    0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63,
    0x4ED8AA4AE3418ACB,
    0x5B9CCA4F7763E373,
    0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC,
    0x78A5636F43172F60,
    0x84C87814A1F0AB72,
    0x8CC702081A6439EC,
    0x90BEFFFA23631E28,
    0xA4506CEBDE82BDE9,
    0xBEF9A3F7B2C67915,
    0xC67178F2E372532B,
    0xCA273ECEEA26619C,
    0xD186B8C721C0C207,
    0xEADA7DD6CDE0EB1E,
    0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA,
    0x0A637DC5A2C898A6,
    0x113F9804BEF90DAE,
    0x1B710B35131C471B,
    0x28DB77F523047D84,
    0x32CAAB7B40C72493,
    0x3C9EBE0A15C9BEBC,
    0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6,
    0x597F299CFC657E2A,
    0x5FCB6FAB3AD6FAEC,
    0x6C44198C4A475817,
)

# Bit Operations for SHA-256 (32-bit)
@always_inline
fn rotr32[n: Int](x: UInt32) -> UInt32:
    """Rotate right 32-bit using compile-time intrinsic."""
    return rotate_bits_right[n](x)


@always_inline
fn rotl32[n: Int](x: UInt32) -> UInt32:
    """Rotate left 32-bit using compile-time intrinsic."""
    return rotate_bits_left[n](x)


@always_inline
fn shr32[n: Int](x: UInt32) -> UInt32:
    return x >> n


@always_inline
fn ch32(x: UInt32, y: UInt32, z: UInt32) -> UInt32:
    return (x & y) ^ ((~x) & z)


@always_inline
fn maj32(x: UInt32, y: UInt32, z: UInt32) -> UInt32:
    return (x & y) ^ (x & z) ^ (y & z)


@always_inline
fn sigma0_32(x: UInt32) -> UInt32:
    return rotr32[2](x) ^ rotr32[13](x) ^ rotr32[22](x)


@always_inline
fn sigma1_32(x: UInt32) -> UInt32:
    return rotr32[6](x) ^ rotr32[11](x) ^ rotr32[25](x)


@always_inline
fn small_sigma0_32(x: UInt32) -> UInt32:
    return rotr32[7](x) ^ rotr32[18](x) ^ shr32[3](x)


@always_inline
fn small_sigma1_32(x: UInt32) -> UInt32:
    return rotr32[17](x) ^ rotr32[19](x) ^ shr32[10](x)


# Bit Operations for SHA-512 (64-bit)
@always_inline
fn rotr64[n: Int](x: UInt64) -> UInt64:
    """Rotate right 64-bit using compile-time intrinsic."""
    return rotate_bits_right[n](x)


@always_inline
fn rotl64[n: Int](x: UInt64) -> UInt64:
    """Rotate left 64-bit using compile-time intrinsic."""
    return rotate_bits_left[n](x)


@always_inline
fn shr64[n: Int](x: UInt64) -> UInt64:
    return x >> n


@always_inline
fn ch64(x: UInt64, y: UInt64, z: UInt64) -> UInt64:
    return (x & y) ^ ((~x) & z)


@always_inline
fn maj64(x: UInt64, y: UInt64, z: UInt64) -> UInt64:
    return (x & y) ^ (x & z) ^ (y & z)


@always_inline
fn sigma0_64(x: UInt64) -> UInt64:
    return rotr64[28](x) ^ rotr64[34](x) ^ rotr64[39](x)


@always_inline
fn sigma1_64(x: UInt64) -> UInt64:
    return rotr64[14](x) ^ rotr64[18](x) ^ rotr64[41](x)


@always_inline
fn small_sigma0_64(x: UInt64) -> UInt64:
    return rotr64[1](x) ^ rotr64[8](x) ^ shr64[7](x)


@always_inline
fn small_sigma1_64(x: UInt64) -> UInt64:
    return rotr64[19](x) ^ rotr64[61](x) ^ shr64[6](x)


# hex conversions
@always_inline
fn nibble_to_hex_char(nibble: UInt8) -> UInt8:
    """Convert a nibble (0-15) to its hex character ASCII value."""
    if nibble < 10:
        return nibble + 0x30  # '0' = 0x30
    else:
        return nibble - 10 + 0x61  # 'a' = 0x61


fn bytes_to_hex(data: List[UInt8]) -> String:
    """Convert a byte list to a hexadecimal string."""
    var result = String()
    for i in range(len(data)):
        var b = data[i]
        var high = (b >> 4) & 0x0F
        var low = b & 0x0F
        result += chr(Int(nibble_to_hex_char(high)))
        result += chr(Int(nibble_to_hex_char(low)))
    return result


fn bytes_to_hex(data: SIMD[DType.uint8, 16]) -> String:
    """Convert a 16-byte SIMD vector to a hexadecimal string."""
    var result = String()
    for i in range(16):
        var b = data[i]
        var high = (b >> 4) & 0x0F
        var low = b & 0x0F
        result += chr(Int(nibble_to_hex_char(high)))
        result += chr(Int(nibble_to_hex_char(low)))
    return result


fn string_to_bytes(s: String) -> List[UInt8]:
    """Convert a string to a list of bytes."""
    var data = List[UInt8]()
    var bytes = s.as_bytes()
    for i in range(len(bytes)):
        data.append(bytes[i])
    return data^

# SHA-256
struct SHA256Context(Movable):
    var state: SIMD[DType.uint32, 8]
    var count: UInt64
    var buffer: InlineArray[UInt8, 64]
    var buffer_len: Int

    fn __init__(out self):
        self.state = SIMD[DType.uint32, 8](
            sha256_init_h0(),
            sha256_init_h1(),
            sha256_init_h2(),
            sha256_init_h3(),
            sha256_init_h4(),
            sha256_init_h5(),
            sha256_init_h6(),
            sha256_init_h7(),
        )
        self.count = 0
        self.buffer = InlineArray[UInt8, 64](fill=0)
        self.buffer_len = 0

    fn __moveinit__(out self, deinit other: Self):
        self.state = other.state
        self.count = other.count
        self.buffer = other.buffer^
        self.buffer_len = other.buffer_len

@always_inline
fn sha256_transform(
    state: SIMD[DType.uint32, 8], block: Span[UInt8]
) -> SIMD[DType.uint32, 8]:
    var w = InlineArray[UInt32, 16](uninitialized=True)

    var a = state[0]
    var b = state[1]
    var c = state[2]
    var d = state[3]
    var e = state[4]
    var f = state[5]
    var g = state[6]
    var h = state[7]

    # First 16 rounds - load words and process
    @parameter
    for i in range(16):
        var byte_offset = i * 4
        var word = (UInt32(block[byte_offset]) << 24) | 
                   (UInt32(block[byte_offset + 1]) << 16) | 
                   (UInt32(block[byte_offset + 2]) << 8) | 
                   UInt32(block[byte_offset + 3])
        w[i] = word

        var t1 = h + sigma1_32(e) + ch32(e, f, g) + SHA256_K[i] + word
        var t2 = sigma0_32(a) + maj32(a, b, c)
        h = g
        g = f
        f = e
        e = d + t1
        d = c
        c = b
        b = a
        a = t1 + t2

    # Remaining 48 rounds with message schedule expansion
    @parameter
    for i in range(16, 64):
        var idx = i & 0xF
        var s0 = small_sigma0_32(w[(i - 15) & 0xF])
        var s1 = small_sigma1_32(w[(i - 2) & 0xF])
        var word = s1 + w[(i - 7) & 0xF] + s0 + w[(i - 16) & 0xF]
        w[idx] = word

        var t1 = h + sigma1_32(e) + ch32(e, f, g) + SHA256_K[i] + word
        var t2 = sigma0_32(a) + maj32(a, b, c)
        h = g
        g = f
        f = e
        e = d + t1
        d = c
        c = b
        b = a
        a = t1 + t2

    return state + SIMD[DType.uint32, 8](a, b, c, d, e, f, g, h)


fn sha256_update(mut ctx: SHA256Context, data: Span[UInt8]):
    var i = 0
    var total_len = len(data)

    if ctx.buffer_len > 0:
        var available = 64 - ctx.buffer_len
        if total_len >= available:
            for j in range(available):
                ctx.buffer[ctx.buffer_len + j] = data[i + j]
            ctx.state = sha256_transform(
                ctx.state, Span[UInt8](ptr=ctx.buffer.unsafe_ptr(), length=64)
            )
            ctx.count += 512
            i += available
            ctx.buffer_len = 0
        else:
            for j in range(total_len):
                ctx.buffer[ctx.buffer_len + j] = data[i + j]
            ctx.buffer_len += total_len
            return

    while i + 64 <= total_len:
        ctx.state = sha256_transform(ctx.state, data[i : i + 64])
        ctx.count += 512
        i += 64

    if i < total_len:
        var remaining = total_len - i
        for j in range(remaining):
            ctx.buffer[ctx.buffer_len + j] = data[i + j]
        ctx.buffer_len += remaining


fn sha256_final(mut ctx: SHA256Context) -> List[UInt8]:
    var bit_count = ctx.count + UInt64(ctx.buffer_len) * 8

    ctx.buffer[ctx.buffer_len] = 0x80
    ctx.buffer_len += 1

    if ctx.buffer_len > 56:
        while ctx.buffer_len < 64:
            ctx.buffer[ctx.buffer_len] = 0
            ctx.buffer_len += 1
        ctx.state = sha256_transform(
            ctx.state, Span[UInt8](ptr=ctx.buffer.unsafe_ptr(), length=64)
        )
        ctx.buffer_len = 0

    while ctx.buffer_len < 56:
        ctx.buffer[ctx.buffer_len] = 0
        ctx.buffer_len += 1

    for i in range(8):
        ctx.buffer[56 + i] = UInt8((bit_count >> (56 - i * 8)) & 0xFF)

    ctx.state = sha256_transform(
        ctx.state, Span[UInt8](ptr=ctx.buffer.unsafe_ptr(), length=64)
    )

    var output = List[UInt8](capacity=32)
    for i in range(8):
        output.append(UInt8((ctx.state[i] >> 24) & 0xFF))
        output.append(UInt8((ctx.state[i] >> 16) & 0xFF))
        output.append(UInt8((ctx.state[i] >> 8) & 0xFF))
        output.append(UInt8(ctx.state[i] & 0xFF))
    return output^


fn sha256_hash(data: Span[UInt8]) -> List[UInt8]:
    var ctx = SHA256Context()
    sha256_update(ctx, data)
    return sha256_final(ctx)


struct SHA512Context(Movable):
    var state: SIMD[DType.uint64, 8]
    var count_high: UInt64
    var count_low: UInt64
    var buffer: InlineArray[UInt8, 128]
    var buffer_len: Int

    fn __init__(out self):
        self.state = SIMD[DType.uint64, 8](
            0x6A09E667F3BCC908,
            0xBB67AE8584CAA73B,
            0x3C6EF372FE94F82B,
            0xA54FF53A5F1D36F1,
            0x510E527FADE682D1,
            0x9B05688C2B3E6C1F,
            0x1F83D9ABFB41BD6B,
            0x5BE0CD19137E2179,
        )
        self.count_high = 0
        self.count_low = 0
        self.buffer = InlineArray[UInt8, 128](fill=0)
        self.buffer_len = 0

    fn __moveinit__(out self, deinit other: Self):
        self.state = other.state
        self.count_high = other.count_high
        self.count_low = other.count_low
        self.buffer = other.buffer^
        self.buffer_len = other.buffer_len


@always_inline
fn sha512_transform(
    state: SIMD[DType.uint64, 8], block: Span[UInt8]
) -> SIMD[DType.uint64, 8]:
    var w = InlineArray[UInt64, 16](uninitialized=True)

    var a = state[0]
    var b = state[1]
    var c = state[2]
    var d = state[3]
    var e = state[4]
    var f = state[5]
    var g = state[6]
    var h = state[7]

    # First 16 rounds
    @parameter
    for i in range(16):
        var word: UInt64 = 0
        word |= UInt64(block[i * 8 + 0]) << 56
        word |= UInt64(block[i * 8 + 1]) << 48
        word |= UInt64(block[i * 8 + 2]) << 40
        word |= UInt64(block[i * 8 + 3]) << 32
        word |= UInt64(block[i * 8 + 4]) << 24
        word |= UInt64(block[i * 8 + 5]) << 16
        word |= UInt64(block[i * 8 + 6]) << 8
        word |= UInt64(block[i * 8 + 7])
        w[i] = word

        var t1 = h + sigma1_64(e) + ch64(e, f, g) + SHA512_K[i] + word
        var t2 = sigma0_64(a) + maj64(a, b, c)
        h = g
        g = f
        f = e
        e = d + t1
        d = c
        c = b
        b = a
        a = t1 + t2

    # Remaining 64 rounds
    @parameter
    for i in range(16, 80):
        var s0 = small_sigma0_64(w[(i - 15) & 0xF])
        var s1 = small_sigma1_64(w[(i - 2) & 0xF])
        var word = s1 + w[(i - 7) & 0xF] + s0 + w[(i - 16) & 0xF]
        w[i & 0xF] = word

        var t1 = h + sigma1_64(e) + ch64(e, f, g) + SHA512_K[i] + word
        var t2 = sigma0_64(a) + maj64(a, b, c)
        h = g
        g = f
        f = e
        e = d + t1
        d = c
        c = b
        b = a
        a = t1 + t2

    return state + SIMD[DType.uint64, 8](a, b, c, d, e, f, g, h)


fn sha512_update(mut ctx: SHA512Context, data: Span[UInt8]):
    var i = 0
    var total_len = len(data)

    if ctx.buffer_len > 0:
        var available = 128 - ctx.buffer_len
        if total_len >= available:
            for j in range(available):
                ctx.buffer[ctx.buffer_len + j] = data[i + j]
            ctx.state = sha512_transform(
                ctx.state, Span[UInt8](ptr=ctx.buffer.unsafe_ptr(), length=128)
            )

            # Increment 128-bit counter
            var old_low = ctx.count_low
            ctx.count_low += 1024
            if ctx.count_low < old_low:
                ctx.count_high += 1

            i += available
            ctx.buffer_len = 0
        else:
            for j in range(total_len):
                ctx.buffer[ctx.buffer_len + j] = data[i + j]
            ctx.buffer_len += total_len
            return

    while i + 128 <= total_len:
        ctx.state = sha512_transform(ctx.state, data[i : i + 128])

        var old_low = ctx.count_low
        ctx.count_low += 1024
        if ctx.count_low < old_low:
            ctx.count_high += 1

        i += 128

    if i < total_len:
        var remaining = total_len - i
        for j in range(remaining):
            ctx.buffer[ctx.buffer_len + j] = data[i + j]
        ctx.buffer_len += remaining


fn sha512_final(mut ctx: SHA512Context) -> List[UInt8]:
    # Total bits processed
    var final_low = ctx.count_low + UInt64(ctx.buffer_len) * 8
    var final_high = ctx.count_high
    if final_low < ctx.count_low:
        final_high += 1

    # Append the '1' bit (0x80)
    ctx.buffer[ctx.buffer_len] = 0x80
    ctx.buffer_len += 1

    # We need 16 bytes for the length at the end. If len > 112, we need a new block.
    if ctx.buffer_len > 112:
        while ctx.buffer_len < 128:
            ctx.buffer[ctx.buffer_len] = 0
            ctx.buffer_len += 1
        ctx.state = sha512_transform(
            ctx.state, Span[UInt8](ptr=ctx.buffer.unsafe_ptr(), length=128)
        )
        ctx.buffer_len = 0

    # Fill with zeros until the length field
    while ctx.buffer_len < 112:
        ctx.buffer[ctx.buffer_len] = 0
        ctx.buffer_len += 1

    # Append 128-bit length (Big-Endian)
    for i in range(8):
        ctx.buffer[112 + i] = UInt8((final_high >> (56 - i * 8)) & 0xFF)
    for i in range(8):
        ctx.buffer[120 + i] = UInt8((final_low >> (56 - i * 8)) & 0xFF)

    # Final Transform
    ctx.state = sha512_transform(
        ctx.state, Span[UInt8](ptr=ctx.buffer.unsafe_ptr(), length=128)
    )

    # Extract Big-Endian results
    var output = List[UInt8](capacity=64)
    for i in range(8):
        var s = ctx.state[i]
        output.append(UInt8((s >> 56) & 0xFF))
        output.append(UInt8((s >> 48) & 0xFF))
        output.append(UInt8((s >> 40) & 0xFF))
        output.append(UInt8((s >> 32) & 0xFF))
        output.append(UInt8((s >> 24) & 0xFF))
        output.append(UInt8((s >> 16) & 0xFF))
        output.append(UInt8((s >> 8) & 0xFF))
        output.append(UInt8(s & 0xFF))
    return output^


fn sha512_hash(data: Span[UInt8]) -> List[UInt8]:
    var ctx = SHA512Context()
    sha512_update(ctx, data)
    return sha512_final(ctx)


# SHA-224 Implementation (truncated SHA-256)
@always_inline
fn sha224_init_h0() -> UInt32:
    return 0xC1059ED8


@always_inline
fn sha224_init_h1() -> UInt32:
    return 0x367CD507


@always_inline
fn sha224_init_h2() -> UInt32:
    return 0x3070DD17


@always_inline
fn sha224_init_h3() -> UInt32:
    return 0xF70E5939


@always_inline
fn sha224_init_h4() -> UInt32:
    return 0xFFC00B31


@always_inline
fn sha224_init_h5() -> UInt32:
    return 0x68581511


@always_inline
fn sha224_init_h6() -> UInt32:
    return 0x64F98FA7


@always_inline
fn sha224_init_h7() -> UInt32:
    return 0xBEFA4FA4


struct SHA224Context(Movable):
    var state: SIMD[DType.uint32, 8]
    var count: UInt64
    var buffer: InlineArray[UInt8, 64]
    var buffer_len: Int

    fn __init__(out self):
        self.state = SIMD[DType.uint32, 8](
            sha224_init_h0(),
            sha224_init_h1(),
            sha224_init_h2(),
            sha224_init_h3(),
            sha224_init_h4(),
            sha224_init_h5(),
            sha224_init_h6(),
            sha224_init_h7(),
        )
        self.count = 0
        self.buffer = InlineArray[UInt8, 64](fill=0)
        self.buffer_len = 0

    fn __moveinit__(out self, deinit other: Self):
        self.state = other.state
        self.count = other.count
        self.buffer = other.buffer^
        self.buffer_len = other.buffer_len


fn sha224_hash(data: Span[UInt8]) -> List[UInt8]:
    var ctx = SHA224Context()

    # Use SHA-256 logic with SHA-224 initial values
    var sha256_ctx = SHA256Context()
    sha256_ctx.state = ctx.state
    sha256_ctx.count = ctx.count
    # Copy buffer instead of transferring
    for j in range(64):
        sha256_ctx.buffer[j] = ctx.buffer[j]

    sha256_update(sha256_ctx, data)
    var full_hash = sha256_final(sha256_ctx)

    # Truncate to 28 bytes
    var output = List[UInt8](capacity=28)
    for i in range(28):
        output.append(full_hash[i])
    return output^


# SHA-384 Implementation (truncated SHA-512)
@always_inline
fn sha384_init_h0() -> UInt64:
    return 0xCBBB9D5DC1059ED8


@always_inline
fn sha384_init_h1() -> UInt64:
    return 0x629A292A367CD507


@always_inline
fn sha384_init_h2() -> UInt64:
    return 0x9159015A3070DD17


@always_inline
fn sha384_init_h3() -> UInt64:
    return 0x152FECD8F70E5939


@always_inline
fn sha384_init_h4() -> UInt64:
    return 0x67332667FFC00B31


@always_inline
fn sha384_init_h5() -> UInt64:
    return 0x8EB44A8768581511


@always_inline
fn sha384_init_h6() -> UInt64:
    return 0xDB0C2E0D64F98FA7


@always_inline
fn sha384_init_h7() -> UInt64:
    return 0x47B5481DBEFA4FA4


struct SHA384Context(Movable):
    var state: SIMD[DType.uint64, 8]
    var count_high: UInt64
    var count_low: UInt64
    var buffer: InlineArray[UInt8, 128]
    var buffer_len: Int

    fn __init__(out self):
        self.state = SIMD[DType.uint64, 8](
            sha384_init_h0(),
            sha384_init_h1(),
            sha384_init_h2(),
            sha384_init_h3(),
            sha384_init_h4(),
            sha384_init_h5(),
            sha384_init_h6(),
            sha384_init_h7(),
        )
        self.count_high = 0
        self.count_low = 0
        self.buffer = InlineArray[UInt8, 128](fill=0)
        self.buffer_len = 0

    fn __moveinit__(out self, deinit other: Self):
        self.state = other.state
        self.count_high = other.count_high
        self.count_low = other.count_low
        self.buffer = other.buffer^
        self.buffer_len = other.buffer_len


fn sha384_hash(data: Span[UInt8]) -> List[UInt8]:
    var ctx = SHA512Context()

    # SHA-384 Initial Hash Values
    ctx.state = SIMD[DType.uint64, 8](
        0xCBBB9D5DC1059ED8,
        0x629A292A367CD507,
        0x9159015A3070DD17,
        0x152FECD8F70E5939,
        0x67332667FFC00B31,
        0x8EB44A8768581511,
        0xDB0C2E0D64F98FA7,
        0x47B5481DBEFA4FA4,
    )
    # counters are zeroed for the new message
    ctx.count_high = 0
    ctx.count_low = 0

    # Process the data using SHA-512
    sha512_update(ctx, data)
    var full_hash = sha512_final(ctx)

    # SHA-384 is the first 48 bytes of the result
    var output = List[UInt8](capacity=48)
    for i in range(48):
        output.append(full_hash[i])
    return output^


# String functions
fn sha256_hash_string(s: String) -> String:
    var data = string_to_bytes(s)
    var hash = sha256_hash(Span[UInt8](data))
    return bytes_to_hex(hash)


fn sha512_hash_string(s: String) -> String:
    var data = string_to_bytes(s)
    var hash = sha512_hash(Span[UInt8](data))
    return bytes_to_hex(hash)


fn sha224_hash_string(s: String) -> String:
    var data = string_to_bytes(s)
    var hash = sha224_hash(Span[UInt8](data))
    return bytes_to_hex(hash)


fn sha384_hash_string(s: String) -> String:
    var data = string_to_bytes(s)
    var hash = sha384_hash(Span[UInt8](data))
    return bytes_to_hex(hash)
