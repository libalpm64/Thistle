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
BLAKE2b Implementation in Mojo
RFC 7693
By Libalpm64, Attribute not required.
"""

from collections import List
from memory import UnsafePointer

comptime BLAKE2B_IV = SIMD[DType.uint64, 8](
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
)

comptime SIGMA = (
    SIMD[DType.uint8, 16](0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    SIMD[DType.uint8, 16](14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
    SIMD[DType.uint8, 16](11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
    SIMD[DType.uint8, 16](7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
    SIMD[DType.uint8, 16](9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
    SIMD[DType.uint8, 16](2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
    SIMD[DType.uint8, 16](12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
    SIMD[DType.uint8, 16](13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
    SIMD[DType.uint8, 16](6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
    SIMD[DType.uint8, 16](10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
    SIMD[DType.uint8, 16](0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    SIMD[DType.uint8, 16](14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
)


@always_inline
fn rotr64(x: UInt64, n: Int) -> UInt64:
    return (x >> n) | (x << (64 - n))


@always_inline
fn g(
    mut v: SIMD[DType.uint64, 16],
    a: Int,
    b: Int,
    c: Int,
    d: Int,
    x: UInt64,
    y: UInt64,
):
    v[a] = v[a] + v[b] + x
    v[d] = rotr64(v[d] ^ v[a], 32)
    v[c] = v[c] + v[d]
    v[b] = rotr64(v[b] ^ v[c], 24)
    v[a] = v[a] + v[b] + y
    v[d] = rotr64(v[d] ^ v[a], 16)
    v[c] = v[c] + v[d]
    v[b] = rotr64(v[b] ^ v[c], 63)


@always_inline
fn round_fn[r: Int](mut v: SIMD[DType.uint64, 16], m: SIMD[DType.uint64, 16]):
    comptime s = SIGMA[r]
    g(v, 0, 4, 8, 12, m[Int(s[0])], m[Int(s[1])])
    g(v, 1, 5, 9, 13, m[Int(s[2])], m[Int(s[3])])
    g(v, 2, 6, 10, 14, m[Int(s[4])], m[Int(s[5])])
    g(v, 3, 7, 11, 15, m[Int(s[6])], m[Int(s[7])])
    g(v, 0, 5, 10, 15, m[Int(s[8])], m[Int(s[9])])
    g(v, 1, 6, 11, 12, m[Int(s[10])], m[Int(s[11])])
    g(v, 2, 7, 8, 13, m[Int(s[12])], m[Int(s[13])])
    g(v, 3, 4, 9, 14, m[Int(s[14])], m[Int(s[15])])


struct Blake2b(Movable):
    var h: SIMD[DType.uint64, 8]
    var t_low: UInt64
    var t_high: UInt64
    var buffer: List[UInt8]
    var buffer_len: Int
    var out_len: Int
    var key_len: Int

    fn __init__(out self, out_len: Int = 64):
        self.out_len = out_len
        self.key_len = 0
        self.h = BLAKE2B_IV
        self.t_low = 0
        self.t_high = 0
        self.buffer = List[UInt8](capacity=128)
        for _ in range(128):
            self.buffer.append(0)
        self.buffer_len = 0

        # Parameter block
        var p0: UInt64 = 0x01010000
        p0 |= UInt64(self.key_len) << 8
        p0 |= UInt64(self.out_len)

        self.h[0] ^= p0

    fn __init__(out self, out_len: Int, key: Span[UInt8]):
        self.out_len = out_len
        self.key_len = len(key)
        self.h = BLAKE2B_IV
        self.t_low = 0
        self.t_high = 0
        self.buffer = List[UInt8](capacity=128)
        for _ in range(128):
            self.buffer.append(0)
        self.buffer_len = 0

        # Parameter block p[0]
        var p0: UInt64 = 0x01010000
        p0 |= UInt64(self.key_len) << 8
        p0 |= UInt64(self.out_len)

        self.h[0] ^= p0

        if self.key_len > 0:
            self.update(key)
            var pad_len = 128 - self.buffer_len
            for _ in range(pad_len):
                self.buffer[self.buffer_len] = 0
                self.buffer_len += 1
            # don't compress here (if exits)

    fn __moveinit__(out self, deinit other: Self):
        self.h = other.h
        self.t_low = other.t_low
        self.t_high = other.t_high
        self.buffer = other.buffer^
        self.buffer_len = other.buffer_len
        self.out_len = other.out_len
        self.key_len = other.key_len

    fn compress(mut self, is_last: Bool):
        # Initialize local work vector v
        var v = SIMD[DType.uint64, 16](0)
        for i in range(8):
            v[i] = self.h[i]
            v[i + 8] = BLAKE2B_IV[i]

        # T adjustment
        v[12] ^= self.t_low
        v[13] ^= self.t_high

        # F flag
        if is_last:
            v[14] ^= 0xFFFFFFFFFFFFFFFF

        # message block
        var m = SIMD[DType.uint64, 16](0)
        for i in range(16):
            var word: UInt64 = 0
            word |= UInt64(self.buffer[i * 8 + 0])
            word |= UInt64(self.buffer[i * 8 + 1]) << 8
            word |= UInt64(self.buffer[i * 8 + 2]) << 16
            word |= UInt64(self.buffer[i * 8 + 3]) << 24
            word |= UInt64(self.buffer[i * 8 + 4]) << 32
            word |= UInt64(self.buffer[i * 8 + 5]) << 40
            word |= UInt64(self.buffer[i * 8 + 6]) << 48
            word |= UInt64(self.buffer[i * 8 + 7]) << 56
            m[i] = word

        # Rounds
        round_fn[0](v, m)
        round_fn[1](v, m)
        round_fn[2](v, m)
        round_fn[3](v, m)
        round_fn[4](v, m)
        round_fn[5](v, m)
        round_fn[6](v, m)
        round_fn[7](v, m)
        round_fn[8](v, m)
        round_fn[9](v, m)
        round_fn[10](v, m)
        round_fn[11](v, m)

        for i in range(8):
            self.h[i] ^= v[i] ^ v[i + 8]

    fn update(mut self, data: Span[UInt8]):
        var i = 0
        while i < len(data):
            if self.buffer_len == 128:
                self.t_low += 128
                # Overflow check
                if self.t_low < 128:
                    self.t_high += 1

                self.compress(False)
                self.buffer_len = 0

            # Copy data to buffer
            var available = 128 - self.buffer_len
            var remaining_data = len(data) - i
            var to_copy = available
            if remaining_data < available:
                to_copy = remaining_data

            for k in range(to_copy):
                self.buffer[self.buffer_len + k] = data[i + k]

            self.buffer_len += to_copy
            i += to_copy

    fn finalize(mut self) -> List[UInt8]:
        var old_low = self.t_low
        self.t_low += UInt64(self.buffer_len)
        if self.t_low < old_low:
            self.t_high += 1

        # Pad with zeros
        while self.buffer_len < 128:
            self.buffer[self.buffer_len] = 0
            self.buffer_len += 1

        self.compress(True)

        var output = List[UInt8](capacity=self.out_len)
        for i in range(self.out_len):
            # Little endian extraction
            var word_idx = i // 8
            var byte_idx = i % 8
            var word = self.h[word_idx]
            output.append(UInt8((word >> (byte_idx * 8)) & 0xFF))

        return output^


fn nibble_to_hex_char(nibble: UInt8) -> UInt8:
    if nibble < 10:
        return nibble + 0x30
    else:
        return nibble - 10 + 0x61


fn bytes_to_hex(data: List[UInt8]) -> String:
    var result = String()
    for i in range(len(data)):
        var b = data[i]
        var high = (b >> 4) & 0x0F
        var low = b & 0x0F
        result += chr(Int(nibble_to_hex_char(high)))
        result += chr(Int(nibble_to_hex_char(low)))
    return result


fn string_to_bytes(s: String) -> List[UInt8]:
    var data = List[UInt8]()
    var bytes = s.as_bytes()
    for i in range(len(bytes)):
        data.append(bytes[i])
    return data^


fn blake2b_hash(data: Span[UInt8], out_len: Int = 64) -> List[UInt8]:
    var ctx = Blake2b(out_len)
    ctx.update(data)
    return ctx.finalize()


fn blake2b_hash_keyed(
    data: Span[UInt8], key: Span[UInt8], out_len: Int = 64
) -> List[UInt8]:
    var ctx = Blake2b(out_len, key)
    ctx.update(data)
    return ctx.finalize()


fn blake2b_hash_string(s: String, out_len: Int = 64) -> String:
    var data = string_to_bytes(s)
    var hash = blake2b_hash(Span[UInt8](data), out_len)
    return bytes_to_hex(hash)
