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
from memory import UnsafePointer, alloc, memcpy

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
fn rotr64[n: Int](x: UInt64) -> UInt64:
    return (x >> n) | (x << (64 - n))


@always_inline
fn g(a: UInt64, b: UInt64, c: UInt64, d: UInt64, x: UInt64, y: UInt64) -> Tuple[UInt64, UInt64, UInt64, UInt64]:
    var va = a + b + x
    var vd = rotr64[32](d ^ va)
    var vc = c + vd
    var vb = rotr64[24](b ^ vc)
    va = va + vb + y
    vd = rotr64[16](vd ^ va)
    vc = vc + vd
    vb = rotr64[63](vb ^ vc)
    return (va, vb, vc, vd)


@always_inline
fn round_fn[r: Int](
    mut v0: UInt64, mut v1: UInt64, mut v2: UInt64, mut v3: UInt64,
    mut v4: UInt64, mut v5: UInt64, mut v6: UInt64, mut v7: UInt64,
    mut v8: UInt64, mut v9: UInt64, mut v10: UInt64, mut v11: UInt64,
    mut v12: UInt64, mut v13: UInt64, mut v14: UInt64, mut v15: UInt64,
    m: UnsafePointer[UInt64, ImmutAnyOrigin],
) -> Tuple[UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64]:
    comptime s = SIGMA[r]
    
    v0, v4, v8, v12 = g(v0, v4, v8, v12, m[Int(s[0])], m[Int(s[1])])
    v1, v5, v9, v13 = g(v1, v5, v9, v13, m[Int(s[2])], m[Int(s[3])])
    v2, v6, v10, v14 = g(v2, v6, v10, v14, m[Int(s[4])], m[Int(s[5])])
    v3, v7, v11, v15 = g(v3, v7, v11, v15, m[Int(s[6])], m[Int(s[7])])
    
    v0, v5, v10, v15 = g(v0, v5, v10, v15, m[Int(s[8])], m[Int(s[9])])
    v1, v6, v11, v12 = g(v1, v6, v11, v12, m[Int(s[10])], m[Int(s[11])])
    v2, v7, v8, v13 = g(v2, v7, v8, v13, m[Int(s[12])], m[Int(s[13])])
    v3, v4, v9, v14 = g(v3, v4, v9, v14, m[Int(s[14])], m[Int(s[15])])
    
    return (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15)


@always_inline
fn zero_buffer(ptr: UnsafePointer[UInt8, MutAnyOrigin], len: Int):
    for i in range(len):
        ptr[i] = 0

@always_inline
fn zero_and_free(ptr: UnsafePointer[UInt8, MutAnyOrigin], len: Int):
    zero_buffer(ptr, len)
    ptr.free()


struct Blake2b(Movable):
    var h: SIMD[DType.uint64, 8]
    var t_low: UInt64
    var t_high: UInt64
    var buffer: UnsafePointer[UInt8, MutAnyOrigin]
    var buffer_len: Int
    var out_len: Int
    var key_len: Int

    fn __init__(out self, out_len: Int = 64):
        self.out_len = out_len
        self.key_len = 0
        self.h = BLAKE2B_IV
        self.t_low = 0
        self.t_high = 0
        self.buffer = alloc[UInt8](128)
        for i in range(128):
            self.buffer[i] = 0
        self.buffer_len = 0

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
        self.buffer = alloc[UInt8](128)
        for i in range(128):
            self.buffer[i] = 0
        self.buffer_len = 0

        var p0: UInt64 = 0x01010000
        p0 |= UInt64(self.key_len) << 8
        p0 |= UInt64(self.out_len)

        self.h[0] ^= p0

        if self.key_len > 0:
            self.update(key)
            while self.buffer_len < 128:
                self.buffer[self.buffer_len] = 0
                self.buffer_len += 1

    fn __moveinit__(out self, deinit other: Self):
        self.h = other.h
        self.t_low = other.t_low
        self.t_high = other.t_high
        self.buffer = other.buffer
        self.buffer_len = other.buffer_len
        self.out_len = other.out_len
        self.key_len = other.key_len

    fn __del__(deinit self):
        zero_and_free(self.buffer, 128)

    fn compress(mut self, is_last: Bool):
        var v0 = self.h[0]
        var v1 = self.h[1]
        var v2 = self.h[2]
        var v3 = self.h[3]
        var v4 = self.h[4]
        var v5 = self.h[5]
        var v6 = self.h[6]
        var v7 = self.h[7]
        var v8 = BLAKE2B_IV[0]
        var v9 = BLAKE2B_IV[1]
        var v10 = BLAKE2B_IV[2]
        var v11 = BLAKE2B_IV[3]
        var v12 = BLAKE2B_IV[4]
        var v13 = BLAKE2B_IV[5]
        var v14 = BLAKE2B_IV[6]
        var v15 = BLAKE2B_IV[7]

        v12 ^= self.t_low
        v13 ^= self.t_high

        if is_last:
            v14 ^= 0xFFFFFFFFFFFFFFFF

        var m = self.buffer.bitcast[UInt64]()
        
        (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) = round_fn[0](v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, m)
        (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) = round_fn[1](v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, m)
        (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) = round_fn[2](v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, m)
        (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) = round_fn[3](v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, m)
        (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) = round_fn[4](v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, m)
        (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) = round_fn[5](v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, m)
        (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) = round_fn[6](v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, m)
        (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) = round_fn[7](v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, m)
        (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) = round_fn[8](v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, m)
        (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) = round_fn[9](v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, m)
        (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) = round_fn[10](v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, m)
        (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) = round_fn[11](v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, m)

        self.h[0] ^= v0 ^ v8
        self.h[1] ^= v1 ^ v9
        self.h[2] ^= v2 ^ v10
        self.h[3] ^= v3 ^ v11
        self.h[4] ^= v4 ^ v12
        self.h[5] ^= v5 ^ v13
        self.h[6] ^= v6 ^ v14
        self.h[7] ^= v7 ^ v15

    fn update(mut self, data: Span[UInt8]):
        var i = 0
        while i < len(data):
            if self.buffer_len == 128:
                self.t_low += 128
                if self.t_low < 128:
                    self.t_high += 1
                self.compress(False)
                self.buffer_len = 0

            var available = 128 - self.buffer_len
            var remaining_data = len(data) - i
            var to_copy = available
            if remaining_data < available:
                to_copy = remaining_data

            memcpy(
                dest=self.buffer + self.buffer_len,
                src=data.unsafe_ptr() + i,
                count=to_copy,
            )

            self.buffer_len += to_copy
            i += to_copy

    fn finalize(mut self) -> List[UInt8]:
        var old_low = self.t_low
        self.t_low += UInt64(self.buffer_len)
        if self.t_low < old_low:
            self.t_high += 1

        while self.buffer_len < 128:
            self.buffer[self.buffer_len] = 0
            self.buffer_len += 1

        self.compress(True)

        var output = List[UInt8](capacity=self.out_len)
        for i in range(self.out_len):
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
