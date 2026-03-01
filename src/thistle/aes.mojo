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
AES-128-CPU implementation
By Libalpm64 no attribution required.
Experimental - NOT meant for production.
"""

from memory import alloc, memset
from utils import StaticTuple


comptime AESError = Error


struct AESConfig:
    var num_rounds: Int
    var block_size: Int
    var key_size: Int

    fn __init__(out self):
        self.num_rounds = 10
        self.block_size = 16
        self.key_size = 16


comptime ROUNDS_128: Int = 10
comptime BLOCK_SIZE: Int = 16



@always_inline
fn gf_mul2(a: UInt8) -> UInt8:
    return (a << 1) ^ (0x1b if (a & 0x80) != 0 else 0)

@always_inline
fn gf_mul3(a: UInt8) -> UInt8:
    return a ^ gf_mul2(a)

@always_inline
fn cpu_aes_encrypt(
    pt_bytes: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
    rounds: Int = ROUNDS_128
) -> None:
    var s0 = pt_bytes.load(0)
    var s1 = pt_bytes.load(1)
    var s2 = pt_bytes.load(2)
    var s3 = pt_bytes.load(3)
    var s4 = pt_bytes.load(4)
    var s5 = pt_bytes.load(5)
    var s6 = pt_bytes.load(6)
    var s7 = pt_bytes.load(7)
    var s8 = pt_bytes.load(8)
    var s9 = pt_bytes.load(9)
    var s10 = pt_bytes.load(10)
    var s11 = pt_bytes.load(11)
    var s12 = pt_bytes.load(12)
    var s13 = pt_bytes.load(13)
    var s14 = pt_bytes.load(14)
    var s15 = pt_bytes.load(15)

    var w0 = round_keys.load(0)
    s0 ^= UInt8((w0 >> 24) & 0xff)
    s1 ^= UInt8((w0 >> 16) & 0xff)
    s2 ^= UInt8((w0 >> 8) & 0xff)
    s3 ^= UInt8(w0 & 0xff)
    var w1 = round_keys.load(1)
    s4 ^= UInt8((w1 >> 24) & 0xff)
    s5 ^= UInt8((w1 >> 16) & 0xff)
    s6 ^= UInt8((w1 >> 8) & 0xff)
    s7 ^= UInt8(w1 & 0xff)
    var w2 = round_keys.load(2)
    s8 ^= UInt8((w2 >> 24) & 0xff)
    s9 ^= UInt8((w2 >> 16) & 0xff)
    s10 ^= UInt8((w2 >> 8) & 0xff)
    s11 ^= UInt8(w2 & 0xff)
    var w3 = round_keys.load(3)
    s12 ^= UInt8((w3 >> 24) & 0xff)
    s13 ^= UInt8((w3 >> 16) & 0xff)
    s14 ^= UInt8((w3 >> 8) & 0xff)
    s15 ^= UInt8(w3 & 0xff)

    for r in range(1, rounds):
        var rk_ptr = round_keys + (r * 4)

        s0 = SBOX[Int(s0)]
        s1 = SBOX[Int(s1)]
        s2 = SBOX[Int(s2)]
        s3 = SBOX[Int(s3)]
        s4 = SBOX[Int(s4)]
        s5 = SBOX[Int(s5)]
        s6 = SBOX[Int(s6)]
        s7 = SBOX[Int(s7)]
        s8 = SBOX[Int(s8)]
        s9 = SBOX[Int(s9)]
        s10 = SBOX[Int(s10)]
        s11 = SBOX[Int(s11)]
        s12 = SBOX[Int(s12)]
        s13 = SBOX[Int(s13)]
        s14 = SBOX[Int(s14)]
        s15 = SBOX[Int(s15)]

        var t1 = s1
        s1 = s5
        s5 = s9
        s9 = s13
        s13 = t1
        var t2 = s2
        s2 = s10
        s10 = t2
        var t6 = s6
        s6 = s14
        s14 = t6
        var t15 = s15
        s15 = s11
        s11 = s7
        s7 = s3
        s3 = t15

        var a0 = s0; var a1 = s1; var a2 = s2; var a3 = s3
        s0 = gf_mul2(a0) ^ gf_mul3(a1) ^ a2 ^ a3
        s1 = a0 ^ gf_mul2(a1) ^ gf_mul3(a2) ^ a3
        s2 = a0 ^ a1 ^ gf_mul2(a2) ^ gf_mul3(a3)
        s3 = gf_mul3(a0) ^ a1 ^ a2 ^ gf_mul2(a3)

        a0 = s4; a1 = s5; a2 = s6; a3 = s7
        s4 = gf_mul2(a0) ^ gf_mul3(a1) ^ a2 ^ a3
        s5 = a0 ^ gf_mul2(a1) ^ gf_mul3(a2) ^ a3
        s6 = a0 ^ a1 ^ gf_mul2(a2) ^ gf_mul3(a3)
        s7 = gf_mul3(a0) ^ a1 ^ a2 ^ gf_mul2(a3)

        a0 = s8; a1 = s9; a2 = s10; a3 = s11
        s8 = gf_mul2(a0) ^ gf_mul3(a1) ^ a2 ^ a3
        s9 = a0 ^ gf_mul2(a1) ^ gf_mul3(a2) ^ a3
        s10 = a0 ^ a1 ^ gf_mul2(a2) ^ gf_mul3(a3)
        s11 = gf_mul3(a0) ^ a1 ^ a2 ^ gf_mul2(a3)

        a0 = s12; a1 = s13; a2 = s14; a3 = s15
        s12 = gf_mul2(a0) ^ gf_mul3(a1) ^ a2 ^ a3
        s13 = a0 ^ gf_mul2(a1) ^ gf_mul3(a2) ^ a3
        s14 = a0 ^ a1 ^ gf_mul2(a2) ^ gf_mul3(a3)
        s15 = gf_mul3(a0) ^ a1 ^ a2 ^ gf_mul2(a3)

        w0 = rk_ptr.load(0)
        s0 ^= UInt8((w0 >> 24) & 0xff)
        s1 ^= UInt8((w0 >> 16) & 0xff)
        s2 ^= UInt8((w0 >> 8) & 0xff)
        s3 ^= UInt8(w0 & 0xff)
        w1 = rk_ptr.load(1)
        s4 ^= UInt8((w1 >> 24) & 0xff)
        s5 ^= UInt8((w1 >> 16) & 0xff)
        s6 ^= UInt8((w1 >> 8) & 0xff)
        s7 ^= UInt8(w1 & 0xff)
        w2 = rk_ptr.load(2)
        s8 ^= UInt8((w2 >> 24) & 0xff)
        s9 ^= UInt8((w2 >> 16) & 0xff)
        s10 ^= UInt8((w2 >> 8) & 0xff)
        s11 ^= UInt8(w2 & 0xff)
        w3 = rk_ptr.load(3)
        s12 ^= UInt8((w3 >> 24) & 0xff)
        s13 ^= UInt8((w3 >> 16) & 0xff)
        s14 ^= UInt8((w3 >> 8) & 0xff)
        s15 ^= UInt8(w3 & 0xff)

    var final_rk = round_keys + (rounds * 4)
    s0 = SBOX[Int(s0)]
    s1 = SBOX[Int(s1)]
    s2 = SBOX[Int(s2)]
    s3 = SBOX[Int(s3)]
    s4 = SBOX[Int(s4)]
    s5 = SBOX[Int(s5)]
    s6 = SBOX[Int(s6)]
    s7 = SBOX[Int(s7)]
    s8 = SBOX[Int(s8)]
    s9 = SBOX[Int(s9)]
    s10 = SBOX[Int(s10)]
    s11 = SBOX[Int(s11)]
    s12 = SBOX[Int(s12)]
    s13 = SBOX[Int(s13)]
    s14 = SBOX[Int(s14)]
    s15 = SBOX[Int(s15)]

    var ft1 = s1
    s1 = s5
    s5 = s9
    s9 = s13
    s13 = ft1
    var ft2 = s2
    s2 = s10
    s10 = ft2
    var ft6 = s6
    s6 = s14
    s14 = ft6
    var ft15 = s15
    s15 = s11
    s11 = s7
    s7 = s3
    s3 = ft15

    w0 = final_rk.load(0)
    s0 ^= UInt8((w0 >> 24) & 0xff)
    s1 ^= UInt8((w0 >> 16) & 0xff)
    s2 ^= UInt8((w0 >> 8) & 0xff)
    s3 ^= UInt8(w0 & 0xff)
    w1 = final_rk.load(1)
    s4 ^= UInt8((w1 >> 24) & 0xff)
    s5 ^= UInt8((w1 >> 16) & 0xff)
    s6 ^= UInt8((w1 >> 8) & 0xff)
    s7 ^= UInt8(w1 & 0xff)
    w2 = final_rk.load(2)
    s8 ^= UInt8((w2 >> 24) & 0xff)
    s9 ^= UInt8((w2 >> 16) & 0xff)
    s10 ^= UInt8((w2 >> 8) & 0xff)
    s11 ^= UInt8(w2 & 0xff)
    w3 = final_rk.load(3)
    s12 ^= UInt8((w3 >> 24) & 0xff)
    s13 ^= UInt8((w3 >> 16) & 0xff)
    s14 ^= UInt8((w3 >> 8) & 0xff)
    s15 ^= UInt8(w3 & 0xff)

    pt_bytes.store(0, s0)
    pt_bytes.store(1, s1)
    pt_bytes.store(2, s2)
    pt_bytes.store(3, s3)
    pt_bytes.store(4, s4)
    pt_bytes.store(5, s5)
    pt_bytes.store(6, s6)
    pt_bytes.store(7, s7)
    pt_bytes.store(8, s8)
    pt_bytes.store(9, s9)
    pt_bytes.store(10, s10)
    pt_bytes.store(11, s11)
    pt_bytes.store(12, s12)
    pt_bytes.store(13, s13)
    pt_bytes.store(14, s14)
    pt_bytes.store(15, s15)



@always_inline
fn sbox_lookup(idx: UInt8) -> UInt8:
    return SBOX[idx]

@always_inline
fn sub_word(w: UInt32) -> UInt32:
    var b0 = UInt32(sbox_lookup(UInt8((w >> 24) & 0xff)))
    var b1 = UInt32(sbox_lookup(UInt8((w >> 16) & 0xff)))
    var b2 = UInt32(sbox_lookup(UInt8((w >> 8) & 0xff)))
    var b3 = UInt32(sbox_lookup(UInt8(w & 0xff)))
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3


comptime SBOX: StaticTuple[UInt8, 256] = StaticTuple[UInt8, 256](
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
)

comptime RCON: StaticTuple[UInt8, 11] = StaticTuple[UInt8, 11](
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c
)


fn ttable0(x: UInt8) -> UInt32:
    var s = SBOX[x]
    var m2 = gf_mul2(s)
    var m3 = gf_mul3(s)
    return (UInt32(m2) << 24) | (UInt32(s) << 16) | (UInt32(s) << 8) | UInt32(m3)

fn ttable1(x: UInt8) -> UInt32:
    var s = SBOX[x]
    var m2 = gf_mul2(s)
    var m3 = gf_mul3(s)
    return (UInt32(m3) << 24) | (UInt32(m2) << 16) | (UInt32(s) << 8) | UInt32(s)

fn ttable2(x: UInt8) -> UInt32:
    var s = SBOX[x]
    var m2 = gf_mul2(s)
    var m3 = gf_mul3(s)
    return (UInt32(s) << 24) | (UInt32(m3) << 16) | (UInt32(m2) << 8) | UInt32(s)

fn ttable3(x: UInt8) -> UInt32:
    var s = SBOX[x]
    var m2 = gf_mul2(s)
    var m3 = gf_mul3(s)
    return (UInt32(s) << 24) | (UInt32(s) << 16) | (UInt32(m3) << 8) | UInt32(m2)


fn expand_key_128(key_bytes: UnsafePointer[UInt8, MutAnyOrigin]) raises -> UnsafePointer[UInt32, MutAnyOrigin]:
    var w = alloc[UInt32](44)
    
    for i in range(4):
        var key_val: UInt32 = 0
        for j in range(4):
            key_val |= UInt32(key_bytes.load(i * 4 + j)) << ((3 - j) * 8)
        w.store(i, key_val)
    for i in range(4, 44):
        var temp = w.load(i - 1)
        if i % 4 == 0:
            var rotated = (temp >> 24) | ((temp << 8) & 0xffffffff)
            temp = sub_word(rotated)
            temp ^= UInt32(RCON[i // 4 - 1]) << 24
        w.store(i, w.load(i - 4) ^ temp)
    return w


struct AESKey:
    var _data: UnsafePointer[UInt8, MutAnyOrigin]
    var _round_keys: UnsafePointer[UInt32, MutAnyOrigin]
    
    fn __init__(out self, key: StaticTuple[UInt8, 16]) raises:
        self._data = alloc[UInt8](16)
        for i in range(16):
            self._data.store(i, key[i])
        self._round_keys = expand_key_128(self._data)
    
    fn __del__(deinit self):
        memset(self._data, 0, 16)
        self._data.free()
        memset(self._round_keys, 0, 44 * 4)
        self._round_keys.free()
    
    fn round_keys(self) -> UnsafePointer[UInt32, MutAnyOrigin]:
        return self._round_keys
