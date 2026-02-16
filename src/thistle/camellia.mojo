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
Camellia block cipher implementation per RFC 3713
"""

from memory import bitcast, UnsafePointer
from bit import byte_swap, rotate_bits_left, rotate_bits_right

comptime SBOX1 = SIMD[DType.uint8, 256](
    112, 130,  44, 236, 179,  39, 192, 229, 228, 133,  87,  53, 234,  12, 174,  65,
     35, 239, 107, 147,  69,  25, 165,  33, 237,  14,  79,  78,  29, 101, 146, 189,
    134, 184, 175, 143, 124, 235,  31, 206,  62,  48, 220,  95,  94, 197,  11,  26,
    166, 225,  57, 202, 213,  71,  93,  61, 217,   1,  90, 214,  81,  86, 108,  77,
    139,  13, 154, 102, 251, 204, 176,  45, 116,  18,  43,  32, 240, 177, 132, 153,
    223,  76, 203, 194,  52, 126, 118,   5, 109, 183, 169,  49, 209,  23,   4, 215,
     20,  88,  58,  97, 222,  27,  17,  28,  50,  15, 156,  22,  83,  24, 242,  34,
    254,  68, 207, 178, 195, 181, 122, 145,  36,   8, 232, 168,  96, 252, 105,  80,
    170, 208, 160, 125, 161, 137,  98, 151,  84,  91,  30, 149, 224, 255, 100, 210,
     16, 196,   0,  72, 163, 247, 117, 219, 138,   3, 230, 218,   9,  63, 221, 148,
    135,  92, 131,   2, 205,  74, 144,  51, 115, 103, 246, 243, 157, 127, 191, 226,
     82, 155, 216,  38, 200,  55, 198,  59, 129, 150, 111,  75,  19, 190,  99,  46,
    233, 121, 167, 140, 159, 110, 188, 142,  41, 245, 249, 182,  47, 253, 180,  89,
    120, 152,   6, 106, 231,  70, 113, 186, 212,  37, 171,  66, 136, 162, 141, 250,
    114,   7, 185,  85, 248, 238, 172,  10,  54,  73,  42, 104,  60,  56, 241, 164,
     64,  40, 211, 123, 187, 201,  67, 193,  21, 227, 173, 244, 119, 199, 128, 158
)

comptime SIGMA1 = 0xA09E667F3BCC908B
comptime SIGMA2 = 0xB67AE8584CAA73B2
comptime SIGMA3 = 0xC6EF372FE94F82BE
comptime SIGMA4 = 0x54FF53A5F1D36F1C
comptime SIGMA5 = 0x10E527FADE682D1D
comptime SIGMA6 = 0xB05688C2B3E6C1FD


@always_inline
fn rotl128(high: UInt64, low: UInt64, n: Int) -> SIMD[DType.uint64, 2]:
    """Rotate 128-bit value left by n bits."""
    var nh: UInt64
    var nl: UInt64
    if n < 64:
        nh = (high << n) | (low >> (64 - n))
        nl = (low << n) | (high >> (64 - n))
    else:
        var shift = n - 64
        nh = (low << shift) | (high >> (64 - shift))
        nl = (high << shift) | (low >> (64 - shift))
    return SIMD[DType.uint64, 2](nh, nl)


@always_inline
fn camellia_f_arx(f_in: UInt64, ke: UInt64) -> UInt64:
    """F-function using word-oriented operations with S-box substitutions.
    
    Per RFC 3713:
    - t1, t4, t6, t7 use SBOX1 directly
    - t2, t5 use SBOX2 = SBOX1 <<< 1
    - t3, t6 use SBOX3 = SBOX1 <<< 7
    - t4, t7 use SBOX4 = SBOX1(x <<< 1)
    """
    var x = f_in ^ ke
    
    # Extract bytes (still scalar due to S-box dependency)
    var t1 = UInt8((x >> 56) & 0xFF)
    var t2 = UInt8((x >> 48) & 0xFF)
    var t3 = UInt8((x >> 40) & 0xFF)
    var t4 = UInt8((x >> 32) & 0xFF)
    var t5 = UInt8((x >> 24) & 0xFF)
    var t6 = UInt8((x >> 16) & 0xFF)
    var t7 = UInt8((x >>  8) & 0xFF)
    var t8 = UInt8(x & 0xFF)
    
    # S-box lookups with rotations
    # SBOX1 direct
    t1 = SBOX1[Int(t1)]
    t8 = SBOX1[Int(t8)]
    
    # SBOX2 = SBOX1 <<< 1
    t2 = SBOX1[Int(t2)]
    t2 = rotate_bits_left[1](t2)
    t5 = SBOX1[Int(t5)]
    t5 = rotate_bits_left[1](t5)
    
    # SBOX3 = SBOX1 <<< 7
    t3 = SBOX1[Int(t3)]
    t3 = rotate_bits_left[7](t3)
    t6 = SBOX1[Int(t6)]
    t6 = rotate_bits_left[7](t6)
    
    # SBOX4 = SBOX1(x <<< 1)
    var t4_rot = rotate_bits_left[1](t4)
    t4 = SBOX1[Int(t4_rot)]
    var t7_rot = rotate_bits_left[1](t7)
    t7 = SBOX1[Int(t7_rot)]
    
    # P-function XOR operations
    var y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8
    var y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8
    var y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8
    var y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7
    var y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8
    var y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8
    var y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8
    var y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7
    
    return (UInt64(y1) << 56) | (UInt64(y2) << 48) | (UInt64(y3) << 40) | (UInt64(y4) << 32) | 
           (UInt64(y5) << 24) | (UInt64(y6) << 16) | (UInt64(y7) << 8)  | UInt64(y8)


@always_inline
fn camellia_fl_arx(fl_in: UInt64, ke: UInt64) -> UInt64:
    """FL function using 32-bit word operations.
    
    Per RFC 3713:
    x1 || x2 = fl_in
    x2 = x2 XOR ROL(x1 AND k1, 1)
    x1 = x1 XOR (x2 OR k2)
    """
    var x1 = UInt32(fl_in >> 32)
    var x2 = UInt32(fl_in & 0xFFFFFFFF)
    var k1 = UInt32(ke >> 32)
    var k2 = UInt32(ke & 0xFFFFFFFF)
    
    # Use rotate_bits_left for the 32-bit rotation
    x2 = x2 ^ rotate_bits_left[1](x1 & k1)
    x1 = x1 ^ (x2 | k2)
    
    return (UInt64(x1) << 32) | UInt64(x2)


@always_inline
fn camellia_flinv_arx(flinv_in: UInt64, ke: UInt64) -> UInt64:
    """FL^-1 function using 32-bit word operations.
    
    Per RFC 3713:
    y1 || y2 = flinv_in
    y1 = y1 XOR (y2 OR k2)
    y2 = y2 XOR ROL(y1 AND k1, 1)
    """
    var y1 = UInt32(flinv_in >> 32)
    var y2 = UInt32(flinv_in & 0xFFFFFFFF)
    var k1 = UInt32(ke >> 32)
    var k2 = UInt32(ke & 0xFFFFFFFF)
    
    y1 = y1 ^ (y2 | k2)
    y2 = y2 ^ rotate_bits_left[1](y1 & k1)
    
    return (UInt64(y1) << 32) | UInt64(y2)


struct CamelliaCipher:
    """Camellia block cipher per RFC 3713 with optimized intrinsics."""
    var kw: SIMD[DType.uint64, 4]
    var k: SIMD[DType.uint64, 24]
    var ke: SIMD[DType.uint64, 6]
    var num_rounds: Int
    var is_128: Bool
    
    fn __init__(out self, key: Span[UInt8]):
        self.kw = SIMD[DType.uint64, 4](0)
        self.k = SIMD[DType.uint64, 24](0)
        self.ke = SIMD[DType.uint64, 6](0)
        self.num_rounds = 18
        self.is_128 = True
        
        var k_len = len(key)
        if k_len == 16:
            self._key_schedule_128(key)
        elif k_len == 24 or k_len == 32:
            self.is_128 = False
            self.num_rounds = 24
            self._key_schedule_192_256(key)
        else:
            print("Error: Invalid key length. Must be 16, 24, or 32 bytes.")
            self._key_schedule_128(key)

    @always_inline
    fn _bytes_to_u64_be(ref self, b: Span[UInt8]) -> UInt64:
        """Convert 8 bytes to big-endian UInt64 using byte_swap."""
        var ptr = b.unsafe_ptr()
        var vec = ptr.load[width=8](0)
        var val_simd = bitcast[DType.uint64, 1](vec)
        # byte_swap converts from little-endian load to big-endian interpretation
        return byte_swap(val_simd[0])

    fn _key_schedule_128(mut self, key: Span[UInt8]):
        var kl_h = self._bytes_to_u64_be(key[0:8])
        var kl_l = self._bytes_to_u64_be(key[8:16])
        var kr_h: UInt64 = 0
        var kr_l: UInt64 = 0
        
        var d1 = kl_h ^ kr_h
        var d2 = kl_l ^ kr_l
        
        d2 = d2 ^ camellia_f_arx(d1, SIGMA1)
        d1 = d1 ^ camellia_f_arx(d2, SIGMA2)
        d1 = d1 ^ kl_h
        d2 = d2 ^ kl_l
        d2 = d2 ^ camellia_f_arx(d1, SIGMA3)
        d1 = d1 ^ camellia_f_arx(d2, SIGMA4)
        
        var ka_h = d1
        var ka_l = d2
        
        self.kw[0] = kl_h
        self.kw[1] = kl_l
        
        self.k[0] = ka_h
        self.k[1] = ka_l
        
        var rot = rotl128(kl_h, kl_l, 15)
        self.k[2] = rot[0]
        self.k[3] = rot[1]
        rot = rotl128(ka_h, ka_l, 15)
        self.k[4] = rot[0]
        self.k[5] = rot[1]
        
        rot = rotl128(ka_h, ka_l, 30)
        self.ke[0] = rot[0]
        self.ke[1] = rot[1]
        
        rot = rotl128(kl_h, kl_l, 45)
        self.k[6] = rot[0]
        self.k[7] = rot[1]
        rot = rotl128(ka_h, ka_l, 45)
        self.k[8] = rot[0]
        
        rot = rotl128(kl_h, kl_l, 60)
        self.k[9] = rot[1]
        rot = rotl128(ka_h, ka_l, 60)
        self.k[10] = rot[0]
        self.k[11] = rot[1]
        
        rot = rotl128(kl_h, kl_l, 77)
        self.ke[2] = rot[0]
        self.ke[3] = rot[1]
        
        rot = rotl128(kl_h, kl_l, 94)
        self.k[12] = rot[0]
        self.k[13] = rot[1]
        rot = rotl128(ka_h, ka_l, 94)
        self.k[14] = rot[0]
        self.k[15] = rot[1]
        
        rot = rotl128(kl_h, kl_l, 111)
        self.k[16] = rot[0]
        self.k[17] = rot[1]
        
        rot = rotl128(ka_h, ka_l, 111)
        self.kw[2] = rot[0]
        self.kw[3] = rot[1]

    fn _key_schedule_192_256(mut self, key: Span[UInt8]):
        var kl_h = self._bytes_to_u64_be(key[0:8])
        var kl_l = self._bytes_to_u64_be(key[8:16])
        var kr_h: UInt64
        var kr_l: UInt64
        
        if len(key) == 32:
            kr_h = self._bytes_to_u64_be(key[16:24])
            kr_l = self._bytes_to_u64_be(key[24:32])
        else:
            kr_h = self._bytes_to_u64_be(key[16:24])
            kr_l = ~kr_h
            
        var d1 = kl_h ^ kr_h
        var d2 = kl_l ^ kr_l
        
        d2 = d2 ^ camellia_f_arx(d1, SIGMA1)
        d1 = d1 ^ camellia_f_arx(d2, SIGMA2)
        d1 = d1 ^ kl_h
        d2 = d2 ^ kl_l
        d2 = d2 ^ camellia_f_arx(d1, SIGMA3)
        d1 = d1 ^ camellia_f_arx(d2, SIGMA4)
        
        var ka_h = d1
        var ka_l = d2
        
        d1 = ka_h ^ kr_h
        d2 = ka_l ^ kr_l
        d2 = d2 ^ camellia_f_arx(d1, SIGMA5)
        d1 = d1 ^ camellia_f_arx(d2, SIGMA6)
        var kb_h = d1
        var kb_l = d2
        
        self.kw[0] = kl_h
        self.kw[1] = kl_l
        
        self.k[0] = kb_h
        self.k[1] = kb_l
        
        var rot = rotl128(kr_h, kr_l, 15)
        self.k[2] = rot[0]
        self.k[3] = rot[1]
        rot = rotl128(ka_h, ka_l, 15)
        self.k[4] = rot[0]
        self.k[5] = rot[1]
        
        rot = rotl128(kr_h, kr_l, 30)
        self.ke[0] = rot[0]
        self.ke[1] = rot[1]
        rot = rotl128(kb_h, kb_l, 30)
        self.k[6] = rot[0]
        self.k[7] = rot[1]
        
        rot = rotl128(kl_h, kl_l, 45)
        self.k[8] = rot[0]
        self.k[9] = rot[1]
        rot = rotl128(ka_h, ka_l, 45)
        self.k[10] = rot[0]
        self.k[11] = rot[1]
        
        rot = rotl128(kl_h, kl_l, 60)
        self.ke[2] = rot[0]
        self.ke[3] = rot[1]
        rot = rotl128(kr_h, kr_l, 60)
        self.k[12] = rot[0]
        self.k[13] = rot[1]
        rot = rotl128(kb_h, kb_l, 60)
        self.k[14] = rot[0]
        self.k[15] = rot[1]
        
        rot = rotl128(kl_h, kl_l, 77)
        self.k[16] = rot[0]
        self.k[17] = rot[1]
        rot = rotl128(ka_h, ka_l, 77)
        self.ke[4] = rot[0]
        self.ke[5] = rot[1]
        
        rot = rotl128(kr_h, kr_l, 94)
        self.k[18] = rot[0]
        self.k[19] = rot[1]
        rot = rotl128(ka_h, ka_l, 94)
        self.k[20] = rot[0]
        self.k[21] = rot[1]
        rot = rotl128(kl_h, kl_l, 111)
        self.k[22] = rot[0]
        self.k[23] = rot[1]
        
        rot = rotl128(kb_h, kb_l, 111)
        self.kw[2] = rot[0]
        self.kw[3] = rot[1]

    fn encrypt(self, block: SIMD[DType.uint8, 16]) -> SIMD[DType.uint8, 16]:
        var cast_block = bitcast[DType.uint64, 2](block)
        
        # Use byte_swap for big-endian conversion
        var d1 = byte_swap(cast_block[0])
        var d2 = byte_swap(cast_block[1])
        
        d1 = d1 ^ self.kw[0]
        d2 = d2 ^ self.kw[1]
        
        # Rounds 1-6
        d2 = d2 ^ camellia_f_arx(d1, self.k[0])
        d1 = d1 ^ camellia_f_arx(d2, self.k[1])
        d2 = d2 ^ camellia_f_arx(d1, self.k[2])
        d1 = d1 ^ camellia_f_arx(d2, self.k[3])
        d2 = d2 ^ camellia_f_arx(d1, self.k[4])
        d1 = d1 ^ camellia_f_arx(d2, self.k[5])
        
        # FL layer 1
        d1 = camellia_fl_arx(d1, self.ke[0])
        d2 = camellia_flinv_arx(d2, self.ke[1])
        
        # Rounds 7-12
        d2 = d2 ^ camellia_f_arx(d1, self.k[6])
        d1 = d1 ^ camellia_f_arx(d2, self.k[7])
        d2 = d2 ^ camellia_f_arx(d1, self.k[8])
        d1 = d1 ^ camellia_f_arx(d2, self.k[9])
        d2 = d2 ^ camellia_f_arx(d1, self.k[10])
        d1 = d1 ^ camellia_f_arx(d2, self.k[11])
        
        # FL layer 2
        d1 = camellia_fl_arx(d1, self.ke[2])
        d2 = camellia_flinv_arx(d2, self.ke[3])
        
        # Rounds 13-18
        d2 = d2 ^ camellia_f_arx(d1, self.k[12])
        d1 = d1 ^ camellia_f_arx(d2, self.k[13])
        d2 = d2 ^ camellia_f_arx(d1, self.k[14])
        d1 = d1 ^ camellia_f_arx(d2, self.k[15])
        d2 = d2 ^ camellia_f_arx(d1, self.k[16])
        d1 = d1 ^ camellia_f_arx(d2, self.k[17])
        
        if not self.is_128:
            d1 = camellia_fl_arx(d1, self.ke[4])
            d2 = camellia_flinv_arx(d2, self.ke[5])
            
            d2 = d2 ^ camellia_f_arx(d1, self.k[18])
            d1 = d1 ^ camellia_f_arx(d2, self.k[19])
            d2 = d2 ^ camellia_f_arx(d1, self.k[20])
            d1 = d1 ^ camellia_f_arx(d2, self.k[21])
            d2 = d2 ^ camellia_f_arx(d1, self.k[22])
            d1 = d1 ^ camellia_f_arx(d2, self.k[23])
        
        d2 = d2 ^ self.kw[2]
        d1 = d1 ^ self.kw[3]
        
        var res = SIMD[DType.uint64, 2](byte_swap(d2), byte_swap(d1))
        return bitcast[DType.uint8, 16](res)

    fn decrypt(self, block: SIMD[DType.uint8, 16]) -> SIMD[DType.uint8, 16]:
        var cast_block = bitcast[DType.uint64, 2](block)
        
        var d1 = byte_swap(cast_block[1])
        var d2 = byte_swap(cast_block[0])
        
        d2 = d2 ^ self.kw[2]
        d1 = d1 ^ self.kw[3]
        
        if not self.is_128:
            d1 = d1 ^ camellia_f_arx(d2, self.k[23])
            d2 = d2 ^ camellia_f_arx(d1, self.k[22])
            d1 = d1 ^ camellia_f_arx(d2, self.k[21])
            d2 = d2 ^ camellia_f_arx(d1, self.k[20])
            d1 = d1 ^ camellia_f_arx(d2, self.k[19])
            d2 = d2 ^ camellia_f_arx(d1, self.k[18])
            
            d1 = camellia_flinv_arx(d1, self.ke[4])
            d2 = camellia_fl_arx(d2, self.ke[5])
        
        d1 = d1 ^ camellia_f_arx(d2, self.k[17])
        d2 = d2 ^ camellia_f_arx(d1, self.k[16])
        d1 = d1 ^ camellia_f_arx(d2, self.k[15])
        d2 = d2 ^ camellia_f_arx(d1, self.k[14])
        d1 = d1 ^ camellia_f_arx(d2, self.k[13])
        d2 = d2 ^ camellia_f_arx(d1, self.k[12])
        
        d1 = camellia_flinv_arx(d1, self.ke[2])
        d2 = camellia_fl_arx(d2, self.ke[3])
        
        d1 = d1 ^ camellia_f_arx(d2, self.k[11])
        d2 = d2 ^ camellia_f_arx(d1, self.k[10])
        d1 = d1 ^ camellia_f_arx(d2, self.k[9])
        d2 = d2 ^ camellia_f_arx(d1, self.k[8])
        d1 = d1 ^ camellia_f_arx(d2, self.k[7])
        d2 = d2 ^ camellia_f_arx(d1, self.k[6])
        
        d1 = camellia_flinv_arx(d1, self.ke[0])
        d2 = camellia_fl_arx(d2, self.ke[1])
        
        d1 = d1 ^ camellia_f_arx(d2, self.k[5])
        d2 = d2 ^ camellia_f_arx(d1, self.k[4])
        d1 = d1 ^ camellia_f_arx(d2, self.k[3])
        d2 = d2 ^ camellia_f_arx(d1, self.k[2])
        d1 = d1 ^ camellia_f_arx(d2, self.k[1])
        d2 = d2 ^ camellia_f_arx(d1, self.k[0])
        
        d1 = d1 ^ self.kw[0]
        d2 = d2 ^ self.kw[1]
        
        var res = SIMD[DType.uint64, 2](byte_swap(d1), byte_swap(d2))
        return bitcast[DType.uint8, 16](res)

    fn encrypt(self, block: Span[UInt8]) -> SIMD[DType.uint8, 16]:
        """Encrypt a 16-byte block from a Span[UInt8]."""
        var ptr = block.unsafe_ptr()
        var simd_block = ptr.load[width=16](0)
        return self.encrypt(simd_block)

    fn decrypt(self, block: Span[UInt8]) -> SIMD[DType.uint8, 16]:
        """Decrypt a 16-byte block from a Span[UInt8]."""
        var ptr = block.unsafe_ptr()
        var simd_block = ptr.load[width=16](0)
        return self.decrypt(simd_block)
