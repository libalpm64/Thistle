"""
Camellia block cipher implementation per RFC 3713
"""

from std.memory import bitcast, UnsafePointer
from std.bit import byte_swap, rotate_bits_left
from std.collections import InlineArray
from std.utils import StaticTuple

comptime SBOX1: StaticTuple[UInt8, 256] = StaticTuple[UInt8, 256](
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
     64,  40, 211, 123, 187, 201,  67, 193,  21, 227, 173, 244, 119, 199, 128, 158,
)

comptime SBOX2: StaticTuple[UInt8, 256] = StaticTuple[UInt8, 256](
    224,   5,  88, 217, 103,  78, 129, 203, 201,  11, 174, 106, 213,  24,  93, 130,
     70, 223, 214,  39, 138,  50,  75,  66, 219,  28, 158, 156,  58, 202,  37, 123,
     13, 113,  95,  31, 248, 215,  62, 157, 124,  96, 185, 190, 188, 139,  22,  52,
     77, 195, 114, 149, 171, 142, 186, 122, 179,   2, 180, 173, 162, 172, 216, 154,
     23,  26,  53, 204, 247, 153,  97,  90, 232,  36,  86,  64, 225,  99,   9,  51,
    191, 152, 151, 133, 104, 252, 236,  10, 218, 111,  83,  98, 163,  46,   8, 175,
     40, 176, 116, 194, 189,  54,  34,  56, 100,  30,  57,  44, 166,  48, 229,  68,
    253, 136, 159, 101, 135, 107, 244,  35,  72,  16, 209,  81, 192, 249, 210, 160,
     85, 161,  65, 250,  67,  19, 196,  47, 168, 182,  60,  43, 193, 255, 200, 165,
     32, 137,   0, 144,  71, 239, 234, 183,  21,   6, 205, 181,  18, 126, 187,  41,
     15, 184,   7,   4, 155, 148,  33, 102, 230, 206, 237, 231,  59, 254, 127, 197,
    164,  55, 177,  76, 145, 110, 141, 118,   3,  45, 222, 150,  38, 125, 198,  92,
    211, 242,  79,  25,  63, 220, 121,  29,  82, 235, 243, 109,  94, 251, 105, 178,
    240,  49,  12, 212, 207, 140, 226, 117, 169,  74,  87, 132,  17,  69,  27, 245,
    228,  14, 115, 170, 241, 221,  89,  20, 108, 146,  84, 208, 120, 112, 227,  73,
    128,  80, 167, 246, 119, 147, 134, 131,  42, 199,  91, 233, 238, 143,   1,  61,
)

comptime SBOX3: StaticTuple[UInt8, 256] = StaticTuple[UInt8, 256](
     56,  65,  22, 118, 217, 147,  96, 242, 114, 194, 171, 154, 117,   6,  87, 160,
    145, 247, 181, 201, 162, 140, 210, 144, 246,   7, 167,  39, 142, 178,  73, 222,
     67,  92, 215, 199,  62, 245, 143, 103,  31,  24, 110, 175,  47, 226, 133,  13,
     83, 240, 156, 101, 234, 163, 174, 158, 236, 128,  45, 107, 168,  43,  54, 166,
    197, 134,  77,  51, 253, 102,  88, 150,  58,   9, 149,  16, 120, 216,  66, 204,
    239,  38, 229,  97,  26,  63,  59, 130, 182, 219, 212, 152, 232, 139,   2, 235,
     10,  44,  29, 176, 111, 141, 136,  14,  25, 135,  78,  11, 169,  12, 121,  17,
    127,  34, 231,  89, 225, 218,  61, 200,  18,   4, 116,  84,  48, 126, 180,  40,
     85, 104,  80, 190, 208, 196,  49, 203,  42, 173,  15, 202, 112, 255,  50, 105,
      8,  98,   0,  36, 209, 251, 186, 237,  69, 129, 115, 109, 132, 159, 238,  74,
    195,  46, 193,   1, 230,  37,  72, 153, 185, 179, 123, 249, 206, 191, 223, 113,
     41, 205, 108,  19, 100, 155,  99, 157, 192,  75, 183, 165, 137,  95, 177,  23,
    244, 188, 211,  70, 207,  55,  94,  71, 148, 250, 252,  91, 151, 254,  90, 172,
     60,  76,   3,  53, 243,  35, 184,  93, 106, 146, 213,  33,  68,  81, 198, 125,
     57, 131, 220, 170, 124, 119,  86,   5,  27, 164,  21,  52,  30,  28, 248,  82,
     32,  20, 233, 189, 221, 228, 161, 224, 138, 241, 214, 122, 187, 227,  64,  79,
)

comptime SBOX4: StaticTuple[UInt8, 256] = StaticTuple[UInt8, 256](
    112,  44, 179, 192, 228,  87, 234, 174,  35, 107,  69, 165, 237,  79,  29, 146,
    134, 175, 124,  31,  62, 220,  94,  11, 166,  57, 213,  93, 217,  90,  81, 108,
    139, 154, 251, 176, 116,  43, 240, 132, 223, 203,  52, 118, 109, 169, 209,   4,
     20,  58, 222,  17,  50, 156,  83, 242, 254, 207, 195, 122,  36, 232,  96, 105,
    170, 160, 161,  98,  84,  30, 224, 100,  16,   0, 163, 117, 138, 230,   9, 221,
    135, 131, 205, 144, 115, 246, 157, 191,  82, 216, 200, 198, 129, 111,  19,  99,
    233, 167, 159, 188,  41, 249,  47, 180, 120,   6, 231, 113, 212, 171, 136, 141,
    114, 185, 248, 172,  54,  42,  60, 241,  64, 211, 187,  67,  21, 173, 119, 128,
    130, 236,  39, 229, 133,  53,  12,  65, 239, 147,  25,  33,  14,  78, 101, 189,
    184, 143, 235, 206,  48,  95, 197,  26, 225, 202,  71,  61,   1, 214,  86,  77,
     13, 102, 204,  45,  18,  32, 177, 153,  76, 194, 126,   5, 183,  49,  23, 215,
     88,  97,  27,  28,  15,  22,  24,  34,  68, 178, 181, 145,   8, 168, 252,  80,
    208, 125, 137, 151,  91, 149, 255, 210, 196,  72, 247, 219,   3, 218,  63, 148,
     92,   2,  74,  51, 103, 243, 127, 226, 155,  38,  55,  59, 150,  75, 190,  46,
    121, 140, 110, 142, 245, 182, 253,  89, 152, 106,  70, 186,  37,  66, 162, 250,
      7,  85, 238,  10,  73, 104,  56, 164,  40, 123, 201, 193, 227, 244, 199, 158,
)

@always_inline
def sbox1_lookup(idx: UInt8) -> UInt8:
    return SBOX1._unsafe_ref(Int(idx))

@always_inline
def sbox2_lookup(idx: UInt8) -> UInt8:
    return SBOX2._unsafe_ref(Int(idx))

@always_inline
def sbox3_lookup(idx: UInt8) -> UInt8:
    return SBOX3._unsafe_ref(Int(idx))

@always_inline
def sbox4_lookup(idx: UInt8) -> UInt8:
    return SBOX4._unsafe_ref(Int(idx))

comptime SIGMA1 = 0xA09E667F3BCC908B
comptime SIGMA2 = 0xB67AE8584CAA73B2
comptime SIGMA3 = 0xC6EF372FE94F82BE
comptime SIGMA4 = 0x54FF53A5F1D36F1C
comptime SIGMA5 = 0x10E527FADE682D1D
comptime SIGMA6 = 0xB05688C2B3E6C1FD


@always_inline
def rotl128[n: Int](high: UInt64, low: UInt64) -> SIMD[DType.uint64, 2]:
    comptime shift = n % 128

    comptime if shift == 0:
        return SIMD[DType.uint64, 2](high, low)
    else:
        comptime if shift == 64:
            return SIMD[DType.uint64, 2](low, high)
        else:
            comptime if shift < 64:
                comptime s = UInt64(shift)
                return SIMD[DType.uint64, 2](
                    (high << s) | (low >> (UInt64(64) - s)),
                    (low << s) | (high >> (UInt64(64) - s)),
                )
            else:
                comptime s = UInt64(shift - 64)
                return SIMD[DType.uint64, 2](
                    (low << s) | (high >> (UInt64(64) - s)),
                    (high << s) | (low >> (UInt64(64) - s)),
                )


# Table-based S-box lookups are not constant-time against cache-timing observers.
@always_inline
def camellia_f(f_in: UInt64, ke: UInt64) -> UInt64:
    var x = f_in ^ ke
    
    var t1 = UInt8((x >> 56) & 0xFF)
    var t2 = UInt8((x >> 48) & 0xFF)
    var t3 = UInt8((x >> 40) & 0xFF)
    var t4 = UInt8((x >> 32) & 0xFF)
    var t5 = UInt8((x >> 24) & 0xFF)
    var t6 = UInt8((x >> 16) & 0xFF)
    var t7 = UInt8((x >>  8) & 0xFF)
    var t8 = UInt8(x & 0xFF)
    
    t1 = sbox1_lookup(t1)
    t8 = sbox1_lookup(t8)
    
    t2 = sbox2_lookup(t2)
    t5 = sbox2_lookup(t5)
    
    t3 = sbox3_lookup(t3)
    t6 = sbox3_lookup(t6)
    
    t4 = sbox4_lookup(t4)
    t7 = sbox4_lookup(t7)
    
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
def camellia_fl(fl_in: UInt64, ke: UInt64) -> UInt64:
    var x1 = UInt32(fl_in >> 32)
    var x2 = UInt32(fl_in & 0xFFFFFFFF)
    var k1 = UInt32(ke >> 32)
    var k2 = UInt32(ke & 0xFFFFFFFF)
    
    x2 ^= rotate_bits_left[1](x1 & k1)
    x1 ^= x2 | k2
    
    return (UInt64(x1) << 32) | UInt64(x2)


@always_inline
def camellia_flinv(flinv_in: UInt64, ke: UInt64) -> UInt64:
    var y1 = UInt32(flinv_in >> 32)
    var y2 = UInt32(flinv_in & 0xFFFFFFFF)
    var k1 = UInt32(ke >> 32)
    var k2 = UInt32(ke & 0xFFFFFFFF)
    
    y1 ^= y2 | k2
    y2 ^= rotate_bits_left[1](y1 & k1)
    
    return (UInt64(y1) << 32) | UInt64(y2)


struct CamelliaCipher:
    var kw: SIMD[DType.uint64, 4]
    var k: InlineArray[UInt64, 24]
    var ke: InlineArray[UInt64, 6]
    var is_128: Bool
    
    def __init__(out self, key: Span[UInt8, ...]) raises:
        self.kw = SIMD[DType.uint64, 4](0)
        self.k = InlineArray[UInt64, 24](fill=0)
        self.ke = InlineArray[UInt64, 6](fill=0)
        self.is_128 = len(key) == 16

        if self.is_128:
            self._key_schedule_128(key)
        elif len(key) == 24 or len(key) == 32:
            self._key_schedule_192_256(key)
        else:
            raise Error("Camellia key must be 16, 24, or 32 bytes")

    def wipe(mut self):
        var kw_ptr = UnsafePointer(to=self.kw).bitcast[UInt64]()
        kw_ptr.store[volatile=True](0, SIMD[DType.uint64, 4](0))
        var k_ptr = self.k.unsafe_ptr()
        for i in range(24):
            k_ptr.store[volatile=True](i, UInt64(0))
        var ke_ptr = self.ke.unsafe_ptr()
        for i in range(6):
            ke_ptr.store[volatile=True](i, UInt64(0))

    @always_inline
    def _bytes_to_u64_be(ref self, b: Span[UInt8, ...]) -> UInt64:
        return byte_swap(bitcast[DType.uint64, 1](b.unsafe_ptr().load[width=8, alignment=1](0))[0])

    def _key_schedule_128(mut self, key: Span[UInt8, ...]):
        var kl_h = self._bytes_to_u64_be(key[0:8])
        var kl_l = self._bytes_to_u64_be(key[8:16])
        var kr_h: UInt64 = 0
        var kr_l: UInt64 = 0
        
        var d1 = kl_h ^ kr_h
        var d2 = kl_l ^ kr_l
        
        d2 ^= camellia_f(d1, SIGMA1)
        d1 ^= camellia_f(d2, SIGMA2)
        d1 ^= kl_h
        d2 ^= kl_l
        d2 ^= camellia_f(d1, SIGMA3)
        d1 ^= camellia_f(d2, SIGMA4)
        
        var ka_h = d1
        var ka_l = d2
        
        self.kw[0] = kl_h
        self.kw[1] = kl_l
        self.k[0] = ka_h
        self.k[1] = ka_l
        
        var rot = rotl128[15](kl_h, kl_l)
        self.k[2] = rot[0]
        self.k[3] = rot[1]
        rot = rotl128[15](ka_h, ka_l)
        self.k[4] = rot[0]
        self.k[5] = rot[1]
        
        rot = rotl128[30](ka_h, ka_l)
        self.ke[0] = rot[0]
        self.ke[1] = rot[1]
        
        rot = rotl128[45](kl_h, kl_l)
        self.k[6] = rot[0]
        self.k[7] = rot[1]
        rot = rotl128[45](ka_h, ka_l)
        self.k[8] = rot[0]
        
        rot = rotl128[60](kl_h, kl_l)
        self.k[9] = rot[1]
        rot = rotl128[60](ka_h, ka_l)
        self.k[10] = rot[0]
        self.k[11] = rot[1]
        
        rot = rotl128[77](kl_h, kl_l)
        self.ke[2] = rot[0]
        self.ke[3] = rot[1]
        
        rot = rotl128[94](kl_h, kl_l)
        self.k[12] = rot[0]
        self.k[13] = rot[1]
        rot = rotl128[94](ka_h, ka_l)
        self.k[14] = rot[0]
        self.k[15] = rot[1]
        
        rot = rotl128[111](kl_h, kl_l)
        self.k[16] = rot[0]
        self.k[17] = rot[1]
        
        rot = rotl128[111](ka_h, ka_l)
        self.kw[2] = rot[0]
        self.kw[3] = rot[1]

    def _key_schedule_192_256(mut self, key: Span[UInt8, ...]):
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
        
        d2 ^= camellia_f(d1, SIGMA1)
        d1 ^= camellia_f(d2, SIGMA2)
        d1 ^= kl_h
        d2 ^= kl_l
        d2 ^= camellia_f(d1, SIGMA3)
        d1 ^= camellia_f(d2, SIGMA4)
        
        var ka_h = d1
        var ka_l = d2
        
        d1 = ka_h ^ kr_h
        d2 = ka_l ^ kr_l
        d2 ^= camellia_f(d1, SIGMA5)
        d1 ^= camellia_f(d2, SIGMA6)
        var kb_h = d1
        var kb_l = d2
        
        self.kw[0] = kl_h
        self.kw[1] = kl_l
        self.k[0] = kb_h
        self.k[1] = kb_l
        
        var rot = rotl128[15](kr_h, kr_l)
        self.k[2] = rot[0]
        self.k[3] = rot[1]
        rot = rotl128[15](ka_h, ka_l)
        self.k[4] = rot[0]
        self.k[5] = rot[1]
        
        rot = rotl128[30](kr_h, kr_l)
        self.ke[0] = rot[0]
        self.ke[1] = rot[1]
        rot = rotl128[30](kb_h, kb_l)
        self.k[6] = rot[0]
        self.k[7] = rot[1]
        
        rot = rotl128[45](kl_h, kl_l)
        self.k[8] = rot[0]
        self.k[9] = rot[1]
        rot = rotl128[45](ka_h, ka_l)
        self.k[10] = rot[0]
        self.k[11] = rot[1]
        
        rot = rotl128[60](kl_h, kl_l)
        self.ke[2] = rot[0]
        self.ke[3] = rot[1]
        rot = rotl128[60](kr_h, kr_l)
        self.k[12] = rot[0]
        self.k[13] = rot[1]
        rot = rotl128[60](kb_h, kb_l)
        self.k[14] = rot[0]
        self.k[15] = rot[1]
        
        rot = rotl128[77](kl_h, kl_l)
        self.k[16] = rot[0]
        self.k[17] = rot[1]
        rot = rotl128[77](ka_h, ka_l)
        self.ke[4] = rot[0]
        self.ke[5] = rot[1]
        
        rot = rotl128[94](kr_h, kr_l)
        self.k[18] = rot[0]
        self.k[19] = rot[1]
        rot = rotl128[94](ka_h, ka_l)
        self.k[20] = rot[0]
        self.k[21] = rot[1]
        rot = rotl128[111](kl_h, kl_l)
        self.k[22] = rot[0]
        self.k[23] = rot[1]
        
        rot = rotl128[111](kb_h, kb_l)
        self.kw[2] = rot[0]
        self.kw[3] = rot[1]

    def encrypt(self, block: SIMD[DType.uint8, 16]) -> SIMD[DType.uint8, 16]:
        var cast_block = bitcast[DType.uint64, 2](block)
        var d1 = byte_swap(cast_block[0])
        var d2 = byte_swap(cast_block[1])
        
        d1 ^= self.kw[0]
        d2 ^= self.kw[1]
        
        d2 ^= camellia_f(d1, self.k[0])
        d1 ^= camellia_f(d2, self.k[1])
        d2 ^= camellia_f(d1, self.k[2])
        d1 ^= camellia_f(d2, self.k[3])
        d2 ^= camellia_f(d1, self.k[4])
        d1 ^= camellia_f(d2, self.k[5])
        
        d1 = camellia_fl(d1, self.ke[0])
        d2 = camellia_flinv(d2, self.ke[1])
        
        d2 ^= camellia_f(d1, self.k[6])
        d1 ^= camellia_f(d2, self.k[7])
        d2 ^= camellia_f(d1, self.k[8])
        d1 ^= camellia_f(d2, self.k[9])
        d2 ^= camellia_f(d1, self.k[10])
        d1 ^= camellia_f(d2, self.k[11])
        
        d1 = camellia_fl(d1, self.ke[2])
        d2 = camellia_flinv(d2, self.ke[3])
        
        d2 ^= camellia_f(d1, self.k[12])
        d1 ^= camellia_f(d2, self.k[13])
        d2 ^= camellia_f(d1, self.k[14])
        d1 ^= camellia_f(d2, self.k[15])
        d2 ^= camellia_f(d1, self.k[16])
        d1 ^= camellia_f(d2, self.k[17])
        
        if not self.is_128:
            d1 = camellia_fl(d1, self.ke[4])
            d2 = camellia_flinv(d2, self.ke[5])
            
            d2 ^= camellia_f(d1, self.k[18])
            d1 ^= camellia_f(d2, self.k[19])
            d2 ^= camellia_f(d1, self.k[20])
            d1 ^= camellia_f(d2, self.k[21])
            d2 ^= camellia_f(d1, self.k[22])
            d1 ^= camellia_f(d2, self.k[23])
        
        d2 ^= self.kw[2]
        d1 ^= self.kw[3]
        
        return bitcast[DType.uint8, 16](SIMD[DType.uint64, 2](byte_swap(d2), byte_swap(d1)))

    def decrypt(self, block: SIMD[DType.uint8, 16]) -> SIMD[DType.uint8, 16]:
        var cast_block = bitcast[DType.uint64, 2](block)
        var d1 = byte_swap(cast_block[1])
        var d2 = byte_swap(cast_block[0])
        
        d2 ^= self.kw[2]
        d1 ^= self.kw[3]
        
        if not self.is_128:
            d1 ^= camellia_f(d2, self.k[23])
            d2 ^= camellia_f(d1, self.k[22])
            d1 ^= camellia_f(d2, self.k[21])
            d2 ^= camellia_f(d1, self.k[20])
            d1 ^= camellia_f(d2, self.k[19])
            d2 ^= camellia_f(d1, self.k[18])
            
            d1 = camellia_flinv(d1, self.ke[4])
            d2 = camellia_fl(d2, self.ke[5])
        
        d1 ^= camellia_f(d2, self.k[17])
        d2 ^= camellia_f(d1, self.k[16])
        d1 ^= camellia_f(d2, self.k[15])
        d2 ^= camellia_f(d1, self.k[14])
        d1 ^= camellia_f(d2, self.k[13])
        d2 ^= camellia_f(d1, self.k[12])
        
        d1 = camellia_flinv(d1, self.ke[2])
        d2 = camellia_fl(d2, self.ke[3])
        
        d1 ^= camellia_f(d2, self.k[11])
        d2 ^= camellia_f(d1, self.k[10])
        d1 ^= camellia_f(d2, self.k[9])
        d2 ^= camellia_f(d1, self.k[8])
        d1 ^= camellia_f(d2, self.k[7])
        d2 ^= camellia_f(d1, self.k[6])
        
        d1 = camellia_flinv(d1, self.ke[0])
        d2 = camellia_fl(d2, self.ke[1])
        
        d1 ^= camellia_f(d2, self.k[5])
        d2 ^= camellia_f(d1, self.k[4])
        d1 ^= camellia_f(d2, self.k[3])
        d2 ^= camellia_f(d1, self.k[2])
        d1 ^= camellia_f(d2, self.k[1])
        d2 ^= camellia_f(d1, self.k[0])
        
        d1 ^= self.kw[0]
        d2 ^= self.kw[1]
        
        return bitcast[DType.uint8, 16](SIMD[DType.uint64, 2](byte_swap(d1), byte_swap(d2)))

    def encrypt(self, block: Span[UInt8, ...]) raises -> SIMD[DType.uint8, 16]:
        if len(block) < 16:
            raise Error("Camellia block must be 16 bytes")
        return self.encrypt(block.unsafe_ptr().load[width=16, alignment=1](0))

    def decrypt(self, block: Span[UInt8, ...]) raises -> SIMD[DType.uint8, 16]:
        if len(block) < 16:
            raise Error("Camellia block must be 16 bytes")
        return self.decrypt(block.unsafe_ptr().load[width=16, alignment=1](0))
