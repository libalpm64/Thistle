"""
KCipher-2 stream cipher implemented in Mojo.
"""

from std.memory import bitcast
from .utils import transpose8x8
from .aes_ni import (
    _aese,
    _aesmc,
    _mm_aesenc_si128,
    has_arm_crypto,
    has_x86_aes_ni,
)

comptime AMUL_BASIS_0 = SIMD[DType.uint32, 4](
    0xB6086D1A, 0xA0F5FC2E, 0x5BF87F93, 0x4559568B
)
comptime AMUL_BASIS_1 = SIMD[DType.uint32, 4](
    0xAF10DA34, 0x6DC7D55C, 0xB6BDFE6B, 0x8AB2AC73
)
comptime AMUL_BASIS_2 = SIMD[DType.uint32, 4](
    0x9D207768, 0xDAA387B8, 0x2137B1D6, 0x71013DE6
)
comptime AMUL_BASIS_3 = SIMD[DType.uint32, 4](
    0xF940EED0, 0x996B235D, 0x426E2FE1, 0xE2027AA9
)
comptime AMUL_BASIS_4 = SIMD[DType.uint32, 4](
    0x31801F63, 0x1FD646BA, 0x84DC5E8F, 0xA104F437
)
comptime AMUL_BASIS_5 = SIMD[DType.uint32, 4](
    0x62C33EC6, 0x3E818C59, 0x45F5BC53, 0x27088D6E
)
comptime AMUL_BASIS_6 = SIMD[DType.uint32, 4](
    0xC4457C4F, 0x7C2F35B2, 0x8AA735A6, 0x4E107FDC
)
comptime AMUL_BASIS_7 = SIMD[DType.uint32, 4](
    0x4B8AF89E, 0xF85E6A49, 0x59036A01, 0x9C20FEDD
)

@always_inline
def _amul4(b: SIMD[DType.uint32, 4]) -> SIMD[DType.uint32, 4]:
    var zero = SIMD[DType.uint32, 4](0)
    var r = (zero - (b & 1)) & AMUL_BASIS_0
    r ^= (zero - ((b >> 1) & 1)) & AMUL_BASIS_1
    r ^= (zero - ((b >> 2) & 1)) & AMUL_BASIS_2
    r ^= (zero - ((b >> 3) & 1)) & AMUL_BASIS_3
    r ^= (zero - ((b >> 4) & 1)) & AMUL_BASIS_4
    r ^= (zero - ((b >> 5) & 1)) & AMUL_BASIS_5
    r ^= (zero - ((b >> 6) & 1)) & AMUL_BASIS_6
    r ^= (zero - ((b >> 7) & 1)) & AMUL_BASIS_7
    return r


@always_inline
def _rho(x: UInt32) -> UInt32:
    # byte k+1 (mod 4)
    return ((x >> 1) & 0x7777) | ((x << 3) & 0x8888)


@always_inline
def _rho2(x: UInt32) -> UInt32:
    # rho applied twice
    return ((x >> 2) & 0x3333) | ((x << 2) & 0xCCCC)


@always_inline
def _sbox_planes(mut p: InlineArray[UInt32, 8]):
    # Boyar-Peralta AES S-box circuit.
	# https://tches.iacr.org/index.php/TCHES/article/view/11940/11800
    var x0 = p[7]
    var x1 = p[6]
    var x2 = p[5]
    var x3 = p[4]
    var x4 = p[3]
    var x5 = p[2]
    var x6 = p[1]
    var x7 = p[0]

    var y14 = x3 ^ x5
    var y13 = x0 ^ x6
    var y9 = x0 ^ x3
    var y8 = x0 ^ x5
    var t0 = x1 ^ x2
    var y1 = t0 ^ x7
    var y4 = y1 ^ x3
    var y12 = y13 ^ y14
    var y2 = y1 ^ x0
    var y5 = y1 ^ x6
    var y3 = y5 ^ y8
    var t1 = x4 ^ y12
    var y15 = t1 ^ x5
    var y20 = t1 ^ x1
    var y6 = y15 ^ x7
    var y10 = y15 ^ t0
    var y11 = y20 ^ y9
    var y7 = x7 ^ y11
    var y17 = y10 ^ y11
    var y19 = y10 ^ y8
    var y16 = t0 ^ y11
    var y21 = y13 ^ y16
    var y18 = x0 ^ y16

    var t2 = y12 & y15
    var t3 = y3 & y6
    var t4 = t3 ^ t2
    var t5 = y4 & x7
    var t6 = t5 ^ t2
    var t7 = y13 & y16
    var t8 = y5 & y1
    var t9 = t8 ^ t7
    var t10 = y2 & y7
    var t11 = t10 ^ t7
    var t12 = y9 & y11
    var t13 = y14 & y17
    var t14 = t13 ^ t12
    var t15 = y8 & y10
    var t16 = t15 ^ t12
    var t17 = t4 ^ t14
    var t18 = t6 ^ t16
    var t19 = t9 ^ t14
    var t20 = t11 ^ t16
    var t21 = t17 ^ y20
    var t22 = t18 ^ y19
    var t23 = t19 ^ y21
    var t24 = t20 ^ y18
    var t25 = t21 ^ t22
    var t26 = t21 & t23
    var t27 = t24 ^ t26
    var t28 = t25 & t27
    var t29 = t28 ^ t22
    var t30 = t23 ^ t24
    var t31 = t22 ^ t26
    var t32 = t31 & t30
    var t33 = t32 ^ t24
    var t34 = t23 ^ t33
    var t35 = t27 ^ t33
    var t36 = t24 & t35
    var t37 = t36 ^ t34
    var t38 = t27 ^ t36
    var t39 = t29 & t38
    var t40 = t25 ^ t39
    var t41 = t40 ^ t37
    var t42 = t29 ^ t33
    var t43 = t29 ^ t40
    var t44 = t33 ^ t37
    var t45 = t42 ^ t41

    var z0 = t44 & y15
    var z1 = t37 & y6
    var z2 = t33 & x7
    var z3 = t43 & y16
    var z4 = t40 & y1
    var z5 = t29 & y7
    var z6 = t42 & y11
    var z7 = t45 & y17
    var z8 = t41 & y10
    var z9 = t44 & y12
    var z10 = t37 & y3
    var z11 = t33 & y4
    var z12 = t43 & y13
    var z13 = t40 & y5
    var z14 = t29 & y2
    var z15 = t42 & y9
    var z16 = t45 & y14
    var z17 = t41 & y8

    var t46 = z15 ^ z16
    var t47 = z10 ^ z11
    var t48 = z5 ^ z13
    var t49 = z9 ^ z10
    var t50 = z2 ^ z12
    var t51 = z2 ^ z5
    var t52 = z7 ^ z8
    var t53 = z0 ^ z3
    var t54 = z6 ^ z7
    var t55 = z16 ^ z17
    var t56 = z12 ^ t48
    var t57 = t50 ^ t53
    var t58 = z4 ^ t46
    var t59 = z3 ^ t54
    var t60 = t46 ^ t57
    var t61 = z14 ^ t57
    var t62 = t52 ^ t58
    var t63 = t49 ^ t58
    var t64 = z4 ^ t59
    var t65 = t61 ^ t62
    var t66 = z1 ^ t63
    var s0 = t59 ^ t63
    var s6 = ~(t56 ^ t62)
    var s7 = ~(t48 ^ t60)
    var t67 = t64 ^ t65
    var s3 = t53 ^ t66
    var s4 = t51 ^ t66
    var s5 = t47 ^ t65
    var s1 = ~(t64 ^ s3)
    var s2 = ~(t55 ^ t67)

    p[0] = s7
    p[1] = s6
    p[2] = s5
    p[3] = s4
    p[4] = s3
    p[5] = s2
    p[6] = s1
    p[7] = s0


# idx[4*c + r] = 4*((c - r) mod 4) + r.
@always_inline
def sub_k2_x4(
    w0: UInt32, w1: UInt32, w2: UInt32, w3: UInt32
) -> SIMD[DType.uint32, 4]:
    comptime if has_arm_crypto():
        var v = bitcast[DType.uint8, 16](SIMD[DType.uint32, 4](w0, w1, w2, w3))
        var s = v.shuffle[
            0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3
        ]()
        return bitcast[DType.uint32, 4](
            _aesmc(_aese(s, SIMD[DType.uint8, 16](0)))
        )
    elif has_x86_aes_ni():
        var v = bitcast[DType.uint8, 16](SIMD[DType.uint32, 4](w0, w1, w2, w3))
        var s = v.shuffle[
            0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3
        ]()
        return bitcast[DType.uint32, 4](
            _mm_aesenc_si128(
                bitcast[DType.uint64, 2](s), SIMD[DType.uint64, 2](0)
            )
        )
    else:
        return _sub_k2_x4_bitsliced(w0, w1, w2, w3)


@always_inline
def _sub_k2_x4_bitsliced(
    w0: UInt32, w1: UInt32, w2: UInt32, w3: UInt32
) -> SIMD[DType.uint32, 4]:
    # Attempt to defeat SROA
    var tlo = transpose8x8(UInt64(w0) | (UInt64(w1) << 32))
    var thi = transpose8x8(UInt64(w2) | (UInt64(w3) << 32))
    var p = InlineArray[UInt32, 8](fill=0)

    comptime for j in range(8):
        p[j] = UInt32((tlo >> UInt64(8 * j)) & 0xFF) | (
            UInt32((thi >> UInt64(8 * j)) & 0xFF) << 8
        )

    _sbox_planes(p)

    # q_k = 2*t_k ^ 3*t_{k+1} ^ t_{k+2} ^ t_{k+3}.
    # e = t ^ rho(t) this reduces to xtime(e) ^ e ^ rho2(e) ^ t
    # rho(t) ^ rho2(t) ^ rho3(t) = e ^ rho2(e) ^ t.
    var e = InlineArray[UInt32, 8](fill=0)
    var s = InlineArray[UInt32, 8](fill=0)

    comptime for j in range(8):
        e[j] = p[j] ^ _rho(p[j])
        s[j] = e[j] ^ _rho2(e[j]) ^ p[j]

    # xtime permutation plane fold carry plane e[7] back
    # into planes 1, 3 and 4 (AES 0x1B).
    var q = InlineArray[UInt32, 8](fill=0)
    q[0] = e[7] ^ s[0]
    q[1] = e[0] ^ e[7] ^ s[1]
    q[2] = e[1] ^ s[2]
    q[3] = e[2] ^ e[7] ^ s[3]
    q[4] = e[3] ^ e[7] ^ s[4]
    q[5] = e[4] ^ s[5]
    q[6] = e[5] ^ s[6]
    q[7] = e[6] ^ s[7]

    # Upper 16 bits of each plane are garbage (S-box XNOR outputs)
    var olo = UInt64(0)
    var ohi = UInt64(0)

    comptime for j in range(8):
        olo |= UInt64(q[j] & 0xFF) << UInt64(8 * j)
        ohi |= UInt64((q[j] >> 8) & 0xFF) << UInt64(8 * j)
    olo = transpose8x8(olo)
    ohi = transpose8x8(ohi)

    return SIMD[DType.uint32, 4](
        UInt32(olo & 0xFFFFFFFF),
        UInt32(olo >> 32),
        UInt32(ohi & 0xFFFFFFFF),
        UInt32(ohi >> 32),
    )


@always_inline
def sub_k2(in_val: UInt32) -> UInt32:
    return sub_k2_x4(in_val, in_val, in_val, in_val)[0]


@always_inline
def nlf(a: UInt32, b: UInt32, c: UInt32, d: UInt32) -> UInt32:
    return (a + b) ^ c ^ d


struct KCipher2:
    var a0: UInt32
    var a1: UInt32
    var a2: UInt32
    var a3: UInt32
    var a4: UInt32
    var b0: UInt32
    var b1: UInt32
    var b2: UInt32
    var b3: UInt32
    var b4: UInt32
    var b5: UInt32
    var b6: UInt32
    var b7: UInt32
    var b8: UInt32
    var b9: UInt32
    var b10: UInt32
    var l1: UInt32
    var r1: UInt32
    var l2: UInt32
    var r2: UInt32

    def __init__(out self):
        self.a0 = 0
        self.a1 = 0
        self.a2 = 0
        self.a3 = 0
        self.a4 = 0
        self.b0 = 0
        self.b1 = 0
        self.b2 = 0
        self.b3 = 0
        self.b4 = 0
        self.b5 = 0
        self.b6 = 0
        self.b7 = 0
        self.b8 = 0
        self.b9 = 0
        self.b10 = 0
        self.l1 = 0
        self.r1 = 0
        self.l2 = 0
        self.r2 = 0

    def __init__(
        out self, key: SIMD[DType.uint32, 4], iv: SIMD[DType.uint32, 4]
    ):
        self.a0 = 0
        self.a1 = 0
        self.a2 = 0
        self.a3 = 0
        self.a4 = 0
        self.b0 = 0
        self.b1 = 0
        self.b2 = 0
        self.b3 = 0
        self.b4 = 0
        self.b5 = 0
        self.b6 = 0
        self.b7 = 0
        self.b8 = 0
        self.b9 = 0
        self.b10 = 0
        self.l1 = 0
        self.r1 = 0
        self.l2 = 0
        self.r2 = 0
        self._init(key, iv)

    def _key_expansion(
        mut self, key: SIMD[DType.uint32, 4], iv: SIMD[DType.uint32, 4]
    ) -> InlineArray[UInt32, 12]:
        var ik = InlineArray[UInt32, 12](fill=0)

        ik[0] = key[0]
        ik[1] = key[1]
        ik[2] = key[2]
        ik[3] = key[3]

        ik[4] = (
            ik[0]
            ^ sub_k2(((ik[3] << 8) & 0xFFFFFFFF) ^ (ik[3] >> 24))
            ^ 0x01000000
        )
        ik[5] = ik[1] ^ ik[4]
        ik[6] = ik[2] ^ ik[5]
        ik[7] = ik[3] ^ ik[6]

        ik[8] = (
            ik[4]
            ^ sub_k2(((ik[7] << 8) & 0xFFFFFFFF) ^ (ik[7] >> 24))
            ^ 0x02000000
        )
        ik[9] = ik[5] ^ ik[8]
        ik[10] = ik[6] ^ ik[9]
        ik[11] = ik[7] ^ ik[10]

        return ik

    @always_inline
    def _select_u32(self, a: UInt32, b: UInt32, choice: UInt32) -> UInt32:
        var mask = UInt32(0) - choice
        return a ^ (mask & (a ^ b))

    def _init(mut self, key: SIMD[DType.uint32, 4], iv: SIMD[DType.uint32, 4]):
        var ik = self._key_expansion(key, iv)

        self.a0 = ik[4]
        self.a1 = ik[3]
        self.a2 = ik[2]
        self.a3 = ik[1]
        self.a4 = ik[0]

        self.b0 = ik[10]
        self.b1 = ik[11]
        self.b2 = iv[0]
        self.b3 = iv[1]
        self.b4 = ik[8]
        self.b5 = ik[9]
        self.b6 = iv[2]
        self.b7 = iv[3]
        self.b8 = ik[7]
        self.b9 = ik[5]
        self.b10 = ik[6]

        self.l1 = 0
        self.r1 = 0
        self.l2 = 0
        self.r2 = 0

        for _ in range(24):
            self._next_init()

    @always_inline
    def _next_init(mut self):
        var fsm = sub_k2_x4(
            self.r2 + self.b4, self.l2 + self.b9, self.l1, self.r1
        )
        var nL1 = fsm[0]
        var nR1 = fsm[1]
        var nL2 = fsm[2]
        var nR2 = fsm[3]

        var old_a0 = self.a0
        var old_a2 = self.a2

        var am = _amul4(
            SIMD[DType.uint32, 4](
                self.a0 >> 24, self.b0 >> 24, self.b0 >> 24, self.b8 >> 24
            )
        )

        var temp1 = ((self.a0 << 8) & 0xFFFFFF00) ^ am[0]
        var new_a4 = temp1 ^ self.a3 ^ nlf(self.b0, self.r2, self.r1, self.a4)

        self.a0 = self.a1
        self.a1 = self.a2
        self.a2 = self.a3
        self.a3 = self.a4
        self.a4 = new_a4

        var b0_shift = (self.b0 << 8) & 0xFFFFFF00
        var temp1_amul1 = b0_shift ^ am[1]
        var temp1_amul2 = b0_shift ^ am[2]
        temp1 = self._select_u32(temp1_amul2, temp1_amul1, (old_a2 >> 30) & 1)

        var temp2_amul3 = ((self.b8 << 8) & 0xFFFFFF00) ^ am[3]
        var temp2 = self._select_u32(self.b8, temp2_amul3, (old_a2 >> 31) & 1)

        var new_b10 = (
            temp1
            ^ self.b1
            ^ self.b6
            ^ temp2
            ^ nlf(self.b10, self.l2, self.l1, old_a0)
        )

        self.b0 = self.b1
        self.b1 = self.b2
        self.b2 = self.b3
        self.b3 = self.b4
        self.b4 = self.b5
        self.b5 = self.b6
        self.b6 = self.b7
        self.b7 = self.b8
        self.b8 = self.b9
        self.b9 = self.b10
        self.b10 = new_b10

        self.l1 = nL1
        self.r1 = nR1
        self.l2 = nL2
        self.r2 = nR2

    @always_inline
    def _next_normal(mut self):
        var fsm = sub_k2_x4(
            self.r2 + self.b4, self.l2 + self.b9, self.l1, self.r1
        )
        var nL1 = fsm[0]
        var nR1 = fsm[1]
        var nL2 = fsm[2]
        var nR2 = fsm[3]

        var old_a2 = self.a2

        var am = _amul4(
            SIMD[DType.uint32, 4](
                self.a0 >> 24, self.b0 >> 24, self.b0 >> 24, self.b8 >> 24
            )
        )

        var temp1 = ((self.a0 << 8) & 0xFFFFFF00) ^ am[0]
        var new_a4 = temp1 ^ self.a3

        self.a0 = self.a1
        self.a1 = self.a2
        self.a2 = self.a3
        self.a3 = self.a4
        self.a4 = new_a4

        var b0_shift = (self.b0 << 8) & 0xFFFFFF00
        var temp1_amul1 = b0_shift ^ am[1]
        var temp1_amul2 = b0_shift ^ am[2]
        temp1 = self._select_u32(temp1_amul2, temp1_amul1, (old_a2 >> 30) & 1)

        var temp2_amul3 = ((self.b8 << 8) & 0xFFFFFF00) ^ am[3]
        var temp2 = self._select_u32(self.b8, temp2_amul3, (old_a2 >> 31) & 1)

        var new_b10 = temp1 ^ self.b1 ^ self.b6 ^ temp2

        self.b0 = self.b1
        self.b1 = self.b2
        self.b2 = self.b3
        self.b3 = self.b4
        self.b4 = self.b5
        self.b5 = self.b6
        self.b6 = self.b7
        self.b7 = self.b8
        self.b8 = self.b9
        self.b9 = self.b10
        self.b10 = new_b10

        self.l1 = nL1
        self.r1 = nR1
        self.l2 = nL2
        self.r2 = nR2

    @always_inline
    def stream(mut self) -> UInt64:
        var zh = nlf(self.b10, self.l2, self.l1, self.a0)
        var zl = nlf(self.b0, self.r2, self.r1, self.a4)
        return (UInt64(zh) << 32) | UInt64(zl)

    def encrypt_inplace[
        origin: Origin[mut=True]
    ](mut self, mut data: Span[mut=True, UInt8, origin]):
        var len_data = len(data)
        var data_ptr = data.unsafe_ptr()
        var data_u64 = data_ptr.bitcast[UInt64]()
        var num_u64 = len_data // 8
        var i = 0

        while i + 3 < num_u64:
            var ks0 = self.stream()
            self._next_normal()
            var ks1 = self.stream()
            self._next_normal()
            var ks2 = self.stream()
            self._next_normal()
            var ks3 = self.stream()
            self._next_normal()
            (data_u64 + i).store[alignment=1](
                (data_u64 + i).load[width=1, alignment=1]() ^ ks0
            )
            (data_u64 + i + 1).store[alignment=1](
                (data_u64 + i + 1).load[width=1, alignment=1]() ^ ks1
            )
            (data_u64 + i + 2).store[alignment=1](
                (data_u64 + i + 2).load[width=1, alignment=1]() ^ ks2
            )
            (data_u64 + i + 3).store[alignment=1](
                (data_u64 + i + 3).load[width=1, alignment=1]() ^ ks3
            )
            i += 4

        while i < num_u64:
            var ks = self.stream()
            self._next_normal()
            (data_u64 + i).store[alignment=1](
                (data_u64 + i).load[width=1, alignment=1]() ^ ks
            )
            i += 1

        var offset = num_u64 * 8
        if offset < len_data:
            var z = self.stream()
            self._next_normal()
            var ks = SIMD[DType.uint8, 8](
                UInt8(z),
                UInt8(z >> 8),
                UInt8(z >> 16),
                UInt8(z >> 24),
                UInt8(z >> 32),
                UInt8(z >> 40),
                UInt8(z >> 48),
                UInt8(z >> 56),
            )

            for j in range(len_data - offset):
                data[offset + j] ^= ks[j]
