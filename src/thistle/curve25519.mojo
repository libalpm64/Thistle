# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Libalpm64, Lostlab Technologies.

"""
Curve25519 implementation
By Libalpm64
"""
from std.builtin.dtype import DType
from std.builtin.simd import SIMD

@always_inline
def _u128_shr(x: UInt128, shift: Int) -> UInt128:
    if shift <= 0:
        return x
    if shift >= 128:
        return UInt128(0)
    var lo = x.cast[DType.uint64]()
    var hi = (x >> UInt128(64)).cast[DType.uint64]()
    if shift < 64:
        var out_lo = (lo >> UInt64(shift)) | (hi << UInt64(64 - shift))
        var out_hi = hi >> UInt64(shift)
        return (UInt128(out_hi) << UInt128(64)) | UInt128(out_lo)
    if shift == 64:
        return UInt128(hi)
    var s = shift - 64
    return UInt128(hi >> UInt64(s))

struct FieldElement51(Movable, Copyable, ImplicitlyCopyable):
    var limbs: SIMD[DType.uint64, 5]

    @always_inline
    def __init__(out self):
        self.limbs = SIMD[DType.uint64, 5](0, 0, 0, 0, 0)

    @always_inline
    def __init__(out self, l0: UInt64, l1: UInt64, l2: UInt64, l3: UInt64, l4: UInt64):
        self.limbs = SIMD[DType.uint64, 5](l0, l1, l2, l3, l4)

    @always_inline
    def __init__(out self, limbs: SIMD[DType.uint64, 5]):
        self.limbs = limbs

    @always_inline
    def __copyinit__(out self, copy: Self):
        self.limbs = copy.limbs

    @always_inline
    def __moveinit__(out self, deinit take: Self):
        self.limbs = take.limbs

    @staticmethod
    def ZERO() -> FieldElement51:
        return FieldElement51(0, 0, 0, 0, 0)

    @staticmethod
    def ONE() -> FieldElement51:
        return FieldElement51(1, 0, 0, 0, 0)

    @staticmethod
    def MINUS_ONE() -> FieldElement51:
        return FieldElement51(
            2251799813685228,
            2251799813685247,
            2251799813685247,
            2251799813685247,
            2251799813685247,
        )

    @always_inline
    def to_int(self) -> Int:
        # Producer must use a canonical form first.
		# Note: this is the same reduction is the same as with bytes so interpept this to the same as as_bytes.
        var res = self._reduce(self.limbs)
        var limbs = res.limbs

        var q = (limbs[0] + 19) >> 51
        q = (limbs[1] + q) >> 51
        q = (limbs[2] + q) >> 51
        q = (limbs[3] + q) >> 51
        q = (limbs[4] + q) >> 51

        limbs[0] += 19 * q

        var MASK = UInt64(0x7FFFFFFFFFFFF)
        limbs[1] += limbs[0] >> 51; limbs[0] &= MASK
        limbs[2] += limbs[1] >> 51; limbs[1] &= MASK
        limbs[3] += limbs[2] >> 51; limbs[2] &= MASK
        limbs[4] += limbs[3] >> 51; limbs[3] &= MASK
        limbs[4] &= MASK
        var v: UInt64 = limbs[0]
        v |= limbs[1] << 51
        return Int(v)

    @staticmethod
    def from_int(x: Int) -> FieldElement51:
        if x >= 0 and x < 2251799813685248:
            return FieldElement51(UInt64(x), 0, 0, 0, 0)
        
        var v = x
        if v < 0:
            v = v + 57896044618658097711785492504343953926634992332820282019728792003956564819949
        
        var p2_51 = UInt128(2251799813685248)
        var p2_102 = p2_51 * p2_51
        var p2_153 = p2_102 * p2_51
        var p2_204 = p2_153 * p2_51
        
        var l0 = UInt64(v & 0x7FFFFFFFFFFFF)
        var v1 = v - Int(l0)
        var l1 = UInt64((v1 // 2251799813685248) & 0x7FFFFFFFFFFFF)
        var v2 = v1 - Int(l1) * 2251799813685248
        var l2 = UInt64((v2 // Int(p2_102)) & 0x7FFFFFFFFFFFF)
        var v3 = v2 - Int(l2) * Int(p2_102)
        var l3 = UInt64((v3 // Int(p2_153)) & 0x7FFFFFFFFFFFF)
        var v4 = v3 - Int(l3) * Int(p2_153)
        var l4 = UInt64(v4 // Int(p2_204))
        
        return FieldElement51(l0, l1, l2, l3, l4)

    @always_inline
    def __add__(self, other: FieldElement51) -> FieldElement51:
        var a0 = self.limbs[0] + other.limbs[0]
        var a1 = self.limbs[1] + other.limbs[1]
        var a2 = self.limbs[2] + other.limbs[2]
        var a3 = self.limbs[3] + other.limbs[3]
        var a4 = self.limbs[4] + other.limbs[4]
        
        var carry0 = a0 >> 51
        a0 = a0 & 0x7FFFFFFFFFFFF
        a1 = a1 + carry0
        
        var carry1 = a1 >> 51
        a1 = a1 & 0x7FFFFFFFFFFFF
        a2 = a2 + carry1
        
        var carry2 = a2 >> 51
        a2 = a2 & 0x7FFFFFFFFFFFF
        a3 = a3 + carry2
        
        var carry3 = a3 >> 51
        a3 = a3 & 0x7FFFFFFFFFFFF
        a4 = a4 + carry3
        
        var carry4 = a4 >> 51
        a4 = a4 & 0x7FFFFFFFFFFFF
        
        a0 = a0 + carry4 * 19
        var carry5 = a0 >> 51
        a0 = a0 & 0x7FFFFFFFFFFFF
        a1 = a1 + carry5
        
        # Final carry propagation
        var carry6 = a1 >> 51
        a1 = a1 & 0x7FFFFFFFFFFFF
        a2 = a2 + carry6
        
        var carry7 = a2 >> 51
        a2 = a2 & 0x7FFFFFFFFFFFF
        a3 = a3 + carry7
        
        var carry8 = a3 >> 51
        a3 = a3 & 0x7FFFFFFFFFFFF
        a4 = a4 + carry8
        
        var carry9 = a4 >> 51
        a4 = a4 & 0x7FFFFFFFFFFFF
        a0 = a0 + carry9 * 19
        
        return FieldElement51(a0, a1, a2, a3, a4)

    @always_inline
    def __sub__(self, other: FieldElement51) -> FieldElement51:
        var l = SIMD[DType.uint64, 5]()
        # Add 2*p to ensure results are positive
        # p_limbs = [2^51-19, 2^51-1, 2^51-1, 2^51-1, 2^51-1]
        # 2*p_limbs = [2^52-38, 2^52-2, 2^52-2, 2^52-2, 2^52-2]
        l[0] = (self.limbs[0] + 0xFFFFFFFFFFFDA) - other.limbs[0]
        l[1] = (self.limbs[1] + 0xFFFFFFFFFFFFE) - other.limbs[1]
        l[2] = (self.limbs[2] + 0xFFFFFFFFFFFFE) - other.limbs[2]
        l[3] = (self.limbs[3] + 0xFFFFFFFFFFFFE) - other.limbs[3]
        l[4] = (self.limbs[4] + 0xFFFFFFFFFFFFE) - other.limbs[4]
        return self._carry_reduce_from_limbs(l)

    @always_inline
    def _carry_reduce_from_limbs(self, limbs: SIMD[DType.uint64, 5]) -> FieldElement51:
        var l = limbs
        var MASK = UInt64(0x7FFFFFFFFFFFF)
        
        # Iterate until there are no more carries
        for _ in range(5):
            l[1] += l[0] >> 51
            l[0] = l[0] & MASK
            l[2] += l[1] >> 51
            l[1] = l[1] & MASK
            l[3] += l[2] >> 51
            l[2] = l[2] & MASK
            l[4] += l[3] >> 51
            l[3] = l[3] & MASK
            l[0] += (l[4] >> 51) * 19
            l[4] = l[4] & MASK
        
        return FieldElement51(l)

    @always_inline
    def __mul__(self, other: FieldElement51) -> FieldElement51:
        var a = self.limbs
        var b = other.limbs

        var b0 = UInt128(b[0])
        var b1 = UInt128(b[1])
        var b2 = UInt128(b[2])
        var b3 = UInt128(b[3])
        var b4 = UInt128(b[4])
        var b1_19 = b1 * 19
        var b2_19 = b2 * 19
        var b3_19 = b3 * 19
        var b4_19 = b4 * 19

        var a0 = UInt128(a[0])
        var a1 = UInt128(a[1])
        var a2 = UInt128(a[2])
        var a3 = UInt128(a[3])
        var a4 = UInt128(a[4])

        var c0 = a0 * b0 + a4 * b1_19 + a3 * b2_19 + a2 * b3_19 + a1 * b4_19
        var c1 = a1 * b0 + a0 * b1 + a4 * b2_19 + a3 * b3_19 + a2 * b4_19
        var c2 = a2 * b0 + a1 * b1 + a0 * b2 + a4 * b3_19 + a3 * b4_19
        var c3 = a3 * b0 + a2 * b1 + a1 * b2 + a0 * b3 + a4 * b4_19
        var c4 = a4 * b0 + a3 * b1 + a2 * b2 + a1 * b3 + a0 * b4

        return self._carry_reduce(c0, c1, c2, c3, c4)

    @always_inline
    def mul_u32(self, other: UInt32) -> FieldElement51:
        var a = self.limbs
        var b = UInt128(other)
        
        var c0 = UInt128(a[0]) * b
        var c1 = UInt128(a[1]) * b
        var c2 = UInt128(a[2]) * b
        var c3 = UInt128(a[3]) * b
        var c4 = UInt128(a[4]) * b
        
        return self._carry_reduce(c0, c1, c2, c3, c4)

    @always_inline
    def square(self) -> FieldElement51:
        var a = self.limbs
        var a0 = UInt128(a[0])
        var a1 = UInt128(a[1])
        var a2 = UInt128(a[2])
        var a3 = UInt128(a[3])
        var a4 = UInt128(a[4])
        
        var a3_19 = a3 * 19
        var a4_19 = a4 * 19

        var c0 = a0 * a0 + (a1 * a4_19 + a2 * a3_19) * 2
        var c1 = a3 * a3_19 + (a0 * a1 + a2 * a4_19) * 2
        var c2 = a1 * a1 + (a0 * a2 + a4 * a3_19) * 2
        var c3 = a4 * a4_19 + (a0 * a3 + a1 * a2) * 2
        var c4 = a2 * a2 + (a0 * a4 + a1 * a3) * 2

        return self._carry_reduce(c0, c1, c2, c3, c4)

    @always_inline
    def invert(self) -> FieldElement51:
        var t0 = self.square()
        var t1 = t0.pow2k(2)
        var t2 = self * t1
        var t3 = t0 * t2
        var t4 = t3.square()
        var t5 = t2 * t4
        var t6 = t5.pow2k(5)
        var t7 = t6 * t5
        var t8 = t7.pow2k(10)
        var t9 = t8 * t7
        var t10 = t9.pow2k(20)
        var t11 = t10 * t9
        var t12 = t11.pow2k(10)
        var t13 = t12 * t7
        var t14 = t13.pow2k(50)
        var t15 = t14 * t13
        var t16 = t15.pow2k(100)
        var t17 = t16 * t15
        var t18 = t17.pow2k(50)
        var t19 = t18 * t13
        var t20 = t19.pow2k(5)
        return t20 * t3

    def pow2k(self, k: Int) -> FieldElement51:
        var res = self
        for _ in range(k):
            res = res.square()
        return res

    @always_inline
    def _carry_reduce(self, var c0: UInt128, var c1: UInt128, var c2: UInt128, var c3: UInt128, var c4: UInt128) -> FieldElement51:
        var MASK = UInt64(0x7FFFFFFFFFFFF)
        
        c1 += _u128_shr(c0, 51)
        var l0 = (c0.cast[DType.uint64]()) & MASK
        c2 += _u128_shr(c1, 51)
        var l1 = (c1.cast[DType.uint64]()) & MASK
        c3 += _u128_shr(c2, 51)
        var l2 = (c2.cast[DType.uint64]()) & MASK
        c4 += _u128_shr(c3, 51)
        var l3 = (c3.cast[DType.uint64]()) & MASK
        
        # C4 becomes UInt128, we need do carry propagation from it
        var q4 = _u128_shr(c4, 51)
        var l4 = (c4.cast[DType.uint64]()) & MASK
        
        # q4*19 back to l0
        var l0_2 = UInt128(l0) + q4 * 19
        
		# Guard Check make sure everything is 51 bits otherwise Mojo will collapse if its a shuffle over 64 bits and return 0.
        var l1_2 = UInt128(l1) + _u128_shr(l0_2, 51)
        var l0_final = (l0_2.cast[DType.uint64]()) & MASK
        
        var l2_2 = UInt128(l2) + _u128_shr(l1_2, 51)
        var l1_final = (l1_2.cast[DType.uint64]()) & MASK
        
        var l3_2 = UInt128(l3) + _u128_shr(l2_2, 51)
        var l2_final = (l2_2.cast[DType.uint64]()) & MASK
        
        var l4_2 = UInt128(l4) + _u128_shr(l3_2, 51)
        var l3_final = (l3_2.cast[DType.uint64]()) & MASK
        
        var l0_final_2 = UInt128(l0_final) + _u128_shr(l4_2, 51) * 19
        var l4_final = (l4_2.cast[DType.uint64]()) & MASK
        
        var carry = _u128_shr(l0_final_2, 51)
        var l0_out = (l0_final_2.cast[DType.uint64]()) & MASK
        var l1_out = UInt64(l1_final) + carry.cast[DType.uint64]()
        
        var raw = FieldElement51(l0_out, l1_out, l2_final, l3_final, l4_final)
        return raw._reduce(raw.limbs)

    @always_inline
    def _reduce(self, limbs: SIMD[DType.uint64, 5]) -> FieldElement51:
        var l = limbs
        var MASK = UInt64(0x7FFFFFFFFFFFF)
        for _ in range(5):
            l[1] += l[0] >> 51; l[0] &= MASK
            l[2] += l[1] >> 51; l[1] &= MASK
            l[3] += l[2] >> 51; l[2] &= MASK
            l[4] += l[3] >> 51; l[3] &= MASK
            l[0] += (l[4] >> 51) * 19; l[4] &= MASK
        return FieldElement51(l)

    @staticmethod
    def from_bytes_span(bytes: Span[UInt8, ...]) -> FieldElement51:
        def load8(ptr: UnsafePointer[UInt8, _]) -> UInt64:
            var v: UInt64 = 0
            for j in range(8):
                v |= UInt64(ptr[j]) << UInt64(j * 8)
            return v

        var ptr = bytes.unsafe_ptr()
        var MASK = UInt64(0x7FFFFFFFFFFFF)
        
        var l0 = load8(ptr) & MASK
        var l1 = (load8(ptr + 6) >> 3) & MASK
        var l2 = (load8(ptr + 12) >> 6) & MASK
        var l3 = (load8(ptr + 19) >> 1) & MASK
        var l4 = (load8(ptr + 24) >> 12) & MASK
        
        return FieldElement51(l0, l1, l2, l3, l4)

    def to_bytes_into(self, output: UnsafePointer[UInt8, MutAnyOrigin]):
        var res = self._reduce(self.limbs)
        var limbs = res.limbs

        var q = (limbs[0] + 19) >> 51
        q = (limbs[1] + q) >> 51
        q = (limbs[2] + q) >> 51
        q = (limbs[3] + q) >> 51
        q = (limbs[4] + q) >> 51

        limbs[0] += 19 * q

        var MASK = UInt64(0x7FFFFFFFFFFFF)
        limbs[1] += limbs[0] >> 51; limbs[0] &= MASK
        limbs[2] += limbs[1] >> 51; limbs[1] &= MASK
        limbs[3] += limbs[2] >> 51; limbs[2] &= MASK
        limbs[4] += limbs[3] >> 51; limbs[3] &= MASK
        limbs[4] &= MASK

        output[0] = UInt8(limbs[0] & 0xFF)
        output[1] = UInt8((limbs[0] >> 8) & 0xFF)
        output[2] = UInt8((limbs[0] >> 16) & 0xFF)
        output[3] = UInt8((limbs[0] >> 24) & 0xFF)
        output[4] = UInt8((limbs[0] >> 32) & 0xFF)
        output[5] = UInt8((limbs[0] >> 40) & 0xFF)
        output[6] = UInt8(((limbs[0] >> 48) | (limbs[1] << 3)) & 0xFF)
        output[7] = UInt8((limbs[1] >> 5) & 0xFF)
        output[8] = UInt8((limbs[1] >> 13) & 0xFF)
        output[9] = UInt8((limbs[1] >> 21) & 0xFF)
        output[10] = UInt8((limbs[1] >> 29) & 0xFF)
        output[11] = UInt8((limbs[1] >> 37) & 0xFF)
        output[12] = UInt8(((limbs[1] >> 45) | (limbs[2] << 6)) & 0xFF)
        output[13] = UInt8((limbs[2] >> 2) & 0xFF)
        output[14] = UInt8((limbs[2] >> 10) & 0xFF)
        output[15] = UInt8((limbs[2] >> 18) & 0xFF)
        output[16] = UInt8((limbs[2] >> 26) & 0xFF)
        output[17] = UInt8((limbs[2] >> 34) & 0xFF)
        output[18] = UInt8((limbs[2] >> 42) & 0xFF)
        output[19] = UInt8(((limbs[2] >> 50) | (limbs[3] << 1)) & 0xFF)
        output[20] = UInt8((limbs[3] >> 7) & 0xFF)
        output[21] = UInt8((limbs[3] >> 15) & 0xFF)
        output[22] = UInt8((limbs[3] >> 23) & 0xFF)
        output[23] = UInt8((limbs[3] >> 31) & 0xFF)
        output[24] = UInt8((limbs[3] >> 39) & 0xFF)
        output[25] = UInt8(((limbs[3] >> 47) | (limbs[4] << 4)) & 0xFF)
        output[26] = UInt8((limbs[4] >> 4) & 0xFF)
        output[27] = UInt8((limbs[4] >> 12) & 0xFF)
        output[28] = UInt8((limbs[4] >> 20) & 0xFF)
        output[29] = UInt8((limbs[4] >> 28) & 0xFF)
        output[30] = UInt8((limbs[4] >> 36) & 0xFF)
        output[31] = UInt8((limbs[4] >> 44) & 0xFF)