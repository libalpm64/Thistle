"""Little field helpers that power Curve25519"""

from std.builtin.dtype import DType


@always_inline
def _u128_shr[shift: Int](x: UInt128) -> UInt128:
    comptime if shift <= 0:
        return x
    else:
        comptime if shift >= 128:
            return UInt128(0)
        else:
            var lo = x.cast[DType.uint64]()
            var hi = (x >> UInt128(64)).cast[DType.uint64]()
            comptime if shift < 64:
                var out_lo = (lo >> UInt64(shift)) | (hi << UInt64(64 - shift))
                var out_hi = hi >> UInt64(shift)
                return (UInt128(out_hi) << UInt128(64)) | UInt128(out_lo)
            else:
                comptime if shift == 64:
                    return UInt128(hi)
                else:
                    return UInt128(hi >> UInt64(shift - 64))


struct FieldElement51(Copyable, ImplicitlyCopyable, Movable):
    """Field element in five fifty one bit limbs that can stay redundant until you reduce"""
    var limbs: SIMD[DType.uint64, 8]

    @always_inline
    def __init__(out self):
        self.limbs = SIMD[DType.uint64, 8](0)

    @always_inline
    def __init__(out self, l0: UInt64, l1: UInt64, l2: UInt64, l3: UInt64, l4: UInt64):
        self.limbs = SIMD[DType.uint64, 8](l0, l1, l2, l3, l4, 0, 0, 0)

    @always_inline
    def __init__(out self, limbs: SIMD[DType.uint64, 8]):
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
            2251799813685247
        )

    @always_inline
    def to_int(self) -> Int:
        var res = self._reduce(self.limbs)
        var limbs = res.limbs

        var q = (limbs[0] + 19) >> 51
        q = (limbs[1] + q) >> 51
        q = (limbs[2] + q) >> 51
        q = (limbs[3] + q) >> 51
        q = (limbs[4] + q) >> 51

        limbs[0] += 19 * q

        var MASK = UInt64(0x7FFFFFFFFFFFF)
        limbs[1] += limbs[0] >> 51
        limbs[0] &= MASK
        limbs[2] += limbs[1] >> 51
        limbs[1] &= MASK
        limbs[3] += limbs[2] >> 51
        limbs[2] &= MASK
        limbs[4] += limbs[3] >> 51
        limbs[3] &= MASK
        limbs[4] &= MASK

        var value = Int(limbs[0])
        value += Int(limbs[1]) * 2251799813685248
        value += Int(limbs[2]) * 5070602400912917605986812821504
        value += Int(limbs[3]) * 11417981541647679048466287755595961091061972992
        value += Int(limbs[4]) * 25711008708143844408671393477458601640355247900524685364822016
        return value

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
        return FieldElement51(
            self.limbs[0] + other.limbs[0],
            self.limbs[1] + other.limbs[1],
            self.limbs[2] + other.limbs[2],
            self.limbs[3] + other.limbs[3],
            self.limbs[4] + other.limbs[4]
        )

    @always_inline
    def __sub__(self, other: FieldElement51) -> FieldElement51:
        var l = SIMD[DType.uint64, 8](0)
        l[0] = (self.limbs[0] + 0x7FFFFFFFFFFED0) - other.limbs[0]
        l[1] = (self.limbs[1] + 0x7FFFFFFFFFFFF0) - other.limbs[1]
        l[2] = (self.limbs[2] + 0x7FFFFFFFFFFFF0) - other.limbs[2]
        l[3] = (self.limbs[3] + 0x7FFFFFFFFFFFF0) - other.limbs[3]
        l[4] = (self.limbs[4] + 0x7FFFFFFFFFFFF0) - other.limbs[4]
        var MASK = UInt64(0x7FFFFFFFFFFFF)
        l[1] += l[0] >> 51
        l[0] &= MASK
        l[2] += l[1] >> 51
        l[1] &= MASK
        l[3] += l[2] >> 51
        l[2] &= MASK
        l[4] += l[3] >> 51
        l[3] &= MASK
        l[0] += (l[4] >> 51) * 19
        l[4] &= MASK
        return FieldElement51(l)

    @always_inline
    def __mul__(self, other: FieldElement51) -> FieldElement51:
        """Field multiply that keeps things redundant and holds off on carries
        Upper limbs come pre scaled by nineteen since two to the 255 wraps to nineteen
        Folds the tall products then lets the carry helper cascade them down"""
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
        # Upper limbs come pre scaled by nineteen because two to the 255 wraps to nineteen

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
        """Field square that reuses symmetry and folds the overflow with nineteen"""
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
        """Invert with Fermat power through a short addition chain you can follow by hand
        Squares climb through powers of two then multiplies collect the pieces
        Shares its prefix with the p minus five over eight power"""
        var t0 = self.square()
        var t1 = t0.pow2k[2]()
        var t2 = self * t1
        var t3 = t0 * t2
        var t4 = t3.square()
        var t5 = t2 * t4
        var t6 = t5.pow2k[5]()
        var t7 = t6 * t5
        var t8 = t7.pow2k[10]()
        var t9 = t8 * t7
        var t10 = t9.pow2k[20]()
        var t11 = t10 * t9
        var t12 = t11.pow2k[10]()
        var t13 = t12 * t7
        var t14 = t13.pow2k[50]()
        var t15 = t14 * t13
        var t16 = t15.pow2k[100]()
        var t17 = t16 * t15
        var t18 = t17.pow2k[50]()
        var t19 = t18 * t13
        var t20 = t19.pow2k[5]()
        return t20 * t3

    @always_inline
    def pow_p58(self) -> FieldElement51:
        var t0 = self.square()
        var t1 = t0.pow2k[2]()
        var t2 = self * t1
        var t3 = t0 * t2
        var t5 = t2 * t3.square()
        var t7 = t5.pow2k[5]() * t5
        var t9 = t7.pow2k[10]() * t7
        var t11 = t9.pow2k[20]() * t9
        var t13 = t11.pow2k[10]() * t7
        var t15 = t13.pow2k[50]() * t13
        var t17 = t15.pow2k[100]() * t15
        var t19 = t17.pow2k[50]() * t13
        return t19.pow2k[2]() * self

    @always_inline
    def pow2k[exp: Int](self) -> FieldElement51:
        var res = self
        comptime for _ in range(exp):
            res = res.square()
        return res

    @always_inline
    def _carry_reduce(self, var c0: UInt128, var c1: UInt128, var c2: UInt128, var c3: UInt128, var c4: UInt128
    ) -> FieldElement51:
        """Carry the tall accumulator back into five fifty one bit limbs
        Top overflow wraps with nineteen since two to the 255 acts like nineteen then ripples forward
        Leaves limbs a little redundant so the next multiply stays happy"""
        var MASK = UInt64(0x7FFFFFFFFFFFF)
        # Top overflow wraps with nineteen and cascades down by fifty one bits
        
        c1 += _u128_shr[51](c0)
        var l0 = (c0.cast[DType.uint64]()) & MASK
        c2 += _u128_shr[51](c1)
        var l1 = (c1.cast[DType.uint64]()) & MASK
        c3 += _u128_shr[51](c2)
        var l2 = (c2.cast[DType.uint64]()) & MASK
        c4 += _u128_shr[51](c3)
        var l3 = (c3.cast[DType.uint64]()) & MASK
        
        var carry = (_u128_shr[51](c4)).cast[DType.uint64]()
        var l4 = (c4.cast[DType.uint64]()) & MASK

        var l0_2 = l0 + carry * 19
        var l1_2 = l1 + (l0_2 >> 51)
        l0_2 &= MASK

        return FieldElement51(l0_2, l1_2, l2, l3, l4)

    @always_inline
    def _reduce(self, limbs: SIMD[DType.uint64, 8]) -> FieldElement51:
        var l = limbs
        var MASK = UInt64(0x7FFFFFFFFFFFF)
        for _ in range(5):
            l[1] += l[0] >> 51
            l[0] &= MASK
            l[2] += l[1] >> 51
            l[1] &= MASK
            l[3] += l[2] >> 51
            l[2] &= MASK
            l[4] += l[3] >> 51
            l[3] &= MASK
            l[0] += (l[4] >> 51) * 19
            l[4] &= MASK
        return FieldElement51(l)

    @staticmethod
    def from_bytes_span(bytes: Span[UInt8, ...]) raises -> FieldElement51:
        """Decode thirty two little endian bytes without checking the range"""
        if len(bytes) != 32:
            raise Error("FieldElement51 input must be exactly 32 bytes")
        @always_inline
        def load8(ptr: Pointer[mut=False, UInt8, _, address_space=_]) -> UInt64:
            return ptr.unsafe_bitcast[UInt64]().unsafe_load[width=1, alignment=1]()

        var ptr = bytes.unsafe_ptr()
        var MASK = UInt64(0x7FFFFFFFFFFFF)
        
        var l0 = load8(ptr) & MASK
        var l1 = (load8(ptr.unsafe_offset(6)) >> 3) & MASK
        var l2 = (load8(ptr.unsafe_offset(12)) >> 6) & MASK
        var l3 = (load8(ptr.unsafe_offset(19)) >> 1) & MASK
        var l4 = (load8(ptr.unsafe_offset(24)) >> 12) & MASK
        
        return FieldElement51(l0, l1, l2, l3, l4)

    def to_bytes_into(self, output: Pointer[mut=True, UInt8, _, address_space=_]):
        """Encode to thirty two canonical bytes after fully reducing"""
        var res = self._reduce(self.limbs)
        var limbs = res.limbs

        var q = (limbs[0] + 19) >> 51
        q = (limbs[1] + q) >> 51
        q = (limbs[2] + q) >> 51
        q = (limbs[3] + q) >> 51
        q = (limbs[4] + q) >> 51

        limbs[0] += 19 * q

        var MASK = UInt64(0x7FFFFFFFFFFFF)
        limbs[1] += limbs[0] >> 51
        limbs[0] &= MASK
        limbs[2] += limbs[1] >> 51
        limbs[1] &= MASK
        limbs[3] += limbs[2] >> 51
        limbs[2] &= MASK
        limbs[4] += limbs[3] >> 51
        limbs[3] &= MASK
        limbs[4] &= MASK

        var w0 = limbs[0] | (limbs[1] << 51)
        var w1 = (limbs[1] >> 13) | (limbs[2] << 38)
        var w2 = (limbs[2] >> 26) | (limbs[3] << 25)
        var w3 = (limbs[3] >> 39) | (limbs[4] << 12)

        (output.unsafe_offset(0)).unsafe_bitcast[UInt64]().unsafe_store[alignment=1](w0)
        (output.unsafe_offset(8)).unsafe_bitcast[UInt64]().unsafe_store[alignment=1](w1)
        (output.unsafe_offset(16)).unsafe_bitcast[UInt64]().unsafe_store[alignment=1](w2)
        (output.unsafe_offset(24)).unsafe_bitcast[UInt64]().unsafe_store[alignment=1](w3)
