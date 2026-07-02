# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Libalpm64, Lostlab Technologies.

"""
NIST P-256 / secp256r1 implementation.
By libalpm64, no attribution required.
"""

comptime P256_SIZE = 32
comptime P256_POINT_SIZE = 65
comptime _MASK32 = UInt64(0xFFFFFFFF)


struct U256(Copyable, ImplicitlyCopyable, Movable):
    var limbs: InlineArray[UInt64, 8]

    def __init__(out self):
        self.limbs = InlineArray[UInt64, 8](fill=0)

    def __init__(
        out self,
        l0: UInt64,
        l1: UInt64,
        l2: UInt64,
        l3: UInt64,
        l4: UInt64,
        l5: UInt64,
        l6: UInt64,
        l7: UInt64,
    ):
        self.limbs = InlineArray[UInt64, 8](uninitialized=True)
        self.limbs[0] = l0 & _MASK32
        self.limbs[1] = l1 & _MASK32
        self.limbs[2] = l2 & _MASK32
        self.limbs[3] = l3 & _MASK32
        self.limbs[4] = l4 & _MASK32
        self.limbs[5] = l5 & _MASK32
        self.limbs[6] = l6 & _MASK32
        self.limbs[7] = l7 & _MASK32

    def __copyinit__(out self, copy: Self):
        self.limbs = copy.limbs

    def __moveinit__(out self, deinit take: Self):
        self.limbs = take.limbs^

    @staticmethod
    def one() -> U256:
        return U256(1, 0, 0, 0, 0, 0, 0, 0)

    def is_zero(self) -> Bool:
        for i in range(8):
            if self.limbs[i] != 0:
                return False
        return True

    def bit(self, i: Int) -> UInt64:
        return (self.limbs[i // 32] >> UInt64(i % 32)) & 1


def _p() -> U256:
    return U256(
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0x00000000,
        0x00000000,
        0x00000000,
        0x00000001,
        0xFFFFFFFF,
    )


def _a() -> U256:
    return U256(
        0xFFFFFFFC,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0x00000000,
        0x00000000,
        0x00000000,
        0x00000001,
        0xFFFFFFFF,
    )


def _b() -> U256:
    return U256(
        0x27D2604B,
        0x3BCE3C3E,
        0xCC53B0F6,
        0x651D06B0,
        0x769886BC,
        0xB3EBBD55,
        0xAA3A93E7,
        0x5AC635D8,
    )


def _n() -> U256:
    return U256(
        0xFC632551,
        0xF3B9CAC2,
        0xA7179E84,
        0xBCE6FAAD,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0x00000000,
        0xFFFFFFFF,
    )


def _gx() -> U256:
    return U256(
        0xD898C296,
        0xF4A13945,
        0x2DEB33A0,
        0x77037D81,
        0x63A440F2,
        0xF8BCE6E5,
        0xE12C4247,
        0x6B17D1F2,
    )


def _gy() -> U256:
    return U256(
        0x37BF51F5,
        0xCBB64068,
        0x6B315ECE,
        0x2BCE3357,
        0x7C0F9E16,
        0x8EE7EB4A,
        0xFE1A7F9B,
        0x4FE342E2,
    )


def _sqrt_exp() -> U256:
    # p == 3 mod 4, so sqrt(x) = x^((p + 1) / 4).
    return U256(
        0x00000000,
        0x00000000,
        0x40000000,
        0x00000000,
        0x00000000,
        0x40000000,
        0xC0000000,
        0x3FFFFFFF,
    )


def _p_overflow_correction() -> U256:
    return U256(
        0x00000001,
        0x00000000,
        0x00000000,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFE,
        0x00000000,
    )


@always_inline
def _cmp(a: U256, b: U256) -> Int:
    comptime for j in range(8):
        var i = 7 - j
        if a.limbs[i] > b.limbs[i]:
            return 1
        if a.limbs[i] < b.limbs[i]:
            return -1
    return 0


@always_inline
def _eq(a: U256, b: U256) -> Bool:
    return _cmp(a, b) == 0


@always_inline
def _sub_raw(a: U256, b: U256) -> Tuple[U256, UInt64]:
    var out = U256()
    var borrow: UInt64 = 0
    comptime for i in range(8):
        var d = (UInt64(1) << UInt64(32)) + a.limbs[i] - b.limbs[i] - borrow
        out.limbs[i] = d & _MASK32
        borrow = (d >> UInt64(32)) ^ UInt64(1)
    return out, borrow


@always_inline
def _add_raw(a: U256, b: U256) -> Tuple[U256, UInt64]:
    var out = U256()
    var carry: UInt64 = 0
    comptime for i in range(8):
        var s = UInt128(a.limbs[i]) + UInt128(b.limbs[i]) + UInt128(carry)
        out.limbs[i] = UInt64(s & UInt128(_MASK32))
        carry = UInt64(s >> UInt128(32))
    return out, carry


@always_inline
def _add_mod(a: U256, b: U256, m: U256) -> U256:
    var sum, carry = _add_raw(a, b)
    var sum_folded, _ = _add_raw(sum, _p_overflow_correction())
    sum = _select_u256(sum, sum_folded, carry)
    var sum_minus_m, borrow = _sub_raw(sum, m)
    return _select_u256(sum_minus_m, sum, borrow)


@always_inline
def _sub_mod(a: U256, b: U256, m: U256) -> U256:
    var diff, borrow = _sub_raw(a, b)
    var diff_plus_m, _ = _add_raw(diff, m)
    return _select_u256(diff, diff_plus_m, borrow)


@always_inline
def _add_small_mod(a: U256, small: UInt64, m: U256) -> U256:
    var b = U256(small, 0, 0, 0, 0, 0, 0, 0)
    return _add_mod(a, b, m)


@always_inline
def _add_signed_limb(
    acc: InlineArray[Int64, 9], i: Int, value: UInt64, multiplier: Int64
) -> InlineArray[Int64, 9]:
    var out = acc
    out[i] += Int64(value) * multiplier
    return out


@always_inline
def _normalize_signed_p256(acc_in: InlineArray[Int64, 9]) -> U256:
    var acc = acc_in
    comptime for _ in range(4):
        comptime for i in range(8):
            var carry = acc[i] >> 32
            acc[i] -= carry << 32
            acc[i + 1] += carry

        # Fold overflow 2^256 ≡ 2^224 - 2^192 - 2^96 + 1 mod p256.
        var hi = acc[8]
        acc[8] = 0
        acc[0] += hi
        acc[3] -= hi
        acc[6] -= hi
        acc[7] += hi

    var out = U256()
    comptime for i in range(8):
        var carry = acc[i] >> 32
        acc[i] -= carry << 32
        if i < 7:
            acc[i + 1] += carry
        out.limbs[i] = UInt64(acc[i])

    var minus_p, borrow = _sub_raw(out, _p())
    out = _select_u256(minus_p, out, borrow)
    var minus_p2, borrow2 = _sub_raw(out, _p())
    return _select_u256(minus_p2, out, borrow2)


@always_inline
def _reduce_p256(t: InlineArray[UInt64, 16]) -> U256:
    # FIPS 186-4 D.2.3 P-256 Mersenne reduction:
    # r = s1 + 2*s2 + 2*s3 + s4 + s5 - s6 - s7 - s8 - s9 mod p.
    var acc = InlineArray[Int64, 9](fill=0)

    # s1 = (c7, ..., c0)
    comptime for i in range(8):
        acc = _add_signed_limb(acc, i, t[i], 1)

    # 2*s2 = 2 * (c15, c14, c13, c12, c11, 0, 0, 0)
    acc = _add_signed_limb(acc, 3, t[11], 2)
    acc = _add_signed_limb(acc, 4, t[12], 2)
    acc = _add_signed_limb(acc, 5, t[13], 2)
    acc = _add_signed_limb(acc, 6, t[14], 2)
    acc = _add_signed_limb(acc, 7, t[15], 2)

    # 2*s3 = 2 * (0, c15, c14, c13, c12, 0, 0, 0)
    acc = _add_signed_limb(acc, 3, t[12], 2)
    acc = _add_signed_limb(acc, 4, t[13], 2)
    acc = _add_signed_limb(acc, 5, t[14], 2)
    acc = _add_signed_limb(acc, 6, t[15], 2)

    # s4 = (c15, c14, 0, 0, 0, c10, c9, c8)
    acc = _add_signed_limb(acc, 0, t[8], 1)
    acc = _add_signed_limb(acc, 1, t[9], 1)
    acc = _add_signed_limb(acc, 2, t[10], 1)
    acc = _add_signed_limb(acc, 6, t[14], 1)
    acc = _add_signed_limb(acc, 7, t[15], 1)

    # s5 = (c8, c13, c15, c14, c13, c11, c10, c9)
    acc = _add_signed_limb(acc, 0, t[9], 1)
    acc = _add_signed_limb(acc, 1, t[10], 1)
    acc = _add_signed_limb(acc, 2, t[11], 1)
    acc = _add_signed_limb(acc, 3, t[13], 1)
    acc = _add_signed_limb(acc, 4, t[14], 1)
    acc = _add_signed_limb(acc, 5, t[15], 1)
    acc = _add_signed_limb(acc, 6, t[13], 1)
    acc = _add_signed_limb(acc, 7, t[8], 1)

    # s6 = (c10, c8, 0, 0, 0, c13, c12, c11)
    acc = _add_signed_limb(acc, 0, t[11], -1)
    acc = _add_signed_limb(acc, 1, t[12], -1)
    acc = _add_signed_limb(acc, 2, t[13], -1)
    acc = _add_signed_limb(acc, 6, t[8], -1)
    acc = _add_signed_limb(acc, 7, t[10], -1)

    # s7 = (c11, c9, 0, 0, c15, c14, c13, c12)
    acc = _add_signed_limb(acc, 0, t[12], -1)
    acc = _add_signed_limb(acc, 1, t[13], -1)
    acc = _add_signed_limb(acc, 2, t[14], -1)
    acc = _add_signed_limb(acc, 3, t[15], -1)
    acc = _add_signed_limb(acc, 6, t[9], -1)
    acc = _add_signed_limb(acc, 7, t[11], -1)

    # s8 = (c12, 0, c10, c9, c8, c15, c14, c13)
    acc = _add_signed_limb(acc, 0, t[13], -1)
    acc = _add_signed_limb(acc, 1, t[14], -1)
    acc = _add_signed_limb(acc, 2, t[15], -1)
    acc = _add_signed_limb(acc, 3, t[8], -1)
    acc = _add_signed_limb(acc, 4, t[9], -1)
    acc = _add_signed_limb(acc, 5, t[10], -1)
    acc = _add_signed_limb(acc, 7, t[12], -1)

    # s9 = (c13, 0, c11, c10, c9, 0, c15, c14)
    acc = _add_signed_limb(acc, 0, t[14], -1)
    acc = _add_signed_limb(acc, 1, t[15], -1)
    acc = _add_signed_limb(acc, 3, t[9], -1)
    acc = _add_signed_limb(acc, 4, t[10], -1)
    acc = _add_signed_limb(acc, 5, t[11], -1)
    acc = _add_signed_limb(acc, 7, t[13], -1)

    return _normalize_signed_p256(acc)


@always_inline
def _mul_mod(a: U256, b: U256, m: U256) -> U256:
    var t = InlineArray[UInt64, 16](fill=0)
    comptime for i in range(8):
        var carry = UInt128(0)
        comptime for j in range(8):
            var k = i + j
            var prod = (
                UInt128(a.limbs[i]) * UInt128(b.limbs[j])
                + UInt128(t[k])
                + carry
            )
            t[k] = UInt64(prod & UInt128(_MASK32))
            carry = prod >> UInt128(32)
        var k2 = i + 8
        while carry != 0:
            var s = UInt128(t[k2]) + carry
            t[k2] = UInt64(s & UInt128(_MASK32))
            carry = s >> UInt128(32)
            k2 += 1
    return _reduce_p256(t)


@always_inline
def _square_mod(a: U256, m: U256) -> U256:
    return _mul_mod(a, a, m)


def _pow_mod(base_in: U256, exponent: U256) -> U256:
    var result = U256.one()
    var base = base_in
    for i in range(256):
        if exponent.bit(i) != 0:
            result = _mul_mod(result, base, _p())
        base = _square_mod(base, _p())
    return result


def _inv_p(x: U256) -> U256:
    var exponent = _sub_mod(_p(), U256(2, 0, 0, 0, 0, 0, 0, 0), _p())
    return _pow_mod(x, exponent)


def _sqrt_p(x: U256) -> U256:
    return _pow_mod(x, _sqrt_exp())


def _from_be(bytes: Span[UInt8, ...]) -> U256:
    # SEC 1: fixed-width big-endian integer/field encoding.
    var out = U256()
    for i in range(8):
        var off = 28 - i * 4
        out.limbs[i] = (
            (UInt64(bytes[off]) << UInt64(24))
            | (UInt64(bytes[off + 1]) << UInt64(16))
            | (UInt64(bytes[off + 2]) << UInt64(8))
            | UInt64(bytes[off + 3])
        )
    return out


def _to_be(x: U256, output: UnsafePointer[UInt8, MutAnyOrigin]):
    # SEC 1: fixed-width big-endian integer/field encoding.
    for i in range(8):
        var limb = x.limbs[7 - i]
        var off = i * 4
        output[off] = UInt8((limb >> UInt64(24)) & 0xFF)
        output[off + 1] = UInt8((limb >> UInt64(16)) & 0xFF)
        output[off + 2] = UInt8((limb >> UInt64(8)) & 0xFF)
        output[off + 3] = UInt8(limb & 0xFF)


struct P256Point(Copyable, ImplicitlyCopyable, Movable):
    var x: U256
    var y: U256
    var infinity: Bool

    def __init__(out self):
        self.x = U256()
        self.y = U256()
        self.infinity = True

    def __init__(out self, x: U256, y: U256, infinity: Bool):
        self.x = x
        self.y = y
        self.infinity = infinity

    def __copyinit__(out self, copy: Self):
        self.x = copy.x
        self.y = copy.y
        self.infinity = copy.infinity

    def __moveinit__(out self, deinit take: Self):
        self.x = take.x
        self.y = take.y
        self.infinity = take.infinity

    @staticmethod
    def generator() -> P256Point:
        return P256Point(_gx(), _gy(), False)


struct P256JacobianPoint(Copyable, ImplicitlyCopyable, Movable):
    var x: U256
    var y: U256
    var z: U256
    var infinity: Bool

    def __init__(out self):
        self.x = U256()
        self.y = U256()
        self.z = U256()
        self.infinity = True

    def __init__(out self, x: U256, y: U256, z: U256, infinity: Bool):
        self.x = x
        self.y = y
        self.z = z
        self.infinity = infinity

    def __copyinit__(out self, copy: Self):
        self.x = copy.x
        self.y = copy.y
        self.z = copy.z
        self.infinity = copy.infinity

    def __moveinit__(out self, deinit take: Self):
        self.x = take.x
        self.y = take.y
        self.z = take.z
        self.infinity = take.infinity

    @staticmethod
    def from_affine(point: P256Point) -> P256JacobianPoint:
        if point.infinity:
            return P256JacobianPoint()
        return P256JacobianPoint(point.x, point.y, U256.one(), False)


@always_inline
def _select_u256(a: U256, b: U256, choice: UInt64) -> U256:
    var mask = UInt64(0) - choice
    var out = U256()
    comptime for i in range(8):
        out.limbs[i] = a.limbs[i] ^ (mask & (a.limbs[i] ^ b.limbs[i]))
    return out


@always_inline
def _select_jacobian(
    a: P256JacobianPoint, b: P256JacobianPoint, choice: UInt64
) -> P256JacobianPoint:
    # infinity flag is not used on the constant-time path
    var infinity = a.infinity
    if choice != 0:
        infinity = b.infinity
    return P256JacobianPoint(
        _select_u256(a.x, b.x, choice),
        _select_u256(a.y, b.y, choice),
        _select_u256(a.z, b.z, choice),
        infinity,
    )


@always_inline
def _u64_nonzero_choice(x: UInt64) -> UInt64:
    return ((x | (UInt64(0) - x)) >> UInt64(63)) & UInt64(1)


@always_inline
def _u64_zero_choice(x: UInt64) -> UInt64:
    return _u64_nonzero_choice(x) ^ UInt64(1)


@always_inline
def _u256_zero_choice(x: U256) -> UInt64:
    var acc: UInt64 = 0
    comptime for i in range(8):
        acc |= x.limbs[i]
    return _u64_zero_choice(acc)


@always_inline
def _jacobian_infinity() -> P256JacobianPoint:
    # Scalar-core infinity is Z == 0.
    return P256JacobianPoint(U256(), U256.one(), U256(), False)


@always_inline
def _select_jacobian_ct(
    a: P256JacobianPoint, b: P256JacobianPoint, choice: UInt64
) -> P256JacobianPoint:
    return P256JacobianPoint(
        _select_u256(a.x, b.x, choice),
        _select_u256(a.y, b.y, choice),
        _select_u256(a.z, b.z, choice),
        False,
    )


@always_inline
def _mul_small_mod(x: U256, c: UInt64) -> U256:
    # c is a public formula constant, doubling chains are fine
    if c == 2:
        return _add_mod(x, x, _p())
    if c == 3:
        return _add_mod(_add_mod(x, x, _p()), x, _p())
    if c == 4:
        var x2 = _add_mod(x, x, _p())
        return _add_mod(x2, x2, _p())
    if c == 8:
        var x2 = _add_mod(x, x, _p())
        var x4 = _add_mod(x2, x2, _p())
        return _add_mod(x4, x4, _p())
    var out = U256()
    for _ in range(c):
        out = _add_mod(out, x, _p())
    return out


def _is_on_curve(point: P256Point) -> Bool:
    # cofactor-1 short Weierstrass curves validation for pub keys
    if point.infinity:
        return False
    if _cmp(point.x, _p()) >= 0 or _cmp(point.y, _p()) >= 0:
        return False
    var yy = _square_mod(point.y, _p())
    var xx = _square_mod(point.x, _p())
    var xxx = _mul_mod(xx, point.x, _p())
    var ax = _mul_mod(_a(), point.x, _p())
    var rhs = _add_mod(_add_mod(xxx, ax, _p()), _b(), _p())
    return _eq(yy, rhs)


def _jacobian_double_ct(p: P256JacobianPoint) -> P256JacobianPoint:
    # EFD shortw/jacobian-3 doubling, a = -3; scalar-core infinity is Z == 0.
    var delta = _square_mod(p.z, _p())
    var gamma = _square_mod(p.y, _p())
    var beta = _mul_mod(p.x, gamma, _p())
    var alpha = _mul_small_mod(
        _mul_mod(_sub_mod(p.x, delta, _p()), _add_mod(p.x, delta, _p()), _p()),
        3,
    )
    var x3 = _sub_mod(_square_mod(alpha, _p()), _mul_small_mod(beta, 8), _p())
    var z3 = _sub_mod(
        _sub_mod(_square_mod(_add_mod(p.y, p.z, _p()), _p()), gamma, _p()),
        delta,
        _p(),
    )
    var y3 = _sub_mod(
        _mul_mod(alpha, _sub_mod(_mul_small_mod(beta, 4), x3, _p()), _p()),
        _mul_small_mod(_square_mod(gamma, _p()), 8),
        _p(),
    )
    return P256JacobianPoint(x3, y3, z3, False)


def _jacobian_add_affine_ct(
    p: P256JacobianPoint, q: P256Point
) -> P256JacobianPoint:
    var z1z1 = _square_mod(p.z, _p())
    var u2 = _mul_mod(q.x, z1z1, _p())
    var s2 = _mul_mod(q.y, _mul_mod(p.z, z1z1, _p()), _p())
    var h = _sub_mod(u2, p.x, _p())
    var r = _mul_small_mod(_sub_mod(s2, p.y, _p()), 2)

    var i = _square_mod(_mul_small_mod(h, 2), _p())
    var j = _mul_mod(h, i, _p())
    var v = _mul_mod(p.x, i, _p())
    var x3 = _sub_mod(
        _sub_mod(_square_mod(r, _p()), j, _p()), _mul_small_mod(v, 2), _p()
    )
    var y3 = _sub_mod(
        _mul_mod(r, _sub_mod(v, x3, _p()), _p()),
        _mul_small_mod(_mul_mod(p.y, j, _p()), 2),
        _p(),
    )
    var hh = _square_mod(h, _p())
    var z3 = _sub_mod(
        _sub_mod(_square_mod(_add_mod(p.z, h, _p()), _p()), z1z1, _p()),
        hh,
        _p(),
    )
    var generic = P256JacobianPoint(x3, y3, z3, False)

    var doubled = _jacobian_double_ct(p)
    var inf = _jacobian_infinity()
    var q_as_jac = P256JacobianPoint(q.x, q.y, U256.one(), False)

    var p_is_inf = _u256_zero_choice(p.z)
    var h_is_zero = _u256_zero_choice(h)
    var r_is_zero = _u256_zero_choice(r)

    var use_double = h_is_zero & r_is_zero
    var use_inf = h_is_zero & (r_is_zero ^ UInt64(1))

    var out = generic
    out = _select_jacobian_ct(out, doubled, use_double)
    out = _select_jacobian_ct(out, inf, use_inf)
    out = _select_jacobian_ct(out, q_as_jac, p_is_inf)
    return out


def _jacobian_to_affine(p: P256JacobianPoint) -> P256Point:
    if p.infinity or p.z.is_zero():
        return P256Point()
    var zinv = _inv_p(p.z)
    var zinv2 = _square_mod(zinv, _p())
    var zinv3 = _mul_mod(zinv2, zinv, _p())
    return P256Point(
        _mul_mod(p.x, zinv2, _p()), _mul_mod(p.y, zinv3, _p()), False
    )


def _scalar_mult(k: U256, p: P256Point) -> P256Point:
    var acc = _jacobian_infinity()
    for j in range(256):
        var i = 255 - j
        var doubled = _jacobian_double_ct(acc)
        var added = _jacobian_add_affine_ct(doubled, p)
        acc = _select_jacobian_ct(doubled, added, k.bit(i))
    return _jacobian_to_affine(acc)


def p256_decode_uncompressed(point: Span[UInt8, ...]) -> P256Point:
    # compressed 02/03||X and uncompressed 04||X||Y.
    if len(point) == 33 and (point[0] == 0x02 or point[0] == 0x03):
        var x = _from_be(
            Span[UInt8, ...](ptr=point.unsafe_ptr() + 1, length=32)
        )
        if _cmp(x, _p()) >= 0:
            return P256Point()
        var xx = _square_mod(x, _p())
        var xxx = _mul_mod(xx, x, _p())
        var ax = _mul_mod(_a(), x, _p())
        var rhs = _add_mod(_add_mod(xxx, ax, _p()), _b(), _p())
        var y = _sqrt_p(rhs)
        if not _eq(_square_mod(y, _p()), rhs):
            return P256Point()
        if UInt8(y.limbs[0] & 1) != (point[0] & 1):
            y = _sub_mod(_p(), y, _p())
        var p = P256Point(x, y, False)
        if not _is_on_curve(p):
            return P256Point()
        return p
    if len(point) != P256_POINT_SIZE or point[0] != 0x04:
        return P256Point()
    var x = _from_be(Span[UInt8, ...](ptr=point.unsafe_ptr() + 1, length=32))
    var y = _from_be(Span[UInt8, ...](ptr=point.unsafe_ptr() + 33, length=32))
    var p = P256Point(x, y, False)
    if not _is_on_curve(p):
        return P256Point()
    return p


def p256_encode_uncompressed(
    point: P256Point, output: UnsafePointer[UInt8, MutAnyOrigin]
) -> Bool:
    # uncompressed point encoding: 04 || X || Y.
    if point.infinity or not _is_on_curve(point):
        return False
    output[0] = 0x04
    _to_be(point.x, output + 1)
    _to_be(point.y, output + 33)
    return True


@no_inline
def p256_public_key(
    private_key: Span[UInt8, ...], output: UnsafePointer[UInt8, MutAnyOrigin]
) -> Bool:
    # Q = dG with d in [1, n - 1].
    if len(private_key) != 32:
        return False
    var d = _from_be(private_key)
    if d.is_zero() or _cmp(d, _n()) >= 0:
        return False
    var q = _scalar_mult(d, P256Point.generator())
    return p256_encode_uncompressed(q, output)


@no_inline
def p256_ecdh(
    private_key: Span[UInt8, ...],
    public_key: Span[UInt8, ...],
    output: UnsafePointer[UInt8, MutAnyOrigin],
) -> Bool:
    # validate Q, compute dQ, reject infinity, output x-coordinate.
    if len(private_key) != 32:
        return False
    var d = _from_be(private_key)
    if d.is_zero() or _cmp(d, _n()) >= 0:
        return False
    var q = p256_decode_uncompressed(public_key)
    if q.infinity:
        return False
    var shared = _scalar_mult(d, q)
    if shared.infinity:
        return False
    _to_be(shared.x, output)
    return True
