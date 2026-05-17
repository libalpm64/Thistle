# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Libalpm64, Lostlab Technologies.

"""
NIST P-384 / secp384r1 implementation.
By libalpm64, no attribution required.
"""

comptime P384_SIZE = 48
comptime P384_POINT_SIZE = 97
comptime _MASK32 = UInt64(0xFFFFFFFF)


struct U384(Copyable, ImplicitlyCopyable, Movable):
    var limbs: InlineArray[UInt64, 12]

    def __init__(out self):
        self.limbs = InlineArray[UInt64, 12](fill=0)

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
        l8: UInt64,
        l9: UInt64,
        l10: UInt64,
        l11: UInt64,
    ):
        self.limbs = InlineArray[UInt64, 12](uninitialized=True)
        self.limbs[0] = l0 & _MASK32
        self.limbs[1] = l1 & _MASK32
        self.limbs[2] = l2 & _MASK32
        self.limbs[3] = l3 & _MASK32
        self.limbs[4] = l4 & _MASK32
        self.limbs[5] = l5 & _MASK32
        self.limbs[6] = l6 & _MASK32
        self.limbs[7] = l7 & _MASK32
        self.limbs[8] = l8 & _MASK32
        self.limbs[9] = l9 & _MASK32
        self.limbs[10] = l10 & _MASK32
        self.limbs[11] = l11 & _MASK32

    def __copyinit__(out self, copy: Self):
        self.limbs = copy.limbs

    def __moveinit__(out self, deinit take: Self):
        self.limbs = take.limbs^

    @staticmethod
    def one() -> U384:
        return U384(1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

    def is_zero(self) -> Bool:
        for i in range(12):
            if self.limbs[i] != 0:
                return False
        return True

    def bit(self, i: Int) -> UInt64:
        return (self.limbs[i // 32] >> UInt64(i % 32)) & 1


def _p() -> U384:
    # P-384 prime: 2^384 - 2^128 - 2^96 + 2^32 - 1.
    return U384(
        0xFFFFFFFF,
        0x00000000,
        0x00000000,
        0xFFFFFFFF,
        0xFFFFFFFE,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
    )


def _a() -> U384:
    return U384(
        0xFFFFFFFC,
        0x00000000,
        0x00000000,
        0xFFFFFFFF,
        0xFFFFFFFE,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
    )


def _b() -> U384:
    return U384(
        0xD3EC2AEF,
        0x2A85C8ED,
        0x8A2ED19D,
        0xC656398D,
        0x5013875A,
        0x0314088F,
        0xFE814112,
        0x181D9C6E,
        0xE3F82D19,
        0x988E056B,
        0xE23EE7E4,
        0xB3312FA7,
    )


def _n() -> U384:
    return U384(
        0xCCC52973,
        0xECEC196A,
        0x48B0A77A,
        0x581A0DB2,
        0xF4372DDF,
        0xC7634D81,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
    )


def _gx() -> U384:
    return U384(
        0x72760AB7,
        0x3A545E38,
        0xBF55296C,
        0x5502F25D,
        0x82542A38,
        0x59F741E0,
        0x8BA79B98,
        0x6E1D3B62,
        0xF320AD74,
        0x8EB1C71E,
        0xBE8B0537,
        0xAA87CA22,
    )


def _gy() -> U384:
    return U384(
        0x90EA0E5F,
        0x7A431D7C,
        0x1D7E819D,
        0x0A60B1CE,
        0xB5F0B8C0,
        0xE9DA3113,
        0x289A147C,
        0xF8F41DBD,
        0x9292DC29,
        0x5D9E98BF,
        0x96262C6F,
        0x3617DE4A,
    )


def _sqrt_exp() -> U384:
    # p == 3 mod 4, so sqrt(x) = x^((p + 1) / 4).
    return U384(
        0x40000000,
        0x00000000,
        0xC0000000,
        0xBFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0x3FFFFFFF,
    )


def _p_overflow_correction() -> U384:
    # 2^384 ≡ 2^128 + 2^96 - 2^32 + 1 mod p384.
    return U384(
        0x00000001,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0x00000000,
        0x00000001,
        0x00000000,
        0x00000000,
        0x00000000,
        0x00000000,
        0x00000000,
        0x00000000,
        0x00000000,
    )


@always_inline
def _cmp(a: U384, b: U384) -> Int:
    comptime for j in range(12):
        var i = 11 - j
        if a.limbs[i] > b.limbs[i]:
            return 1
        if a.limbs[i] < b.limbs[i]:
            return -1
    return 0


@always_inline
def _eq(a: U384, b: U384) -> Bool:
    return _cmp(a, b) == 0


@always_inline
def _sub_raw(a: U384, b: U384) -> Tuple[U384, UInt64]:
    var out = U384()
    var borrow: UInt64 = 0
    comptime for i in range(12):
        var ai = a.limbs[i]
        var bi = b.limbs[i] + borrow
        if ai >= bi:
            out.limbs[i] = ai - bi
            borrow = 0
        else:
            out.limbs[i] = (UInt64(1) << UInt64(32)) + ai - bi
            borrow = 1
    return out, borrow


@always_inline
def _add_raw(a: U384, b: U384) -> Tuple[U384, UInt64]:
    var out = U384()
    var carry: UInt64 = 0
    comptime for i in range(12):
        var s = UInt128(a.limbs[i]) + UInt128(b.limbs[i]) + UInt128(carry)
        out.limbs[i] = UInt64(s & UInt128(_MASK32))
        carry = UInt64(s >> UInt128(32))
    return out, carry


@always_inline
def _add_mod(a: U384, b: U384, m: U384) -> U384:
    var sum, carry = _add_raw(a, b)
    if carry != 0:
        sum, _ = _add_raw(sum, _p_overflow_correction())
    if _cmp(sum, m) >= 0:
        var reduced, _ = _sub_raw(sum, m)
        return reduced
    return sum


@always_inline
def _sub_mod(a: U384, b: U384, m: U384) -> U384:
    var diff, borrow = _sub_raw(a, b)
    if borrow != 0:
        var fixed, _ = _add_raw(diff, m)
        return fixed
    return diff


@always_inline
def _add_small_mod(a: U384, small: UInt64, m: U384) -> U384:
    var b = U384(small, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return _add_mod(a, b, m)


@always_inline
def _add_signed_limb(
    acc: InlineArray[Int64, 13], i: Int, value: UInt64, multiplier: Int64
) -> InlineArray[Int64, 13]:
    var out = acc
    out[i] += Int64(value) * multiplier
    return out


@always_inline
def _normalize_signed_p384(acc_in: InlineArray[Int64, 13]) -> U384:
    var acc = acc_in
    comptime for _ in range(4):
        comptime for i in range(12):
            var carry = acc[i] >> 32
            acc[i] -= carry << 32
            acc[i + 1] += carry

        # Fold overflow using 2^384 ≡ 2^128 + 2^96 - 2^32 + 1.
        var hi = acc[12]
        acc[12] = 0
        acc[0] += hi
        acc[1] -= hi
        acc[3] += hi
        acc[4] += hi

    var out = U384()
    comptime for i in range(12):
        var carry = acc[i] >> 32
        acc[i] -= carry << 32
        if i < 11:
            acc[i + 1] += carry
        out.limbs[i] = UInt64(acc[i])

    if _cmp(out, _p()) >= 0:
        out, _ = _sub_raw(out, _p())
    if _cmp(out, _p()) >= 0:
        out, _ = _sub_raw(out, _p())
    return out


@always_inline
def _reduce_p384(t: InlineArray[UInt64, 24]) -> U384:
    # FIPS 186-4 D.2.4 P-384 generalized-Mersenne reduction.
    var acc = InlineArray[Int64, 13](fill=0)

    comptime for i in range(12):
        acc = _add_signed_limb(acc, i, t[i], 1)

    acc = _add_signed_limb(acc, 4, t[21], 2)
    acc = _add_signed_limb(acc, 5, t[22], 2)
    acc = _add_signed_limb(acc, 6, t[23], 2)

    comptime for i in range(12):
        acc = _add_signed_limb(acc, i, t[i + 12], 1)

    acc = _add_signed_limb(acc, 0, t[21], 1)
    acc = _add_signed_limb(acc, 1, t[22], 1)
    acc = _add_signed_limb(acc, 2, t[23], 1)
    comptime for i in range(3, 12):
        acc = _add_signed_limb(acc, i, t[i + 9], 1)

    acc = _add_signed_limb(acc, 1, t[23], 1)
    acc = _add_signed_limb(acc, 3, t[20], 1)
    comptime for i in range(4, 12):
        acc = _add_signed_limb(acc, i, t[i + 8], 1)

    acc = _add_signed_limb(acc, 4, t[20], 1)
    acc = _add_signed_limb(acc, 5, t[21], 1)
    acc = _add_signed_limb(acc, 6, t[22], 1)
    acc = _add_signed_limb(acc, 7, t[23], 1)

    acc = _add_signed_limb(acc, 0, t[20], 1)
    acc = _add_signed_limb(acc, 3, t[21], 1)
    acc = _add_signed_limb(acc, 4, t[22], 1)
    acc = _add_signed_limb(acc, 5, t[23], 1)

    acc = _add_signed_limb(acc, 0, t[23], -1)
    comptime for i in range(1, 12):
        acc = _add_signed_limb(acc, i, t[i + 11], -1)

    acc = _add_signed_limb(acc, 1, t[20], -1)
    acc = _add_signed_limb(acc, 2, t[21], -1)
    acc = _add_signed_limb(acc, 3, t[22], -1)
    acc = _add_signed_limb(acc, 4, t[23], -1)

    acc = _add_signed_limb(acc, 3, t[23], -1)
    acc = _add_signed_limb(acc, 4, t[23], -1)

    return _normalize_signed_p384(acc)


@always_inline
def _mul_mod(a: U384, b: U384, m: U384) -> U384:
    var t = InlineArray[UInt64, 24](fill=0)
    comptime for i in range(12):
        var carry = UInt128(0)
        comptime for j in range(12):
            var k = i + j
            var prod = (
                UInt128(a.limbs[i]) * UInt128(b.limbs[j])
                + UInt128(t[k])
                + carry
            )
            t[k] = UInt64(prod & UInt128(_MASK32))
            carry = prod >> UInt128(32)
        var k2 = i + 12
        while carry != 0:
            var s = UInt128(t[k2]) + carry
            t[k2] = UInt64(s & UInt128(_MASK32))
            carry = s >> UInt128(32)
            k2 += 1
    return _reduce_p384(t)


@always_inline
def _square_mod(a: U384, m: U384) -> U384:
    return _mul_mod(a, a, m)


def _pow_mod(base_in: U384, exponent: U384) -> U384:
    var result = U384.one()
    var base = base_in
    for i in range(384):
        if exponent.bit(i) != 0:
            result = _mul_mod(result, base, _p())
        base = _square_mod(base, _p())
    return result


def _inv_p(x: U384) -> U384:
    var exponent = _sub_mod(
        _p(), U384(2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0), _p()
    )
    return _pow_mod(x, exponent)


def _sqrt_p(x: U384) -> U384:
    return _pow_mod(x, _sqrt_exp())


def _from_be(bytes: Span[UInt8, ...]) -> U384:
    # SEC 1: fixed-width big-endian integer/field encoding.
    var out = U384()
    for i in range(12):
        var off = 44 - i * 4
        out.limbs[i] = (
            (UInt64(bytes[off]) << UInt64(24))
            | (UInt64(bytes[off + 1]) << UInt64(16))
            | (UInt64(bytes[off + 2]) << UInt64(8))
            | UInt64(bytes[off + 3])
        )
    return out


def _to_be(x: U384, output: UnsafePointer[UInt8, MutAnyOrigin]):
    # SEC 1: fixed-width big-endian integer/field encoding.
    for i in range(12):
        var limb = x.limbs[11 - i]
        var off = i * 4
        output[off] = UInt8((limb >> UInt64(24)) & 0xFF)
        output[off + 1] = UInt8((limb >> UInt64(16)) & 0xFF)
        output[off + 2] = UInt8((limb >> UInt64(8)) & 0xFF)
        output[off + 3] = UInt8(limb & 0xFF)


struct P384Point(Copyable, ImplicitlyCopyable, Movable):
    var x: U384
    var y: U384
    var infinity: Bool

    def __init__(out self):
        self.x = U384()
        self.y = U384()
        self.infinity = True

    def __init__(out self, x: U384, y: U384, infinity: Bool):
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
    def generator() -> P384Point:
        return P384Point(_gx(), _gy(), False)


struct P384JacobianPoint(Copyable, ImplicitlyCopyable, Movable):
    var x: U384
    var y: U384
    var z: U384
    var infinity: Bool

    def __init__(out self):
        self.x = U384()
        self.y = U384()
        self.z = U384()
        self.infinity = True

    def __init__(out self, x: U384, y: U384, z: U384, infinity: Bool):
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
    def from_affine(point: P384Point) -> P384JacobianPoint:
        if point.infinity:
            return P384JacobianPoint()
        return P384JacobianPoint(point.x, point.y, U384.one(), False)


@always_inline
def _select_u384(a: U384, b: U384, choice: UInt64) -> U384:
    var mask = UInt64(0) - choice
    var out = U384()
    comptime for i in range(12):
        out.limbs[i] = a.limbs[i] ^ (mask & (a.limbs[i] ^ b.limbs[i]))
    return out


@always_inline
def _select_jacobian(
    a: P384JacobianPoint, b: P384JacobianPoint, choice: UInt64
) -> P384JacobianPoint:
    # Coordinate path uses mask-select; infinity Bool is not on the CT scalar core.
    var infinity = a.infinity
    if choice != 0:
        infinity = b.infinity
    return P384JacobianPoint(
        _select_u384(a.x, b.x, choice),
        _select_u384(a.y, b.y, choice),
        _select_u384(a.z, b.z, choice),
        infinity,
    )


@always_inline
def _u64_nonzero_choice(x: UInt64) -> UInt64:
    return ((x | (UInt64(0) - x)) >> UInt64(63)) & UInt64(1)


@always_inline
def _u64_zero_choice(x: UInt64) -> UInt64:
    return _u64_nonzero_choice(x) ^ UInt64(1)


@always_inline
def _u384_zero_choice(x: U384) -> UInt64:
    var acc: UInt64 = 0
    comptime for i in range(12):
        acc |= x.limbs[i]
    return _u64_zero_choice(acc)


@always_inline
def _jacobian_infinity() -> P384JacobianPoint:
    # Scalar-core infinity is Z == 0.
    return P384JacobianPoint(U384(), U384.one(), U384(), False)


@always_inline
def _select_jacobian_ct(
    a: P384JacobianPoint, b: P384JacobianPoint, choice: UInt64
) -> P384JacobianPoint:
    return P384JacobianPoint(
        _select_u384(a.x, b.x, choice),
        _select_u384(a.y, b.y, choice),
        _select_u384(a.z, b.z, choice),
        False,
    )


@always_inline
def _mul_small_mod(x: U384, c: UInt64) -> U384:
    var out = U384()
    for _ in range(c):
        out = _add_mod(out, x, _p())
    return out


def _is_on_curve(point: P384Point) -> Bool:
    # SEC 1 public-key validation for cofactor-1 short Weierstrass curves.
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


def _jacobian_double_ct(p: P384JacobianPoint) -> P384JacobianPoint:
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
    return P384JacobianPoint(x3, y3, z3, False)


def _jacobian_add_affine_ct(
    p: P384JacobianPoint, q: P384Point
) -> P384JacobianPoint:
    # EFD mixed add; handle H == 0 by mask-selecting exceptional candidates.
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
    var generic = P384JacobianPoint(x3, y3, z3, False)

    var doubled = _jacobian_double_ct(p)
    var inf = _jacobian_infinity()
    var q_as_jac = P384JacobianPoint(q.x, q.y, U384.one(), False)

    var p_is_inf = _u384_zero_choice(p.z)
    var h_is_zero = _u384_zero_choice(h)
    var r_is_zero = _u384_zero_choice(r)

    var use_double = h_is_zero & r_is_zero
    var use_inf = h_is_zero & (r_is_zero ^ UInt64(1))

    var out = generic
    out = _select_jacobian_ct(out, doubled, use_double)
    out = _select_jacobian_ct(out, inf, use_inf)
    out = _select_jacobian_ct(out, q_as_jac, p_is_inf)
    return out


def _jacobian_to_affine(p: P384JacobianPoint) -> P384Point:
    if p.infinity or p.z.is_zero():
        return P384Point()
    var zinv = _inv_p(p.z)
    var zinv2 = _square_mod(zinv, _p())
    var zinv3 = _mul_mod(zinv2, zinv, _p())
    return P384Point(
        _mul_mod(p.x, zinv2, _p()), _mul_mod(p.y, zinv3, _p()), False
    )


def _scalar_mult(k: U384, p: P384Point) -> P384Point:
    # Secret scalar loop: always double/add/select; scalar-core infinity is Z == 0.
    var acc = _jacobian_infinity()
    for j in range(384):
        var i = 383 - j
        var doubled = _jacobian_double_ct(acc)
        var added = _jacobian_add_affine_ct(doubled, p)
        acc = _select_jacobian_ct(doubled, added, k.bit(i))
    return _jacobian_to_affine(acc)


def p384_decode_uncompressed(point: Span[UInt8, ...]) -> P384Point:
    # SEC 1 point decoding: compressed 02/03||X and uncompressed 04||X||Y.
    if len(point) == 49 and (point[0] == 0x02 or point[0] == 0x03):
        var x = _from_be(
            Span[UInt8, ...](ptr=point.unsafe_ptr() + 1, length=48)
        )
        if _cmp(x, _p()) >= 0:
            return P384Point()
        var xx = _square_mod(x, _p())
        var xxx = _mul_mod(xx, x, _p())
        var ax = _mul_mod(_a(), x, _p())
        var rhs = _add_mod(_add_mod(xxx, ax, _p()), _b(), _p())
        var y = _sqrt_p(rhs)
        if not _eq(_square_mod(y, _p()), rhs):
            return P384Point()
        if UInt8(y.limbs[0] & 1) != (point[0] & 1):
            y = _sub_mod(_p(), y, _p())
        var p = P384Point(x, y, False)
        if not _is_on_curve(p):
            return P384Point()
        return p
    if len(point) != P384_POINT_SIZE or point[0] != 0x04:
        return P384Point()
    var x = _from_be(Span[UInt8, ...](ptr=point.unsafe_ptr() + 1, length=48))
    var y = _from_be(Span[UInt8, ...](ptr=point.unsafe_ptr() + 49, length=48))
    var p = P384Point(x, y, False)
    if not _is_on_curve(p):
        return P384Point()
    return p


def p384_encode_uncompressed(
    point: P384Point, output: UnsafePointer[UInt8, MutAnyOrigin]
) -> Bool:
    # SEC 1 uncompressed point encoding: 04 || X || Y.
    if point.infinity or not _is_on_curve(point):
        return False
    output[0] = 0x04
    _to_be(point.x, output + 1)
    _to_be(point.y, output + 49)
    return True


def p384_public_key(
    private_key: Span[UInt8, ...], output: UnsafePointer[UInt8, MutAnyOrigin]
) -> Bool:
    # SEC 1 key generation: Q = dG with d in [1, n - 1].
    if len(private_key) != 48:
        return False
    var d = _from_be(private_key)
    if d.is_zero() or _cmp(d, _n()) >= 0:
        return False
    var q = _scalar_mult(d, P384Point.generator())
    return p384_encode_uncompressed(q, output)


def p384_ecdh(
    private_key: Span[UInt8, ...],
    public_key: Span[UInt8, ...],
    output: UnsafePointer[UInt8, MutAnyOrigin],
) -> Bool:
    # SEC 1 ECDH: validate Q, compute dQ, reject infinity, output x-coordinate.
    if len(private_key) != 48:
        return False
    var d = _from_be(private_key)
    if d.is_zero() or _cmp(d, _n()) >= 0:
        return False
    var q = p384_decode_uncompressed(public_key)
    if q.infinity:
        return False
    var shared = _scalar_mult(d, q)
    if shared.infinity:
        return False
    _to_be(shared.x, output)
    return True