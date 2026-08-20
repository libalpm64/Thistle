"""
NIST P-256 / secp256r1 implementation.
"""

from .p256_table import p256_base_table
from .utils import u64_nonzero_choice, u64_zero_choice
from .sha2 import sha256_hash
from .pbkdf2 import hmac_sha256
from std.utils import StaticTuple

comptime P256_SIZE = 32
comptime P256_POINT_SIZE = 65
comptime P256_SIGNATURE_SIZE = 64
comptime _MASK64 = UInt128(0xFFFFFFFFFFFFFFFF)


struct U256(Copyable, ImplicitlyCopyable, Movable):
    var limbs: StaticTuple[UInt64, 4]

    def __init__(out self):
        self.limbs = StaticTuple[UInt64, 4]()
        comptime for i in range(4):
            self.limbs[i] = 0

    def __init__(out self, l0: UInt64, l1: UInt64, l2: UInt64, l3: UInt64):
        self.limbs = StaticTuple[UInt64, 4]()
        self.limbs[0] = l0
        self.limbs[1] = l1
        self.limbs[2] = l2
        self.limbs[3] = l3

    def __copyinit__(out self, copy: Self):
        self.limbs = copy.limbs

    def __moveinit__(out self, deinit take: Self):
        self.limbs = take.limbs^

    @staticmethod
    def one() -> U256:
        return U256(1, 0, 0, 0)

    def is_zero(self) -> Bool:
        for i in range(4):
            if self.limbs[i] != 0:
                return False
        return True

    def bit(self, i: Int) -> UInt64:
        return (self.limbs[i // 64] >> UInt64(i % 64)) & 1


def _p() -> U256:
    return U256(
        0xFFFFFFFFFFFFFFFF,
        0x00000000FFFFFFFF,
        0x0000000000000000,
        0xFFFFFFFF00000001,
    )


def _a() -> U256:
    return U256(
        0xFFFFFFFFFFFFFFFC,
        0x00000000FFFFFFFF,
        0x0000000000000000,
        0xFFFFFFFF00000001,
    )


def _b() -> U256:
    return U256(
        0x3BCE3C3E27D2604B,
        0x651D06B0CC53B0F6,
        0xB3EBBD55769886BC,
        0x5AC635D8AA3A93E7,
    )


def _n() -> U256:
    return U256(
        0xF3B9CAC2FC632551,
        0xBCE6FAADA7179E84,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFF00000000,
    )


def _gx() -> U256:
    return U256(
        0xF4A13945D898C296,
        0x77037D812DEB33A0,
        0xF8BCE6E563A440F2,
        0x6B17D1F2E12C4247,
    )


def _gy() -> U256:
    return U256(
        0xCBB6406837BF51F5,
        0x2BCE33576B315ECE,
        0x8EE7EB4A7C0F9E16,
        0x4FE342E2FE1A7F9B,
    )


def _sqrt_exp() -> U256:
    # p == 3 mod 4
    return U256(
        0x0000000000000000,
        0x0000000040000000,
        0x4000000000000000,
        0x3FFFFFFFC0000000,
    )


def _rr() -> U256:
    # 2^512 mod p
    return U256(
        0x0000000000000003,
        0xFFFFFFFBFFFFFFFF,
        0xFFFFFFFFFFFFFFFE,
        0x00000004FFFFFFFD,
    )


def _one_mont() -> U256:
    # 2^256 mod p
    return U256(
        0x0000000000000001,
        0xFFFFFFFF00000000,
        0xFFFFFFFFFFFFFFFF,
        0x00000000FFFFFFFE,
    )


@always_inline
def _cmp(a: U256, b: U256) -> Int:
    comptime for j in range(4):
        var i = 3 - j
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
    comptime for i in range(4):
        var d = UInt128(a.limbs[i]) - UInt128(b.limbs[i]) - UInt128(borrow)
        out.limbs[i] = UInt64(d & _MASK64)
        borrow = UInt64((d >> UInt128(64)) & UInt128(1))
    return out, borrow


@always_inline
def _add_raw(a: U256, b: U256) -> Tuple[U256, UInt64]:
    var out = U256()
    var carry: UInt64 = 0
    comptime for i in range(4):
        var s = UInt128(a.limbs[i]) + UInt128(b.limbs[i]) + UInt128(carry)
        out.limbs[i] = UInt64(s & _MASK64)
        carry = UInt64(s >> UInt128(64))
    return out, carry


@always_inline
def _add_mod(a: U256, b: U256, m: U256) -> U256:
    var sum, carry = _add_raw(a, b)
    var d, borrow = _sub_raw(sum, m)
    var take_d = (carry | (borrow ^ UInt64(1))) & UInt64(1)
    return _select_u256(sum, d, take_d)


@always_inline
def _sub_mod(a: U256, b: U256, m: U256) -> U256:
    var diff, borrow = _sub_raw(a, b)
    var diff_plus_m, _ = _add_raw(diff, m)
    return _select_u256(diff, diff_plus_m, borrow)


@always_inline
def _add_mod(a: U256, b: U256) -> U256:
    return _add_mod(a, b, _p())


@always_inline
def _sub_mod(a: U256, b: U256) -> U256:
    return _sub_mod(a, b, _p())


@always_inline
def _mont_final_sub(
    acc0: UInt64, acc1: UInt64, acc2: UInt64, acc3: UInt64, acc4: UInt64
) -> U256:
    var out = U256(acc0, acc1, acc2, acc3)
    var d, borrow = _sub_raw(out, _p())
    var take_d = (acc4 | (borrow ^ UInt64(1))) & UInt64(1)
    return _select_u256(out, d, take_d)


@always_inline
def _mont_mul(a: U256, b: U256) -> U256:
    # -p^-1 mod 2^64 == 1, reduce digit is acc0 acp0*p folds shift+add
    var a0 = a.limbs[0]
    var a1 = a.limbs[1]
    var a2 = a.limbs[2]
    var a3 = a.limbs[3]

    var bi = b.limbs[0]
    var p0 = UInt128(a0) * UInt128(bi)
    var p1 = UInt128(a1) * UInt128(bi)
    var p2 = UInt128(a2) * UInt128(bi)
    var p3 = UInt128(a3) * UInt128(bi)
    var acc0 = UInt64(p0 & _MASK64)
    var s = (p1 & _MASK64) + (p0 >> UInt128(64))
    var acc1 = UInt64(s & _MASK64)
    s = (p2 & _MASK64) + (p1 >> UInt128(64)) + (s >> UInt128(64))
    var acc2 = UInt64(s & _MASK64)
    s = (p3 & _MASK64) + (p2 >> UInt128(64)) + (s >> UInt128(64))
    var acc3 = UInt64(s & _MASK64)
    var acc4 = UInt64(p3 >> UInt128(64)) + UInt64(s >> UInt128(64))
    var acc5 = UInt64(0)

    comptime for i in range(1, 4):
        var t0 = acc0 << 32
        var t1 = acc0 >> 32
        var brw = UInt64(
            (UInt128(acc0) - UInt128(t0)) >> UInt128(64)
        ) & UInt64(1)
        var t2 = acc0 - t0
        var t3 = acc0 - t1 - brw
        s = UInt128(acc1) + UInt128(t0)
        acc0 = UInt64(s & _MASK64)
        s = UInt128(acc2) + UInt128(t1) + (s >> UInt128(64))
        acc1 = UInt64(s & _MASK64)
        s = UInt128(acc3) + UInt128(t2) + (s >> UInt128(64))
        acc2 = UInt64(s & _MASK64)
        s = UInt128(acc4) + UInt128(t3) + (s >> UInt128(64))
        acc3 = UInt64(s & _MASK64)
        acc4 = acc5 + UInt64(s >> UInt128(64))

        bi = b.limbs[i]
        p0 = UInt128(a0) * UInt128(bi)
        p1 = UInt128(a1) * UInt128(bi)
        p2 = UInt128(a2) * UInt128(bi)
        p3 = UInt128(a3) * UInt128(bi)
        s = UInt128(acc0) + (p0 & _MASK64)
        acc0 = UInt64(s & _MASK64)
        s = UInt128(acc1) + (p1 & _MASK64) + (s >> UInt128(64))
        acc1 = UInt64(s & _MASK64)
        s = UInt128(acc2) + (p2 & _MASK64) + (s >> UInt128(64))
        acc2 = UInt64(s & _MASK64)
        s = UInt128(acc3) + (p3 & _MASK64) + (s >> UInt128(64))
        acc3 = UInt64(s & _MASK64)
        acc4 += UInt64(s >> UInt128(64))
        s = UInt128(acc1) + (p0 >> UInt128(64))
        acc1 = UInt64(s & _MASK64)
        s = UInt128(acc2) + (p1 >> UInt128(64)) + (s >> UInt128(64))
        acc2 = UInt64(s & _MASK64)
        s = UInt128(acc3) + (p2 >> UInt128(64)) + (s >> UInt128(64))
        acc3 = UInt64(s & _MASK64)
        s = UInt128(acc4) + (p3 >> UInt128(64)) + (s >> UInt128(64))
        acc4 = UInt64(s & _MASK64)
        acc5 = UInt64(s >> UInt128(64))

    var t0 = acc0 << 32
    var t1 = acc0 >> 32
    var brw = UInt64(
        (UInt128(acc0) - UInt128(t0)) >> UInt128(64)
    ) & UInt64(1)
    var t2 = acc0 - t0
    var t3 = acc0 - t1 - brw
    s = UInt128(acc1) + UInt128(t0)
    acc0 = UInt64(s & _MASK64)
    s = UInt128(acc2) + UInt128(t1) + (s >> UInt128(64))
    acc1 = UInt64(s & _MASK64)
    s = UInt128(acc3) + UInt128(t2) + (s >> UInt128(64))
    acc2 = UInt64(s & _MASK64)
    s = UInt128(acc4) + UInt128(t3) + (s >> UInt128(64))
    acc3 = UInt64(s & _MASK64)
    acc4 = acc5 + UInt64(s >> UInt128(64))

    return _mont_final_sub(acc0, acc1, acc2, acc3, acc4)


@always_inline
def _mont_sqr(a: U256) -> U256:
    var a0 = a.limbs[0]
    var a1 = a.limbs[1]
    var a2 = a.limbs[2]
    var a3 = a.limbs[3]

    var p10 = UInt128(a1) * UInt128(a0)
    var p20 = UInt128(a2) * UInt128(a0)
    var p30 = UInt128(a3) * UInt128(a0)
    var p21 = UInt128(a2) * UInt128(a1)
    var p31 = UInt128(a3) * UInt128(a1)
    var p32 = UInt128(a3) * UInt128(a2)

    var acc1 = UInt64(p10 & _MASK64)
    var s = (p20 & _MASK64) + (p10 >> UInt128(64))
    var acc2 = UInt64(s & _MASK64)
    s = (
        (p30 & _MASK64)
        + (p20 >> UInt128(64))
        + (p21 & _MASK64)
        + (s >> UInt128(64))
    )
    var acc3 = UInt64(s & _MASK64)
    s = (
        (p30 >> UInt128(64))
        + (p21 >> UInt128(64))
        + (p31 & _MASK64)
        + (s >> UInt128(64))
    )
    var acc4 = UInt64(s & _MASK64)
    s = (p31 >> UInt128(64)) + (p32 & _MASK64) + (s >> UInt128(64))
    var acc5 = UInt64(s & _MASK64)
    var acc6 = UInt64(p32 >> UInt128(64)) + UInt64(s >> UInt128(64))

    var acc7 = acc6 >> 63
    acc6 = (acc6 << 1) | (acc5 >> 63)
    acc5 = (acc5 << 1) | (acc4 >> 63)
    acc4 = (acc4 << 1) | (acc3 >> 63)
    acc3 = (acc3 << 1) | (acc2 >> 63)
    acc2 = (acc2 << 1) | (acc1 >> 63)
    acc1 = acc1 << 1

    var d0 = UInt128(a0) * UInt128(a0)
    var d1 = UInt128(a1) * UInt128(a1)
    var d2 = UInt128(a2) * UInt128(a2)
    var d3 = UInt128(a3) * UInt128(a3)
    var acc0 = UInt64(d0 & _MASK64)
    s = UInt128(acc1) + (d0 >> UInt128(64))
    acc1 = UInt64(s & _MASK64)
    s = UInt128(acc2) + (d1 & _MASK64) + (s >> UInt128(64))
    acc2 = UInt64(s & _MASK64)
    s = UInt128(acc3) + (d1 >> UInt128(64)) + (s >> UInt128(64))
    acc3 = UInt64(s & _MASK64)
    s = UInt128(acc4) + (d2 & _MASK64) + (s >> UInt128(64))
    acc4 = UInt64(s & _MASK64)
    s = UInt128(acc5) + (d2 >> UInt128(64)) + (s >> UInt128(64))
    acc5 = UInt64(s & _MASK64)
    s = UInt128(acc6) + (d3 & _MASK64) + (s >> UInt128(64))
    acc6 = UInt64(s & _MASK64)
    acc7 = acc7 + UInt64(d3 >> UInt128(64)) + UInt64(s >> UInt128(64))

    comptime for _ in range(4):
        var t0 = acc0 << 32
        var t1 = acc0 >> 32
        var brw = UInt64(
            (UInt128(acc0) - UInt128(t0)) >> UInt128(64)
        ) & UInt64(1)
        var t2 = acc0 - t0
        var t3 = acc0 - t1 - brw
        s = UInt128(acc1) + UInt128(t0)
        acc0 = UInt64(s & _MASK64)
        s = UInt128(acc2) + UInt128(t1) + (s >> UInt128(64))
        acc1 = UInt64(s & _MASK64)
        s = UInt128(acc3) + UInt128(t2) + (s >> UInt128(64))
        acc2 = UInt64(s & _MASK64)
        acc3 = t3 + UInt64(s >> UInt128(64))

    s = UInt128(acc0) + UInt128(acc4)
    acc0 = UInt64(s & _MASK64)
    s = UInt128(acc1) + UInt128(acc5) + (s >> UInt128(64))
    acc1 = UInt64(s & _MASK64)
    s = UInt128(acc2) + UInt128(acc6) + (s >> UInt128(64))
    acc2 = UInt64(s & _MASK64)
    s = UInt128(acc3) + UInt128(acc7) + (s >> UInt128(64))
    acc3 = UInt64(s & _MASK64)
    acc4 = UInt64(s >> UInt128(64))

    return _mont_final_sub(acc0, acc1, acc2, acc3, acc4)


@always_inline
def _to_mont(x: U256) -> U256:
    return _mont_mul(x, _rr())


@always_inline
def _from_mont(x: U256) -> U256:
    return _mont_mul(x, U256.one())


@always_inline
def _mul_mod(a: U256, b: U256, m: U256) -> U256:
    return _mont_mul(_to_mont(a), b)


@always_inline
def _square_mod(a: U256, m: U256) -> U256:
    return _mul_mod(a, a, m)


def _pow_mod(base_in: U256, exponent: U256) -> U256:
    var result = _one_mont()
    var base = _to_mont(base_in)
    for i in range(256):
        if exponent.bit(i) != 0:
            result = _mont_mul(result, base)
        base = _mont_sqr(base)
    return _from_mont(result)


@always_inline
def _sqn_p(x: U256, n: Int) -> U256:
    var r = x
    for _ in range(n):
        r = _mont_sqr(r)
    return r


def _inv_p(x: U256) -> U256:
    # x^(p-2) p-2 = ffffffff 00000001 0 0 0 ffffffff ffffffff fffffffd
    var x2 = _mont_mul(_mont_sqr(x), x)
    var x3 = _mont_mul(_mont_sqr(x2), x)
    var x6 = _mont_mul(_sqn_p(x3, 3), x3)
    var x12 = _mont_mul(_sqn_p(x6, 6), x6)
    var x15 = _mont_mul(_sqn_p(x12, 3), x3)
    var x30 = _mont_mul(_sqn_p(x15, 15), x15)
    var x32 = _mont_mul(_sqn_p(x30, 2), x2)

    var t = _mont_mul(_sqn_p(x32, 32), x)
    t = _sqn_p(t, 96)
    t = _mont_mul(_sqn_p(t, 32), x32)
    t = _mont_mul(_sqn_p(t, 32), x32)
    t = _mont_mul(_sqn_p(t, 30), x30)
    t = _mont_mul(_sqn_p(t, 2), x)
    return t


def _sqrt_p(x: U256) -> U256:
    return _pow_mod(x, _sqrt_exp())


def _from_be(bytes: Span[UInt8, ...]) -> U256:
    var out = U256()
    for i in range(4):
        var off = 24 - i * 8
        var v: UInt64 = 0
        for k in range(8):
            v = (v << 8) | UInt64(bytes[off + k])
        out.limbs[i] = v
    return out


def _to_be(x: U256, output: UnsafePointer[mut=True, UInt8, _, address_space=_]):
    for i in range(4):
        var limb = x.limbs[3 - i]
        for k in range(8):
            output[i * 8 + k] = UInt8((limb >> UInt64(56 - 8 * k)) & 0xFF)


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


@always_inline
def _select_u256(a: U256, b: U256, choice: UInt64) -> U256:
    var mask = UInt64(0) - choice
    var out = U256()
    comptime for i in range(4):
        out.limbs[i] = a.limbs[i] ^ (mask & (a.limbs[i] ^ b.limbs[i]))
    return out


@always_inline
def _u256_zero_choice(x: U256) -> UInt64:
    var acc: UInt64 = 0
    comptime for i in range(4):
        acc |= x.limbs[i]
    return u64_zero_choice(acc)


@always_inline
def _jacobian_infinity() -> P256JacobianPoint:
    return P256JacobianPoint(U256(), _one_mont(), U256(), False)


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


@always_inline
def _jacobian_double_ct(p: P256JacobianPoint) -> P256JacobianPoint:
    var delta = _mont_sqr(p.z)
    var gamma = _mont_sqr(p.y)
    var beta = _mont_mul(p.x, gamma)
    var alpha = _mul_small_mod(
        _mont_mul(_sub_mod(p.x, delta), _add_mod(p.x, delta)),
        3,
    )
    var x3 = _sub_mod(_mont_sqr(alpha), _mul_small_mod(beta, 8))
    var z3 = _sub_mod(
        _sub_mod(_mont_sqr(_add_mod(p.y, p.z)), gamma),
        delta,
        _p(),
    )
    var y3 = _sub_mod(
        _mont_mul(alpha, _sub_mod(_mul_small_mod(beta, 4), x3)),
        _mul_small_mod(_mont_sqr(gamma), 8),
        _p(),
    )
    return P256JacobianPoint(x3, y3, z3, False)


@always_inline
def _jacobian_add_affine_non_equal_ct(
    p: P256JacobianPoint, q: P256Point
) -> P256JacobianPoint:
    # Scalar multiplication only adds distinct, non-opposite multiples.
    # The infinity input is still handled without branching on scalar bits.
    var z1z1 = _mont_sqr(p.z)
    var u2 = _mont_mul(q.x, z1z1)
    var s2 = _mont_mul(q.y, _mont_mul(p.z, z1z1))
    var h = _sub_mod(u2, p.x)
    var r = _mul_small_mod(_sub_mod(s2, p.y), 2)

    var i = _mont_sqr(_mul_small_mod(h, 2))
    var j = _mont_mul(h, i)
    var v = _mont_mul(p.x, i)
    var x3 = _sub_mod(_sub_mod(_mont_sqr(r), j), _mul_small_mod(v, 2), _p())
    var y3 = _sub_mod(
        _mont_mul(r, _sub_mod(v, x3)),
        _mul_small_mod(_mont_mul(p.y, j), 2),
        _p(),
    )
    var hh = _mont_sqr(h)
    var z3 = _sub_mod(
        _sub_mod(_mont_sqr(_add_mod(p.z, h)), z1z1),
        hh,
        _p(),
    )
    var generic = P256JacobianPoint(x3, y3, z3, False)

    var q_as_jac = P256JacobianPoint(q.x, q.y, _one_mont(), False)
    var p_is_inf = _u256_zero_choice(p.z)
    return _select_jacobian_ct(generic, q_as_jac, p_is_inf)


def _jacobian_to_affine(p: P256JacobianPoint) -> P256Point:
    if p.infinity or p.z.is_zero():
        return P256Point()
    var zinv = _inv_p(p.z)
    var zinv2 = _mont_sqr(zinv)
    var zinv3 = _mont_mul(zinv2, zinv)
    return P256Point(
        _from_mont(_mont_mul(p.x, zinv2)),
        _from_mont(_mont_mul(p.y, zinv3)),
        False,
    )


def _scalar_mult(k: U256, p: P256Point) -> P256Point:
    # Fixed-window scan keeps scalar access constant-time.
    var pm = P256Point(_to_mont(p.x), _to_mont(p.y), False)
    var jac = InlineArray[P256JacobianPoint, 15](uninitialized=True)
    jac[0] = P256JacobianPoint(pm.x, pm.y, _one_mont(), False)
    jac[1] = _jacobian_double_ct(jac[0])
    for i in range(2, 15):
        jac[i] = _jacobian_add_affine_non_equal_ct(jac[i - 1], pm)

    # Normalize the table with one inversion.
    var prefix = InlineArray[U256, 15](uninitialized=True)
    prefix[0] = jac[0].z
    for i in range(1, 15):
        prefix[i] = _mont_mul(prefix[i - 1], jac[i].z)
    var inv_acc = _inv_p(prefix[14])

    var tx = InlineArray[U256, 15](uninitialized=True)
    var ty = InlineArray[U256, 15](uninitialized=True)
    for jj in range(15):
        var j = 14 - jj
        var zinv = inv_acc
        if j > 0:
            zinv = _mont_mul(inv_acc, prefix[j - 1])
            inv_acc = _mont_mul(inv_acc, jac[j].z)
        var zinv2 = _mont_sqr(zinv)
        tx[j] = _mont_mul(jac[j].x, zinv2)
        ty[j] = _mont_mul(jac[j].y, _mont_mul(zinv2, zinv))

    var acc = _jacobian_infinity()
    for w in range(63, -1, -1):
        if w != 63:
            acc = _jacobian_double_ct(acc)
            acc = _jacobian_double_ct(acc)
            acc = _jacobian_double_ct(acc)
            acc = _jacobian_double_ct(acc)

        var d = (k.limbs[w >> 4] >> UInt64(4 * (w & 15))) & UInt64(0xF)
        var qx = tx[0]
        var qy = ty[0]
        for i in range(1, 15):
            var hit = u64_zero_choice(UInt64(i + 1) ^ d)
            qx = _select_u256(qx, tx[i], hit)
            qy = _select_u256(qy, ty[i], hit)

        var added = _jacobian_add_affine_non_equal_ct(
            acc, P256Point(qx, qy, False)
        )
        acc = _select_jacobian_ct(acc, added, u64_nonzero_choice(d))
    return _jacobian_to_affine(acc)


@always_inline
def _base_table_entry(
    tptr: UnsafePointer[UInt64, _], j: Int, d: UInt64
) -> P256Point:
    var qx = U256()
    var qy = U256()
    for t in range(1, 16):
        var hit = u64_zero_choice(UInt64(t) ^ d)
        var base = (j * 15 + (t - 1)) * 8
        var ex = U256(tptr[base], tptr[base + 1], tptr[base + 2], tptr[base + 3])
        var ey = U256(tptr[base + 4], tptr[base + 5], tptr[base + 6], tptr[base + 7])
        qx = _select_u256(qx, ex, hit)
        qy = _select_u256(qy, ey, hit)
    return P256Point(qx, qy, False)


def _scalar_mult_base(k: U256) -> P256Point:
    var table = p256_base_table()
    var tptr = table.unsafe_ptr()

    var acc = _jacobian_infinity()
    for i in range(1, 64, 2):
        var d = (k.limbs[i >> 4] >> UInt64(4 * (i & 15))) & UInt64(0xF)
        var q = _base_table_entry(tptr, i >> 1, d)
        var added = _jacobian_add_affine_non_equal_ct(acc, q)
        acc = _select_jacobian_ct(acc, added, u64_nonzero_choice(d))

    acc = _jacobian_double_ct(acc)
    acc = _jacobian_double_ct(acc)
    acc = _jacobian_double_ct(acc)
    acc = _jacobian_double_ct(acc)

    for i in range(0, 64, 2):
        var d = (k.limbs[i >> 4] >> UInt64(4 * (i & 15))) & UInt64(0xF)
        var q = _base_table_entry(tptr, i >> 1, d)
        var added = _jacobian_add_affine_non_equal_ct(acc, q)
        acc = _select_jacobian_ct(acc, added, u64_nonzero_choice(d))

    return _jacobian_to_affine(acc)


def p256_decode_uncompressed(point: Span[UInt8, ...]) -> P256Point:
    if len(point) == 33 and (point[0] == 0x02 or point[0] == 0x03):
        var x = _from_be(
            Span[UInt8, ...](unsafe_ptr=point.unsafe_ptr() + 1, length=32)
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
    var x = _from_be(Span[UInt8, ...](unsafe_ptr=point.unsafe_ptr() + 1, length=32))
    var y = _from_be(Span[UInt8, ...](unsafe_ptr=point.unsafe_ptr() + 33, length=32))
    var p = P256Point(x, y, False)
    if not _is_on_curve(p):
        return P256Point()
    return p


def p256_encode_uncompressed(
    point: P256Point, output: Span[mut=True, UInt8, ...]
) -> Bool:
    if len(output) < P256_POINT_SIZE or point.infinity or not _is_on_curve(point):
        return False
    var out_ptr = output.unsafe_ptr()
    out_ptr[0] = 0x04
    _to_be(point.x, out_ptr + 1)
    _to_be(point.y, out_ptr + 33)
    return True


@no_inline
def p256_public_key(
    private_key: Span[UInt8, ...], output: Span[mut=True, UInt8, ...]
) -> Bool:
    if len(private_key) != 32 or len(output) < P256_POINT_SIZE:
        return False
    var d = _from_be(private_key)
    if d.is_zero() or _cmp(d, _n()) >= 0:
        var dp = UnsafePointer(to=d.limbs[0]).unsafe_mut_cast[True]()
        for i in range(4):
            dp.store[volatile=True](i, UInt64(0))
        return False
    var q = _scalar_mult_base(d)
    var ok = p256_encode_uncompressed(q, output)
    var dp = UnsafePointer(to=d.limbs[0]).unsafe_mut_cast[True]()
    for i in range(4):
        dp.store[volatile=True](i, UInt64(0))
    return ok


@no_inline
def p256_ecdh(
    private_key: Span[UInt8, ...],
    public_key: Span[UInt8, ...],
    output: Span[mut=True, UInt8, ...],
) -> Bool:
    if len(private_key) != 32 or len(output) < P256_SIZE:
        return False
    var d = _from_be(private_key)
    if d.is_zero() or _cmp(d, _n()) >= 0:
        var dp = UnsafePointer(to=d.limbs[0]).unsafe_mut_cast[True]()
        for i in range(4):
            dp.store[volatile=True](i, UInt64(0))
        return False
    var q = p256_decode_uncompressed(public_key)
    if q.infinity:
        var dp = UnsafePointer(to=d.limbs[0]).unsafe_mut_cast[True]()
        for i in range(4):
            dp.store[volatile=True](i, UInt64(0))
        return False
    var shared = _scalar_mult(d, q)
    var dp = UnsafePointer(to=d.limbs[0]).unsafe_mut_cast[True]()
    for i in range(4):
        dp.store[volatile=True](i, UInt64(0))
    if shared.infinity:
        return False
    _to_be(shared.x, output.unsafe_ptr())
    return True


def _n_rr() -> U256:
    return U256(
        0x83244C95BE79EEA2,
        0x4699799C49BD6FA6,
        0x2845B2392B6BEC59,
        0x66E12D94F3D95620,
    )


def _n_one_mont() -> U256:
    return U256(
        0x0C46353D039CDAAF,
        0x4319055258E8617B,
        0x0000000000000000,
        0x00000000FFFFFFFF,
    )


def _n_minus_2() -> U256:
    return U256(
        0xF3B9CAC2FC63254F,
        0xBCE6FAADA7179E84,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFF00000000,
    )


@always_inline
def _n_mont_mul(a: U256, b: U256) -> U256:
    comptime n0 = UInt64(0xCCD1C8AAEE00BC4F)
    var n = _n()
    var t = U256()
    var t_hi = UInt64(0)
    comptime for i in range(4):
        var ai = a.limbs[i]
        var s = UInt128(ai) * UInt128(b.limbs[0]) + UInt128(t.limbs[0])
        var m = s.cast[DType.uint64]() * n0
        var q = UInt128(m) * UInt128(n.limbs[0]) + UInt128(s.cast[DType.uint64]())
        var ca = s >> 64
        var cb = q >> 64
        comptime for j in range(1, 4):
            var u = UInt128(ai) * UInt128(b.limbs[j]) + UInt128(t.limbs[j]) + ca
            ca = u >> 64
            var v = UInt128(m) * UInt128(n.limbs[j]) + UInt128(u.cast[DType.uint64]()) + cb
            t.limbs[j - 1] = v.cast[DType.uint64]()
            cb = v >> 64
        var w = UInt128(t_hi) + ca + cb
        t.limbs[3] = w.cast[DType.uint64]()
        t_hi = (w >> 64).cast[DType.uint64]()
    var reduced, borrow = _sub_raw(t, n)
    var take = u64_nonzero_choice(t_hi) | (borrow ^ UInt64(1))
    return _select_u256(t, reduced, take & UInt64(1))


@always_inline
def _n_to_mont(x: U256) -> U256:
    return _n_mont_mul(x, _n_rr())


@always_inline
def _n_from_mont(x: U256) -> U256:
    return _n_mont_mul(x, U256.one())


@always_inline
def _n_mul(a: U256, b: U256) -> U256:
    return _n_mont_mul(_n_to_mont(a), b)


def _n_inv(x: U256) -> U256:
    var result = _n_one_mont()
    var base = _n_to_mont(x)
    var exponent = _n_minus_2()
    for i in range(255, -1, -1):
        result = _n_mont_mul(result, result)
        var product = _n_mont_mul(result, base)
        result = _select_u256(result, product, exponent.bit(i))
    return _n_from_mont(result)


@always_inline
def _reduce_n(x: U256) -> U256:
    var reduced, borrow = _sub_raw(x, _n())
    return _select_u256(reduced, x, borrow)


def _wipe_u256(mut x: U256):
    var ptr = UnsafePointer(to=x.limbs[0]).unsafe_mut_cast[True]()
    for i in range(4):
        ptr.store[volatile=True](i, UInt64(0))


def _wipe_list_u8(mut data: List[UInt8]):
    var ptr = data.unsafe_ptr()
    for i in range(len(data)):
        ptr.store[volatile=True](i, UInt8(0))


def _rfc6979_p256(private_key: Span[UInt8, ...], digest: Span[UInt8, ...], skip: Int) -> U256:
    var h1 = _reduce_n(_from_be(digest))
    var h1_bytes = InlineArray[UInt8, 32](uninitialized=True)
    _to_be(h1, h1_bytes.unsafe_ptr())
    var k = List[UInt8](length=32, fill=0)
    var v = List[UInt8](length=32, fill=1)

    var seed = List[UInt8](capacity=97)
    for i in range(32):
        seed.append(v[i])
    seed.append(0)
    for i in range(32):
        seed.append(private_key[i])
    for i in range(32):
        seed.append(h1_bytes[i])
    var next_k = hmac_sha256(Span[UInt8, ...](k), Span[UInt8, ...](seed))
    _wipe_list_u8(k)
    k = next_k^
    var next_v = hmac_sha256(Span[UInt8, ...](k), Span[UInt8, ...](v))
    _wipe_list_u8(v)
    v = next_v^

    _wipe_list_u8(seed)
    seed.clear()
    for i in range(32):
        seed.append(v[i])
    seed.append(1)
    for i in range(32):
        seed.append(private_key[i])
    for i in range(32):
        seed.append(h1_bytes[i])
    next_k = hmac_sha256(Span[UInt8, ...](k), Span[UInt8, ...](seed))
    _wipe_list_u8(k)
    k = next_k^
    next_v = hmac_sha256(Span[UInt8, ...](k), Span[UInt8, ...](v))
    _wipe_list_u8(v)
    v = next_v^

    var accepted = 0
    while True:
        next_v = hmac_sha256(Span[UInt8, ...](k), Span[UInt8, ...](v))
        _wipe_list_u8(v)
        v = next_v^
        var candidate = _from_be(Span[UInt8, ...](v))
        if not candidate.is_zero() and _cmp(candidate, _n()) < 0:
            if accepted == skip:
                _wipe_list_u8(k)
                _wipe_list_u8(v)
                _wipe_list_u8(seed)
                var hp = h1_bytes.unsafe_ptr()
                for i in range(32):
                    hp.store[volatile=True](i, UInt8(0))
                _wipe_u256(h1)
                return candidate
            accepted += 1
        _wipe_u256(candidate)
        _wipe_list_u8(seed)
        seed.clear()
        for i in range(32):
            seed.append(v[i])
        seed.append(0)
        next_k = hmac_sha256(Span[UInt8, ...](k), Span[UInt8, ...](seed))
        _wipe_list_u8(k)
        k = next_k^
        next_v = hmac_sha256(Span[UInt8, ...](k), Span[UInt8, ...](v))
        _wipe_list_u8(v)
        v = next_v^


def p256_ecdsa_sign_digest(
    private_key: Span[UInt8, ...],
    digest: Span[UInt8, ...],
    signature: Span[mut=True, UInt8, ...],
) -> Bool:
    if (
        len(private_key) != 32 or len(digest) != 32
        or len(signature) < P256_SIGNATURE_SIZE
    ):
        return False
    var signature_ptr = signature.unsafe_ptr()
    var d = _from_be(private_key)
    if d.is_zero() or _cmp(d, _n()) >= 0:
        _wipe_u256(d)
        return False
    var z = _reduce_n(_from_be(digest))
    var retry = 0
    while True:
        var k = _rfc6979_p256(private_key, digest, retry)
        var point = _scalar_mult_base(k)
        var r = _reduce_n(point.x)
        if r.is_zero():
            _wipe_u256(k)
            retry += 1
            continue
        var rd = _n_mul(r, d)
        var total = _add_mod(z, rd, _n())
        var kinv = _n_inv(k)
        var s = _n_mul(kinv, total)
        if s.is_zero():
            _wipe_u256(k)
            _wipe_u256(kinv)
            _wipe_u256(rd)
            _wipe_u256(total)
            retry += 1
            continue
        _to_be(r, signature_ptr)
        _to_be(s, signature_ptr + 32)
        _wipe_u256(d)
        _wipe_u256(z)
        _wipe_u256(k)
        _wipe_u256(kinv)
        _wipe_u256(rd)
        _wipe_u256(total)
        return True


def p256_ecdsa_sign(
    private_key: Span[UInt8, ...],
    message: Span[UInt8, ...],
    signature: Span[mut=True, UInt8, ...],
) -> Bool:
    if len(signature) < P256_SIGNATURE_SIZE:
        return False
    var digest = sha256_hash(message)
    var ok = p256_ecdsa_sign_digest(
        private_key, Span[UInt8, ...](digest), signature
    )
    _wipe_list_u8(digest)
    return ok


def _p256_add_public(a: P256Point, b: P256Point) -> P256Point:
    if a.infinity:
        return b
    if b.infinity:
        return a
    if _eq(a.x, b.x):
        if not _eq(a.y, b.y) or a.y.is_zero():
            return P256Point()
        var am = P256JacobianPoint(_to_mont(a.x), _to_mont(a.y), _one_mont(), False)
        return _jacobian_to_affine(_jacobian_double_ct(am))
    var dx = _sub_mod(b.x, a.x, _p())
    var dy = _sub_mod(b.y, a.y, _p())
    var dx_inv = _from_mont(_inv_p(_to_mont(dx)))
    var slope = _mul_mod(dy, dx_inv, _p())
    var x3 = _sub_mod(_sub_mod(_square_mod(slope, _p()), a.x, _p()), b.x, _p())
    var y3 = _sub_mod(_mul_mod(slope, _sub_mod(a.x, x3, _p()), _p()), a.y, _p())
    return P256Point(x3, y3, False)


def p256_ecdsa_verify_digest(
    public_key: Span[UInt8, ...],
    digest: Span[UInt8, ...],
    signature: Span[UInt8, ...],
) -> Bool:
    if len(digest) != 32 or len(signature) != 64:
        return False
    var q = p256_decode_uncompressed(public_key)
    if q.infinity:
        return False
    var r = _from_be(signature[0:32])
    var s = _from_be(signature[32:64])
    if r.is_zero() or s.is_zero() or _cmp(r, _n()) >= 0 or _cmp(s, _n()) >= 0:
        return False
    var z = _reduce_n(_from_be(digest))
    var w = _n_inv(s)
    var u1 = _n_mul(z, w)
    var u2 = _n_mul(r, w)
    var point = _p256_add_public(_scalar_mult_base(u1), _scalar_mult(u2, q))
    if point.infinity:
        return False
    return _eq(_reduce_n(point.x), r)


def p256_ecdsa_verify(
    public_key: Span[UInt8, ...],
    message: Span[UInt8, ...],
    signature: Span[UInt8, ...],
) -> Bool:
    var digest = sha256_hash(message)
    return p256_ecdsa_verify_digest(public_key, Span[UInt8, ...](digest), signature)


def p256_ecdsa_sign_der(
    private_key: Span[UInt8, ...], message: Span[UInt8, ...]
) raises -> List[UInt8]:
    from .ecdsa_der import ecdsa_der_encode
    var raw = List[UInt8](unsafe_uninit_length=P256_SIGNATURE_SIZE)
    if not p256_ecdsa_sign(
        private_key, message, Span[mut=True, UInt8, ...](raw)
    ):
        raise Error("P-256 ECDSA signing failed")
    return ecdsa_der_encode(Span[UInt8, ...](raw), P256_SIZE)


def p256_ecdsa_verify_der(
    public_key: Span[UInt8, ...], message: Span[UInt8, ...],
    signature: Span[UInt8, ...],
) -> Bool:
    from .ecdsa_der import ecdsa_der_decode
    var raw = ecdsa_der_decode(signature, P256_SIZE)
    if len(raw) != P256_SIGNATURE_SIZE:
        return False
    return p256_ecdsa_verify(public_key, message, Span[UInt8, ...](raw))


def p256_keygen() raises -> Tuple[List[UInt8], List[UInt8]]:
    from .random import random_bytes
    while True:
        var private_key = random_bytes(32)
        var d = _from_be(Span[UInt8, ...](private_key))
        if not d.is_zero() and _cmp(d, _n()) < 0:
            var public_key = List[UInt8](unsafe_uninit_length=65)
            if p256_public_key(
                Span[UInt8, ...](private_key),
                Span[mut=True, UInt8, ...](public_key),
            ):
                _wipe_u256(d)
                return (private_key^, public_key^)
        _wipe_u256(d)
        _wipe_list_u8(private_key)
