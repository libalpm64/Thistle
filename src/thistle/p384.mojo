"""
NIST P-384 / secp384r1 implementation.
"""

from .p384_table import p384_base_table
from .utils import u64_nonzero_choice, u64_zero_choice
from .sha2 import sha384_hash
from .pbkdf2 import hmac_sha384
from std.utils import StaticTuple

comptime P384_SIZE = 48
comptime P384_POINT_SIZE = 97
comptime P384_SIGNATURE_SIZE = 96
comptime _MASK64 = UInt128(0xFFFFFFFFFFFFFFFF)
comptime _N0 = UInt64(0x0000000100000001)  # -p^-1 mod 2^64


struct U384(Copyable, ImplicitlyCopyable, Movable):
    var limbs: StaticTuple[UInt64, 6]

    def __init__(out self):
        self.limbs = StaticTuple[UInt64, 6]()
        comptime for i in range(6):
            self.limbs[i] = 0

    def __init__(
        out self,
        l0: UInt64,
        l1: UInt64,
        l2: UInt64,
        l3: UInt64,
        l4: UInt64,
        l5: UInt64,
    ):
        self.limbs = StaticTuple[UInt64, 6]()
        self.limbs[0] = l0
        self.limbs[1] = l1
        self.limbs[2] = l2
        self.limbs[3] = l3
        self.limbs[4] = l4
        self.limbs[5] = l5

    def __copyinit__(out self, copy: Self):
        self.limbs = copy.limbs

    def __moveinit__(out self, deinit take: Self):
        self.limbs = take.limbs^

    @staticmethod
    def one() -> U384:
        return U384(1, 0, 0, 0, 0, 0)

    def is_zero(self) -> Bool:
        for i in range(6):
            if self.limbs[i] != 0:
                return False
        return True

    def bit(self, i: Int) -> UInt64:
        return (self.limbs[i // 64] >> UInt64(i % 64)) & 1


def _p() -> U384:
    return U384(
        0x00000000FFFFFFFF,
        0xFFFFFFFF00000000,
        0xFFFFFFFFFFFFFFFE,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
    )


def _a() -> U384:
    return U384(
        0x00000000FFFFFFFC,
        0xFFFFFFFF00000000,
        0xFFFFFFFFFFFFFFFE,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
    )


def _b() -> U384:
    return U384(
        0x2A85C8EDD3EC2AEF,
        0xC656398D8A2ED19D,
        0x0314088F5013875A,
        0x181D9C6EFE814112,
        0x988E056BE3F82D19,
        0xB3312FA7E23EE7E4,
    )


def _n() -> U384:
    return U384(
        0xECEC196ACCC52973,
        0x581A0DB248B0A77A,
        0xC7634D81F4372DDF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
    )


def _gx() -> U384:
    return U384(
        0x3A545E3872760AB7,
        0x5502F25DBF55296C,
        0x59F741E082542A38,
        0x6E1D3B628BA79B98,
        0x8EB1C71EF320AD74,
        0xAA87CA22BE8B0537,
    )


def _gy() -> U384:
    return U384(
        0x7A431D7C90EA0E5F,
        0x0A60B1CE1D7E819D,
        0xE9DA3113B5F0B8C0,
        0xF8F41DBD289A147C,
        0x5D9E98BF9292DC29,
        0x3617DE4A96262C6F,
    )


def _sqrt_exp() -> U384:
    # p == 3 mod 4
    return U384(
        0x0000000040000000,
        0xBFFFFFFFC0000000,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0x3FFFFFFFFFFFFFFF,
    )


def _rr() -> U384:
    return U384(
        0xFFFFFFFE00000001,
        0x0000000200000000,
        0xFFFFFFFE00000000,
        0x0000000200000000,
        0x0000000000000001,
        0x0000000000000000,
    )


def _one_mont() -> U384:
    return U384(
        0xFFFFFFFF00000001,
        0x00000000FFFFFFFF,
        0x0000000000000001,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
    )


@always_inline
def _cmp(a: U384, b: U384) -> Int:
    comptime for j in range(6):
        var i = 5 - j
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
    comptime for i in range(6):
        var d = UInt128(a.limbs[i]) - UInt128(b.limbs[i]) - UInt128(borrow)
        out.limbs[i] = UInt64(d & _MASK64)
        borrow = UInt64((d >> UInt128(64)) & UInt128(1))
    return out, borrow


@always_inline
def _add_raw(a: U384, b: U384) -> Tuple[U384, UInt64]:
    var out = U384()
    var carry: UInt64 = 0
    comptime for i in range(6):
        var s = UInt128(a.limbs[i]) + UInt128(b.limbs[i]) + UInt128(carry)
        out.limbs[i] = UInt64(s & _MASK64)
        carry = UInt64(s >> UInt128(64))
    return out, carry


@always_inline
def _add_mod(a: U384, b: U384, m: U384) -> U384:
    var sum, carry = _add_raw(a, b)
    var d, borrow = _sub_raw(sum, m)
    var take_d = (carry | (borrow ^ UInt64(1))) & UInt64(1)
    return _select_u384(sum, d, take_d)


@always_inline
def _sub_mod(a: U384, b: U384, m: U384) -> U384:
    var diff, borrow = _sub_raw(a, b)
    var diff_plus_m, _ = _add_raw(diff, m)
    return _select_u384(diff, diff_plus_m, borrow)


@always_inline
def _add_mod(a: U384, b: U384) -> U384:
    return _add_mod(a, b, _p())


@always_inline
def _sub_mod(a: U384, b: U384) -> U384:
    return _sub_mod(a, b, _p())


@always_inline
def _mont_mul(a: U384, b: U384) -> U384:
    var acc = InlineArray[UInt64, 8](fill=0)
    var pmod = _p()

    comptime for i in range(6):
        var bi = b.limbs[i]
        var carry = UInt64(0)
        comptime for j in range(6):
            var t = (
                UInt128(a.limbs[j]) * UInt128(bi)
                + UInt128(acc[j])
                + UInt128(carry)
            )
            acc[j] = UInt64(t & _MASK64)
            carry = UInt64(t >> UInt128(64))
        var s = UInt128(acc[6]) + UInt128(carry)
        acc[6] = UInt64(s & _MASK64)
        acc[7] += UInt64(s >> UInt128(64))

        var m = acc[0] * _N0
        var t0 = UInt128(acc[0]) + UInt128(m) * UInt128(pmod.limbs[0])
        var c = UInt64(t0 >> UInt128(64))
        comptime for j in range(1, 6):
            var t = (
                UInt128(m) * UInt128(pmod.limbs[j])
                + UInt128(acc[j])
                + UInt128(c)
            )
            acc[j - 1] = UInt64(t & _MASK64)
            c = UInt64(t >> UInt128(64))
        s = UInt128(acc[6]) + UInt128(c)
        acc[5] = UInt64(s & _MASK64)
        acc[6] = acc[7] + UInt64(s >> UInt128(64))
        acc[7] = 0

    var out = U384(acc[0], acc[1], acc[2], acc[3], acc[4], acc[5])
    var d, borrow = _sub_raw(out, pmod)
    var take_d = (acc[6] | (borrow ^ UInt64(1))) & UInt64(1)
    return _select_u384(out, d, take_d)


@always_inline
def _mont_sqr(a: U384) -> U384:
    var acc = InlineArray[UInt64, 13](fill=0)

    comptime for i in range(6):
        comptime for j in range(i + 1, 6):
            comptime k = i + j
            var product = UInt128(a.limbs[i]) * UInt128(a.limbs[j])
            var s = UInt128(acc[k]) + (product & _MASK64)
            acc[k] = UInt64(s & _MASK64)
            var carry = UInt64(product >> UInt128(64)) + UInt64(
                s >> UInt128(64)
            )
            comptime for q in range(k + 1, 12):
                s = UInt128(acc[q]) + UInt128(carry)
                acc[q] = UInt64(s & _MASK64)
                carry = UInt64(s >> UInt128(64))
            acc[12] += carry

    var bit_carry = UInt64(0)
    comptime for i in range(13):
        var next_carry = acc[i] >> UInt64(63)
        acc[i] = (acc[i] << UInt64(1)) | bit_carry
        bit_carry = next_carry

    comptime for i in range(6):
        comptime k = 2 * i
        var product = UInt128(a.limbs[i]) * UInt128(a.limbs[i])
        var s = UInt128(acc[k]) + (product & _MASK64)
        acc[k] = UInt64(s & _MASK64)
        var carry = UInt64(product >> UInt128(64)) + UInt64(s >> UInt128(64))
        comptime for q in range(k + 1, 13):
            s = UInt128(acc[q]) + UInt128(carry)
            acc[q] = UInt64(s & _MASK64)
            carry = UInt64(s >> UInt128(64))

    var pmod = _p()
    comptime for i in range(6):
        var m = acc[i] * _N0
        var carry = UInt64(0)
        comptime for j in range(6):
            var s = (
                UInt128(m) * UInt128(pmod.limbs[j])
                + UInt128(acc[i + j])
                + UInt128(carry)
            )
            acc[i + j] = UInt64(s & _MASK64)
            carry = UInt64(s >> UInt128(64))
        comptime for q in range(i + 6, 13):
            var s = UInt128(acc[q]) + UInt128(carry)
            acc[q] = UInt64(s & _MASK64)
            carry = UInt64(s >> UInt128(64))

    var out = U384(acc[6], acc[7], acc[8], acc[9], acc[10], acc[11])
    var d, borrow = _sub_raw(out, pmod)
    var take_d = (acc[12] | (borrow ^ UInt64(1))) & UInt64(1)
    return _select_u384(out, d, take_d)


@always_inline
def _to_mont(x: U384) -> U384:
    return _mont_mul(x, _rr())


@always_inline
def _from_mont(x: U384) -> U384:
    return _mont_mul(x, U384.one())


@always_inline
def _mul_mod(a: U384, b: U384, m: U384) -> U384:
    return _mont_mul(_to_mont(a), b)


@always_inline
def _square_mod(a: U384, m: U384) -> U384:
    return _mul_mod(a, a, m)


def _pow_mod(base_in: U384, exponent: U384) -> U384:
    var result = _one_mont()
    var base = _to_mont(base_in)
    for i in range(384):
        if exponent.bit(i) != 0:
            result = _mont_mul(result, base)
        base = _mont_sqr(base)
    return _from_mont(result)


@always_inline
def _sqn_p(x: U384, n: Int) -> U384:
    var r = x
    for _ in range(n):
        r = _mont_sqr(r)
    return r


def _inv_p(x: U384) -> U384:
    # Fermat inversion in the Montgomery domain.
    var x2 = _mont_mul(_mont_sqr(x), x)
    var x3 = _mont_mul(_mont_sqr(x2), x)
    var x6 = _mont_mul(_sqn_p(x3, 3), x3)
    var x12 = _mont_mul(_sqn_p(x6, 6), x6)
    var x15 = _mont_mul(_sqn_p(x12, 3), x3)
    var x30 = _mont_mul(_sqn_p(x15, 15), x15)
    var x32 = _mont_mul(_sqn_p(x30, 2), x2)
    var x60 = _mont_mul(_sqn_p(x30, 30), x30)
    var x120 = _mont_mul(_sqn_p(x60, 60), x60)
    var x240 = _mont_mul(_sqn_p(x120, 120), x120)
    var x255 = _mont_mul(_sqn_p(x240, 15), x15)

    var t = _sqn_p(x255, 1)
    t = _mont_mul(_sqn_p(t, 32), x32)
    t = _sqn_p(t, 64)
    t = _mont_mul(_sqn_p(t, 30), x30)
    t = _mont_mul(_sqn_p(t, 2), x)
    return t


def _sqrt_p(x: U384) -> U384:
    return _pow_mod(x, _sqrt_exp())


def _from_be(bytes: Span[UInt8, ...]) -> U384:
    var out = U384()
    for i in range(6):
        var off = 40 - i * 8
        var v: UInt64 = 0
        for k in range(8):
            v = (v << 8) | UInt64(bytes[off + k])
        out.limbs[i] = v
    return out


def _to_be(x: U384, output: Pointer[mut=True, UInt8, _, address_space=_]):
    for i in range(6):
        var limb = x.limbs[5 - i]
        for k in range(8):
            output[unsafe_offset=i * 8 + k] = UInt8((limb >> UInt64(56 - 8 * k)) & 0xFF)


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


@always_inline
def _select_u384(a: U384, b: U384, choice: UInt64) -> U384:
    var mask = UInt64(0) - choice
    var out = U384()
    comptime for i in range(6):
        out.limbs[i] = a.limbs[i] ^ (mask & (a.limbs[i] ^ b.limbs[i]))
    return out


@always_inline
def _u384_zero_choice(x: U384) -> UInt64:
    var acc: UInt64 = 0
    comptime for i in range(6):
        acc |= x.limbs[i]
    return u64_zero_choice(acc)


@always_inline
def _jacobian_infinity() -> P384JacobianPoint:
    return P384JacobianPoint(U384(), _one_mont(), U384(), False)


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
    var out = U384()
    for _ in range(c):
        out = _add_mod(out, x, _p())
    return out


def _is_on_curve(point: P384Point) -> Bool:
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
def _jacobian_double_ct(p: P384JacobianPoint) -> P384JacobianPoint:
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
    return P384JacobianPoint(x3, y3, z3, False)


@always_inline
def _jacobian_add_affine_non_equal_ct(
    p: P384JacobianPoint, q: P384Point
) -> P384JacobianPoint:
    # Scalar multiplication adds distinct non-opposite multiples.
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
    var generic = P384JacobianPoint(x3, y3, z3, False)

    var q_as_jac = P384JacobianPoint(q.x, q.y, _one_mont(), False)
    var p_is_inf = _u384_zero_choice(p.z)
    return _select_jacobian_ct(generic, q_as_jac, p_is_inf)


def _jacobian_to_affine(p: P384JacobianPoint) -> P384Point:
    if p.infinity or p.z.is_zero():
        return P384Point()
    var zinv = _inv_p(p.z)
    var zinv2 = _mont_sqr(zinv)
    var zinv3 = _mont_mul(zinv2, zinv)
    return P384Point(
        _from_mont(_mont_mul(p.x, zinv2)),
        _from_mont(_mont_mul(p.y, zinv3)),
        False,
    )


def _scalar_mult(k: U384, p: P384Point) -> P384Point:
    var pm = P384Point(_to_mont(p.x), _to_mont(p.y), False)
    var jac = InlineArray[P384JacobianPoint, 15](uninitialized=True)
    jac[0] = P384JacobianPoint(pm.x, pm.y, _one_mont(), False)
    jac[1] = _jacobian_double_ct(jac[0])
    for i in range(2, 15):
        jac[i] = _jacobian_add_affine_non_equal_ct(jac[i - 1], pm)

    var prefix = InlineArray[U384, 15](uninitialized=True)
    prefix[0] = jac[0].z
    for i in range(1, 15):
        prefix[i] = _mont_mul(prefix[i - 1], jac[i].z)
    var inv_acc = _inv_p(prefix[14])

    var tx = InlineArray[U384, 15](uninitialized=True)
    var ty = InlineArray[U384, 15](uninitialized=True)
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
    for w in range(95, -1, -1):
        if w != 95:
            acc = _jacobian_double_ct(acc)
            acc = _jacobian_double_ct(acc)
            acc = _jacobian_double_ct(acc)
            acc = _jacobian_double_ct(acc)

        var d = (k.limbs[w >> 4] >> UInt64(4 * (w & 15))) & UInt64(0xF)
        var qx = tx[0]
        var qy = ty[0]
        for i in range(1, 15):
            var hit = u64_zero_choice(UInt64(i + 1) ^ d)
            qx = _select_u384(qx, tx[i], hit)
            qy = _select_u384(qy, ty[i], hit)

        var added = _jacobian_add_affine_non_equal_ct(
            acc, P384Point(qx, qy, False)
        )
        acc = _select_jacobian_ct(acc, added, u64_nonzero_choice(d))
    return _jacobian_to_affine(acc)


@always_inline
def _base_table_entry(
    tptr: Pointer[UInt64, _], j: Int, d: UInt64
) -> P384Point:
    # Scan the whole window.
    var qx = U384()
    var qy = U384()
    for t in range(1, 16):
        var hit = u64_zero_choice(UInt64(t) ^ d)
        var base = (j * 15 + (t - 1)) * 12
        var ex = U384(tptr[unsafe_offset=base], tptr[unsafe_offset=base + 1], tptr[unsafe_offset=base + 2], tptr[unsafe_offset=base + 3], tptr[unsafe_offset=base + 4], tptr[unsafe_offset=base + 5])
        var ey = U384(tptr[unsafe_offset=base + 6], tptr[unsafe_offset=base + 7], tptr[unsafe_offset=base + 8], tptr[unsafe_offset=base + 9], tptr[unsafe_offset=base + 10], tptr[unsafe_offset=base + 11])
        qx = _select_u384(qx, ex, hit)
        qy = _select_u384(qy, ey, hit)
    return P384Point(qx, qy, False)


def _scalar_mult_base(k: U384) -> P384Point:
    # Split odd and even radix-16 digits.
    var table = p384_base_table()
    var tptr = table.unsafe_ptr()

    var acc = _jacobian_infinity()
    for i in range(1, 96, 2):
        var d = (k.limbs[i >> 4] >> UInt64(4 * (i & 15))) & UInt64(0xF)
        var q = _base_table_entry(tptr, i >> 1, d)
        var added = _jacobian_add_affine_non_equal_ct(acc, q)
        acc = _select_jacobian_ct(acc, added, u64_nonzero_choice(d))

    acc = _jacobian_double_ct(acc)
    acc = _jacobian_double_ct(acc)
    acc = _jacobian_double_ct(acc)
    acc = _jacobian_double_ct(acc)

    for i in range(0, 96, 2):
        var d = (k.limbs[i >> 4] >> UInt64(4 * (i & 15))) & UInt64(0xF)
        var q = _base_table_entry(tptr, i >> 1, d)
        var added = _jacobian_add_affine_non_equal_ct(acc, q)
        acc = _select_jacobian_ct(acc, added, u64_nonzero_choice(d))

    return _jacobian_to_affine(acc)


def p384_decode_uncompressed(point: Span[UInt8, ...]) -> P384Point:
    if len(point) == 49 and (point[0] == 0x02 or point[0] == 0x03):
        var x = _from_be(
            Span[UInt8, ...](unsafe_ptr=point.unsafe_ptr().unsafe_offset(1), length=48)
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
    var x = _from_be(Span[UInt8, ...](unsafe_ptr=point.unsafe_ptr().unsafe_offset(1), length=48))
    var y = _from_be(Span[UInt8, ...](unsafe_ptr=point.unsafe_ptr().unsafe_offset(49), length=48))
    var p = P384Point(x, y, False)
    if not _is_on_curve(p):
        return P384Point()
    return p


def p384_encode_uncompressed(
    point: P384Point, output: Span[mut=True, UInt8, ...]
) -> Bool:
    if len(output) < P384_POINT_SIZE or point.infinity or not _is_on_curve(point):
        return False
    var out_ptr = output.unsafe_ptr()
    out_ptr[unsafe_offset=0] = 0x04
    _to_be(point.x, out_ptr.unsafe_offset(1))
    _to_be(point.y, out_ptr.unsafe_offset(49))
    return True


@no_inline
def p384_public_key(
    private_key: Span[UInt8, ...], output: Span[mut=True, UInt8, ...]
) -> Bool:
    if len(private_key) != 48 or len(output) < P384_POINT_SIZE:
        return False
    var d = _from_be(private_key)
    if d.is_zero() or _cmp(d, _n()) >= 0:
        var dp = Pointer(to=d.limbs[0]).unsafe_mut_cast[True]()
        for i in range(6):
            dp.unsafe_store[volatile=True](i, UInt64(0))
        return False
    var q = _scalar_mult_base(d)
    var ok = p384_encode_uncompressed(q, output)
    var dp = Pointer(to=d.limbs[0]).unsafe_mut_cast[True]()
    for i in range(6):
        dp.unsafe_store[volatile=True](i, UInt64(0))
    return ok


@no_inline
def p384_ecdh(
    private_key: Span[UInt8, ...],
    public_key: Span[UInt8, ...],
    output: Span[mut=True, UInt8, ...],
) -> Bool:
    if len(private_key) != 48 or len(output) < P384_SIZE:
        return False
    var d = _from_be(private_key)
    if d.is_zero() or _cmp(d, _n()) >= 0:
        var dp = Pointer(to=d.limbs[0]).unsafe_mut_cast[True]()
        for i in range(6):
            dp.unsafe_store[volatile=True](i, UInt64(0))
        return False
    var q = p384_decode_uncompressed(public_key)
    if q.infinity:
        var dp = Pointer(to=d.limbs[0]).unsafe_mut_cast[True]()
        for i in range(6):
            dp.unsafe_store[volatile=True](i, UInt64(0))
        return False
    var shared = _scalar_mult(d, q)
    var dp = Pointer(to=d.limbs[0]).unsafe_mut_cast[True]()
    for i in range(6):
        dp.unsafe_store[volatile=True](i, UInt64(0))
    if shared.infinity:
        return False
    _to_be(shared.x, output.unsafe_ptr())
    return True


def _n_rr() -> U384:
    return U384(
        0x2D319B2419B409A9,
        0xFF3D81E5DF1AA419,
        0xBC3E483AFCB82947,
        0xD40D49174AAB1CC5,
        0x3FB05B7A28266895,
        0x0C84EE012B39BF21,
    )


def _n_one_mont() -> U384:
    return U384(
        0x1313E695333AD68D,
        0xA7E5F24DB74F5885,
        0x389CB27E0BC8D220,
        0,
        0,
        0,
    )


def _n_minus_2() -> U384:
    return U384(
        0xECEC196ACCC52971,
        0x581A0DB248B0A77A,
        0xC7634D81F4372DDF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
    )


@always_inline
def _n_mont_mul(a: U384, b: U384) -> U384:
    comptime n0 = UInt64(0x6ED46089E88FDC45)
    var n = _n()
    var t = U384()
    var t_hi = UInt64(0)
    comptime for i in range(6):
        var ai = a.limbs[i]
        var s = UInt128(ai) * UInt128(b.limbs[0]) + UInt128(t.limbs[0])
        var m = s.cast[DType.uint64]() * n0
        var q = UInt128(m) * UInt128(n.limbs[0]) + UInt128(s.cast[DType.uint64]())
        var ca = s >> 64
        var cb = q >> 64
        comptime for j in range(1, 6):
            var u = UInt128(ai) * UInt128(b.limbs[j]) + UInt128(t.limbs[j]) + ca
            ca = u >> 64
            var v = UInt128(m) * UInt128(n.limbs[j]) + UInt128(u.cast[DType.uint64]()) + cb
            t.limbs[j - 1] = v.cast[DType.uint64]()
            cb = v >> 64
        var w = UInt128(t_hi) + ca + cb
        t.limbs[5] = w.cast[DType.uint64]()
        t_hi = (w >> 64).cast[DType.uint64]()
    var reduced, borrow = _sub_raw(t, n)
    var take = u64_nonzero_choice(t_hi) | (borrow ^ UInt64(1))
    return _select_u384(t, reduced, take & UInt64(1))


@always_inline
def _n_to_mont(x: U384) -> U384:
    return _n_mont_mul(x, _n_rr())


@always_inline
def _n_from_mont(x: U384) -> U384:
    return _n_mont_mul(x, U384.one())


@always_inline
def _n_mul(a: U384, b: U384) -> U384:
    return _n_mont_mul(_n_to_mont(a), b)


def _n_inv(x: U384) -> U384:
    var result = _n_one_mont()
    var base = _n_to_mont(x)
    var exponent = _n_minus_2()
    for i in range(383, -1, -1):
        result = _n_mont_mul(result, result)
        var product = _n_mont_mul(result, base)
        result = _select_u384(result, product, exponent.bit(i))
    return _n_from_mont(result)


@always_inline
def _reduce_n(x: U384) -> U384:
    var reduced, borrow = _sub_raw(x, _n())
    return _select_u384(reduced, x, borrow)


def _wipe_u384(mut x: U384):
    var ptr = Pointer(to=x.limbs[0]).unsafe_mut_cast[True]()
    for i in range(6):
        ptr.unsafe_store[volatile=True](i, UInt64(0))


def _wipe_list_u8(mut data: List[UInt8]):
    var ptr = data.unsafe_ptr()
    for i in range(len(data)):
        ptr.unsafe_store[volatile=True](i, UInt8(0))


def _rfc6979_p384(private_key: Span[UInt8, ...], digest: Span[UInt8, ...], skip: Int) -> U384:
    var h1 = _reduce_n(_from_be(digest))
    var h1_bytes = InlineArray[UInt8, 48](uninitialized=True)
    _to_be(h1, h1_bytes.unsafe_ptr())
    var k = List[UInt8](length=48, fill=0)
    var v = List[UInt8](length=48, fill=1)

    var seed = List[UInt8](capacity=145)
    for i in range(48):
        seed.append(v[i])
    seed.append(0)
    for i in range(48):
        seed.append(private_key[i])
    for i in range(48):
        seed.append(h1_bytes[i])
    var next_k = hmac_sha384(Span[UInt8, ...](k), Span[UInt8, ...](seed))
    _wipe_list_u8(k)
    k = next_k^
    var next_v = hmac_sha384(Span[UInt8, ...](k), Span[UInt8, ...](v))
    _wipe_list_u8(v)
    v = next_v^

    _wipe_list_u8(seed)
    seed.clear()
    for i in range(48):
        seed.append(v[i])
    seed.append(1)
    for i in range(48):
        seed.append(private_key[i])
    for i in range(48):
        seed.append(h1_bytes[i])
    next_k = hmac_sha384(Span[UInt8, ...](k), Span[UInt8, ...](seed))
    _wipe_list_u8(k)
    k = next_k^
    next_v = hmac_sha384(Span[UInt8, ...](k), Span[UInt8, ...](v))
    _wipe_list_u8(v)
    v = next_v^

    var accepted = 0
    while True:
        next_v = hmac_sha384(Span[UInt8, ...](k), Span[UInt8, ...](v))
        _wipe_list_u8(v)
        v = next_v^
        var candidate = _from_be(Span[UInt8, ...](v))
        if not candidate.is_zero() and _cmp(candidate, _n()) < 0:
            if accepted == skip:
                _wipe_list_u8(k)
                _wipe_list_u8(v)
                _wipe_list_u8(seed)
                var hp = h1_bytes.unsafe_ptr()
                for i in range(48):
                    hp.unsafe_store[volatile=True](i, UInt8(0))
                _wipe_u384(h1)
                return candidate
            accepted += 1
        _wipe_u384(candidate)
        _wipe_list_u8(seed)
        seed.clear()
        for i in range(48):
            seed.append(v[i])
        seed.append(0)
        next_k = hmac_sha384(Span[UInt8, ...](k), Span[UInt8, ...](seed))
        _wipe_list_u8(k)
        k = next_k^
        next_v = hmac_sha384(Span[UInt8, ...](k), Span[UInt8, ...](v))
        _wipe_list_u8(v)
        v = next_v^


def p384_ecdsa_sign_digest(
    private_key: Span[UInt8, ...],
    digest: Span[UInt8, ...],
    signature: Span[mut=True, UInt8, ...],
) -> Bool:
    if (
        len(private_key) != 48 or len(digest) != 48
        or len(signature) < P384_SIGNATURE_SIZE
    ):
        return False
    var signature_ptr = signature.unsafe_ptr()
    var d = _from_be(private_key)
    if d.is_zero() or _cmp(d, _n()) >= 0:
        _wipe_u384(d)
        return False
    var z = _reduce_n(_from_be(digest))
    var retry = 0
    while True:
        var k = _rfc6979_p384(private_key, digest, retry)
        var point = _scalar_mult_base(k)
        var r = _reduce_n(point.x)
        if r.is_zero():
            _wipe_u384(k)
            retry += 1
            continue
        var rd = _n_mul(r, d)
        var total = _add_mod(z, rd, _n())
        var kinv = _n_inv(k)
        var s = _n_mul(kinv, total)
        if s.is_zero():
            _wipe_u384(k)
            _wipe_u384(kinv)
            _wipe_u384(rd)
            _wipe_u384(total)
            retry += 1
            continue
        _to_be(r, signature_ptr)
        _to_be(s, signature_ptr.unsafe_offset(48))
        _wipe_u384(d)
        _wipe_u384(z)
        _wipe_u384(k)
        _wipe_u384(kinv)
        _wipe_u384(rd)
        _wipe_u384(total)
        return True


def p384_ecdsa_sign(
    private_key: Span[UInt8, ...],
    message: Span[UInt8, ...],
    signature: Span[mut=True, UInt8, ...],
) -> Bool:
    if len(signature) < P384_SIGNATURE_SIZE:
        return False
    var digest = sha384_hash(message)
    var ok = p384_ecdsa_sign_digest(
        private_key, Span[UInt8, ...](digest), signature
    )
    _wipe_list_u8(digest)
    return ok


def _p384_add_public(a: P384Point, b: P384Point) -> P384Point:
    if a.infinity:
        return b
    if b.infinity:
        return a
    if _eq(a.x, b.x):
        if not _eq(a.y, b.y) or a.y.is_zero():
            return P384Point()
        var am = P384JacobianPoint(_to_mont(a.x), _to_mont(a.y), _one_mont(), False)
        return _jacobian_to_affine(_jacobian_double_ct(am))
    var dx = _sub_mod(b.x, a.x, _p())
    var dy = _sub_mod(b.y, a.y, _p())
    var dx_inv = _from_mont(_inv_p(_to_mont(dx)))
    var slope = _mul_mod(dy, dx_inv, _p())
    var x3 = _sub_mod(_sub_mod(_square_mod(slope, _p()), a.x, _p()), b.x, _p())
    var y3 = _sub_mod(_mul_mod(slope, _sub_mod(a.x, x3, _p()), _p()), a.y, _p())
    return P384Point(x3, y3, False)


def p384_ecdsa_verify_digest(
    public_key: Span[UInt8, ...],
    digest: Span[UInt8, ...],
    signature: Span[UInt8, ...],
) -> Bool:
    if len(digest) != 48 or len(signature) != 96:
        return False
    var q = p384_decode_uncompressed(public_key)
    if q.infinity:
        return False
    var r = _from_be(signature[0:48])
    var s = _from_be(signature[48:96])
    if r.is_zero() or s.is_zero() or _cmp(r, _n()) >= 0 or _cmp(s, _n()) >= 0:
        return False
    var z = _reduce_n(_from_be(digest))
    var w = _n_inv(s)
    var u1 = _n_mul(z, w)
    var u2 = _n_mul(r, w)
    var point = _p384_add_public(_scalar_mult_base(u1), _scalar_mult(u2, q))
    if point.infinity:
        return False
    return _eq(_reduce_n(point.x), r)


def p384_ecdsa_verify(
    public_key: Span[UInt8, ...],
    message: Span[UInt8, ...],
    signature: Span[UInt8, ...],
) -> Bool:
    var digest = sha384_hash(message)
    return p384_ecdsa_verify_digest(public_key, Span[UInt8, ...](digest), signature)


def p384_ecdsa_sign_der(
    private_key: Span[UInt8, ...], message: Span[UInt8, ...]
) raises -> List[UInt8]:
    from .ecdsa_der import ecdsa_der_encode
    var raw = List[UInt8](unsafe_uninit_length=P384_SIGNATURE_SIZE)
    if not p384_ecdsa_sign(
        private_key, message, Span[mut=True, UInt8, ...](raw)
    ):
        raise Error("P-384 ECDSA signing failed")
    return ecdsa_der_encode(Span[UInt8, ...](raw), P384_SIZE)


def p384_ecdsa_verify_der(
    public_key: Span[UInt8, ...], message: Span[UInt8, ...],
    signature: Span[UInt8, ...],
) -> Bool:
    from .ecdsa_der import ecdsa_der_decode
    var raw = ecdsa_der_decode(signature, P384_SIZE)
    if len(raw) != P384_SIGNATURE_SIZE:
        return False
    return p384_ecdsa_verify(public_key, message, Span[UInt8, ...](raw))


def p384_keygen() raises -> Tuple[List[UInt8], List[UInt8]]:
    from .random import random_bytes
    while True:
        var private_key = random_bytes(48)
        var d = _from_be(Span[UInt8, ...](private_key))
        if not d.is_zero() and _cmp(d, _n()) < 0:
            var public_key = List[UInt8](unsafe_uninit_length=97)
            if p384_public_key(
                Span[UInt8, ...](private_key),
                Span[mut=True, UInt8, ...](public_key),
            ):
                _wipe_u384(d)
                return (private_key^, public_key^)
        _wipe_u384(d)
        _wipe_list_u8(private_key)
