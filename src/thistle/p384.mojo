"""
NIST P-384 / secp384r1 implementation.
"""

from .p384_table import p384_base_table

comptime P384_SIZE = 48
comptime P384_POINT_SIZE = 97
comptime _MASK64 = UInt128(0xFFFFFFFFFFFFFFFF)
comptime _N0 = UInt64(0x0000000100000001)  # -p^-1 mod 2^64


struct U384(Copyable, ImplicitlyCopyable, Movable):
    var limbs: InlineArray[UInt64, 6]

    def __init__(out self):
        self.limbs = InlineArray[UInt64, 6](fill=0)

    def __init__(
        out self,
        l0: UInt64,
        l1: UInt64,
        l2: UInt64,
        l3: UInt64,
        l4: UInt64,
        l5: UInt64,
    ):
        self.limbs = InlineArray[UInt64, 6](uninitialized=True)
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
def _add_small_mod(a: U384, small: UInt64, m: U384) -> U384:
    var b = U384(small, 0, 0, 0, 0, 0)
    return _add_mod(a, b, m)


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


def _to_be(x: U384, output: UnsafePointer[UInt8, MutAnyOrigin]):
    for i in range(6):
        var limb = x.limbs[5 - i]
        for k in range(8):
            output[i * 8 + k] = UInt8((limb >> UInt64(56 - 8 * k)) & 0xFF)


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
        return P384JacobianPoint(
            _to_mont(point.x), _to_mont(point.y), _one_mont(), False
        )


@always_inline
def _select_u384(a: U384, b: U384, choice: UInt64) -> U384:
    var mask = UInt64(0) - choice
    var out = U384()
    comptime for i in range(6):
        out.limbs[i] = a.limbs[i] ^ (mask & (a.limbs[i] ^ b.limbs[i]))
    return out


@always_inline
def _select_jacobian(
    a: P384JacobianPoint, b: P384JacobianPoint, choice: UInt64
) -> P384JacobianPoint:
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
    comptime for i in range(6):
        acc |= x.limbs[i]
    return _u64_zero_choice(acc)


@always_inline
def _jacobian_infinity() -> P384JacobianPoint:
    # Infinity Z = 0.
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
    # Jacobian doubling a = -3.
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
def _jacobian_add_affine_ct(
    p: P384JacobianPoint, q: P384Point
) -> P384JacobianPoint:
    # H is nonzero for fixed-window inputs.
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
        jac[i] = _jacobian_add_affine_ct(jac[i - 1], pm)

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
            var hit = _u64_zero_choice(UInt64(i + 1) ^ d)
            qx = _select_u384(qx, tx[i], hit)
            qy = _select_u384(qy, ty[i], hit)

        var added = _jacobian_add_affine_ct(acc, P384Point(qx, qy, False))
        acc = _select_jacobian_ct(acc, added, _u64_nonzero_choice(d))
    return _jacobian_to_affine(acc)


def _scalar_mult_generator(k: U384) -> P384Point:
    var tx = InlineArray[U384, 15](uninitialized=True)
    var ty = InlineArray[U384, 15](uninitialized=True)
    tx[0] = U384(
        0x3DD0756649C0B528,
        0x20E378E2A0D6CE38,
        0x879C3AFC541B4D6E,
        0x6454868459A30EFF,
        0x812FF723614EDE2B,
        0x4D3AADC2299E1513,
    )
    tx[1] = U384(
        0xC8229E55783DDE91,
        0x8E6C8F2E022B53F0,
        0x3504E6F0FF9D48A1,
        0xDA821495F0687F50,
        0x9C90A4FD2DE4B506,
        0xDB93B776427460C3,
    )
    tx[2] = U384(
        0x05E4DBE6C1DC4073,
        0xC54EA9FFF04F779C,
        0x6B2034E9A170CCF0,
        0x3A48D732D51C6C3E,
        0xE36F7E2D263AA470,
        0xD283FE68E7C1C3AC,
    )
    tx[3] = U384(
        0x0AAE8477EBB68F2C,
        0x30594CCBEE0421E3,
        0x2E4F153B0AECAC46,
        0x078358D4736400AD,
        0xFB40F647D685D979,
        0xCFEEE6DD34179228,
    )
    tx[4] = U384(
        0xBB595EBA68F1F0DF,
        0xC185C0CBCC873466,
        0x7F1EB1B5293C703B,
        0x60DB2CF5AACC05E6,
        0xC676B987E2E8E4C6,
        0xE1BB26B11D178FFB,
    )
    tx[5] = U384(
        0x7EB5C9317D56DAD8,
        0xCB2454B339D3413A,
        0xEC52930F580D57F2,
        0x2A33F6661BDF6015,
        0x4F0F6A962B02D33B,
        0xC482E189F0430C40,
    )
    tx[6] = U384(
        0xDF13B9D17D69222B,
        0x4CE6415F874774B1,
        0x731EDCF8211FAA95,
        0x5F4215D1659753ED,
        0xF893DB589DB2DF55,
        0x932C9F811C89025B,
    )
    tx[7] = U384(
        0x23F60A05DD9BCBBA,
        0x9E336DE5AE9B587A,
        0x1C5C2E7193D7E30F,
        0x1D9AEBD64F3DDB37,
        0x1C7B5FE116B66423,
        0x5DB4F184349CD9B1,
    )
    tx[8] = U384(
        0x2F5D200E2353B92F,
        0xE35D87293FD7E4F9,
        0x26094833A96D745D,
        0xDC351DC13CBFFF3F,
        0x26D464C6DAD54D6A,
        0x5CAB1D1D53636C6A,
    )
    tx[9] = U384(
        0x845539D3C8D99C02,
        0x2A15A9A6E58D6787,
        0xE9F6368EAB225FA3,
        0x54A612D7EB32CABE,
        0xC2F646025C4845EC,
        0xA91A5280DB1C212E,
    )
    tx[10] = U384(
        0xC7708B19B68B8C7D,
        0x4532077C44377ABA,
        0x0DCC67706CDAD64F,
        0x01B8BF56147B6602,
        0xF8D89885F0561D79,
        0x9C19E9FC7BA9C437,
    )
    tx[11] = U384(
        0x3DB8477270313DE0,
        0xD4258CC55D970420,
        0x03ACED26C8EDFEE1,
        0xF67EB42235D77D83,
        0x523C40DBCF9AB45C,
        0x627B415F9C35B26D,
    )
    tx[12] = U384(
        0x9B7AEB7E75CCBDFB,
        0xB25E28C5F6749A95,
        0x8A7A8E4633B7D4AE,
        0xDB5203A8D9C1BD56,
        0xD2657265ED22DF97,
        0xB51C56E18CF23C94,
    )
    tx[13] = U384(
        0x5865E5018F75244C,
        0xD02225FB01EC909F,
        0xCA6B1AF8B1F85C2A,
        0x44CE05FF88957166,
        0x8058994C5710C0C9,
        0x46D227C432F6B1BA,
    )
    tx[14] = U384(
        0x446AD8884709F4A9,
        0x2B7210E2EC3DABD8,
        0x83CCF19550E07B34,
        0x59500917789B3075,
        0x0FC01FD4EB085993,
        0xFB62D26F4903026B,
    )
    ty[0] = U384(
        0x23043DAD4B03A4FE,
        0xA1BFA8BF7BB4A9AC,
        0x8BADE7562E83B050,
        0xC6C3521968F4FFD9,
        0xDD8002263969A840,
        0x2B78ABC25A15C5E9,
    )
    ty[1] = U384(
        0x42EA84633140BFDA,
        0xE8E8E4A8C2AACCD8,
        0x15E4F18BDC588258,
        0x09F1FE415172BAD9,
        0x070D430900B0E684,
        0xE34947F7123DF0C2,
    )
    ty[2] = U384(
        0x7E284821C04EE157,
        0x92D789A77AE0E36D,
        0x132663C04EF67446,
        0x68012D5AD2E1D0B4,
        0xF6DB68B15102B339,
        0x465465FC983292AF,
    )
    ty[3] = U384(
        0x54F3E8E79B3A03B2,
        0xE74BB7F17BFEC97E,
        0x8E3E61A34C542AD1,
        0x147162D30418C693,
        0xE607B9E33820017D,
        0x50946875303DF319,
    )
    ty[4] = U384(
        0x2B694BA07073FA21,
        0x22C16E2E72F34566,
        0x80B61B3101C35B99,
        0x4B237FAF982C0411,
        0xE6C5944024DE236D,
        0x4DB1C9D6E209E4A3,
    )
    ty[5] = U384(
        0x3F62B16EA7B08203,
        0x739AC69D5B3D4DCE,
        0x8BD4BFFCB79E33B0,
        0x93C9E5F61B546F05,
        0x586D8EDEDF21559A,
        0xC9962152AF2A9EBA,
    )
    ty[6] = U384(
        0x0996B2207706A61E,
        0x135349D5A8641C79,
        0x65AAD76F50130844,
        0x0FF37C0401FFF780,
        0xF57F238E693B0706,
        0xD90A16B6AF6C9B3E,
    )
    ty[7] = U384(
        0x0D2CFE83E6655A44,
        0x836DBB36B7E55E87,
        0x701754BF7D8686E4,
        0xE9923263A42DBBA2,
        0x7008D943C48ECF0E,
        0x3C0C6DD70D27EF61,
    )
    ty[8] = U384(
        0xF2813072B18EC0B0,
        0x3777E270D742AA2F,
        0x27F061C7033CA7C2,
        0xA6ECACCC68EAD0D8,
        0x7D9429F4EE69A754,
        0xE770633431E8F5C6,
    )
    ty[9] = U384(
        0xBB971F78E67B5FCE,
        0x03A530EB13B9E85C,
        0x592AC0BA794EABFD,
        0x81961B8CCFD7FD1D,
        0x3E03370A47A9B8AA,
        0x6EB995BEC80174E8,
    )
    ty[10] = U384(
        0x764EB146BDC4BA25,
        0x604FE46BAC144B83,
        0x3CE813298A77E780,
        0x2E070F36FE9E682E,
        0x41821D0C3A53287A,
        0x9AA62F9F3533F918,
    )
    ty[11] = U384(
        0xFACC45E48BE55ED8,
        0x80D60AF627AA651A,
        0x8C79848FD0E102AC,
        0x40C64A4E66BED5AF,
        0x0329EAB1F7942F0E,
        0x0C6E430EF9C4AF3D,
    )
    ty[12] = U384(
        0xF4D394596C3D812D,
        0xD8E88F1A87CAE0C2,
        0x789A2A48CF4D0FE3,
        0xB7FEAC2DFEC38D60,
        0x81FDBD1C3B490EC3,
        0x4617ADB7CC6979E1,
    )
    ty[13] = U384(
        0xBE4B4A9003CB68E5,
        0x540B8B82730A99D1,
        0x1ECC8585E11DBBBF,
        0x72445345D9C3B691,
        0x647D24DB13690A74,
        0x4429839DDEFBADF5,
    )
    ty[14] = U384(
        0x2309CC9D6FE989BB,
        0x61609CBD144BD586,
        0x4B23D3A0DE06610C,
        0xDDDC2866D898F470,
        0x8733FC41400C5797,
        0x5A68C6FED0BC2716,
    )

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
            var hit = _u64_zero_choice(UInt64(i + 1) ^ d)
            qx = _select_u384(qx, tx[i], hit)
            qy = _select_u384(qy, ty[i], hit)

        var added = _jacobian_add_affine_ct(acc, P384Point(qx, qy, False))
        acc = _select_jacobian_ct(acc, added, _u64_nonzero_choice(d))
    return _jacobian_to_affine(acc)


@always_inline
def _base_table_entry(
    tptr: UnsafePointer[UInt64, _], j: Int, d: UInt64
) -> P384Point:
    # constant-time scan of the 15 entries for window j
    var qx = U384()
    var qy = U384()
    for t in range(1, 16):
        var hit = _u64_zero_choice(UInt64(t) ^ d)
        var base = (j * 15 + (t - 1)) * 12
        var ex = U384(tptr[base], tptr[base + 1], tptr[base + 2], tptr[base + 3], tptr[base + 4], tptr[base + 5])
        var ey = U384(tptr[base + 6], tptr[base + 7], tptr[base + 8], tptr[base + 9], tptr[base + 10], tptr[base + 11])
        qx = _select_u384(qx, ex, hit)
        qy = _select_u384(qy, ey, hit)
    return P384Point(qx, qy, False)


def _scalar_mult_base(k: U384) -> P384Point:
    # fixed-base multiply from the precomputed d * 16^(2j) * G table:
    # odd radix-16 digits, four doublings, then even digits
    var table = p384_base_table()
    var tptr = table.unsafe_ptr()

    var acc = _jacobian_infinity()
    for i in range(1, 96, 2):
        var d = (k.limbs[i >> 4] >> UInt64(4 * (i & 15))) & UInt64(0xF)
        var q = _base_table_entry(tptr, i >> 1, d)
        var added = _jacobian_add_affine_ct(acc, q)
        acc = _select_jacobian_ct(acc, added, _u64_nonzero_choice(d))

    acc = _jacobian_double_ct(acc)
    acc = _jacobian_double_ct(acc)
    acc = _jacobian_double_ct(acc)
    acc = _jacobian_double_ct(acc)

    for i in range(0, 96, 2):
        var d = (k.limbs[i >> 4] >> UInt64(4 * (i & 15))) & UInt64(0xF)
        var q = _base_table_entry(tptr, i >> 1, d)
        var added = _jacobian_add_affine_ct(acc, q)
        acc = _select_jacobian_ct(acc, added, _u64_nonzero_choice(d))

    return _jacobian_to_affine(acc)


def p384_decode_uncompressed(point: Span[UInt8, ...]) -> P384Point:
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
    if point.infinity or not _is_on_curve(point):
        return False
    output[0] = 0x04
    _to_be(point.x, output + 1)
    _to_be(point.y, output + 49)
    return True


@no_inline
def p384_public_key(
    private_key: Span[UInt8, ...], output: UnsafePointer[UInt8, MutAnyOrigin]
) -> Bool:
    if len(private_key) != 48:
        return False
    var d = _from_be(private_key)
    if d.is_zero() or _cmp(d, _n()) >= 0:
        return False
    var q = _scalar_mult_base(d)
    return p384_encode_uncompressed(q, output)


@no_inline
def p384_ecdh(
    private_key: Span[UInt8, ...],
    public_key: Span[UInt8, ...],
    output: UnsafePointer[UInt8, MutAnyOrigin],
) -> Bool:
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
