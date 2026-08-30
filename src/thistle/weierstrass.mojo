"""
Generic Weierstrass limb operations for P-256 (N=4) and P-384 (N=6).
"""

from std.utils import StaticTuple
from std.memory import Pointer
from std.os import abort
from .utils import u64_nonzero_choice, u64_zero_choice, volatile_wipe
from .pbkdf2 import hmac_sha256, hmac_sha384


comptime _MASK64 = UInt128(0xFFFFFFFFFFFFFFFF)


struct Limbs[N: Int](Copyable, ImplicitlyCopyable, Movable):
    var limbs: StaticTuple[UInt64, Self.N]

    def __init__(out self):
        self.limbs = StaticTuple[UInt64, Self.N]()
        comptime for i in range(Self.N):
            self.limbs[i] = 0

    def __init__(out self, limbs: StaticTuple[UInt64, Self.N]):
        self.limbs = limbs

    def __init__(out self, l0: UInt64, l1: UInt64, l2: UInt64, l3: UInt64) where Self.N == 4:
        self.limbs = StaticTuple[UInt64, Self.N]()
        comptime for i in range(Self.N):
            self.limbs[i] = 0
        self.limbs[0] = l0
        self.limbs[1] = l1
        self.limbs[2] = l2
        self.limbs[3] = l3

    def __init__(out self, l0: UInt64, l1: UInt64, l2: UInt64, l3: UInt64, l4: UInt64, l5: UInt64
    ) where Self.N == 6:
        self.limbs = StaticTuple[UInt64, Self.N]()
        comptime for i in range(Self.N):
            self.limbs[i] = 0
        self.limbs[0] = l0
        self.limbs[1] = l1
        self.limbs[2] = l2
        self.limbs[3] = l3
        self.limbs[4] = l4
        self.limbs[5] = l5

    @staticmethod
    def zero() -> Self:
        return Self()

    @staticmethod
    def one() -> Self where Self.N > 0:
        var r = Self.zero()
        r.limbs[0] = 1
        return r

    def is_zero(self) -> Bool:
        for i in range(Self.N):
            if self.limbs[i] != 0:
                return False
        return True

    def bit(self, i: Int) -> UInt64:
        return (self.limbs[i // 64] >> UInt64(i % 64)) & 1


comptime U256 = Limbs[4]
comptime U384 = Limbs[6]


@always_inline
def cmp[N: Int](a: Limbs[N], b: Limbs[N]) -> Int:
    comptime for j in range(N):
        var i = N - 1 - j
        if a.limbs[i] > b.limbs[i]:
            return 1
        if a.limbs[i] < b.limbs[i]:
            return -1
    return 0


@always_inline
def eq[N: Int](a: Limbs[N], b: Limbs[N]) -> Bool:
    return cmp(a, b) == 0


@always_inline
def sub_raw[N: Int](a: Limbs[N], b: Limbs[N]) -> Tuple[Limbs[N], UInt64]:
    var out = Limbs[N].zero()
    var borrow: UInt64 = 0
    comptime for i in range(N):
        var d = UInt128(a.limbs[i]) - UInt128(b.limbs[i]) - UInt128(borrow)
        out.limbs[i] = UInt64(d & _MASK64)
        borrow = UInt64((d >> UInt128(64)) & UInt128(1))
    return out, borrow


@always_inline
def add_raw[N: Int](a: Limbs[N], b: Limbs[N]) -> Tuple[Limbs[N], UInt64]:
    var out = Limbs[N].zero()
    var carry: UInt64 = 0
    comptime for i in range(N):
        var s = UInt128(a.limbs[i]) + UInt128(b.limbs[i]) + UInt128(carry)
        out.limbs[i] = UInt64(s & _MASK64)
        carry = UInt64(s >> UInt128(64))
    return out, carry


@always_inline
def select[N: Int](a: Limbs[N], b: Limbs[N], choice: UInt64) -> Limbs[N]:
    var mask = UInt64(0) - choice
    var out = Limbs[N].zero()
    comptime for i in range(N):
        out.limbs[i] = a.limbs[i] ^ (mask & (a.limbs[i] ^ b.limbs[i]))
    return out


@always_inline
def zero_choice[N: Int](x: Limbs[N]) -> UInt64:
    var acc: UInt64 = 0
    comptime for i in range(N):
        acc |= x.limbs[i]
    return u64_zero_choice(acc)


@always_inline
def add_mod[N: Int](a: Limbs[N], b: Limbs[N], m: Limbs[N]) -> Limbs[N]:
    var sum, carry = add_raw(a, b)
    var d, borrow = sub_raw(sum, m)
    var take = (carry | (borrow ^ UInt64(1))) & UInt64(1)
    return select(sum, d, take)


@always_inline
def sub_mod[N: Int](a: Limbs[N], b: Limbs[N], m: Limbs[N]) -> Limbs[N]:
    var diff, borrow = sub_raw(a, b)
    var diff2, _ = add_raw(diff, m)
    return select(diff, diff2, borrow)


@always_inline
def from_be[N: Int](bytes: Span[UInt8, ...]) -> Limbs[N]:
    var out = Limbs[N].zero()
    comptime for i in range(N):
        var off = N * 8 - 8 - i * 8
        var v: UInt64 = 0
        for k in range(8):
            v = (v << 8) | UInt64(bytes[off + k])
        out.limbs[i] = v
    return out


@always_inline
def to_be[N: Int](x: Limbs[N], output: Pointer[mut=True, UInt8, _, address_space=_]):
    comptime for i in range(N):
        var limb = x.limbs[N - 1 - i]
        for k in range(8):
            output[unsafe_offset=i * 8 + k] = UInt8((limb >> UInt64(56 - 8 * k)) & 0xFF)


struct Point[N: Int](Copyable, ImplicitlyCopyable, Movable):
    var x: Limbs[Self.N]
    var y: Limbs[Self.N]
    var infinity: Bool

    def __init__(out self):
        self.x = Limbs[Self.N].zero()
        self.y = Limbs[Self.N].zero()
        self.infinity = True

    def __init__(out self, x: Limbs[Self.N], y: Limbs[Self.N], infinity: Bool):
        self.x = x
        self.y = y
        self.infinity = infinity


struct JacobianPoint[N: Int](Copyable, ImplicitlyCopyable, Movable):
    var x: Limbs[Self.N]
    var y: Limbs[Self.N]
    var z: Limbs[Self.N]
    var infinity: Bool

    def __init__(out self):
        self.x = Limbs[Self.N].zero()
        self.y = Limbs[Self.N].zero()
        self.z = Limbs[Self.N].zero()
        self.infinity = True

    def __init__(out self, x: Limbs[Self.N], y: Limbs[Self.N], z: Limbs[Self.N], infinity: Bool
    ):
        self.x = x
        self.y = y
        self.z = z
        self.infinity = infinity


@always_inline
def _p256_final_sub(
    acc0: UInt64,
    acc1: UInt64,
    acc2: UInt64,
    acc3: UInt64,
    acc4: UInt64,
    p: Limbs[4]
) -> Limbs[4]:
    var out = Limbs[4](acc0, acc1, acc2, acc3)
    var d, borrow = sub_raw(out, p)
    var take_d = (acc4 | (borrow ^ UInt64(1))) & UInt64(1)
    return select(out, d, take_d)


@always_inline
def _p256_mont_mul(a: Limbs[4], b: Limbs[4], p: Limbs[4]) -> Limbs[4]:
    """P-256 field Montgomery multiply specialized for its sparse prime."""
    # For P-256, -p^-1 mod 2^64 is 1 and multiplication by each
    # reduction digit folds into shifts and adds.  Keeping this path avoids a
    # measurable regression from the generic CIOS multiplier.
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

    return _p256_final_sub(acc0, acc1, acc2, acc3, acc4, p)


@always_inline
def _p256_mont_sqr(a: Limbs[4], p: Limbs[4]) -> Limbs[4]:
    """P-256 field Montgomery square using symmetry in the product."""
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
    s = (p30 & _MASK64)
        + (p20 >> UInt128(64))
        + (p21 & _MASK64)
        + (s >> UInt128(64))
    var acc3 = UInt64(s & _MASK64)
    s = (p30 >> UInt128(64))
        + (p21 >> UInt128(64))
        + (p31 & _MASK64)
        + (s >> UInt128(64))
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

    return _p256_final_sub(acc0, acc1, acc2, acc3, acc4, p)


@always_inline
def mont_mul[N: Int, N0: UInt64](a: Limbs[N], b: Limbs[N], p: Limbs[N]) -> Limbs[N]:
    comptime if N == 4 and N0 == UInt64(1):
        var a4 = Limbs[4](
            a.limbs[0], a.limbs[1], a.limbs[2], a.limbs[3]
        )
        var b4 = Limbs[4](
            b.limbs[0], b.limbs[1], b.limbs[2], b.limbs[3]
        )
        var p4 = Limbs[4](
            p.limbs[0], p.limbs[1], p.limbs[2], p.limbs[3]
        )
        var fast = _p256_mont_mul(a4, b4, p4)
        var out = Limbs[N].zero()
        comptime for i in range(4):
            out.limbs[i] = fast.limbs[i]
        return out
    var acc = InlineArray[UInt64, 16](fill=0)
    comptime for i in range(N):
        var bi = b.limbs[i]
        var carry: UInt64 = 0
        comptime for j in range(N):
            var t = UInt128(a.limbs[j]) * UInt128(bi) + UInt128(acc[j]) + UInt128(carry)
            acc[j] = UInt64(t & _MASK64)
            carry = UInt64(t >> UInt128(64))
        var s = UInt128(acc[N]) + UInt128(carry)
        acc[N] = UInt64(s & _MASK64)
        acc[N+1] += UInt64(s >> UInt128(64))
        var m = acc[0] * N0
        var t0 = UInt128(acc[0]) + UInt128(m) * UInt128(p.limbs[0])
        var c = UInt64(t0 >> UInt128(64))
        comptime for j in range(1, N):
            var t = UInt128(m) * UInt128(p.limbs[j]) + UInt128(acc[j]) + UInt128(c)
            acc[j-1] = UInt64(t & _MASK64)
            c = UInt64(t >> UInt128(64))
        s = UInt128(acc[N]) + UInt128(c)
        acc[N-1] = UInt64(s & _MASK64)
        acc[N] = acc[N+1] + UInt64(s >> UInt128(64))
        acc[N+1] = 0
    var out = Limbs[N].zero()
    comptime for i in range(N):
        out.limbs[i] = acc[i]
    var d, borrow = sub_raw(out, p)
    var take = (acc[N] | (borrow ^ UInt64(1))) & UInt64(1)
    return select(out, d, take)


@always_inline
def to_mont[N: Int, N0: UInt64](x: Limbs[N], rr: Limbs[N], p: Limbs[N]) -> Limbs[N]:
    return mont_mul[N, N0](x, rr, p)


@always_inline
def from_mont[N: Int, N0: UInt64](x: Limbs[N], p: Limbs[N]) -> Limbs[N]:
    var one = Limbs[N].zero()
    one.limbs[0] = 1
    return mont_mul[N, N0](x, one, p)


@always_inline
def mul_mod[N: Int, N0: UInt64](a: Limbs[N], b: Limbs[N], p: Limbs[N], rr: Limbs[N]) -> Limbs[N]:
    return mont_mul[N, N0](to_mont[N, N0](a, rr, p), b, p)


@always_inline
def square_mod[N: Int, N0: UInt64](a: Limbs[N], p: Limbs[N], rr: Limbs[N]) -> Limbs[N]:
    return mul_mod[N, N0](a, a, p, rr)


@always_inline
def mont_sqr[N: Int, N0: UInt64](a: Limbs[N], p: Limbs[N]) -> Limbs[N]:
    comptime if N == 4 and N0 == UInt64(1):
        var a4 = Limbs[4](
            a.limbs[0], a.limbs[1], a.limbs[2], a.limbs[3]
        )
        var p4 = Limbs[4](
            p.limbs[0], p.limbs[1], p.limbs[2], p.limbs[3]
        )
        var fast = _p256_mont_sqr(a4, p4)
        var out = Limbs[N].zero()
        comptime for i in range(4):
            out.limbs[i] = fast.limbs[i]
        return out
    return mont_mul[N, N0](a, a, p)


@always_inline
def is_on_curve[N: Int, N0: UInt64](point: Point[N], p: Limbs[N], a_coeff: Limbs[N], b_coeff: Limbs[N], rr: Limbs[N]) -> Bool:
    if point.infinity:
        return False
    if cmp(point.x, p) >= 0 or cmp(point.y, p) >= 0:
        return False
    var yy = square_mod[N, N0](point.y, p, rr)
    var xx = square_mod[N, N0](point.x, p, rr)
    var xxx = mul_mod[N, N0](xx, point.x, p, rr)
    var ax = mul_mod[N, N0](a_coeff, point.x, p, rr)
    var rhs = add_mod(add_mod(xxx, ax, p), b_coeff, p)
    return eq(yy, rhs)


@always_inline
def mul_small_mod[N: Int](x: Limbs[N], c: UInt64, p: Limbs[N]) -> Limbs[N]:
    if c == 2:
        return add_mod(x, x, p)
    if c == 3:
        return add_mod(add_mod(x, x, p), x, p)
    if c == 4:
        var x2 = add_mod(x, x, p)
        return add_mod(x2, x2, p)
    if c == 8:
        var x2 = add_mod(x, x, p)
        var x4 = add_mod(x2, x2, p)
        return add_mod(x4, x4, p)
    var out = Limbs[N].zero()
    for _ in range(Int(c)):
        out = add_mod(out, x, p)
    return out


@always_inline
def jacobian_double_ct[N: Int, N0: UInt64](p: JacobianPoint[N], mod: Limbs[N], rr: Limbs[N]) -> JacobianPoint[N]:
    var delta = mont_sqr[N, N0](p.z, mod)
    var gamma = mont_sqr[N, N0](p.y, mod)
    var beta = mont_mul[N, N0](p.x, gamma, mod)
    var alpha = mul_small_mod(mont_mul[N, N0](sub_mod(p.x, delta, mod), add_mod(p.x, delta, mod), mod), 3, mod)
    var x3 = sub_mod(mont_sqr[N, N0](alpha, mod), mul_small_mod(beta, 8, mod), mod)
    var z3 = sub_mod(sub_mod(mont_sqr[N, N0](add_mod(p.y, p.z, mod), mod), gamma, mod), delta, mod)
    var y3 = sub_mod(mont_mul[N, N0](alpha, sub_mod(mul_small_mod(beta, 4, mod), x3, mod), mod), mul_small_mod(mont_sqr[N, N0](gamma, mod), 8, mod), mod)
    return JacobianPoint[N](x3, y3, z3, False)


@always_inline
def select_jacobian_ct[N: Int](a: JacobianPoint[N], b: JacobianPoint[N], choice: UInt64) -> JacobianPoint[N]:
    return JacobianPoint[N](select(a.x, b.x, choice), select(a.y, b.y, choice), select(a.z, b.z, choice), False)


@always_inline
def pow_mod[N: Int, N0: UInt64](base_in: Limbs[N], exponent: Limbs[N], rr: Limbs[N], p: Limbs[N]) -> Limbs[N]:
    """Modular exponentiation. Exponent must be public.

    Branches on exponent.bit(i) and is not constant-time. The only caller
    today is _sqrt_p via the public _sqrt_exp() constant. For secret
    exponents use mod_inv_ct (constant-time select()).
    """
    var one = Limbs[N].zero()
    one.limbs[0] = 1
    var res = to_mont[N, N0](one, rr, p)
    var base = to_mont[N, N0](base_in, rr, p)
    for i in range(N * 64):
        if exponent.bit(i) != 0:
            res = mont_mul[N, N0](res, base, p)
        base = mont_sqr[N, N0](base, p)
    return from_mont[N, N0](res, p)


@always_inline
def sqn[N: Int, N0: UInt64](x: Limbs[N], n: Int, p: Limbs[N]) -> Limbs[N]:
    var r = x
    for _ in range(n):
        r = mont_sqr[N, N0](r, p)
    return r


@always_inline
def inv_p[N: Int, N0: UInt64](x: Limbs[N], p: Limbs[N], rr: Limbs[N]) -> Limbs[N]:
    # Fermat x^(p-2) with curve-specific addition chain selected by N.
    # N==4 -> P-256, N==6 -> P-384, keeps optimized chain vs generic pow.
    var x2 = mont_mul[N, N0](mont_sqr[N, N0](x, p), x, p)
    var x3 = mont_mul[N, N0](mont_sqr[N, N0](x2, p), x, p)
    var x6 = mont_mul[N, N0](sqn[N, N0](x3, 3, p), x3, p)
    var x12 = mont_mul[N, N0](sqn[N, N0](x6, 6, p), x6, p)
    var x15 = mont_mul[N, N0](sqn[N, N0](x12, 3, p), x3, p)
    var x30 = mont_mul[N, N0](sqn[N, N0](x15, 15, p), x15, p)
    var x32 = mont_mul[N, N0](sqn[N, N0](x30, 2, p), x2, p)
    if N == 4:
        var t = mont_mul[N, N0](sqn[N, N0](x32, 32, p), x, p)
        t = sqn[N, N0](t, 96, p)
        t = mont_mul[N, N0](sqn[N, N0](t, 32, p), x32, p)
        t = mont_mul[N, N0](sqn[N, N0](t, 32, p), x32, p)
        t = mont_mul[N, N0](sqn[N, N0](t, 30, p), x30, p)
        t = mont_mul[N, N0](sqn[N, N0](t, 2, p), x, p)
        return t
    else:
        var x60 = mont_mul[N, N0](sqn[N, N0](x30, 30, p), x30, p)
        var x120 = mont_mul[N, N0](sqn[N, N0](x60, 60, p), x60, p)
        var x240 = mont_mul[N, N0](sqn[N, N0](x120, 120, p), x120, p)
        var x255 = mont_mul[N, N0](sqn[N, N0](x240, 15, p), x15, p)
        var t2 = sqn[N, N0](x255, 1, p)
        t2 = mont_mul[N, N0](sqn[N, N0](t2, 32, p), x32, p)
        t2 = sqn[N, N0](t2, 64, p)
        t2 = mont_mul[N, N0](sqn[N, N0](t2, 30, p), x30, p)
        t2 = mont_mul[N, N0](sqn[N, N0](t2, 2, p), x, p)
        return t2


@always_inline
def jacobian_to_affine[N: Int, N0: UInt64](p: JacobianPoint[N], mod: Limbs[N], rr: Limbs[N]) -> Point[N]:
    if p.infinity or zero_choice(p.z) == UInt64(1):
        return Point[N]()
    var zinv = inv_p[N, N0](p.z, mod, rr)
    var zinv2 = mont_sqr[N, N0](zinv, mod)
    var zinv3 = mont_mul[N, N0](zinv2, zinv, mod)
    return Point[N](from_mont[N, N0](mont_mul[N, N0](p.x, zinv2, mod), mod), from_mont[N, N0](mont_mul[N, N0](p.y, zinv3, mod), mod), False)


@always_inline
def jacobian_infinity[N: Int](one_mont: Limbs[N]) -> JacobianPoint[N]:
    return JacobianPoint[N](Limbs[N].zero(), one_mont, Limbs[N].zero(), False)


@always_inline
def scalar_mult[N: Int, N0: UInt64](k: Limbs[N], p: Point[N], mod: Limbs[N], rr: Limbs[N], one_mont: Limbs[N]) -> Point[N]:
    var pm = Point[N](to_mont[N, N0](p.x, rr, mod), to_mont[N, N0](p.y, rr, mod), False)
    var jac = InlineArray[JacobianPoint[N], 15](fill=JacobianPoint[N]())
    jac[0] = JacobianPoint[N](pm.x, pm.y, one_mont, False)
    jac[1] = jacobian_double_ct[N, N0](jac[0], mod, rr)
    for i in range(2, 15):
        jac[i] = jacobian_add_affine_non_equal_ct[N, N0](jac[i - 1], pm, mod, rr, one_mont)
    var prefix = InlineArray[Limbs[N], 15](fill=Limbs[N].zero())
    prefix[0] = jac[0].z
    for i in range(1, 15):
        prefix[i] = mont_mul[N, N0](prefix[i - 1], jac[i].z, mod)
    var inv_acc = inv_p[N, N0](prefix[14], mod, rr)
    var tx = InlineArray[Limbs[N], 15](fill=Limbs[N].zero())
    var ty = InlineArray[Limbs[N], 15](fill=Limbs[N].zero())
    for jj in range(15):
        var j = 14 - jj
        var zinv = inv_acc
        if j > 0:
            zinv = mont_mul[N, N0](inv_acc, prefix[j - 1], mod)
            inv_acc = mont_mul[N, N0](inv_acc, jac[j].z, mod)
        var zinv2 = mont_sqr[N, N0](zinv, mod)
        tx[j] = mont_mul[N, N0](jac[j].x, zinv2, mod)
        ty[j] = mont_mul[N, N0](jac[j].y, mont_mul[N, N0](zinv2, zinv, mod), mod)
    var acc = jacobian_infinity(one_mont)
    for w in range(N * 16 - 1, -1, -1):
        if w != N * 16 - 1:
            acc = jacobian_double_ct[N, N0](acc, mod, rr)
            acc = jacobian_double_ct[N, N0](acc, mod, rr)
            acc = jacobian_double_ct[N, N0](acc, mod, rr)
            acc = jacobian_double_ct[N, N0](acc, mod, rr)
        var d = (k.limbs[w >> 4] >> UInt64(4 * (w & 15))) & UInt64(0xF)
        var qx = tx[0]
        var qy = ty[0]
        for i in range(1, 15):
            var hit = u64_zero_choice(UInt64(i + 1) ^ d)
            qx = select(qx, tx[i], hit)
            qy = select(qy, ty[i], hit)
        var added = jacobian_add_affine_non_equal_ct[N, N0](acc, Point[N](qx, qy, False), mod, rr, one_mont)
        acc = select_jacobian_ct(acc, added, u64_nonzero_choice(d))
    return jacobian_to_affine[N, N0](acc, mod, rr)


@always_inline
def mod_inv_ct[N: Int, N0: UInt64](x: Limbs[N], m: Limbs[N], rr: Limbs[N], m_minus2: Limbs[N], one_mont: Limbs[N]) -> Limbs[N]:
    # Fixed-window exponentiation for x^(m-2).
    var base = to_mont[N, N0](x, rr, m)
    var powers = InlineArray[Limbs[N], 16](fill=Limbs[N].zero())
    powers[0] = one_mont
    powers[1] = base
    for i in range(2, 16):
        powers[i] = mont_mul[N, N0](powers[i - 1], base, m)

    var res = one_mont
    for nibble_idx in range(N * 16 - 1, -1, -1):
        comptime for _ in range(4):
            res = mont_sqr[N, N0](res, m)
        var limb_idx = nibble_idx >> 4
        var shift = UInt64((nibble_idx & 15) * 4)
        var digit = Int((m_minus2.limbs[limb_idx] >> shift) & UInt64(0xF))
        res = mont_mul[N, N0](res, powers[digit], m)
    return from_mont[N, N0](res, m)


@always_inline
def reduce_mod[N: Int](x: Limbs[N], m: Limbs[N]) -> Limbs[N]:
    var reduced, borrow = sub_raw(x, m)
    return select(reduced, x, borrow)


@always_inline
def point_add[N: Int, N0: UInt64](a: Point[N], b: Point[N], mod: Limbs[N], rr: Limbs[N], one_mont: Limbs[N]) -> Point[N]:
    if a.infinity:
        return b
    if b.infinity:
        return a
    if eq(a.x, b.x):
        if not eq(a.y, b.y) or zero_choice(a.y) == UInt64(1):
            return Point[N]()
        var am = JacobianPoint[N](to_mont[N, N0](a.x, rr, mod), to_mont[N, N0](a.y, rr, mod), one_mont, False)
        return jacobian_to_affine[N, N0](jacobian_double_ct[N, N0](am, mod, rr), mod, rr)
    var dx = sub_mod(b.x, a.x, mod)
    var dy = sub_mod(b.y, a.y, mod)
    var dx_inv = from_mont[N, N0](inv_p[N, N0](to_mont[N, N0](dx, rr, mod), mod, rr), mod)
    var slope = mul_mod[N, N0](dy, dx_inv, mod, rr)
    var x3 = sub_mod(sub_mod(square_mod[N, N0](slope, mod, rr), a.x, mod), b.x, mod)
    var y3 = sub_mod(mul_mod[N, N0](slope, sub_mod(a.x, x3, mod), mod, rr), a.y, mod)
    return Point[N](x3, y3, False)


@always_inline
def base_table_entry[N: Int](tptr: Pointer[UInt64, _], j: Int, d: UInt64) -> Point[N]:
    var qx = Limbs[N].zero()
    var qy = Limbs[N].zero()
    for t in range(1, 16):
        var h = u64_zero_choice(UInt64(t) ^ d)
        var base = (j * 15 + (t - 1)) * N * 2
        var ex = Limbs[N].zero()
        var ey = Limbs[N].zero()
        for i in range(N):
            ex.limbs[i] = tptr[unsafe_offset=base + i]
            ey.limbs[i] = tptr[unsafe_offset=base + N + i]
        qx = select(qx, ex, h)
        qy = select(qy, ey, h)
    return Point[N](qx, qy, False)


@always_inline
def scalar_mult_base[N: Int, N0: UInt64](tptr: Pointer[UInt64, _], k: Limbs[N], mod: Limbs[N], rr: Limbs[N], one_mont: Limbs[N]
) -> Point[N]:
    var acc = jacobian_infinity(one_mont)
    for i in range(1, N * 16, 2):
        var d = (k.limbs[i >> 4] >> UInt64(4 * (i & 15))) & UInt64(0xF)
        var q = base_table_entry[N](tptr, i >> 1, d)
        var added = jacobian_add_affine_non_equal_ct[N, N0](acc, q, mod, rr, one_mont)
        acc = select_jacobian_ct(acc, added, u64_nonzero_choice(d))
    acc = jacobian_double_ct[N, N0](acc, mod, rr)
    acc = jacobian_double_ct[N, N0](acc, mod, rr)
    acc = jacobian_double_ct[N, N0](acc, mod, rr)
    acc = jacobian_double_ct[N, N0](acc, mod, rr)
    for i in range(0, N * 16, 2):
        var d = (k.limbs[i >> 4] >> UInt64(4 * (i & 15))) & UInt64(0xF)
        var q = base_table_entry[N](tptr, i >> 1, d)
        var added = jacobian_add_affine_non_equal_ct[N, N0](acc, q, mod, rr, one_mont)
        acc = select_jacobian_ct(acc, added, u64_nonzero_choice(d))
    return jacobian_to_affine[N, N0](acc, mod, rr)


@always_inline
def _hmac[N: Int](key: Span[UInt8, ...], data: Span[UInt8, ...]) -> List[UInt8]:
    if N == 4:
        return hmac_sha256(key, data)
    else:
        return hmac_sha384(key, data)


def rfc6979[N: Int](private_key: Span[UInt8, ...], digest: Span[UInt8, ...], skip: Int, n: Limbs[N]) -> Limbs[N]:
    if len(private_key) != N * 8 or len(digest) != N * 8:
        abort("RFC 6979 inputs must match the curve scalar size")
    if skip < 0:
        abort("RFC 6979 skip count cannot be negative")
    var h1 = reduce_mod(from_be[N](digest), n)
    var h1_bytes = InlineArray[UInt8, N * 8](fill=0)
    to_be(h1, h1_bytes.unsafe_ptr())
    var k = List[UInt8](length=N * 8, fill=0)
    var v = List[UInt8](length=N * 8, fill=1)
    var seed = List[UInt8](capacity=N * 8 * 3 + 1)
    for i in range(N * 8):
        seed.append(v[i])
    seed.append(0)
    for i in range(N * 8):
        seed.append(private_key[i])
    for i in range(N * 8):
        seed.append(h1_bytes[i])
    var next_k: List[UInt8]
    var next_v: List[UInt8]
    next_k = _hmac[N](Span[UInt8, ...](k), Span[UInt8, ...](seed))
    volatile_wipe(k.unsafe_ptr(), len(k))
    k = next_k^
    next_v = _hmac[N](Span[UInt8, ...](k), Span[UInt8, ...](v))
    volatile_wipe(v.unsafe_ptr(), len(v))
    v = next_v^
    volatile_wipe(seed.unsafe_ptr(), len(seed))
    seed.clear()
    for i in range(N * 8):
        seed.append(v[i])
    seed.append(1)
    for i in range(N * 8):
        seed.append(private_key[i])
    for i in range(N * 8):
        seed.append(h1_bytes[i])
    next_k = _hmac[N](Span[UInt8, ...](k), Span[UInt8, ...](seed))
    volatile_wipe(k.unsafe_ptr(), len(k))
    k = next_k^
    next_v = _hmac[N](Span[UInt8, ...](k), Span[UInt8, ...](v))
    volatile_wipe(v.unsafe_ptr(), len(v))
    v = next_v^
    var accepted = 0
    while True:
        next_v = _hmac[N](Span[UInt8, ...](k), Span[UInt8, ...](v))
        volatile_wipe(v.unsafe_ptr(), len(v))
        v = next_v^
        var candidate = from_be[N](Span[UInt8, ...](v))
        if not candidate.is_zero() and cmp(candidate, n) < 0:
            if accepted == skip:
                volatile_wipe(k.unsafe_ptr(), len(k))
                volatile_wipe(v.unsafe_ptr(), len(v))
                volatile_wipe(seed.unsafe_ptr(), len(seed))
                var hp = h1_bytes.unsafe_ptr()
                for i in range(N * 8):
                    hp.unsafe_store[volatile=True](i, UInt8(0))
                # wipe h1
                var h_ptr = Pointer(to=h1).unsafe_bitcast[UInt64]()
                for i in range(N):
                    h_ptr.unsafe_store[volatile=True](i, UInt64(0))
                return candidate^
            accepted += 1
        # wipe candidate
        var c_ptr = Pointer(to=candidate).unsafe_bitcast[UInt64]()
        for i in range(N):
            c_ptr.unsafe_store[volatile=True](i, UInt64(0))
        volatile_wipe(seed.unsafe_ptr(), len(seed))
        seed.clear()
        for i in range(N * 8):
            seed.append(v[i])
        seed.append(0)
        next_k = _hmac[N](Span[UInt8, ...](k), Span[UInt8, ...](seed))
        volatile_wipe(k.unsafe_ptr(), len(k))
        k = next_k^
        next_v = _hmac[N](Span[UInt8, ...](k), Span[UInt8, ...](v))
        volatile_wipe(v.unsafe_ptr(), len(v))
        v = next_v^


@always_inline
def jacobian_add_affine_non_equal_ct[N: Int, N0: UInt64](p: JacobianPoint[N], q: Point[N], mod: Limbs[N], rr: Limbs[N], one_mont: Limbs[N]
) -> JacobianPoint[N]:
    var z1z1 = mont_sqr[N, N0](p.z, mod)
    var u2 = mont_mul[N, N0](q.x, z1z1, mod)
    var s2 = mont_mul[N, N0](q.y, mont_mul[N, N0](p.z, z1z1, mod), mod)
    var h = sub_mod(u2, p.x, mod)
    var r = mul_small_mod(sub_mod(s2, p.y, mod), 2, mod)
    var i = mont_sqr[N, N0](mul_small_mod(h, 2, mod), mod)
    var j = mont_mul[N, N0](h, i, mod)
    var v = mont_mul[N, N0](p.x, i, mod)
    var x3 = sub_mod(sub_mod(mont_sqr[N, N0](r, mod), j, mod), mul_small_mod(v, 2, mod), mod)
    var y3 = sub_mod(mont_mul[N, N0](r, sub_mod(v, x3, mod), mod), mul_small_mod(mont_mul[N, N0](p.y, j, mod), 2, mod), mod)
    var hh = mont_sqr[N, N0](h, mod)
    var z3 = sub_mod(sub_mod(mont_sqr[N, N0](add_mod(p.z, h, mod), mod), z1z1, mod), hh, mod)
    var generic = JacobianPoint[N](x3, y3, z3, False)
    var q_as_jac = JacobianPoint[N](q.x, q.y, one_mont, False)
    var p_is_inf = zero_choice(p.z)
    return select_jacobian_ct(generic, q_as_jac, p_is_inf)
