"""
NIST P-384 / secp384r1 implementation.
"""

from .p384_table import p384_base_table
from .utils import u64_nonzero_choice, u64_zero_choice
from .sha2 import sha384_hash
from .pbkdf2 import hmac_sha384
from std.utils import StaticTuple
from .weierstrass import (
    Limbs, U384, Point, JacobianPoint, cmp as ws_cmp, sub_raw as ws_sub_raw, add_raw as ws_add_raw, select as ws_select, zero_choice as ws_zero_choice, add_mod as ws_add_mod, sub_mod as ws_sub_mod, from_be as ws_from_be, to_be as ws_to_be, mont_mul as ws_mont_mul, mont_sqr as ws_mont_sqr, to_mont as ws_to_mont, from_mont as ws_from_mont, mul_mod as ws_mul_mod, square_mod as ws_square_mod, is_on_curve as ws_is_on_curve, mul_small_mod as ws_mul_small_mod, jacobian_double_ct as ws_jacobian_double_ct, jacobian_add as ws_jacobian_add, jacobian_infinity as ws_jacobian_infinity, select_jacobian_ct as ws_select_jacobian_ct, jacobian_add_affine_non_equal_ct as ws_jacobian_add_affine, pow_mod as ws_pow_mod, sqn as ws_sqn, inv_p as ws_inv_p, jacobian_to_affine as ws_jacobian_to_affine, scalar_mult_jacobian_w5 as ws_scalar_mult_jacobian_w5, scalar_mult_base as ws_scalar_mult_base, scalar_mult_base_jacobian as ws_scalar_mult_base_jacobian, base_table_entry as ws_base_table_entry, mod_inv_ct as ws_mod_inv_ct, reduce_mod as ws_reduce_mod, point_add as ws_point_add, rfc6979 as ws_rfc6979
)

comptime P384_SIZE = 48
comptime P384_POINT_SIZE = 97
comptime P384_SIGNATURE_SIZE = 96
comptime _MASK64 = UInt128(0xFFFFFFFFFFFFFFFF)
comptime _N0 = UInt64(0x0000000100000001)  # -p^-1 mod 2^64
comptime _ORDER_N0 = UInt64(0x6ED46089E88FDC45)


def _p() -> U384:
    return U384(
        0x00000000FFFFFFFF,
        0xFFFFFFFF00000000,
        0xFFFFFFFFFFFFFFFE,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF
    )


def _a() -> U384:
    return U384(
        0x00000000FFFFFFFC,
        0xFFFFFFFF00000000,
        0xFFFFFFFFFFFFFFFE,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF
    )


def _b() -> U384:
    return U384(
        0x2A85C8EDD3EC2AEF,
        0xC656398D8A2ED19D,
        0x0314088F5013875A,
        0x181D9C6EFE814112,
        0x988E056BE3F82D19,
        0xB3312FA7E23EE7E4
    )


def _n() -> U384:
    return U384(
        0xECEC196ACCC52973,
        0x581A0DB248B0A77A,
        0xC7634D81F4372DDF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF
    )


def _gx() -> U384:
    return U384(
        0x3A545E3872760AB7,
        0x5502F25DBF55296C,
        0x59F741E082542A38,
        0x6E1D3B628BA79B98,
        0x8EB1C71EF320AD74,
        0xAA87CA22BE8B0537
    )


def _gy() -> U384:
    return U384(
        0x7A431D7C90EA0E5F,
        0x0A60B1CE1D7E819D,
        0xE9DA3113B5F0B8C0,
        0xF8F41DBD289A147C,
        0x5D9E98BF9292DC29,
        0x3617DE4A96262C6F
    )


def _sqrt_exp() -> U384:
    # p == 3 mod 4
    return U384(
        0x0000000040000000,
        0xBFFFFFFFC0000000,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0x3FFFFFFFFFFFFFFF
    )


def _rr() -> U384:
    return U384(
        0xFFFFFFFE00000001,
        0x0000000200000000,
        0xFFFFFFFE00000000,
        0x0000000200000000,
        0x0000000000000001,
        0x0000000000000000
    )


def _one_mont() -> U384:
    return U384(
        0xFFFFFFFF00000001,
        0x00000000FFFFFFFF,
        0x0000000000000001,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000
    )


@always_inline
def _cmp(a: U384, b: U384) -> Int:
    return ws_cmp(a, b)


@always_inline
def _eq(a: U384, b: U384) -> Bool:
    return _cmp(a, b) == 0


@always_inline
def _sub_raw(a: U384, b: U384) -> Tuple[U384, UInt64]:
    return ws_sub_raw(a, b)


@always_inline
def _add_raw(a: U384, b: U384) -> Tuple[U384, UInt64]:
    return ws_add_raw(a, b)


@always_inline
def _add_mod(a: U384, b: U384, m: U384) -> U384:
    return ws_add_mod(a, b, m)


@always_inline
def _sub_mod(a: U384, b: U384, m: U384) -> U384:
    return ws_sub_mod(a, b, m)


@always_inline
def _add_mod(a: U384, b: U384) -> U384:
    return _add_mod(a, b, _p())


@always_inline
def _sub_mod(a: U384, b: U384) -> U384:
    return _sub_mod(a, b, _p())


@always_inline
def _mont_mul(a: U384, b: U384) -> U384:
    return ws_mont_mul[6, _N0](a, b, _p())


@always_inline
def _mont_sqr(a: U384) -> U384:
    return ws_mont_sqr[6, _N0](a, _p())


@always_inline
def _to_mont(x: U384) -> U384:
    return ws_to_mont[6, _N0](x, _rr(), _p())


@always_inline
def _from_mont(x: U384) -> U384:
    return ws_from_mont[6, _N0](x, _p())


@always_inline
def _mul_mod(a: U384, b: U384, m: U384) -> U384:
    return ws_mul_mod[6, _N0](a, b, m, _rr())


@always_inline
def _square_mod(a: U384, m: U384) -> U384:
    return _mul_mod(a, a, m)


def _pow_mod(base_in: U384, exponent: U384) -> U384:
    return ws_pow_mod[6, _N0](base_in, exponent, _rr(), _p())


@always_inline
def _sqn_p(x: U384, n: Int) -> U384:
    return ws_sqn[6, _N0](x, n, _p())


def _inv_p(x: U384) -> U384:
    return ws_inv_p[6, _N0](x, _p(), _rr())


def _sqrt_p(x: U384) -> U384:
    return _pow_mod(x, _sqrt_exp())


def _from_be(bytes: Span[UInt8, ...]) -> U384:
    return ws_from_be[6](bytes)


def _to_be(x: U384, output: Pointer[mut=True, UInt8, _, address_space=_]):
    ws_to_be(x, output)


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
    return ws_select(a, b, choice)


@always_inline
def _u384_zero_choice(x: U384) -> UInt64:
    return ws_zero_choice(x)


@always_inline
def _jacobian_infinity() -> P384JacobianPoint:
    var res = ws_jacobian_infinity(_one_mont())
    return P384JacobianPoint(res.x, res.y, res.z, res.infinity)


@always_inline
def _select_jacobian_ct(
    a: P384JacobianPoint, b: P384JacobianPoint, choice: UInt64
) -> P384JacobianPoint:
    var ga = JacobianPoint[6](a.x, a.y, a.z, a.infinity)
    var gb = JacobianPoint[6](b.x, b.y, b.z, b.infinity)
    var res = ws_select_jacobian_ct(ga, gb, choice)
    return P384JacobianPoint(res.x, res.y, res.z, res.infinity)


@always_inline
def _mul_small_mod(x: U384, c: UInt64) -> U384:
    return ws_mul_small_mod(x, c, _p())


def _is_on_curve(point: P384Point) -> Bool:
    var gp = Point[6](point.x, point.y, point.infinity)
    return ws_is_on_curve[6, _N0](gp, _p(), _a(), _b(), _rr())


@always_inline
def _jacobian_double_ct(p: P384JacobianPoint) -> P384JacobianPoint:
    var gp = JacobianPoint[6](p.x, p.y, p.z, p.infinity)
    var res = ws_jacobian_double_ct[6, _N0](gp, _p(), _rr())
    return P384JacobianPoint(res.x, res.y, res.z, res.infinity)


@always_inline
def _jacobian_add_affine_non_equal_ct(
    p: P384JacobianPoint, q: P384Point
) -> P384JacobianPoint:
    var gp = JacobianPoint[6](p.x, p.y, p.z, p.infinity)
    var gq = Point[6](q.x, q.y, q.infinity)
    var res = ws_jacobian_add_affine[6, _N0](gp, gq, _p(), _rr(), _one_mont())
    return P384JacobianPoint(res.x, res.y, res.z, res.infinity)


def _jacobian_to_affine(p: P384JacobianPoint) -> P384Point:
    var gp = JacobianPoint[6](p.x, p.y, p.z, p.infinity)
    var res = ws_jacobian_to_affine[6, _N0](gp, _p(), _rr())
    return P384Point(res.x, res.y, res.infinity)


def _scalar_mult(k: U384, p: P384Point) -> P384Point:
    return _jacobian_to_affine(_scalar_mult_jacobian(k, p))


@always_inline
def _scalar_mult_jacobian(k: U384, p: P384Point) -> P384JacobianPoint:
    var pl = Point[6](p.x, p.y, p.infinity)
    var res = ws_scalar_mult_jacobian_w5[6, _N0](k, pl, _p(), _rr(), _one_mont())
    return P384JacobianPoint(res.x, res.y, res.z, res.infinity)


@always_inline
def _base_table_entry(
    tptr: Pointer[UInt64, _], j: Int, d: UInt64
) -> P384Point:
    var res = ws_base_table_entry[6](tptr, j, d)
    return P384Point(res.x, res.y, res.infinity)


def _scalar_mult_base(k: U384) -> P384Point:
    var table = p384_base_table()
    var tptr = table.unsafe_ptr()
    var res = ws_scalar_mult_base[6, _N0](tptr, k, _p(), _rr(), _one_mont())
    return P384Point(res.x, res.y, res.infinity)


@always_inline
def _scalar_mult_base_jacobian(k: U384) -> P384JacobianPoint:
    var table = p384_base_table()
    var tptr = table.unsafe_ptr()
    var res = ws_scalar_mult_base_jacobian[6, _N0](tptr, k, _p(), _rr(), _one_mont())
    return P384JacobianPoint(res.x, res.y, res.z, res.infinity)


@always_inline
def _jacobian_add(p: P384JacobianPoint, q: P384JacobianPoint) -> P384JacobianPoint:
    var gp = JacobianPoint[6](p.x, p.y, p.z, p.infinity)
    var gq = JacobianPoint[6](q.x, q.y, q.z, q.infinity)
    var res = ws_jacobian_add[6, _N0](gp, gq, _p(), _rr(), _one_mont())
    return P384JacobianPoint(res.x, res.y, res.z, res.infinity)


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
        var dp = Pointer(to=d).unsafe_bitcast[UInt64]()
        for i in range(6):
            dp.unsafe_store[volatile=True](i, UInt64(0))
        return False
    var q = _scalar_mult_base(d)
    var ok = p384_encode_uncompressed(q, output)
    var dp = Pointer(to=d).unsafe_bitcast[UInt64]()
    for i in range(6):
        dp.unsafe_store[volatile=True](i, UInt64(0))
    return ok


@no_inline
def p384_ecdh(
    private_key: Span[UInt8, ...],
    public_key: Span[UInt8, ...],
    output: Span[mut=True, UInt8, ...]
) -> Bool:
    if len(private_key) != 48 or len(output) < P384_SIZE:
        return False
    var d = _from_be(private_key)
    if d.is_zero() or _cmp(d, _n()) >= 0:
        var dp = Pointer(to=d).unsafe_bitcast[UInt64]()
        for i in range(6):
            dp.unsafe_store[volatile=True](i, UInt64(0))
        return False
    var q = p384_decode_uncompressed(public_key)
    if q.infinity:
        var dp = Pointer(to=d).unsafe_bitcast[UInt64]()
        for i in range(6):
            dp.unsafe_store[volatile=True](i, UInt64(0))
        return False
    var shared = _scalar_mult(d, q)
    var dp = Pointer(to=d).unsafe_bitcast[UInt64]()
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
        0x0C84EE012B39BF21
    )


def _n_one_mont() -> U384:
    return U384(
        0x1313E695333AD68D,
        0xA7E5F24DB74F5885,
        0x389CB27E0BC8D220,
        0,
        0,
        0
    )


def _n_minus_2() -> U384:
    return U384(
        0xECEC196ACCC52971,
        0x581A0DB248B0A77A,
        0xC7634D81F4372DDF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF
    )


@always_inline
def _n_mont_mul(a: U384, b: U384) -> U384:
    return ws_mont_mul[6, _ORDER_N0](a, b, _n())


@always_inline
def _n_to_mont(x: U384) -> U384:
    return ws_to_mont[6, _ORDER_N0](x, _n_rr(), _n())


@always_inline
def _n_from_mont(x: U384) -> U384:
    return ws_from_mont[6, _ORDER_N0](x, _n())


@always_inline
def _n_mul(a: U384, b: U384) -> U384:
    return ws_mont_mul[6, _ORDER_N0](ws_to_mont[6, _ORDER_N0](a, _n_rr(), _n()), b, _n())


def _n_inv(x: U384) -> U384:
    return ws_mod_inv_ct[6, _ORDER_N0](x, _n(), _n_rr(), _n_minus_2(), _n_one_mont())


@always_inline
def _reduce_n(x: U384) -> U384:
    return ws_reduce_mod(x, _n())


def _wipe_u384(mut x: U384):
    var ptr = Pointer(to=x).unsafe_bitcast[UInt64]()
    for i in range(6):
        ptr.unsafe_store[volatile=True](i, UInt64(0))


def _wipe_list_u8(mut data: List[UInt8]):
    var ptr = data.unsafe_ptr()
    for i in range(len(data)):
        ptr.unsafe_store[volatile=True](i, UInt8(0))


def _rfc6979_p384(private_key: Span[UInt8, ...], digest: Span[UInt8, ...], skip: Int) -> U384:
    return ws_rfc6979[6](private_key, digest, skip, _n())


def p384_ecdsa_sign_digest(
    private_key: Span[UInt8, ...],
    digest: Span[UInt8, ...],
    signature: Span[mut=True, UInt8, ...]
) -> Bool:
    if len(private_key) != 48 or len(digest) != 48
        or len(signature) < P384_SIGNATURE_SIZE:
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
    signature: Span[mut=True, UInt8, ...]
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
    var ga = Point[6](a.x, a.y, a.infinity)
    var gb = Point[6](b.x, b.y, b.infinity)
    var res = ws_point_add[6, _N0](ga, gb, _p(), _rr(), _one_mont())
    return P384Point(res.x, res.y, res.infinity)


def p384_ecdsa_verify_digest(
    public_key: Span[UInt8, ...],
    digest: Span[UInt8, ...],
    signature: Span[UInt8, ...]
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
    var p1 = _scalar_mult_base_jacobian(u1)
    var p2 = _scalar_mult_jacobian(u2, q)
    var point = _jacobian_to_affine(_jacobian_add(p1, p2))
    if point.infinity:
        return False
    return _eq(_reduce_n(point.x), r)


def p384_ecdsa_verify(
    public_key: Span[UInt8, ...],
    message: Span[UInt8, ...],
    signature: Span[UInt8, ...]
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
    signature: Span[UInt8, ...]
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
                Span[mut=True, UInt8, ...](public_key)
            ):
                _wipe_u384(d)
                return (private_key^, public_key^)
        _wipe_u384(d)
        _wipe_list_u8(private_key)
