"""
NIST P-256 / secp256r1 implementation.
"""

from .p256_table import p256_base_table
from .utils import u64_nonzero_choice, u64_zero_choice
from .sha2 import sha256_hash
from .pbkdf2 import hmac_sha256
from std.utils import StaticTuple
from .weierstrass import Limbs, U256, Point, JacobianPoint, cmp as ws_cmp, sub_raw as ws_sub_raw, add_raw as ws_add_raw, select as ws_select, zero_choice as ws_zero_choice, add_mod as ws_add_mod, sub_mod as ws_sub_mod, from_be as ws_from_be, to_be as ws_to_be, mont_mul as ws_mont_mul, mont_sqr as ws_mont_sqr, to_mont as ws_to_mont, from_mont as ws_from_mont, mul_mod as ws_mul_mod, square_mod as ws_square_mod, is_on_curve as ws_is_on_curve, mul_small_mod as ws_mul_small_mod, jacobian_double_ct as ws_jacobian_double_ct, jacobian_infinity as ws_jacobian_infinity, select_jacobian_ct as ws_select_jacobian_ct, jacobian_add_affine_non_equal_ct as ws_jacobian_add_affine, pow_mod as ws_pow_mod, sqn as ws_sqn, inv_p as ws_inv_p, jacobian_to_affine as ws_jacobian_to_affine, scalar_mult as ws_scalar_mult, base_table_entry as ws_base_table_entry, scalar_mult_base as ws_scalar_mult_base, mod_inv_ct as ws_mod_inv_ct, reduce_mod as ws_reduce_mod, point_add as ws_point_add, rfc6979 as ws_rfc6979

comptime P256_SIZE = 32
comptime P256_POINT_SIZE = 65
comptime P256_SIGNATURE_SIZE = 64
comptime _MASK64 = UInt128(0xFFFFFFFFFFFFFFFF)
comptime _N0 = UInt64(1)  # -p^-1 mod 2^64
comptime _ORDER_N0 = UInt64(0xCCD1C8AAEE00BC4F)


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
    return ws_cmp(a, b)


@always_inline
def _eq(a: U256, b: U256) -> Bool:
    return _cmp(a, b) == 0


@always_inline
def _sub_raw(a: U256, b: U256) -> Tuple[U256, UInt64]:
    return ws_sub_raw(a, b)


@always_inline
def _add_raw(a: U256, b: U256) -> Tuple[U256, UInt64]:
    return ws_add_raw(a, b)


@always_inline
def _add_mod(a: U256, b: U256, m: U256) -> U256:
    return ws_add_mod(a, b, m)


@always_inline
def _sub_mod(a: U256, b: U256, m: U256) -> U256:
    return ws_sub_mod(a, b, m)


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
    return ws_mont_mul[4, _N0](a, b, _p())


@always_inline
def _mont_sqr(a: U256) -> U256:
    return ws_mont_sqr[4, _N0](a, _p())


@always_inline
def _to_mont(x: U256) -> U256:
    return ws_to_mont[4, _N0](x, _rr(), _p())


@always_inline
def _from_mont(x: U256) -> U256:
    return ws_from_mont[4, _N0](x, _p())


@always_inline
def _mul_mod(a: U256, b: U256, m: U256) -> U256:
    return ws_mul_mod[4, _N0](a, b, m, _rr())


@always_inline
def _square_mod(a: U256, m: U256) -> U256:
    return _mul_mod(a, a, m)


def _pow_mod(base_in: U256, exponent: U256) -> U256:
    return ws_pow_mod[4, _N0](base_in, exponent, _rr(), _p())


@always_inline
def _sqn_p(x: U256, n: Int) -> U256:
    return ws_sqn[4, _N0](x, n, _p())


def _inv_p(x: U256) -> U256:
    return ws_inv_p[4, _N0](x, _p(), _rr())


def _sqrt_p(x: U256) -> U256:
    return _pow_mod(x, _sqrt_exp())


def _from_be(bytes: Span[UInt8, ...]) -> U256:
    return ws_from_be[4](bytes)


def _to_be(x: U256, output: Pointer[mut=True, UInt8, _, address_space=_]):
    ws_to_be(x, output)


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
    return ws_select(a, b, choice)


@always_inline
def _u256_zero_choice(x: U256) -> UInt64:
    return ws_zero_choice(x)


@always_inline
def _jacobian_infinity() -> P256JacobianPoint:
    var res = ws_jacobian_infinity(_one_mont())
    return P256JacobianPoint(res.x, res.y, res.z, res.infinity)


@always_inline
def _select_jacobian_ct(
    a: P256JacobianPoint, b: P256JacobianPoint, choice: UInt64
) -> P256JacobianPoint:
    # P256JacobianPoint and JacobianPoint[4] have same layout (U256==Limbs[4])
    var ga = JacobianPoint[4](a.x, a.y, a.z, a.infinity)
    var gb = JacobianPoint[4](b.x, b.y, b.z, b.infinity)
    var res = ws_select_jacobian_ct(ga, gb, choice)
    return P256JacobianPoint(res.x, res.y, res.z, res.infinity)


@always_inline
def _mul_small_mod(x: U256, c: UInt64) -> U256:
    return ws_mul_small_mod(x, c, _p())


def _is_on_curve(point: P256Point) -> Bool:
    var gp = Point[4](point.x, point.y, point.infinity)
    return ws_is_on_curve[4, _N0](gp, _p(), _a(), _b(), _rr())


@always_inline
def _jacobian_double_ct(p: P256JacobianPoint) -> P256JacobianPoint:
    var gp = JacobianPoint[4](p.x, p.y, p.z, p.infinity)
    var res = ws_jacobian_double_ct[4, _N0](gp, _p(), _rr())
    return P256JacobianPoint(res.x, res.y, res.z, res.infinity)


@always_inline
def _jacobian_add_affine_non_equal_ct(
    p: P256JacobianPoint, q: P256Point
) -> P256JacobianPoint:
    var gp = JacobianPoint[4](p.x, p.y, p.z, p.infinity)
    var gq = Point[4](q.x, q.y, q.infinity)
    var res = ws_jacobian_add_affine[4, _N0](gp, gq, _p(), _rr(), _one_mont())
    return P256JacobianPoint(res.x, res.y, res.z, res.infinity)


def _jacobian_to_affine(p: P256JacobianPoint) -> P256Point:
    var gp = JacobianPoint[4](p.x, p.y, p.z, p.infinity)
    var res = ws_jacobian_to_affine[4, _N0](gp, _p(), _rr())
    return P256Point(res.x, res.y, res.infinity)


def _scalar_mult(k: U256, p: P256Point) -> P256Point:
    var pl = Point[4](p.x, p.y, p.infinity)
    var res = ws_scalar_mult[4, _N0](k, pl, _p(), _rr(), _one_mont())
    return P256Point(res.x, res.y, res.infinity)


@always_inline
def _base_table_entry(
    tptr: Pointer[UInt64, _], j: Int, d: UInt64
) -> P256Point:
    var res = ws_base_table_entry[4](tptr, j, d)
    return P256Point(res.x, res.y, res.infinity)


def _scalar_mult_base(k: U256) -> P256Point:
    var table = p256_base_table()
    var tptr = table.unsafe_ptr()
    var res = ws_scalar_mult_base[4, _N0](tptr, k, _p(), _rr(), _one_mont())
    return P256Point(res.x, res.y, res.infinity)


def p256_decode_uncompressed(point: Span[UInt8, ...]) -> P256Point:
    if len(point) == 33 and (point[0] == 0x02 or point[0] == 0x03):
        var x = _from_be(
            Span[UInt8, ...](unsafe_ptr=point.unsafe_ptr().unsafe_offset(1), length=32)
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
    var x = _from_be(Span[UInt8, ...](unsafe_ptr=point.unsafe_ptr().unsafe_offset(1), length=32))
    var y = _from_be(Span[UInt8, ...](unsafe_ptr=point.unsafe_ptr().unsafe_offset(33), length=32))
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
    out_ptr[unsafe_offset=0] = 0x04
    _to_be(point.x, out_ptr.unsafe_offset(1))
    _to_be(point.y, out_ptr.unsafe_offset(33))
    return True


@no_inline
def p256_public_key(
    private_key: Span[UInt8, ...], output: Span[mut=True, UInt8, ...]
) -> Bool:
    if len(private_key) != 32 or len(output) < P256_POINT_SIZE:
        return False
    var d = _from_be(private_key)
    if d.is_zero() or _cmp(d, _n()) >= 0:
        var dp = Pointer(to=d).unsafe_bitcast[UInt64]()
        for i in range(4):
            dp.unsafe_store[volatile=True](i, UInt64(0))
        return False
    var q = _scalar_mult_base(d)
    var ok = p256_encode_uncompressed(q, output)
    var dp = Pointer(to=d).unsafe_bitcast[UInt64]()
    for i in range(4):
        dp.unsafe_store[volatile=True](i, UInt64(0))
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
        var dp = Pointer(to=d).unsafe_bitcast[UInt64]()
        for i in range(4):
            dp.unsafe_store[volatile=True](i, UInt64(0))
        return False
    var q = p256_decode_uncompressed(public_key)
    if q.infinity:
        var dp = Pointer(to=d).unsafe_bitcast[UInt64]()
        for i in range(4):
            dp.unsafe_store[volatile=True](i, UInt64(0))
        return False
    var shared = _scalar_mult(d, q)
    var dp = Pointer(to=d).unsafe_bitcast[UInt64]()
    for i in range(4):
        dp.unsafe_store[volatile=True](i, UInt64(0))
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
    return ws_mont_mul[4, _ORDER_N0](a, b, _n())


@always_inline
def _n_to_mont(x: U256) -> U256:
    return ws_to_mont[4, _ORDER_N0](x, _n_rr(), _n())


@always_inline
def _n_from_mont(x: U256) -> U256:
    return ws_from_mont[4, _ORDER_N0](x, _n())


@always_inline
def _n_mul(a: U256, b: U256) -> U256:
    return ws_mont_mul[4, _ORDER_N0](ws_to_mont[4, _ORDER_N0](a, _n_rr(), _n()), b, _n())


def _n_inv(x: U256) -> U256:
    return ws_mod_inv_ct[4, _ORDER_N0](x, _n(), _n_rr(), _n_minus_2(), _n_one_mont())


@always_inline
def _reduce_n(x: U256) -> U256:
    return ws_reduce_mod(x, _n())


def _wipe_u256(mut x: U256):
    var ptr = Pointer(to=x).unsafe_bitcast[UInt64]()
    for i in range(4):
        ptr.unsafe_store[volatile=True](i, UInt64(0))


def _wipe_list_u8(mut data: List[UInt8]):
    var ptr = data.unsafe_ptr()
    for i in range(len(data)):
        ptr.unsafe_store[volatile=True](i, UInt8(0))


def _rfc6979_p256(private_key: Span[UInt8, ...], digest: Span[UInt8, ...], skip: Int) -> U256:
    return ws_rfc6979[4](private_key, digest, skip, _n())


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
        _to_be(s, signature_ptr.unsafe_offset(32))
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
    var ga = Point[4](a.x, a.y, a.infinity)
    var gb = Point[4](b.x, b.y, b.infinity)
    var res = ws_point_add[4, _N0](ga, gb, _p(), _rr(), _one_mont())
    return P256Point(res.x, res.y, res.infinity)


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
