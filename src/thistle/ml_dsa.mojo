# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Libalpm64, Lostlab Technologies.

"""
ML-DSA implementation in Mojo.
By Libalpm64, no attribution required.

Security notice:
ML-DSA is incredibly difficult to implement safely because signing uses rejection sampling
and large polynomial/vector states. Source-level optimizations can accidentally bring in
secret-dependent control-flow, memory access, allocator timing, and temporary writes of sensitive
state into external buffers. By no means is this a perfect implementation. We aim to keep
sensitive signing state in private scratch, avoid early-exit checks on secret-derived polynomial
data, zeroize sensitive temporaries with volatile stores when practical.
"""

from std.collections import List
from std.algorithm.functional import vectorize
from std.builtin.globals import global_constant
from std.memory import memset_zero
from std.sys import simd_width_of
from thistle.sha3 import SHA3Context, sha3_update, shake_final, shake128, shake256
from thistle.random import random_bytes
from thistle.utils import StackBuffer

comptime MLDSA44_PUBLICKEYBYTES = 1312
comptime MLDSA44_SECRETKEYBYTES = 2560
comptime MLDSA44_BYTES = 2420
comptime MLDSA65_PUBLICKEYBYTES = 1952
comptime MLDSA65_SECRETKEYBYTES = 4032
comptime MLDSA65_BYTES = 3309
comptime MLDSA87_PUBLICKEYBYTES = 2592
comptime MLDSA87_SECRETKEYBYTES = 4896
comptime MLDSA87_BYTES = 4627
comptime MLDSA_SEEDBYTES = 32
comptime MLDSA_RNDBYTES = 32
comptime MLDSA_CRHBYTES = 64

comptime Q: UInt32 = 8380417
comptime RR: UInt32 = 2365951
comptime Q_NEG_INV: UInt32 = 4236238847
comptime ONE: UInt32 = 4193792
comptime MINUS_ONE: UInt32 = 4186625
comptime N = 256
comptime MAX_K = 8
comptime MAX_L = 7
comptime DSAPoly = InlineArray[UInt32, N]
comptime DSAHintRow = InlineArray[UInt8, N]
comptime DSAHintVec = InlineArray[DSAHintRow, MAX_K]


comptime ZETAS_TABLE: InlineArray[UInt32, 256] = [
    4193792, 25847, 5771523, 7861508, 237124, 7602457, 7504169, 466468,
    1826347, 2353451, 8021166, 6288512, 3119733, 5495562, 3111497, 2680103,
    2725464, 1024112, 7300517, 3585928, 7830929, 7260833, 2619752, 6271868,
    6262231, 4520680, 6980856, 5102745, 1757237, 8360995, 4010497, 280005,
    2706023, 95776, 3077325, 3530437, 6718724, 4788269, 5842901, 3915439,
    4519302, 5336701, 3574422, 5512770, 3539968, 8079950, 2348700, 7841118,
    6681150, 6736599, 3505694, 4558682, 3507263, 6239768, 6779997, 3699596,
    811944, 531354, 954230, 3881043, 3900724, 5823537, 2071892, 5582638,
    4450022, 6851714, 4702672, 5339162, 6927966, 3475950, 2176455, 6795196,
    7122806, 1939314, 4296819, 7380215, 5190273, 5223087, 4747489, 126922,
    3412210, 7396998, 2147896, 2715295, 5412772, 4686924, 7969390, 5903370,
    7709315, 7151892, 8357436, 7072248, 7998430, 1349076, 1852771, 6949987,
    5037034, 264944, 508951, 3097992, 44288, 7280319, 904516, 3958618,
    4656075, 8371839, 1653064, 5130689, 2389356, 8169440, 759969, 7063561,
    189548, 4827145, 3159746, 6529015, 5971092, 8202977, 1315589, 1341330,
    1285669, 6795489, 7567685, 6940675, 5361315, 4499357, 4751448, 3839961,
    2091667, 3407706, 2316500, 3817976, 5037939, 2244091, 5933984, 4817955,
    266997, 2434439, 7144689, 3513181, 4860065, 4621053, 7183191, 5187039,
    900702, 1859098, 909542, 819034, 495491, 6767243, 8337157, 7857917,
    7725090, 5257975, 2031748, 3207046, 4823422, 7855319, 7611795, 4784579,
    342297, 286988, 5942594, 4108315, 3437287, 5038140, 1735879, 203044,
    2842341, 2691481, 5790267, 1265009, 4055324, 1247620, 2486353, 1595974,
    4613401, 1250494, 2635921, 4832145, 5386378, 1869119, 1903435, 7329447,
    7047359, 1237275, 5062207, 6950192, 7929317, 1312455, 3306115, 6417775,
    7100756, 1917081, 5834105, 7005614, 1500165, 777191, 2235880, 3406031,
    7838005, 5548557, 6709241, 6533464, 5796124, 4656147, 594136, 4603424,
    6366809, 2432395, 2454455, 8215696, 1957272, 3369112, 185531, 7173032,
    5196991, 162844, 1616392, 3014001, 810149, 1652634, 4686184, 6581310,
    5341501, 3523897, 3866901, 269760, 2213111, 7404533, 1717735, 472078,
    7953734, 1723600, 6577327, 1910376, 6712985, 7276084, 8119771, 4546524,
    5441381, 6144432, 7959518, 6094090, 183443, 7403526, 1612842, 4834730,
    7826001, 3919660, 8332111, 7018208, 3937738, 1400424, 7534263, 1976782,
]


@always_inline
def _zeta(i: Int) -> UInt32:
    debug_assert(i >= 0 and i < 256, "ML-DSA zeta index out of bounds")
    ref zetas = global_constant[ZETAS_TABLE]()
    return zetas.unsafe_ptr()[i]


@fieldwise_init
struct MLDSAParams(Copyable, Movable):
    var k: Int
    var l: Int
    var eta: Int
    var gamma1_log: Int
    var gamma2_denom: Int
    var lambda_bits: Int
    var tau: Int
    var omega: Int


struct DSAPolyVec[ROWS: Int](Movable):
    var data: InlineArray[DSAPoly, Self.ROWS]

    @always_inline
    def __init__(out self):
        self.data = InlineArray[DSAPoly, Self.ROWS](fill=DSAPoly(fill=0))

    @always_inline
    def __getitem__(ref self, i: Int) -> ref[self.data] DSAPoly:
        return self.data[i]

    @always_inline
    def __setitem__(mut self, i: Int, value: DSAPoly):
        self.data[i] = value


@fieldwise_init
struct MLDSAPublicKey(Copyable, Movable):
    var p: MLDSAParams
    var raw: List[UInt8]
    var a: List[List[UInt32]]
    var t1_hat: List[List[UInt32]]
    var tr: List[UInt8]


@fieldwise_init
struct MLDSAPrivateKey(Copyable, Movable):
    var p: MLDSAParams
    var seed: List[UInt8]
    var pub: MLDSAPublicKey
    var s1: List[List[UInt32]]
    var s2: List[List[UInt32]]
    var t0: List[List[UInt32]]
    var k_seed: List[UInt8]


def params44() -> MLDSAParams:
    return MLDSAParams(4, 4, 2, 17, 88, 128, 39, 80)


def params65() -> MLDSAParams:
    return MLDSAParams(6, 5, 4, 19, 32, 192, 49, 55)


def params87() -> MLDSAParams:
    return MLDSAParams(8, 7, 2, 19, 32, 256, 60, 75)


def public_key_size(p: MLDSAParams) -> Int:
    return 32 + p.k * N * 10 // 8


def signature_size(p: MLDSAParams) -> Int:
    return p.lambda_bits // 4 + p.l * N * (p.gamma1_log + 1) // 8 + p.omega + p.k


def private_key_size(p: MLDSAParams) -> Int:
    var eta_bitlen = 3
    if p.eta == 4:
        eta_bitlen = 4
    return 32 + 32 + 64 + p.l * N * eta_bitlen // 8 + p.k * N * eta_bitlen // 8 + p.k * N * 13 // 8


def _zero_poly() -> List[UInt32]:
    var r = List[UInt32](unsafe_uninit_length=N)
    memset_zero(r.unsafe_ptr(), N)
    return r^


def _zero_dsa_poly() -> DSAPoly:
    return DSAPoly(fill=0)


def _zero_dsa_poly_vec[ROWS: Int]() -> DSAPolyVec[ROWS]:
    return DSAPolyVec[ROWS]()


def _zero_dsa_poly(mut p: DSAPoly):
    var ptr = p.unsafe_ptr()
    for i in range(N):
        ptr.store[volatile=True](i, UInt32(0))


def _zero_dsa_poly_vec[ROWS: Int](mut v: DSAPolyVec[ROWS]):
    var ptr = v.data.unsafe_ptr().bitcast[UInt32]()
    for i in range(ROWS * N):
        ptr.store[volatile=True](i, UInt32(0))


def _zero_dsa_hint_vec(mut h: DSAHintVec):
    var ptr = h.unsafe_ptr().bitcast[UInt8]()
    for i in range(MAX_K * N):
        ptr.store[volatile=True](i, UInt8(0))


def _zero_dsa_ch(mut ch: InlineArray[UInt8, MLDSA_CRHBYTES]):
    var ptr = ch.unsafe_ptr()
    for i in range(MLDSA_CRHBYTES):
        ptr.store[volatile=True](i, UInt8(0))


def _zero_poly_vec(count: Int) -> List[List[UInt32]]:
    var v = List[List[UInt32]](capacity=count)
    for _ in range(count):
        v.append(_zero_poly())
    return v^


def _zero_hint_vec(count: Int) -> List[List[UInt8]]:
    var v = List[List[UInt8]](capacity=count)
    for _ in range(count):
        var row = List[UInt8](unsafe_uninit_length=N)
        memset_zero(row.unsafe_ptr(), N)
        v.append(row^)
    return v^


def _copy_bytes(src: Span[UInt8, ...]) -> List[UInt8]:
    var out = List[UInt8](capacity=len(src))
    out.extend(src)
    return out^


def _slice_bytes(src: Span[UInt8, ...], start: Int, count: Int) -> List[UInt8]:
    return _copy_bytes(src.unsafe_subspan(offset=start, length=count))


def _append_bytes(mut out: List[UInt8], src: Span[UInt8, ...]):
    out.extend(src)


def _append_bytes_stack(mut out: StackBuffer[UInt8, ...], src: Span[UInt8, ...]):
    for i in range(len(src)):
        out.push_unchecked(src[i])


@always_inline
def _ct_bool_to_u32(b: Bool) -> UInt32:
    return UInt32(Int(b))

@always_inline
def _ct_select_u8(false_value: UInt8, true_value: UInt8, choice: UInt32) -> UInt8:
    var mask = UInt8(0) - UInt8(choice)
    return false_value ^ (mask & (false_value ^ true_value))


@always_inline
def _ct_select_u32(false_value: UInt32, true_value: UInt32, choice: UInt32) -> UInt32:
    var mask = UInt32(0) - choice
    return false_value ^ (mask & (false_value ^ true_value))


# Volatile stores are stronger cleanup than std.memory.memset_zero, which is ordinary stores.
# Note: Still no formal guarantee of safety.
def _zero_list_u8(mut data: List[UInt8]):
    var ptr = data.unsafe_ptr()
    for i in range(len(data)):
        ptr.store[volatile=True](i, UInt8(0))


def _zero_list_u32(mut data: List[UInt32]):
    var ptr = data.unsafe_ptr()
    for i in range(len(data)):
        ptr.store[volatile=True](i, UInt32(0))


def _zero_poly_vec_u32(mut data: List[List[UInt32]]):
    for i in range(len(data)):
        _zero_list_u32(data[i])


def _zero_poly_vec_u8(mut data: List[List[UInt8]]):
    for i in range(len(data)):
        _zero_list_u8(data[i])


def _zero_stack_u8(mut data: StackBuffer[UInt8, ...]):
    var ptr = data.ptr()
    for i in range(data.len()):
        ptr.store[volatile=True](i, UInt8(0))
    data.clear()


def _bytes_equal(a: Span[UInt8, ...], b: Span[UInt8, ...]) -> Bool:
    if len(a) != len(b):
        return False

    var diff = UInt8(0)
    for i in range(len(a)):
        diff |= a[i] ^ b[i]

    return diff == UInt8(0)


@always_inline
def _field_reduce_once(a: UInt32) -> UInt32:
    if a >= Q:
        return a - Q
    return a


@always_inline
def _field_add(a: UInt32, b: UInt32) -> UInt32:
    return _field_reduce_once(a + b)


@always_inline
def _field_sub(a: UInt32, b: UInt32) -> UInt32:
    return _field_reduce_once(a - b + Q)


@always_inline
def _montgomery_reduce(x: UInt64) -> UInt32:
    var t = UInt32(x) * Q_NEG_INV
    var u = (x + UInt64(t) * UInt64(Q)) >> 32
    return _field_reduce_once(UInt32(u))


@always_inline
def _montgomery_mul(a: UInt32, b: UInt32) -> UInt32:
    return _montgomery_reduce(UInt64(a) * UInt64(b))


@always_inline
def _montgomery_mul_sub(a: UInt32, b: UInt32, c: UInt32) -> UInt32:
    return _montgomery_reduce(UInt64(a) * UInt64(b - c + Q))


@always_inline
def _field_to_montgomery_unchecked(a: UInt32) -> UInt32:
    return _montgomery_mul(a, RR)


@always_inline
def _field_sub_to_montgomery(a: UInt32, b: UInt32) -> UInt32:
    return _montgomery_mul(a - b + Q, RR)


@always_inline
def _field_from_montgomery(a: UInt32) -> UInt32:
    return _montgomery_reduce(UInt64(a))


def _centered_mod(r: UInt32) -> Int32:
    var x = Int32(_field_from_montgomery(r))
    if x <= Int32(Q // 2):
        return x
    return x - Int32(Q)


def _infinity_norm(r: UInt32) -> UInt32:
    var x = Int32(_field_from_montgomery(r))
    if x <= Int32(Q // 2):
        return UInt32(x)
    return UInt32(Int32(Q) - x)


def _abs_i32(x: Int32) -> UInt32:
    if x < 0:
        return UInt32(-x)
    return UInt32(x)


def _poly_add_into(mut r: List[UInt32], b: List[UInt32]):
    for i in range(N):
        r[i] = _field_add(r[i], b[i])


def _dsa_poly_add_into(mut r: DSAPoly, b: DSAPoly):
    for i in range(N):
        r[i] = _field_add(r[i], b[i])


def _poly_sub_into(mut r: List[UInt32], b: List[UInt32]):
    for i in range(N):
        r[i] = _field_sub(r[i], b[i])


def _dsa_poly_sub_into(mut r: DSAPoly, b: DSAPoly):
    for i in range(N):
        r[i] = _field_sub(r[i], b[i])


def _copy_poly_into(mut r: List[UInt32], a: List[UInt32]):
    for i in range(N):
        r[i] = a[i]


def _dsa_copy_poly_into(mut r: DSAPoly, a: DSAPoly):
    r = a


def _ntt_mul_into(mut r: List[UInt32], a: List[UInt32], b: List[UInt32]):
    for i in range(N):
        r[i] = _montgomery_mul(a[i], b[i])


def _dsa_ntt_mul_into(mut r: DSAPoly, a: DSAPoly, b: DSAPoly):
    for i in range(N):
        r[i] = _montgomery_mul(a[i], b[i])


def _dsa_ntt_mul_into(mut r: DSAPoly, a: List[UInt32], b: DSAPoly):
    for i in range(N):
        r[i] = _montgomery_mul(a[i], b[i])


def _dsa_ntt_mul_into(mut r: DSAPoly, a: DSAPoly, b: List[UInt32]):
    for i in range(N):
        r[i] = _montgomery_mul(a[i], b[i])


def _ntt_inplace(mut f: List[UInt32]):
    var m = 0
    var length = 128
    while length >= 1:
        var start = 0
        while start < 256:
            m += 1
            var zeta = _zeta(m)
            var j = start
            while j < start + length:
                var t = _montgomery_mul(zeta, f[j + length])
                f[j + length] = _field_sub(f[j], t)
                f[j] = _field_add(f[j], t)
                j += 1
            start += 2 * length
        length //= 2


def _dsa_ntt_inplace(mut f: DSAPoly):
    var m = 0
    var length = 128
    while length >= 1:
        var start = 0
        while start < 256:
            m += 1
            var zeta = _zeta(m)
            var j = start
            while j < start + length:
                var t = _montgomery_mul(zeta, f[j + length])
                f[j + length] = _field_sub(f[j], t)
                f[j] = _field_add(f[j], t)
                j += 1
            start += 2 * length
        length //= 2


def _ntt(var f: List[UInt32]) -> List[UInt32]:
    _ntt_inplace(f)
    return f^


def _inverse_ntt_inplace(mut f: List[UInt32]):
    var m = 255
    var length = 1
    while length < 256:
        var start = 0
        while start < 256:
            var zeta = _zeta(m)
            m -= 1
            var j = start
            while j < start + length:
                var t = f[j]
                f[j] = _field_add(t, f[j + length])
                f[j + length] = _montgomery_mul_sub(zeta, f[j + length], t)
                j += 1
            start += 2 * length
        length *= 2
    for i in range(N):
        f[i] = _montgomery_mul(f[i], 16382)


def _dsa_inverse_ntt_inplace(mut f: DSAPoly):
    var m = 255
    var length = 1
    while length < 256:
        var start = 0
        while start < 256:
            var zeta = _zeta(m)
            m -= 1
            var j = start
            while j < start + length:
                var t = f[j]
                f[j] = _field_add(t, f[j + length])
                f[j + length] = _montgomery_mul_sub(zeta, f[j + length], t)
                j += 1
            start += 2 * length
        length *= 2
    for i in range(N):
        f[i] = _montgomery_mul(f[i], 16382)


def _inverse_ntt(var f: List[UInt32]) -> List[UInt32]:
    _inverse_ntt_inplace(f)
    return f^


def _shake128_expand(seed: Span[UInt8, ...], out_len: Int) -> List[UInt8]:
    return shake128(seed, out_len)


def _shake256_expand(seed: Span[UInt8, ...], out_len: Int) -> List[UInt8]:
    return shake256(seed, out_len)


def _sample_ntt(rho: Span[UInt8, ...], s: UInt8, r: UInt8) raises -> List[UInt32]:
    var input = StackBuffer[UInt8, 34]()
    _append_bytes_stack(input, rho)
    input.push_unchecked(s)
    input.push_unchecked(r)

    var out_len = 168
    while True:
        var buf = _shake128_expand(Span[UInt8, ...](ptr=input.ptr(), length=input.len()), out_len)
        var a = List[UInt32](capacity=N)
        var off = 0
        while off + 2 < len(buf) and len(a) < N:
            var v = UInt32(buf[off]) | (UInt32(buf[off + 1]) << 8) | (UInt32(buf[off + 2]) << 16)
            off += 3
            v &= 0x7FFFFF
            if v < Q:
                a.append(_field_to_montgomery_unchecked(v))
        if len(a) == N:
            return a^
        out_len *= 2


def _coeff_from_half_byte(b: UInt8, p: MLDSAParams) -> Tuple[UInt32, Bool]:
    if p.eta == 2:
        if b > 14:
            return (0, False)
        var quotient = (UInt32(b) * 0x3334) >> 16
        var remainder = UInt32(b) - quotient * 5
        return (_field_sub_to_montgomery(2, remainder), True)
    if p.eta == 4:
        if b > 8:
            return (0, False)
        return (_field_sub_to_montgomery(4, UInt32(b)), True)
    return (0, False)


def _sample_bounded_poly(rho: Span[UInt8, ...], r: UInt8, p: MLDSAParams) -> List[UInt32]:
    var input = StackBuffer[UInt8, 66]()
    _append_bytes_stack(input, rho)
    input.push_unchecked(r)
    input.push_unchecked(0)

    var out_len = 136
    while True:
        var buf = _shake256_expand(Span[UInt8, ...](ptr=input.ptr(), length=input.len()), out_len)
        var a = List[UInt32](capacity=N)
        for i in range(len(buf)):
            var z0 = buf[i] & 0x0F
            var z1 = buf[i] >> 4
            var c0 = _coeff_from_half_byte(z0, p)
            if c0[1]:
                a.append(c0[0])
                if len(a) == N:
                    return a^
            var c1 = _coeff_from_half_byte(z1, p)
            if c1[1]:
                a.append(c1[0])
                if len(a) == N:
                    return a^
        out_len *= 2


def _sample_in_ball(rho: Span[UInt8, ...], p: MLDSAParams) -> List[UInt32]:
    var out_len = 136
    while True:
        var buf = _shake256_expand(rho, out_len)
        var c = _zero_poly()
        var off = 8
        var ok = True
        for i in range(256 - p.tau, 256):
            while True:
                if off >= len(buf):
                    ok = False
                    break
                var j = buf[off]
                off += 1
                if j <= UInt8(i):
                    c[i] = c[Int(j)]
                    var bit_idx = i + p.tau - 256
                    var bit = (buf[bit_idx // 8] >> UInt8(bit_idx % 8)) & 1
                    if bit == 0:
                        c[Int(j)] = ONE
                    else:
                        c[Int(j)] = MINUS_ONE
                    break
            if not ok:
                break
        if ok:
            return c^
        out_len *= 2


def _sample_in_ball_dsa(rho: Span[UInt8, ...], p: MLDSAParams) -> DSAPoly:
    var out_len = 136
    while True:
        var buf = _shake256_expand(rho, out_len)
        var c = DSAPoly(fill=0)
        var off = 8
        var ok = True
        for i in range(256 - p.tau, 256):
            while True:
                if off >= len(buf):
                    ok = False
                    break
                var j = buf[off]
                off += 1
                if j <= UInt8(i):
                    c[i] = c[Int(j)]
                    var bit_idx = i + p.tau - 256
                    var bit = (buf[bit_idx // 8] >> UInt8(bit_idx % 8)) & 1
                    if bit == 0:
                        c[Int(j)] = ONE
                    else:
                        c[Int(j)] = MINUS_ONE
                    break
            if not ok:
                break
        _zero_list_u8(buf)
        if ok:
            return c
        out_len *= 2


def _power2_round(r: UInt32) -> Tuple[UInt16, UInt32]:
    var rr = _field_from_montgomery(r)
    var r1 = (rr + (1 << 12) - 1) >> 13
    var r0 = _field_sub_to_montgomery(rr, r1 << 13)
    return (UInt16(r1), r0)


def _high_bits32(x: UInt32) -> UInt8:
    var r1 = (x + 127) >> 7
    r1 = (r1 * 1025 + (1 << 21)) >> 22
    r1 &= 0x0F
    return UInt8(r1)


def _decompose32(r: UInt32) -> Tuple[UInt8, Int32]:
    var x = _field_from_montgomery(r)
    var r1 = _high_bits32(x)
    var r0 = Int32(x) - Int32(r1) * 2 * Int32((Q - 1) // 32)
    if Int32(Q // 2 + 1) <= r0:
        r0 -= Int32(Q)
    return (r1, r0)


def _high_bits88(x: UInt32) -> UInt8:
    var r1 = (x + 127) >> 7
    r1 = (r1 * 11275 + (1 << 23)) >> 24
    if r1 == 44:
        r1 = 0
    return UInt8(r1)


def _decompose88(r: UInt32) -> Tuple[UInt8, Int32]:
    var x = _field_from_montgomery(r)
    var r1 = _high_bits88(x)
    var r0 = Int32(x) - Int32(r1) * 2 * Int32((Q - 1) // 88)
    if Int32(Q // 2 + 1) <= r0:
        r0 -= Int32(Q)
    return (r1, r0)


def _use_hint_elem(r: UInt32, hint: UInt8, p: MLDSAParams) -> UInt8:
    if p.gamma2_denom == 32:
        var d = _decompose32(r)
        var r1 = d[0]
        var r0 = d[1]
        if hint == 1:
            if r0 > 0:
                r1 = (r1 + 1) % 16
            else:
                r1 = (r1 - 1) % 16
        return r1
    var d = _decompose88(r)
    var r1 = d[0]
    var r0 = d[1]
    if hint == 1:
        if r0 > 0:
            if r1 == 43:
                r1 = 0
            else:
                r1 += 1
        else:
            if r1 == 0:
                r1 = 43
            else:
                r1 -= 1
    return r1


def _make_hint_elem(ct0: UInt32, w: UInt32, cs2: UInt32, p: MLDSAParams) -> UInt8:
    var r_plus_z = _field_sub(w, cs2)
    if p.gamma2_denom == 32:
        var v1 = _high_bits32(_field_from_montgomery(r_plus_z))
        var r1 = _high_bits32(_field_from_montgomery(_field_add(r_plus_z, ct0)))
        return UInt8(_ct_bool_to_u32(v1 != r1))
    var v1 = _high_bits88(_field_from_montgomery(r_plus_z))
    var r1 = _high_bits88(_field_from_montgomery(_field_add(r_plus_z, ct0)))
    return UInt8(_ct_bool_to_u32(v1 != r1))


def _make_hint_into(mut h: List[UInt8], ct0: List[UInt32], w: List[UInt32], cs2: List[UInt32], p: MLDSAParams) -> Int:
    var count = 0
    for i in range(N):
        var bit = _make_hint_elem(ct0[i], w[i], cs2[i], p)
        h[i] = bit
        count += Int(bit)
    return count


def _dsa_make_hint_into(mut h: DSAHintRow, ct0: DSAPoly, w: DSAPoly, cs2: DSAPoly, p: MLDSAParams) -> Int:
    var count = 0
    for i in range(N):
        var bit = _make_hint_elem(ct0[i], w[i], cs2[i], p)
        h[i] = bit
        count += Int(bit)
    return count


def _make_hint(ct0: List[UInt32], w: List[UInt32], cs2: List[UInt32], p: MLDSAParams) -> Tuple[List[UInt8], Int]:
    var h = List[UInt8](unsafe_uninit_length=N)
    var count = _make_hint_into(h, ct0, w, cs2, p)
    return (h^, count)


def _coefficients_exceed_bound(w: List[UInt32], bound: UInt32) -> Bool:
    var fail = UInt32(0)
    for i in range(N):
        fail |= _ct_bool_to_u32(_infinity_norm(w[i]) >= bound)
    return fail != UInt32(0)


def _dsa_coefficients_exceed_bound(w: DSAPoly, bound: UInt32) -> Bool:
    var fail = UInt32(0)
    for i in range(N):
        fail |= _ct_bool_to_u32(_infinity_norm(w[i]) >= bound)
    return fail != UInt32(0)


def _low_bits_exceed_bound(w: List[UInt32], bound: UInt32, p: MLDSAParams) -> Bool:
    var fail = UInt32(0)
    if p.gamma2_denom == 32:
        for i in range(N):
            var d = _decompose32(w[i])
            fail |= _ct_bool_to_u32(_abs_i32(d[1]) >= bound)
    else:
        for i in range(N):
            var d = _decompose88(w[i])
            fail |= _ct_bool_to_u32(_abs_i32(d[1]) >= bound)
    return fail != UInt32(0)


def _dsa_low_bits_exceed_bound(w: DSAPoly, bound: UInt32, p: MLDSAParams) -> Bool:
    var fail = UInt32(0)
    if p.gamma2_denom == 32:
        for i in range(N):
            var d = _decompose32(w[i])
            fail |= _ct_bool_to_u32(_abs_i32(d[1]) >= bound)
    else:
        for i in range(N):
            var d = _decompose88(w[i])
            fail |= _ct_bool_to_u32(_abs_i32(d[1]) >= bound)
    return fail != UInt32(0)


def _pk_encode(rho: Span[UInt8, ...], t1: List[List[UInt16]], p: MLDSAParams) -> List[UInt8]:
    var pk = List[UInt8](capacity=public_key_size(p))
    _append_bytes(pk, rho)
    for r in range(p.k):
        var w = t1[r].copy()
        for i in range(0, N, 4):
            var c0 = w[i]
            var c1 = w[i + 1]
            var c2 = w[i + 2]
            var c3 = w[i + 3]
            pk.append(UInt8(c0))
            pk.append(UInt8((c0 >> 8) | (c1 << 2)))
            pk.append(UInt8((c1 >> 6) | (c2 << 4)))
            pk.append(UInt8((c2 >> 4) | (c3 << 6)))
            pk.append(UInt8(c3 >> 2))
    return pk^


def _pk_decode(pk: Span[UInt8, ...], p: MLDSAParams) raises -> Tuple[List[UInt8], List[List[UInt16]]]:
    if len(pk) != public_key_size(p):
        raise Error("ML-DSA invalid public key length")
    var rho = _slice_bytes(pk, 0, 32)
    var t1 = List[List[UInt16]](capacity=p.k)
    var off = 32
    for _ in range(p.k):
        var row = List[UInt16](capacity=N)
        for _i in range(0, N, 4):
            var b0 = pk[off]
            var b1 = pk[off + 1]
            var b2 = pk[off + 2]
            var b3 = pk[off + 3]
            var b4 = pk[off + 4]
            off += 5
            row.append(UInt16(b0) | (UInt16(b1 & 0x03) << 8))
            row.append((UInt16(b1) >> 2) | (UInt16(b2 & 0x0F) << 6))
            row.append((UInt16(b2) >> 4) | (UInt16(b3 & 0x3F) << 4))
            row.append((UInt16(b3) >> 6) | (UInt16(b4) << 2))
        t1.append(row^)
    return (rho^, t1^)


def _compute_matrix_a(rho: Span[UInt8, ...], p: MLDSAParams) raises -> List[List[UInt32]]:
    var a = List[List[UInt32]](capacity=p.k * p.l)
    for r in range(p.k):
        for s in range(p.l):
            a.append(_sample_ntt(rho, UInt8(s), UInt8(r)))
    return a^


def _compute_public_key_hash(pk: Span[UInt8, ...]) -> List[UInt8]:
    return shake256(pk, 64)


def _compute_t1_hat(t1: List[List[UInt16]], p: MLDSAParams) raises -> List[List[UInt32]]:
    var t1_hat = List[List[UInt32]](capacity=p.k)
    for i in range(p.k):
        var w = List[UInt32](capacity=N)
        for j in range(N):
            w.append(_field_to_montgomery_unchecked(UInt32(t1[i][j]) << 13))
        t1_hat.append(_ntt(w^))
    return t1_hat^


def new_public_key(pk: Span[UInt8, ...], p: MLDSAParams) raises -> MLDSAPublicKey:
    var decoded = _pk_decode(pk, p)
    var rho = decoded[0].copy()
    var t1 = decoded[1].copy()
    var raw = _copy_bytes(pk)
    var a = _compute_matrix_a(Span[UInt8, ...](rho), p)
    var tr = _compute_public_key_hash(pk)
    var t1_hat = _compute_t1_hat(t1, p)
    return MLDSAPublicKey(p.copy(), raw^, a^, t1_hat^, tr^)


def _bit_unpack18_into(mut r: List[UInt32], v: Span[UInt8, ...]):
    var off = 0
    var j = 0
    for _ in range(0, N, 4):
        var w0 = UInt32(v[off]) | (UInt32(v[off + 1]) << 8) | (UInt32(v[off + 2]) << 16)
        var w1 = (UInt32(v[off + 2]) >> 2) | (UInt32(v[off + 3]) << 6) | (UInt32(v[off + 4]) << 14)
        var w2 = (UInt32(v[off + 4]) >> 4) | (UInt32(v[off + 5]) << 4) | (UInt32(v[off + 6]) << 12)
        var w3 = (UInt32(v[off + 6]) >> 6) | (UInt32(v[off + 7]) << 2) | (UInt32(v[off + 8]) << 10)
        r[j] = _field_sub_to_montgomery(1 << 17, w0 & 0x3FFFF)
        r[j + 1] = _field_sub_to_montgomery(1 << 17, w1 & 0x3FFFF)
        r[j + 2] = _field_sub_to_montgomery(1 << 17, w2 & 0x3FFFF)
        r[j + 3] = _field_sub_to_montgomery(1 << 17, w3 & 0x3FFFF)
        off += 9
        j += 4


def _dsa_bit_unpack18_into(mut r: DSAPoly, v: Span[UInt8, ...]):
    var off = 0
    var j = 0
    for _ in range(0, N, 4):
        var w0 = UInt32(v[off]) | (UInt32(v[off + 1]) << 8) | (UInt32(v[off + 2]) << 16)
        var w1 = (UInt32(v[off + 2]) >> 2) | (UInt32(v[off + 3]) << 6) | (UInt32(v[off + 4]) << 14)
        var w2 = (UInt32(v[off + 4]) >> 4) | (UInt32(v[off + 5]) << 4) | (UInt32(v[off + 6]) << 12)
        var w3 = (UInt32(v[off + 6]) >> 6) | (UInt32(v[off + 7]) << 2) | (UInt32(v[off + 8]) << 10)
        r[j] = _field_sub_to_montgomery(1 << 17, w0 & 0x3FFFF)
        r[j + 1] = _field_sub_to_montgomery(1 << 17, w1 & 0x3FFFF)
        r[j + 2] = _field_sub_to_montgomery(1 << 17, w2 & 0x3FFFF)
        r[j + 3] = _field_sub_to_montgomery(1 << 17, w3 & 0x3FFFF)
        off += 9
        j += 4


def _bit_unpack18(v: Span[UInt8, ...]) -> List[UInt32]:
    var r = List[UInt32](unsafe_uninit_length=N)
    _bit_unpack18_into(r, v)
    return r^


def _bit_unpack20_into(mut r: List[UInt32], v: Span[UInt8, ...]):
    var off = 0
    var j = 0
    for _ in range(0, N, 2):
        var w0 = UInt32(v[off]) | (UInt32(v[off + 1]) << 8) | (UInt32(v[off + 2]) << 16)
        var w1 = (UInt32(v[off + 2]) >> 4) | (UInt32(v[off + 3]) << 4) | (UInt32(v[off + 4]) << 12)
        r[j] = _field_sub_to_montgomery(1 << 19, w0 & 0xFFFFF)
        r[j + 1] = _field_sub_to_montgomery(1 << 19, w1 & 0xFFFFF)
        off += 5
        j += 2


def _dsa_bit_unpack20_into(mut r: DSAPoly, v: Span[UInt8, ...]):
    var off = 0
    var j = 0
    for _ in range(0, N, 2):
        var w0 = UInt32(v[off]) | (UInt32(v[off + 1]) << 8) | (UInt32(v[off + 2]) << 16)
        var w1 = (UInt32(v[off + 2]) >> 4) | (UInt32(v[off + 3]) << 4) | (UInt32(v[off + 4]) << 12)
        r[j] = _field_sub_to_montgomery(1 << 19, w0 & 0xFFFFF)
        r[j + 1] = _field_sub_to_montgomery(1 << 19, w1 & 0xFFFFF)
        off += 5
        j += 2


def _bit_unpack20(v: Span[UInt8, ...]) -> List[UInt32]:
    var r = List[UInt32](unsafe_uninit_length=N)
    _bit_unpack20_into(r, v)
    return r^


def _bit_unpack_into(mut r: List[UInt32], v: Span[UInt8, ...], p: MLDSAParams):
    if p.gamma1_log == 17:
        _bit_unpack18_into(r, v)
    else:
        _bit_unpack20_into(r, v)


def _dsa_bit_unpack_into(mut r: DSAPoly, v: Span[UInt8, ...], p: MLDSAParams):
    if p.gamma1_log == 17:
        _dsa_bit_unpack18_into(r, v)
    else:
        _dsa_bit_unpack20_into(r, v)


def _bit_unpack(v: Span[UInt8, ...], p: MLDSAParams) -> List[UInt32]:
    var r = List[UInt32](unsafe_uninit_length=N)
    _bit_unpack_into(r, v, p)
    return r^


def _bit_pack18(mut out: List[UInt8], r: List[UInt32]):
    for i in range(0, N, 4):
        var w0 = Int32(1 << 17) - _centered_mod(r[i])
        var w1 = Int32(1 << 17) - _centered_mod(r[i + 1])
        var w2 = Int32(1 << 17) - _centered_mod(r[i + 2])
        var w3 = Int32(1 << 17) - _centered_mod(r[i + 3])
        out.append(UInt8(w0))
        out.append(UInt8(w0 >> 8))
        out.append(UInt8((w0 >> 16) | (w1 << 2)))
        out.append(UInt8(w1 >> 6))
        out.append(UInt8((w1 >> 14) | (w2 << 4)))
        out.append(UInt8(w2 >> 4))
        out.append(UInt8((w2 >> 12) | (w3 << 6)))
        out.append(UInt8(w3 >> 2))
        out.append(UInt8(w3 >> 10))


def _bit_pack20(mut out: List[UInt8], r: List[UInt32]):
    for i in range(0, N, 2):
        var w0 = Int32(1 << 19) - _centered_mod(r[i])
        var w1 = Int32(1 << 19) - _centered_mod(r[i + 1])
        out.append(UInt8(w0))
        out.append(UInt8(w0 >> 8))
        out.append(UInt8((w0 >> 16) | (w1 << 4)))
        out.append(UInt8(w1 >> 4))
        out.append(UInt8(w1 >> 12))


def _bit_pack(mut out: List[UInt8], r: List[UInt32], p: MLDSAParams):
    if p.gamma1_log == 17:
        _bit_pack18(out, r)
    else:
        _bit_pack20(out, r)


def _dsa_bit_pack18(mut out: List[UInt8], r: DSAPoly):
    for i in range(0, N, 4):
        var w0 = Int32(1 << 17) - _centered_mod(r[i])
        var w1 = Int32(1 << 17) - _centered_mod(r[i + 1])
        var w2 = Int32(1 << 17) - _centered_mod(r[i + 2])
        var w3 = Int32(1 << 17) - _centered_mod(r[i + 3])
        out.append(UInt8(w0))
        out.append(UInt8(w0 >> 8))
        out.append(UInt8((w0 >> 16) | (w1 << 2)))
        out.append(UInt8(w1 >> 6))
        out.append(UInt8((w1 >> 14) | (w2 << 4)))
        out.append(UInt8(w2 >> 4))
        out.append(UInt8((w2 >> 12) | (w3 << 6)))
        out.append(UInt8(w3 >> 2))
        out.append(UInt8(w3 >> 10))


def _dsa_bit_pack20(mut out: List[UInt8], r: DSAPoly):
    for i in range(0, N, 2):
        var w0 = Int32(1 << 19) - _centered_mod(r[i])
        var w1 = Int32(1 << 19) - _centered_mod(r[i + 1])
        out.append(UInt8(w0))
        out.append(UInt8(w0 >> 8))
        out.append(UInt8((w0 >> 16) | (w1 << 4)))
        out.append(UInt8(w1 >> 4))
        out.append(UInt8(w1 >> 12))


def _dsa_bit_pack(mut out: List[UInt8], r: DSAPoly, p: MLDSAParams):
    if p.gamma1_log == 17:
        _dsa_bit_pack18(out, r)
    else:
        _dsa_bit_pack20(out, r)


def _bit_unpack_slow(v: Span[UInt8, ...], a: Int, b: Int) raises -> List[UInt32]:
    var bitlen = 0
    var total = a + b
    while total > 0:
        bitlen += 1
        total >>= 1
    if len(v) != N * bitlen // 8:
        raise Error("ML-DSA invalid slow unpack length")
    var mask = UInt32((1 << bitlen) - 1)
    var max_value = UInt32(a + b)
    var r = List[UInt32](capacity=N)
    var acc: UInt32 = 0
    var acc_bits = 0
    var v_idx = 0
    for _ in range(N):
        while acc_bits < bitlen:
            if v_idx < len(v):
                acc |= UInt32(v[v_idx]) << UInt32(acc_bits)
                v_idx += 1
                acc_bits += 8
        var w = acc & mask
        if w > max_value:
            raise Error("ML-DSA coefficient out of range")
        r.append(_field_sub_to_montgomery(UInt32(b), w))
        acc >>= UInt32(bitlen)
        acc_bits -= bitlen
    return r^


def _append_w1_encoded_stack(mut out: StackBuffer[UInt8, ...], w: List[UInt32], p: MLDSAParams):
    if p.gamma2_denom == 32:
        for i in range(0, N, 2):
            var b0 = _high_bits32(_field_from_montgomery(w[i]))
            var b1 = _high_bits32(_field_from_montgomery(w[i + 1]))
            out.push_unchecked(b0 | (b1 << 4))
    else:
        for i in range(0, N, 4):
            var b0 = _high_bits88(_field_from_montgomery(w[i]))
            var b1 = _high_bits88(_field_from_montgomery(w[i + 1]))
            var b2 = _high_bits88(_field_from_montgomery(w[i + 2]))
            var b3 = _high_bits88(_field_from_montgomery(w[i + 3]))
            out.push_unchecked((b0 >> 0) | (b1 << 6))
            out.push_unchecked((b1 >> 2) | (b2 << 4))
            out.push_unchecked((b2 >> 4) | (b3 << 2))


def _dsa_append_w1_encoded_stack(mut out: StackBuffer[UInt8, ...], w: DSAPoly, p: MLDSAParams):
    if p.gamma2_denom == 32:
        for i in range(0, N, 2):
            var b0 = _high_bits32(_field_from_montgomery(w[i]))
            var b1 = _high_bits32(_field_from_montgomery(w[i + 1]))
            out.push_unchecked(b0 | (b1 << 4))
    else:
        for i in range(0, N, 4):
            var b0 = _high_bits88(_field_from_montgomery(w[i]))
            var b1 = _high_bits88(_field_from_montgomery(w[i + 1]))
            var b2 = _high_bits88(_field_from_montgomery(w[i + 2]))
            var b3 = _high_bits88(_field_from_montgomery(w[i + 3]))
            out.push_unchecked((b0 >> 0) | (b1 << 6))
            out.push_unchecked((b1 >> 2) | (b2 << 4))
            out.push_unchecked((b2 >> 4) | (b3 << 2))


def _append_use_hint_encoded_stack(mut out: StackBuffer[UInt8, ...], w: List[UInt32], h: List[UInt8], p: MLDSAParams):
    if p.gamma2_denom == 32:
        for i in range(0, N, 2):
            var b0 = _use_hint_elem(w[i], h[i], p)
            var b1 = _use_hint_elem(w[i + 1], h[i + 1], p)
            out.push_unchecked(b0 | (b1 << 4))
    else:
        for i in range(0, N, 4):
            var b0 = _use_hint_elem(w[i], h[i], p)
            var b1 = _use_hint_elem(w[i + 1], h[i + 1], p)
            var b2 = _use_hint_elem(w[i + 2], h[i + 2], p)
            var b3 = _use_hint_elem(w[i + 3], h[i + 3], p)
            out.push_unchecked((b0 >> 0) | (b1 << 6))
            out.push_unchecked((b1 >> 2) | (b2 << 4))
            out.push_unchecked((b2 >> 4) | (b3 << 2))


def _hint_encode(mut out: List[UInt8], h: List[List[UInt8]], p: MLDSAParams):
    var y = List[UInt8](unsafe_uninit_length=p.omega + p.k)
    _zero_list_u8(y)
    var idx: UInt8 = 0
    for i in range(p.k):
        for j in range(N):
            if h[i][j] != 0:
                y[Int(idx)] = UInt8(j)
                idx += 1
        y[p.omega + i] = idx
    _append_bytes(out, Span[UInt8, ...](y))
    _zero_list_u8(y)


def _dsa_hint_encode(mut out: List[UInt8], h: DSAHintVec, p: MLDSAParams):
    var y = List[UInt8](unsafe_uninit_length=p.omega + p.k)
    _zero_list_u8(y)
    var idx: UInt8 = 0
    for i in range(p.k):
        for j in range(N):
            if h[i][j] != 0:
                y[Int(idx)] = UInt8(j)
                idx += 1
        y[p.omega + i] = idx
    _append_bytes(out, Span[UInt8, ...](y))
    _zero_list_u8(y)


def _hint_decode(y: Span[UInt8, ...], p: MLDSAParams) raises -> List[List[UInt8]]:
    if len(y) != p.omega + p.k:
        raise Error("ML-DSA invalid hint length")
    var h = List[List[UInt8]](capacity=p.k)
    var idx: UInt8 = 0
    for i in range(p.k):
        var row = List[UInt8](unsafe_uninit_length=N)
        _zero_list_u8(row)
        var limit = y[p.omega + i]
        if limit < idx or limit > UInt8(p.omega):
            raise Error("ML-DSA invalid hint limits")
        var first = idx
        while idx < limit:
            if idx > first and y[Int(idx) - 1] >= y[Int(idx)]:
                raise Error("ML-DSA invalid hint order")
            row[Int(y[Int(idx)])] = 1
            idx += 1
        h.append(row^)
    var i = Int(idx)
    while i < p.omega:
        if y[i] != 0:
            raise Error("ML-DSA invalid hint extra indices")
        i += 1
    return h^


def _sig_encode(ch: Span[UInt8, ...], z: List[List[UInt32]], h: List[List[UInt8]], p: MLDSAParams) -> List[UInt8]:
    var sig = List[UInt8](capacity=signature_size(p))
    _append_bytes(sig, ch)
    for i in range(p.l):
        _bit_pack(sig, z[i], p)
    _hint_encode(sig, h, p)
    return sig^


def _dsa_sig_encode(ch: InlineArray[UInt8, MLDSA_CRHBYTES], z: DSAPolyVec[MAX_L], h: DSAHintVec, p: MLDSAParams) -> List[UInt8]:
    var sig = List[UInt8](capacity=signature_size(p))
    for i in range(p.lambda_bits // 4):
        sig.append(ch[i])
    for i in range(p.l):
        _dsa_bit_pack(sig, z[i], p)
    _dsa_hint_encode(sig, h, p)
    return sig^


def _sig_decode(sig: Span[UInt8, ...], p: MLDSAParams) raises -> Tuple[List[UInt8], List[List[UInt32]], List[List[UInt8]]]:
    if len(sig) != signature_size(p):
        raise Error("ML-DSA invalid signature length")
    var ch_len = p.lambda_bits // 4
    var ch = _copy_bytes(sig.unsafe_subspan(offset=0, length=ch_len))
    var z = List[List[UInt32]](capacity=p.l)
    var off = ch_len
    var part_len = (p.gamma1_log + 1) * N // 8
    for _ in range(p.l):
        z.append(_bit_unpack(sig.unsafe_subspan(offset=off, length=part_len), p))
        off += part_len
    var h = _hint_decode(sig.unsafe_subspan(offset=off, length=p.omega + p.k), p)
    return (ch^, z^, h^)


def _compute_message_hash(tr: Span[UInt8, ...], msg: Span[UInt8, ...], context: Span[UInt8, ...]) raises -> List[UInt8]:
    if len(context) > 255:
        raise Error("ML-DSA context too long")

	# Stream buffer from SHAKE_final
    var ctx = SHA3Context(1088)
    sha3_update(ctx, tr)

    var prefix = StackBuffer[UInt8, 2]()
    prefix.push_unchecked(UInt8(0))
    prefix.push_unchecked(UInt8(len(context)))
    sha3_update(ctx, Span[UInt8, ...](ptr=prefix.ptr(), length=prefix.len()))
    _zero_stack_u8(prefix)

    sha3_update(ctx, context)
    sha3_update(ctx, msg)
    return shake_final(ctx, MLDSA_CRHBYTES)


def mldsa_public_key_from_seed(seed: Span[UInt8, ...], p: MLDSAParams) raises -> MLDSAPublicKey:
    return mldsa_private_key_from_seed(seed, p).pub.copy()


def mldsa_private_key_from_seed(seed: Span[UInt8, ...], p: MLDSAParams) raises -> MLDSAPrivateKey:
    if len(seed) != 32:
        raise Error("ML-DSA invalid seed length")
    var xi = StackBuffer[UInt8, 34]()
    _append_bytes_stack(xi, seed)
    xi.push_unchecked(UInt8(p.k))
    xi.push_unchecked(UInt8(p.l))
    var expanded = shake256(Span[UInt8, ...](ptr=xi.ptr(), length=xi.len()), 128)
    _zero_stack_u8(xi)
    var rho = _slice_bytes(Span[UInt8, ...](expanded), 0, 32)
    var rho_s = _slice_bytes(Span[UInt8, ...](expanded), 32, 64)
    var k_seed = _slice_bytes(Span[UInt8, ...](expanded), 96, 32)
    var a = _compute_matrix_a(Span[UInt8, ...](rho), p)

    var s1 = List[List[UInt32]](capacity=p.l)
    for r in range(p.l):
        s1.append(_ntt(_sample_bounded_poly(Span[UInt8, ...](rho_s), UInt8(r), p)))
    var s2 = List[List[UInt32]](capacity=p.k)
    for r in range(p.k):
        s2.append(_ntt(_sample_bounded_poly(Span[UInt8, ...](rho_s), UInt8(p.l + r), p)))

    var t_hat = List[List[UInt32]](capacity=p.k)
    for i in range(p.k):
        var row = s2[i].copy()
        var product = _zero_poly()
        for j in range(p.l):
            _ntt_mul_into(product, a[i * p.l + j], s1[j])
            _poly_add_into(row, product)
        t_hat.append(row^)
        _zero_list_u32(product)

    var t1 = List[List[UInt16]](capacity=p.k)
    var t0 = List[List[UInt32]](capacity=p.k)
    for i in range(p.k):
        var t = _inverse_ntt(t_hat[i].copy())
        var row_t1 = List[UInt16](capacity=N)
        var row_t0 = List[UInt32](capacity=N)
        for j in range(N):
            var pr = _power2_round(t[j])
            row_t1.append(pr[0])
            row_t0.append(pr[1])
        t1.append(row_t1^)
        t0.append(_ntt(row_t0^))
        _zero_list_u32(t)

    var pk = _pk_encode(Span[UInt8, ...](rho), t1, p)
    var tr = _compute_public_key_hash(Span[UInt8, ...](pk))
    var t1_hat = _compute_t1_hat(t1, p)
    var pub = MLDSAPublicKey(p.copy(), pk^, a^, t1_hat^, tr^)
    _zero_list_u8(expanded)
    _zero_list_u8(rho_s)
    _zero_poly_vec_u32(t_hat)
    return MLDSAPrivateKey(p.copy(), _copy_bytes(seed), pub^, s1^, s2^, t0^, k_seed^)


def mldsa_private_key_from_semiexpanded(sk: Span[UInt8, ...], p: MLDSAParams) raises -> MLDSAPrivateKey:
    if len(sk) != private_key_size(p):
        raise Error("ML-DSA invalid semi-expanded private key length")
    var rho = _slice_bytes(sk, 0, 32)
    var k_seed = _slice_bytes(sk, 32, 32)
    var tr = _slice_bytes(sk, 64, 64)
    var off = 128
    var eta_bitlen = 3
    if p.eta == 4:
        eta_bitlen = 4
    var s1_plain = List[List[UInt32]](capacity=p.l)
    for _ in range(p.l):
        var length = N * eta_bitlen // 8
        s1_plain.append(_bit_unpack_slow(sk.unsafe_subspan(offset=off, length=length), p.eta, p.eta))
        off += length
    var s2_plain = List[List[UInt32]](capacity=p.k)
    for _ in range(p.k):
        var length = N * eta_bitlen // 8
        s2_plain.append(_bit_unpack_slow(sk.unsafe_subspan(offset=off, length=length), p.eta, p.eta))
        off += length
    var t0_plain = List[List[UInt32]](capacity=p.k)
    for _ in range(p.k):
        var length = N * 13 // 8
        t0_plain.append(_bit_unpack_slow(sk.unsafe_subspan(offset=off, length=length), (1 << 12) - 1, 1 << 12))
        off += length

    var a = _compute_matrix_a(Span[UInt8, ...](rho), p)
    var s1 = _zero_poly_vec(p.l)
    for i in range(p.l):
        s1[i] = _ntt(s1_plain[i].copy())
    var s2 = _zero_poly_vec(p.k)
    for i in range(p.k):
        s2[i] = _ntt(s2_plain[i].copy())
    var t0 = _zero_poly_vec(p.k)
    for i in range(p.k):
        t0[i] = _ntt(t0_plain[i].copy())

    var t1 = List[List[UInt16]](capacity=p.k)
    for i in range(p.k):
        var t_hat = s2[i].copy()
        var product = _zero_poly()
        for j in range(p.l):
            _ntt_mul_into(product, a[i * p.l + j], s1[j])
            _poly_add_into(t_hat, product)
        _zero_list_u32(product)
        var t = _inverse_ntt(t_hat^)
        var row_t1 = List[UInt16](capacity=N)
        var t0_mismatch = UInt32(0)
        for j in range(N):
            var pr = _power2_round(t[j])
            row_t1.append(pr[0])
            t0_mismatch |= _ct_bool_to_u32(pr[1] != t0_plain[i][j])
        if t0_mismatch != UInt32(0):
            _zero_list_u32(t)
            _zero_poly_vec_u32(s1_plain)
            _zero_poly_vec_u32(s2_plain)
            _zero_poly_vec_u32(t0_plain)
            _zero_poly_vec_u32(s1)
            _zero_poly_vec_u32(s2)
            _zero_poly_vec_u32(t0)
            raise Error("ML-DSA inconsistent t0")
        t1.append(row_t1^)
        _zero_list_u32(t)
    var pk = _pk_encode(Span[UInt8, ...](rho), t1, p)
    var computed_tr = _compute_public_key_hash(Span[UInt8, ...](pk))
    if not _bytes_equal(Span[UInt8, ...](computed_tr), Span[UInt8, ...](tr)):
        _zero_list_u8(computed_tr)
        _zero_poly_vec_u32(s1_plain)
        _zero_poly_vec_u32(s2_plain)
        _zero_poly_vec_u32(t0_plain)
        _zero_poly_vec_u32(s1)
        _zero_poly_vec_u32(s2)
        _zero_poly_vec_u32(t0)
        raise Error("ML-DSA inconsistent public key hash")
    _zero_list_u8(computed_tr)
    var t1_hat = _compute_t1_hat(t1, p)
    var pub = MLDSAPublicKey(p.copy(), pk^, a^, t1_hat^, tr^)
    _zero_poly_vec_u32(s1_plain)
    _zero_poly_vec_u32(s2_plain)
    _zero_poly_vec_u32(t0_plain)
    return MLDSAPrivateKey(p.copy(), List[UInt8](), pub^, s1^, s2^, t0^, k_seed^)


def mldsa_sign_external_mu(priv: MLDSAPrivateKey, mu: Span[UInt8, ...], random: Span[UInt8, ...]) raises -> List[UInt8]:
    if len(mu) != 64 or len(random) != 32:
        raise Error("ML-DSA invalid sign input")
    var p = priv.p.copy()
    var beta = p.tau * p.eta
    var gamma1 = UInt32(1 << p.gamma1_log)
    var gamma1_beta = gamma1 - UInt32(beta)
    var gamma2 = (Q - 1) // UInt32(p.gamma2_denom)
    var gamma2_beta = gamma2 - UInt32(beta)

    var h_input = StackBuffer[UInt8, 128]()
    _append_bytes_stack(h_input, Span[UInt8, ...](priv.k_seed))
    _append_bytes_stack(h_input, random)
    _append_bytes_stack(h_input, mu)
    var nonce = shake256(Span[UInt8, ...](ptr=h_input.ptr(), length=h_input.len()), 64)
    _zero_stack_u8(h_input)

    # Signing-attempt scratch is allocated once and reused.
    # Note: Still not constant time but reduces a lot of "noise".
    var y = DSAPolyVec[MAX_L]()
    var y_hat = DSAPolyVec[MAX_L]()
    var w = DSAPolyVec[MAX_K]()
    var cs1 = DSAPolyVec[MAX_L]()
    var cs2 = DSAPolyVec[MAX_K]()
    var z = DSAPolyVec[MAX_L]()
    var ct0 = DSAPolyVec[MAX_K]()
    var h = DSAHintVec(fill=DSAHintRow(fill=0))
    var product = DSAPoly(fill=0)

    var kappa = 0
    while True:
        for _r in range(p.l):
            var seed = StackBuffer[UInt8, MLDSA_CRHBYTES + 2]()
            for i in range(MLDSA_CRHBYTES):
                seed.push_unchecked(nonce[i])
            seed.push_unchecked(UInt8(kappa & 0xFF))
            seed.push_unchecked(UInt8((kappa >> 8) & 0xFF))
            kappa += 1
            var v = shake256(Span[UInt8, ...](ptr=seed.ptr(), length=seed.len()), (p.gamma1_log + 1) * N // 8)
            _zero_stack_u8(seed)
            _dsa_bit_unpack_into(y[_r], Span[UInt8, ...](v), p)
            _zero_list_u8(v)

        for i in range(p.l):
            _dsa_copy_poly_into(y_hat[i], y[i])
            _dsa_ntt_inplace(y_hat[i])

        for i in range(p.k):
            _zero_dsa_poly(w[i])
            for j in range(p.l):
                _dsa_ntt_mul_into(product, priv.pub.a[i * p.l + j], y_hat[j])
                _dsa_poly_add_into(w[i], product)
            _dsa_inverse_ntt_inplace(w[i])

        var ch_input = StackBuffer[UInt8, MLDSA_CRHBYTES + MAX_K * 192]()
        _append_bytes_stack(ch_input, mu)
        for i in range(p.k):
            _dsa_append_w1_encoded_stack(ch_input, w[i], p)
        var ch_list = shake256(Span[UInt8, ...](ptr=ch_input.ptr(), length=ch_input.len()), p.lambda_bits // 4)
        _zero_stack_u8(ch_input)
        var ch = InlineArray[UInt8, MLDSA_CRHBYTES](fill=0)
        for i in range(p.lambda_bits // 4):
            ch[i] = ch_list[i]
        var c = _sample_in_ball_dsa(Span[UInt8, ...](ch_list), p)
        _dsa_ntt_inplace(c)

        for i in range(p.l):
            _dsa_ntt_mul_into(cs1[i], c, priv.s1[i])
            _dsa_inverse_ntt_inplace(cs1[i])
        for i in range(p.k):
            _dsa_ntt_mul_into(cs2[i], c, priv.s2[i])
            _dsa_inverse_ntt_inplace(cs2[i])

        var rejected_flag = UInt32(0)
        for i in range(p.l):
            _dsa_copy_poly_into(z[i], y[i])
            _dsa_poly_add_into(z[i], cs1[i])
            rejected_flag |= _ct_bool_to_u32(_dsa_coefficients_exceed_bound(z[i], gamma1_beta))
        var rejected = rejected_flag != UInt32(0)
        if rejected:
            _zero_dsa_poly_vec(y)
            _zero_dsa_poly_vec(y_hat)
            _zero_dsa_poly_vec(w)
            _zero_dsa_poly_vec(cs1)
            _zero_dsa_poly_vec(cs2)
            _zero_dsa_poly_vec(z)
            _zero_dsa_poly_vec(ct0)
            _zero_dsa_hint_vec(h)
            _zero_dsa_poly(product)
            _zero_dsa_ch(ch)
            _zero_list_u8(ch_list)
            _zero_dsa_poly(c)
            continue

        rejected_flag = UInt32(0)
        for i in range(p.k):
            _dsa_copy_poly_into(product, w[i])
            _dsa_poly_sub_into(product, cs2[i])
            rejected_flag |= _ct_bool_to_u32(_dsa_low_bits_exceed_bound(product, gamma2_beta, p))
            _zero_dsa_poly(product)
        rejected = rejected_flag != UInt32(0)
        if rejected:
            _zero_dsa_poly_vec(y)
            _zero_dsa_poly_vec(y_hat)
            _zero_dsa_poly_vec(w)
            _zero_dsa_poly_vec(cs1)
            _zero_dsa_poly_vec(cs2)
            _zero_dsa_poly_vec(z)
            _zero_dsa_poly_vec(ct0)
            _zero_dsa_hint_vec(h)
            _zero_dsa_ch(ch)
            _zero_list_u8(ch_list)
            _zero_dsa_poly(c)
            continue

        rejected_flag = UInt32(0)
        for i in range(p.k):
            _dsa_ntt_mul_into(ct0[i], c, priv.t0[i])
            _dsa_inverse_ntt_inplace(ct0[i])
            rejected_flag |= _ct_bool_to_u32(_dsa_coefficients_exceed_bound(ct0[i], gamma2))
        rejected = rejected_flag != UInt32(0)
        if rejected:
            _zero_dsa_poly_vec(y)
            _zero_dsa_poly_vec(y_hat)
            _zero_dsa_poly_vec(w)
            _zero_dsa_poly_vec(cs1)
            _zero_dsa_poly_vec(cs2)
            _zero_dsa_poly_vec(z)
            _zero_dsa_poly_vec(ct0)
            _zero_dsa_hint_vec(h)
            _zero_dsa_ch(ch)
            _zero_list_u8(ch_list)
            _zero_dsa_poly(c)
            continue

        var count1s = 0
        for i in range(p.k):
            count1s += _dsa_make_hint_into(h[i], ct0[i], w[i], cs2[i], p)
        if count1s > p.omega:
            _zero_dsa_poly_vec(y)
            _zero_dsa_poly_vec(y_hat)
            _zero_dsa_poly_vec(w)
            _zero_dsa_poly_vec(cs1)
            _zero_dsa_poly_vec(cs2)
            _zero_dsa_poly_vec(z)
            _zero_dsa_poly_vec(ct0)
            _zero_dsa_hint_vec(h)
            _zero_dsa_ch(ch)
            _zero_list_u8(ch_list)
            _zero_dsa_poly(c)
            continue
        var sig = _dsa_sig_encode(ch, z, h, p)
        _zero_dsa_poly_vec(y)
        _zero_dsa_poly_vec(y_hat)
        _zero_dsa_poly_vec(w)
        _zero_dsa_poly_vec(cs1)
        _zero_dsa_poly_vec(cs2)
        _zero_dsa_poly_vec(z)
        _zero_dsa_poly_vec(ct0)
        _zero_dsa_hint_vec(h)
        _zero_dsa_poly(product)
        _zero_dsa_ch(ch)
        _zero_list_u8(ch_list)
        _zero_dsa_poly(c)
        _zero_list_u8(nonce)
        return sig^


def mldsa_sign(priv: MLDSAPrivateKey, msg: Span[UInt8, ...], context: Span[UInt8, ...], random: Span[UInt8, ...]) raises -> List[UInt8]:
    var mu = _compute_message_hash(Span[UInt8, ...](priv.pub.tr), msg, context)
    var sig = mldsa_sign_external_mu(priv, Span[UInt8, ...](mu), random)
    _zero_list_u8(mu)
    return sig^


def mldsa_verify_external_mu(pub: MLDSAPublicKey, mu: Span[UInt8, ...], sig: Span[UInt8, ...]) raises -> Bool:
    if len(mu) != 64:
        return False
    var p = pub.p.copy()
    var beta = p.tau * p.eta
    var gamma1 = UInt32(1 << p.gamma1_log)
    var gamma1_beta = gamma1 - UInt32(beta)
    var decoded = _sig_decode(sig, p)
    var ch = decoded[0].copy()
    var z = decoded[1].copy()
    var h = decoded[2].copy()
    var z_bound_fail = UInt32(0)
    for i in range(p.l):
        z_bound_fail |= _ct_bool_to_u32(_coefficients_exceed_bound(z[i], gamma1_beta))
    if z_bound_fail != UInt32(0):
        _zero_list_u8(ch)
        _zero_poly_vec_u32(z)
        _zero_poly_vec_u8(h)
        return False
    var c = _ntt(_sample_in_ball(Span[UInt8, ...](ch), p))

    var z_hat = List[List[UInt32]](capacity=p.l)
    for i in range(p.l):
        z_hat.append(_ntt(z[i].copy()))
    var w = List[List[UInt32]](capacity=p.k)
    for i in range(p.k):
        var w_hat = _zero_poly()
        var product = _zero_poly()
        for j in range(p.l):
            _ntt_mul_into(product, pub.a[i * p.l + j], z_hat[j])
            _poly_add_into(w_hat, product)
        _ntt_mul_into(product, c, pub.t1_hat[i])
        _poly_sub_into(w_hat, product)
        w.append(_inverse_ntt(w_hat^))
        _zero_list_u32(product)

    var ch_input = StackBuffer[UInt8, MLDSA_CRHBYTES + MAX_K * 192]()
    _append_bytes_stack(ch_input, mu)
    for i in range(p.k):
        _append_use_hint_encoded_stack(ch_input, w[i], h[i], p)
    var computed = shake256(Span[UInt8, ...](ptr=ch_input.ptr(), length=ch_input.len()), p.lambda_bits // 4)
    _zero_stack_u8(ch_input)
    var ok = _bytes_equal(Span[UInt8, ...](ch), Span[UInt8, ...](computed))
    _zero_list_u8(ch)
    _zero_poly_vec_u32(z)
    _zero_poly_vec_u8(h)
    _zero_list_u32(c)
    _zero_poly_vec_u32(z_hat)
    _zero_poly_vec_u32(w)
    _zero_list_u8(computed)
    return ok

def mldsa_verify(pub: MLDSAPublicKey, msg: Span[UInt8, ...], sig: Span[UInt8, ...], context: Span[UInt8, ...]) raises -> Bool:
    var mu = _compute_message_hash(Span[UInt8, ...](pub.tr), msg, context)
    var ok = mldsa_verify_external_mu(pub, Span[UInt8, ...](mu), sig)
    _zero_list_u8(mu)
    return ok


def mldsa44_public_key(pk: Span[UInt8, ...]) raises -> MLDSAPublicKey:
    return new_public_key(pk, params44())


def mldsa65_public_key(pk: Span[UInt8, ...]) raises -> MLDSAPublicKey:
    return new_public_key(pk, params65())


def mldsa87_public_key(pk: Span[UInt8, ...]) raises -> MLDSAPublicKey:
    return new_public_key(pk, params87())


def mldsa44_private_key_from_seed(seed: Span[UInt8, ...]) raises -> MLDSAPrivateKey:
    return mldsa_private_key_from_seed(seed, params44())


def mldsa65_private_key_from_seed(seed: Span[UInt8, ...]) raises -> MLDSAPrivateKey:
    return mldsa_private_key_from_seed(seed, params65())


def mldsa87_private_key_from_seed(seed: Span[UInt8, ...]) raises -> MLDSAPrivateKey:
    return mldsa_private_key_from_seed(seed, params87())


def mldsa44_private_key_from_semiexpanded(sk: Span[UInt8, ...]) raises -> MLDSAPrivateKey:
    return mldsa_private_key_from_semiexpanded(sk, params44())


def mldsa65_private_key_from_semiexpanded(sk: Span[UInt8, ...]) raises -> MLDSAPrivateKey:
    return mldsa_private_key_from_semiexpanded(sk, params65())


def mldsa87_private_key_from_semiexpanded(sk: Span[UInt8, ...]) raises -> MLDSAPrivateKey:
    return mldsa_private_key_from_semiexpanded(sk, params87())


def _zero_random32() -> List[UInt8]:
    # Deterministic ML-DSA signing uses rnd = {0}^32.
    var r = List[UInt8](unsafe_uninit_length=MLDSA_RNDBYTES)
    _zero_list_u8(r)
    return r^


def mldsa_keygen(p: MLDSAParams) raises -> MLDSAPrivateKey:
    # FIPS 204 external KeyGen: generate fresh 32-byte xi, then run KeyGen_internal.
    var xi = random_bytes(MLDSA_SEEDBYTES)
    var sk = mldsa_private_key_from_seed(Span[UInt8, ...](xi), p)
    _zero_list_u8(xi)
    return sk^


def mldsa44_keygen() raises -> MLDSAPrivateKey:
    return mldsa_keygen(params44())


def mldsa65_keygen() raises -> MLDSAPrivateKey:
    return mldsa_keygen(params65())


def mldsa87_keygen() raises -> MLDSAPrivateKey:
    return mldsa_keygen(params87())


def mldsa_sign_hedged(priv: MLDSAPrivateKey, msg: Span[UInt8, ...], context: Span[UInt8, ...]) raises -> List[UInt8]:
    # FIPS 204 default signing variant: fresh 32-byte rnd.
    var rnd = random_bytes(MLDSA_RNDBYTES)
    var sig = mldsa_sign(priv, msg, context, Span[UInt8, ...](rnd))
    _zero_list_u8(rnd)
    return sig^


def mldsa_sign_deterministic(priv: MLDSAPrivateKey, msg: Span[UInt8, ...], context: Span[UInt8, ...]) raises -> List[UInt8]:
    # FIPS 204 optional deterministic variant: rnd = {0}^32.
    var rnd = _zero_random32()
    var sig = mldsa_sign(priv, msg, context, Span[UInt8, ...](rnd))
    _zero_list_u8(rnd)
    return sig^


def mldsa_sign_external_mu_hedged(priv: MLDSAPrivateKey, mu: Span[UInt8, ...]) raises -> List[UInt8]:
    var rnd = random_bytes(MLDSA_RNDBYTES)
    var sig = mldsa_sign_external_mu(priv, mu, Span[UInt8, ...](rnd))
    _zero_list_u8(rnd)
    return sig^


def mldsa_sign_external_mu_deterministic(priv: MLDSAPrivateKey, mu: Span[UInt8, ...]) raises -> List[UInt8]:
    var rnd = _zero_random32()
    var sig = mldsa_sign_external_mu(priv, mu, Span[UInt8, ...](rnd))
    _zero_list_u8(rnd)
    return sig^
