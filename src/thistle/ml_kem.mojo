"""
ML-KEM primitives implementation in Mojo
"""

from std.collections import List
from std.algorithm.functional import vectorize
from std.builtin.globals import global_constant
from std.sys import simd_width_of
from thistle.sha3 import (
    SHA3Context,
    sha3_256_into,
    sha3_512_into,
    sha3_update,
    shake128,
    shake256,
    shake256_into,
    shake_advance,
    shake_finalize,
    shake_squeeze_prefix_into,
)
from thistle.random import random_bytes
from thistle.utils import StackBuffer, zero_stack_u8

comptime K_512 = 2
comptime K_768 = 3
comptime K_1024 = 4
comptime K_MAX = K_1024

comptime N = 256
comptime Q = 3329

comptime ETA1_512 = 3
comptime ETA1 = 2
comptime ETA2 = 2

comptime POLYBYTES = 384
comptime SYMBYTES = 32

comptime POLYCOMPRESSEDBYTES_512 = 128
comptime POLYCOMPRESSEDBYTES_768 = 128
comptime POLYCOMPRESSEDBYTES_1024 = 160

comptime POLYVECBYTES_512 = K_512 * POLYBYTES
comptime POLYVECBYTES_768 = K_768 * POLYBYTES
comptime POLYVECBYTES_1024 = K_1024 * POLYBYTES

comptime POLYVECCOMPRESSEDBYTES_512 = K_512 * 320
comptime POLYVECCOMPRESSEDBYTES_768 = K_768 * 320
comptime POLYVECCOMPRESSEDBYTES_1024 = K_1024 * 352

comptime INDCPA_MSGBYTES = SYMBYTES
comptime INDCPA_PUBLICKEYBYTES_512 = POLYVECBYTES_512 + SYMBYTES
comptime INDCPA_SECRETKEYBYTES_512 = POLYVECBYTES_512
comptime INDCPA_PUBLICKEYBYTES_768 = POLYVECBYTES_768 + SYMBYTES
comptime INDCPA_SECRETKEYBYTES_768 = POLYVECBYTES_768
comptime INDCPA_PUBLICKEYBYTES_1024 = POLYVECBYTES_1024 + SYMBYTES
comptime INDCPA_SECRETKEYBYTES_1024 = POLYVECBYTES_1024
comptime INDCPA_PUBLICKEYBYTES_MAX = INDCPA_PUBLICKEYBYTES_1024
comptime INDCPA_BYTES_512 = POLYVECCOMPRESSEDBYTES_512 + POLYCOMPRESSEDBYTES_512
comptime INDCPA_BYTES_768 = POLYVECCOMPRESSEDBYTES_768 + POLYCOMPRESSEDBYTES_768
comptime INDCPA_BYTES_1024 = POLYVECCOMPRESSEDBYTES_1024 + POLYCOMPRESSEDBYTES_1024

comptime ENCAPSKEYBYTES_512 = INDCPA_PUBLICKEYBYTES_512
comptime ENCAPSKEYBYTES_768 = INDCPA_PUBLICKEYBYTES_768
comptime ENCAPSKEYBYTES_1024 = INDCPA_PUBLICKEYBYTES_1024

comptime DECAPSKEYBYTES_512 = INDCPA_SECRETKEYBYTES_512 + INDCPA_PUBLICKEYBYTES_512 + 2 * SYMBYTES
comptime DECAPSKEYBYTES_768 = INDCPA_SECRETKEYBYTES_768 + INDCPA_PUBLICKEYBYTES_768 + 2 * SYMBYTES
comptime DECAPSKEYBYTES_1024 = INDCPA_SECRETKEYBYTES_1024 + INDCPA_PUBLICKEYBYTES_1024 + 2 * SYMBYTES
comptime DECAPSKEYBYTES_MAX = DECAPSKEYBYTES_1024

comptime CIPHERTEXTBYTES_512 = INDCPA_BYTES_512
comptime CIPHERTEXTBYTES_768 = INDCPA_BYTES_768
comptime CIPHERTEXTBYTES_1024 = INDCPA_BYTES_1024
comptime CIPHERTEXTBYTES_MAX = INDCPA_BYTES_1024

comptime MLKEM512_PUBLICKEYBYTES = ENCAPSKEYBYTES_512
comptime MLKEM512_SECRETKEYBYTES = DECAPSKEYBYTES_512
comptime MLKEM512_CIPHERTEXTBYTES = CIPHERTEXTBYTES_512
comptime MLKEM768_PUBLICKEYBYTES = ENCAPSKEYBYTES_768
comptime MLKEM768_SECRETKEYBYTES = DECAPSKEYBYTES_768
comptime MLKEM768_CIPHERTEXTBYTES = CIPHERTEXTBYTES_768
comptime MLKEM1024_PUBLICKEYBYTES = ENCAPSKEYBYTES_1024
comptime MLKEM1024_SECRETKEYBYTES = DECAPSKEYBYTES_1024
comptime MLKEM1024_CIPHERTEXTBYTES = CIPHERTEXTBYTES_1024
comptime MLKEM_BYTES = 32


comptime ZETAS_TABLE: InlineArray[Int16, 128] = [
    -1044, -758, -359, -1517, 1493, 1422, 287, 202,
    -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130,
    -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544,
    516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951,
    -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105,
    422, 587, 177, -235, -291, -460, 1574, 1653,
    -246, 778, 1159, -147, -777, 1483, -602, 1119,
    -1590, 644, -872, 349, 418, 329, -156, -75,
    817, 1097, 603, 610, 1322, -1285, -1465, 384,
    -1215, -136, 1218, -1335, -874, 220, -1187, -1659,
    -1185, -1530, -1278, 794, -1510, -854, -870, 478,
    -108, -308, 996, 991, 958, -1460, 1522, 1628,
]


@always_inline
def _zeta(i: Int) -> Int16:
    debug_assert(i >= 0 and i < 128, "ML-KEM zeta index out of bounds")
    ref zetas = global_constant[ZETAS_TABLE]()
    return zetas.unsafe_ptr()[i]


struct Poly(Copyable, Movable):
    var coeffs: InlineArray[Int16, N]

    @always_inline
    def __init__(out self):
        self.coeffs = InlineArray[Int16, N](fill=0)

    @always_inline
    def __copyinit__(out self, existing: Self):
        self.coeffs = existing.coeffs

    @always_inline
    def __moveinit__(out self, deinit existing: Self):
        self.coeffs = existing.coeffs^


struct Polyvec(Copyable, Movable):
    var vec: InlineArray[Poly, K_MAX]

    @always_inline
    def __init__(out self):
        self.vec = InlineArray[Poly, K_MAX](fill=Poly())

    @always_inline
    def __copyinit__(out self, existing: Self):
        self.vec = existing.vec

    @always_inline
    def __moveinit__(out self, deinit existing: Self):
        self.vec = existing.vec^


@always_inline
def montgomery_reduce(a: Int32) -> Int16:
    # QINV = -3327 = q^-1 mod 2^16.
    var t = Int16(a) * Int16(-3327)
    return Int16((a - Int32(t) * Int32(Q)) >> 16)


@always_inline
def montgomery_reduce_simd[w: Int](a: SIMD[DType.int32, w]) -> SIMD[DType.int16, w]:
    var t = a.cast[DType.int16]() * SIMD[DType.int16, w](Int16(-3327))
    return ((a - t.cast[DType.int32]() * SIMD[DType.int32, w](Int32(Q))) >> 16).cast[DType.int16]()


@always_inline
def barrett_reduce(a: Int16) -> Int16:
    comptime V: Int16 = Int16(((1 << 26) + Q // 2) // Q)
    var t = Int16((Int32(V) * Int32(a) + (1 << 25)) >> 26)
    t *= Int16(Q)
    return a - t


@always_inline
def fqmul(a: Int16, b: Int16) -> Int16:
    return montgomery_reduce(Int32(a) * Int32(b))


@always_inline
def fqmul_simd[w: Int](a: SIMD[DType.int16, w], b: SIMD[DType.int16, w]) -> SIMD[DType.int16, w]:
    return montgomery_reduce_simd(a.cast[DType.int32]() * b.cast[DType.int32]())


@always_inline
def barrett_reduce_simd[w: Int](a: SIMD[DType.int16, w]) -> SIMD[DType.int16, w]:
    comptime V: Int16 = Int16(((1 << 26) + Q // 2) // Q)
    var v = SIMD[DType.int16, w](V)
    var qv = SIMD[DType.int16, w](Int16(Q))
    var t = ((a.cast[DType.int32]() * v.cast[DType.int32]() + (1 << 25)) >> 26).cast[DType.int16]()
    return a - t * qv


@always_inline
def _u24_le(buf: Span[UInt8, ...], offset: Int) -> UInt32:
    if offset + 4 <= len(buf):
        return (buf.unsafe_ptr() + offset).bitcast[UInt32]().load[alignment=1]().cast[DType.uint32]() & 0x00FFFFFF
    return UInt32(buf[offset]) | (UInt32(buf[offset + 1]) << 8) | (UInt32(buf[offset + 2]) << 16)


def cbd3(mut r: Poly, buf: Span[UInt8, ...]) raises:
    if len(buf) != ETA1_512 * N // 4:
        raise Error("ML-KEM cbd3 invalid buffer length")
    var bp = buf.unsafe_ptr()
    var rp = r.coeffs.unsafe_ptr()
    for i in range(N // 4):
        var off = 3 * i
        var t = UInt32(bp[off]) | (UInt32(bp[off + 1]) << 8) | (UInt32(bp[off + 2]) << 16)
        var d = t & 0x00249249
        d += (t >> 1) & 0x00249249
        d += (t >> 2) & 0x00249249
        var a0 = Int16((d >> 0) & 0x7)
        var b0 = Int16((d >> 3) & 0x7)
        var a1 = Int16((d >> 6) & 0x7)
        var b1 = Int16((d >> 9) & 0x7)
        var a2 = Int16((d >> 12) & 0x7)
        var b2 = Int16((d >> 15) & 0x7)
        var a3 = Int16((d >> 18) & 0x7)
        var b3 = Int16((d >> 21) & 0x7)
        var base = 4 * i
        rp.store(base + 0, a0 - b0)
        rp.store(base + 1, a1 - b1)
        rp.store(base + 2, a2 - b2)
        rp.store(base + 3, a3 - b3)


def cbd2(mut r: Poly, buf: Span[UInt8, ...]) raises:
    if len(buf) != ETA1 * N // 4:
        raise Error("ML-KEM cbd2 invalid buffer length")
    var bp = buf.unsafe_ptr()
    var rp = r.coeffs.unsafe_ptr()
    for i in range(N // 8):
        var off = 4 * i
        var t = UInt32(bp[off]) | (UInt32(bp[off + 1]) << 8) | (UInt32(bp[off + 2]) << 16) | (UInt32(bp[off + 3]) << 24)
        var d = t & 0x55555555
        d += (t >> 1) & 0x55555555
        var base = 8 * i
        var a0 = Int16((d >> 0) & 0x3)
        var b0 = Int16((d >> 2) & 0x3)
        var a1 = Int16((d >> 4) & 0x3)
        var b1 = Int16((d >> 6) & 0x3)
        var a2 = Int16((d >> 8) & 0x3)
        var b2 = Int16((d >> 10) & 0x3)
        var a3 = Int16((d >> 12) & 0x3)
        var b3 = Int16((d >> 14) & 0x3)
        var a4 = Int16((d >> 16) & 0x3)
        var b4 = Int16((d >> 18) & 0x3)
        var a5 = Int16((d >> 20) & 0x3)
        var b5 = Int16((d >> 22) & 0x3)
        var a6 = Int16((d >> 24) & 0x3)
        var b6 = Int16((d >> 26) & 0x3)
        var a7 = Int16((d >> 28) & 0x3)
        var b7 = Int16((d >> 30) & 0x3)
        rp.store(base + 0, a0 - b0)
        rp.store(base + 1, a1 - b1)
        rp.store(base + 2, a2 - b2)
        rp.store(base + 3, a3 - b3)
        rp.store(base + 4, a4 - b4)
        rp.store(base + 5, a5 - b5)
        rp.store(base + 6, a6 - b6)
        rp.store(base + 7, a7 - b7)


def poly_cbd_eta1_512(mut r: Poly, buf: Span[UInt8, ...]) raises:
    cbd3(r, buf)


def poly_cbd_eta1(mut r: Poly, buf: Span[UInt8, ...]) raises:
    cbd2(r, buf)


def poly_cbd_eta2(mut r: Poly, buf: Span[UInt8, ...]) raises:
    cbd2(r, buf)


def ntt(mut r: InlineArray[Int16, N]):
    comptime W = simd_width_of[DType.int16]()
    var ptr = r.unsafe_ptr()

    comptime for stage in range(7):
        comptime l = 128 >> stage
        comptime blocks = N // (2 * l)
        comptime for block in range(blocks):
            comptime start = block * 2 * l
            comptime zeta_idx = (1 << stage) + block
            var zeta = _zeta(zeta_idx)
            comptime if l >= W:
                def ntt_chunk[w: Int](off: Int) {ptr, zeta}:
                    var lo = ptr.load[width=w](start + off)
                    var hi = ptr.load[width=w](start + l + off)
                    var t = fqmul_simd(SIMD[DType.int16, w](zeta), hi)
                    ptr.store[width=w](start + l + off, lo - t)
                    ptr.store[width=w](start + off, lo + t)

                vectorize[W, size=l](ntt_chunk)
            else:
                comptime for off in range(l):
                    comptime j = start + off
                    var t = fqmul(zeta, r[j + l])
                    r[j + l] = r[j] - t
                    r[j] = r[j] + t


def invntt(mut r: InlineArray[Int16, N]):
    comptime F: Int16 = 1441
    comptime W = simd_width_of[DType.int16]()
    var ptr = r.unsafe_ptr()

    comptime for stage in range(7):
        comptime l = 2 << stage
        comptime blocks = N // (2 * l)
        comptime for block in range(blocks):
            comptime start = block * 2 * l
            comptime zeta_idx = (128 >> stage) - 1 - block
            var zeta = _zeta(zeta_idx)
            comptime if l >= W:
                def invntt_chunk[w: Int](off: Int) {ptr, zeta}:
                    var lo = ptr.load[width=w](start + off)
                    var hi = ptr.load[width=w](start + l + off)
                    ptr.store[width=w](start + off, barrett_reduce_simd(lo + hi))
                    ptr.store[width=w](start + l + off, fqmul_simd(SIMD[DType.int16, w](zeta), hi - lo))

                vectorize[W, size=l](invntt_chunk)
            else:
                comptime for off in range(l):
                    comptime j = start + off
                    var t = r[j]
                    r[j] = barrett_reduce(t + r[j + l])
                    r[j + l] = r[j + l] - t
                    r[j + l] = fqmul(zeta, r[j + l])

    def final_mul_chunk[w: Int](i: Int) {ptr}:
        var a = ptr.load[width=w](i)
        var f = SIMD[DType.int16, w](F)
        ptr.store[width=w](i, fqmul_simd(a, f))

    vectorize[W, size=N](final_mul_chunk)


@always_inline
def base_case_multiply(a0: Int16, a1: Int16, b0: Int16, b1: Int16, zeta: Int16) -> Tuple[Int16, Int16]:
    var r0 = fqmul(a1, b1)
    r0 = fqmul(r0, zeta)
    r0 += fqmul(a0, b0)
    var r1 = fqmul(a0, b1)
    r1 += fqmul(a1, b0)
    return (r0, r1)


def poly_reduce(mut r: Poly):
    comptime W = simd_width_of[DType.int16]()
    var ptr = r.coeffs.unsafe_ptr()

    def reduce_chunk[w: Int](i: Int) {ptr}:
        var a = ptr.load[width=w](i)
        var v = SIMD[DType.int16, w](Int16(((1 << 26) + Q // 2) // Q))
        var qv = SIMD[DType.int16, w](Int16(Q))
        var t = ((a.cast[DType.int32]() * v.cast[DType.int32]() + (1 << 25)) >> 26).cast[DType.int16]()
        ptr.store[width=w](i, a - t * qv)

    vectorize[W, size=N](reduce_chunk)


def poly_ntt(mut r: Poly):
    ntt(r.coeffs)
    poly_reduce(r)


def poly_invntt_tomont(mut r: Poly):
    invntt(r.coeffs)


def poly_basemul_montgomery(mut r: Poly, ref a: Poly, ref b: Poly):
    comptime for i in range(N // 4):
        comptime j = 4 * i
        var zeta = _zeta(64 + i)
        var p0 = base_case_multiply(a.coeffs[j], a.coeffs[j + 1], b.coeffs[j], b.coeffs[j + 1], zeta)
        r.coeffs[j] = p0[0]
        r.coeffs[j + 1] = p0[1]
        var p1 = base_case_multiply(a.coeffs[j + 2], a.coeffs[j + 3], b.coeffs[j + 2], b.coeffs[j + 3], -zeta)
        r.coeffs[j + 2] = p1[0]
        r.coeffs[j + 3] = p1[1]


def poly_tomont(mut r: Poly):
    comptime F: Int16 = Int16((1 << 32) % Q)
    comptime W = simd_width_of[DType.int16]()
    var ptr = r.coeffs.unsafe_ptr()

    def tomont_chunk[w: Int](i: Int) {ptr}:
        var a = ptr.load[width=w](i)
        var f = SIMD[DType.int16, w](F)
        ptr.store[width=w](i, montgomery_reduce_simd(a.cast[DType.int32]() * f.cast[DType.int32]()))

    vectorize[W, size=N](tomont_chunk)


def poly_add_inplace(mut r: Poly, ref b: Poly):
    comptime W = simd_width_of[DType.int16]()
    var rp = r.coeffs.unsafe_ptr()
    var bp = b.coeffs.unsafe_ptr()

    def add_inplace_chunk[w: Int](i: Int) {rp, bp}:
        rp.store[width=w](i, rp.load[width=w](i) + bp.load[width=w](i))

    vectorize[W, size=N](add_inplace_chunk)


def poly_sub_from(mut r: Poly, ref a: Poly):
    comptime W = simd_width_of[DType.int16]()
    var rp = r.coeffs.unsafe_ptr()
    var ap = a.coeffs.unsafe_ptr()

    def sub_from_chunk[w: Int](i: Int) {rp, ap}:
        rp.store[width=w](i, ap.load[width=w](i) - rp.load[width=w](i))

    vectorize[W, size=N](sub_from_chunk)


@always_inline
def _positive_coeff(x: Int16) -> UInt16:
    var u = x
    u += (u >> 15) & Int16(Q)
    return UInt16(u)


def poly_tobytes(mut out: List[UInt8], a: Poly):
    for i in range(N // 2):
        var t0 = _positive_coeff(a.coeffs[2 * i])
        var t1 = _positive_coeff(a.coeffs[2 * i + 1])
        out.append(UInt8(t0))
        out.append(UInt8((t0 >> 8) | (t1 << 4)))
        out.append(UInt8(t1 >> 4))


def poly_tobytes_stack(mut out: StackBuffer[UInt8, ...], a: Poly):
    for i in range(N // 2):
        var t0 = _positive_coeff(a.coeffs[2 * i])
        var t1 = _positive_coeff(a.coeffs[2 * i + 1])
        out.push_unchecked(UInt8(t0))
        out.push_unchecked(UInt8((t0 >> 8) | (t1 << 4)))
        out.push_unchecked(UInt8(t1 >> 4))


def poly_frombytes(mut r: Poly, a: Span[UInt8, ...]) raises -> Bool:
    if len(a) < POLYBYTES:
        raise Error("ML-KEM poly_frombytes invalid buffer length")
    var ok = True
    for i in range(N // 2):
        var t = _u24_le(a, 3 * i)
        r.coeffs[2 * i] = Int16(t & 0xFFF)
        r.coeffs[2 * i + 1] = Int16((t >> 12) & 0xFFF)
        ok = ok & (r.coeffs[2 * i] < Int16(Q)) & (r.coeffs[2 * i + 1] < Int16(Q))
    return ok


def polyvec_tobytes_stack(mut out: StackBuffer[UInt8, ...], ref a: Polyvec, k: Int):
    for i in range(k):
        poly_tobytes_stack(out, a.vec[i])


def polyvec_frombytes(mut r: Polyvec, a: Span[UInt8, ...], k: Int) raises -> Bool:
    if len(a) != k * POLYBYTES:
        raise Error("ML-KEM polyvec_frombytes invalid buffer length")
    var ok = True
    for i in range(k):
        ok = poly_frombytes(r.vec[i], a[i * POLYBYTES : (i + 1) * POLYBYTES]) & ok
    return ok


def polyvec_compress(mut out: List[UInt8], ref a: Polyvec, k: Int) raises:
    if k == K_512 or k == K_768:
        for i in range(k):
            for j in range(N // 4):
                var t = InlineArray[UInt16, 4](fill=0)
                for l in range(4):
                    t[l] = _positive_coeff(a.vec[i].coeffs[4 * j + l])
                    var d0 = UInt64(t[l]) << 10
                    d0 += 1665
                    d0 *= 1290167
                    d0 >>= 32
                    t[l] = UInt16(d0 & 0x3FF)
                out.append(UInt8(t[0] >> 0))
                out.append(UInt8((t[0] >> 8) | (t[1] << 2)))
                out.append(UInt8((t[1] >> 6) | (t[2] << 4)))
                out.append(UInt8((t[2] >> 4) | (t[3] << 6)))
                out.append(UInt8(t[3] >> 2))
    elif k == K_1024:
        for i in range(k):
            for j in range(N // 8):
                var t = InlineArray[UInt16, 8](fill=0)
                for l in range(8):
                    t[l] = _positive_coeff(a.vec[i].coeffs[8 * j + l])
                    var d0 = UInt64(t[l]) << 11
                    d0 += 1664
                    d0 *= 645084
                    d0 >>= 31
                    t[l] = UInt16(d0 & 0x7FF)
                out.append(UInt8(t[0] >> 0))
                out.append(UInt8((t[0] >> 8) | (t[1] << 3)))
                out.append(UInt8((t[1] >> 5) | (t[2] << 6)))
                out.append(UInt8(t[2] >> 2))
                out.append(UInt8((t[2] >> 10) | (t[3] << 1)))
                out.append(UInt8((t[3] >> 7) | (t[4] << 4)))
                out.append(UInt8((t[4] >> 4) | (t[5] << 7)))
                out.append(UInt8(t[5] >> 1))
                out.append(UInt8((t[5] >> 9) | (t[6] << 2)))
                out.append(UInt8((t[6] >> 6) | (t[7] << 5)))
                out.append(UInt8(t[7] >> 3))
    else:
        raise Error("ML-KEM polyvec_compress invalid k")


def polyvec_compress_stack(mut out: StackBuffer[UInt8, CIPHERTEXTBYTES_MAX], ref a: Polyvec, k: Int) raises:
    if k == K_512 or k == K_768:
        for i in range(k):
            for j in range(N // 4):
                var t = InlineArray[UInt16, 4](fill=0)
                for l in range(4):
                    t[l] = _positive_coeff(a.vec[i].coeffs[4 * j + l])
                    var d0 = UInt64(t[l]) << 10
                    d0 += 1665
                    d0 *= 1290167
                    d0 >>= 32
                    t[l] = UInt16(d0 & 0x3FF)
                out.push_unchecked(UInt8(t[0] >> 0))
                out.push_unchecked(UInt8((t[0] >> 8) | (t[1] << 2)))
                out.push_unchecked(UInt8((t[1] >> 6) | (t[2] << 4)))
                out.push_unchecked(UInt8((t[2] >> 4) | (t[3] << 6)))
                out.push_unchecked(UInt8(t[3] >> 2))
    elif k == K_1024:
        for i in range(k):
            for j in range(N // 8):
                var t = InlineArray[UInt16, 8](fill=0)
                for l in range(8):
                    t[l] = _positive_coeff(a.vec[i].coeffs[8 * j + l])
                    var d0 = UInt64(t[l]) << 11
                    d0 += 1664
                    d0 *= 645084
                    d0 >>= 31
                    t[l] = UInt16(d0 & 0x7FF)
                out.push_unchecked(UInt8(t[0] >> 0))
                out.push_unchecked(UInt8((t[0] >> 8) | (t[1] << 3)))
                out.push_unchecked(UInt8((t[1] >> 5) | (t[2] << 6)))
                out.push_unchecked(UInt8(t[2] >> 2))
                out.push_unchecked(UInt8((t[2] >> 10) | (t[3] << 1)))
                out.push_unchecked(UInt8((t[3] >> 7) | (t[4] << 4)))
                out.push_unchecked(UInt8((t[4] >> 4) | (t[5] << 7)))
                out.push_unchecked(UInt8(t[5] >> 1))
                out.push_unchecked(UInt8((t[5] >> 9) | (t[6] << 2)))
                out.push_unchecked(UInt8((t[6] >> 6) | (t[7] << 5)))
                out.push_unchecked(UInt8(t[7] >> 3))
    else:
        raise Error("ML-KEM polyvec_compress invalid k")


def polyvec_decompress(mut r: Polyvec, a: Span[UInt8, ...], k: Int) raises:
    if k == K_512 or k == K_768:
        if len(a) != polyvec_compressed_byte_size(k):
            raise Error("ML-KEM polyvec_decompress invalid buffer length")
        var off = 0
        for i in range(k):
            for j in range(N // 4):
                var t0 = UInt16(a[off + 0]) | (UInt16(a[off + 1]) << 8)
                var t1 = (UInt16(a[off + 1]) >> 2) | (UInt16(a[off + 2]) << 6)
                var t2 = (UInt16(a[off + 2]) >> 4) | (UInt16(a[off + 3]) << 4)
                var t3 = (UInt16(a[off + 3]) >> 6) | (UInt16(a[off + 4]) << 2)
                off += 5
                r.vec[i].coeffs[4 * j + 0] = Int16((UInt32(t0 & 0x3FF) * Q + 512) >> 10)
                r.vec[i].coeffs[4 * j + 1] = Int16((UInt32(t1 & 0x3FF) * Q + 512) >> 10)
                r.vec[i].coeffs[4 * j + 2] = Int16((UInt32(t2 & 0x3FF) * Q + 512) >> 10)
                r.vec[i].coeffs[4 * j + 3] = Int16((UInt32(t3 & 0x3FF) * Q + 512) >> 10)
    elif k == K_1024:
        if len(a) != POLYVECCOMPRESSEDBYTES_1024:
            raise Error("ML-KEM polyvec_decompress invalid buffer length")
        var off = 0
        for i in range(k):
            for j in range(N // 8):
                var t0 = UInt16(a[off + 0]) | (UInt16(a[off + 1]) << 8)
                var t1 = (UInt16(a[off + 1]) >> 3) | (UInt16(a[off + 2]) << 5)
                var t2 = (UInt16(a[off + 2]) >> 6) | (UInt16(a[off + 3]) << 2) | (UInt16(a[off + 4]) << 10)
                var t3 = (UInt16(a[off + 4]) >> 1) | (UInt16(a[off + 5]) << 7)
                var t4 = (UInt16(a[off + 5]) >> 4) | (UInt16(a[off + 6]) << 4)
                var t5 = (UInt16(a[off + 6]) >> 7) | (UInt16(a[off + 7]) << 1) | (UInt16(a[off + 8]) << 9)
                var t6 = (UInt16(a[off + 8]) >> 2) | (UInt16(a[off + 9]) << 6)
                var t7 = (UInt16(a[off + 9]) >> 5) | (UInt16(a[off + 10]) << 3)
                off += 11
                r.vec[i].coeffs[8 * j + 0] = Int16((UInt32(t0 & 0x7FF) * Q + 1024) >> 11)
                r.vec[i].coeffs[8 * j + 1] = Int16((UInt32(t1 & 0x7FF) * Q + 1024) >> 11)
                r.vec[i].coeffs[8 * j + 2] = Int16((UInt32(t2 & 0x7FF) * Q + 1024) >> 11)
                r.vec[i].coeffs[8 * j + 3] = Int16((UInt32(t3 & 0x7FF) * Q + 1024) >> 11)
                r.vec[i].coeffs[8 * j + 4] = Int16((UInt32(t4 & 0x7FF) * Q + 1024) >> 11)
                r.vec[i].coeffs[8 * j + 5] = Int16((UInt32(t5 & 0x7FF) * Q + 1024) >> 11)
                r.vec[i].coeffs[8 * j + 6] = Int16((UInt32(t6 & 0x7FF) * Q + 1024) >> 11)
                r.vec[i].coeffs[8 * j + 7] = Int16((UInt32(t7 & 0x7FF) * Q + 1024) >> 11)
    else:
        raise Error("ML-KEM polyvec_decompress invalid k")


def poly_frommsg(mut r: Poly, msg: Span[UInt8, ...]) raises:
    if len(msg) != INDCPA_MSGBYTES:
        raise Error("ML-KEM poly_frommsg invalid message length")
    for i in range(N // 8):
        for j in range(8):
            # message bits are secret during decaps, don't branch on them
            var mask = Int16(0) - Int16((msg[i] >> UInt8(j)) & 1)
            r.coeffs[8 * i + j] = mask & Int16((Q + 1) // 2)


def poly_tomsg(mut msg: List[UInt8], a: Poly):
    for _ in range(INDCPA_MSGBYTES):
        msg.append(0)
    for i in range(N // 8):
        for j in range(8):
            var u = Int32(a.coeffs[8 * i + j])
            u += (u >> 31) & Int32(Q)
            var t = UInt32(u)
            t <<= 1
            t += 1665
            t *= 80635
            t >>= 28
            t &= 1
            msg[i] |= UInt8(t << UInt32(j))


def poly_tomsg_stack(mut msg: StackBuffer[UInt8, SYMBYTES], a: Poly):
    msg.clear()
    for _ in range(INDCPA_MSGBYTES):
        msg.push_unchecked(UInt8(0))
    for i in range(N // 8):
        for j in range(8):
            var u = Int32(a.coeffs[8 * i + j])
            u += (u >> 31) & Int32(Q)
            var t = UInt32(u)
            t <<= 1
            t += 1665
            t *= 80635
            t >>= 28
            t &= 1
            msg[i] = msg[i] | UInt8(t << UInt32(j))


def poly_compress(mut out: List[UInt8], ref a: Poly, k: Int) raises:
    if k == K_512 or k == K_768:
        for i in range(N // 8):
            var t = InlineArray[UInt8, 8](fill=0)
            for j in range(8):
                var u = a.coeffs[8 * i + j]
                u += (u >> 15) & Int16(Q)
                var d0 = UInt32(u) << 4
                d0 += 1665
                d0 *= 80635
                d0 >>= 28
                t[j] = UInt8(d0) & 0x0F
            out.append(t[0] | (t[1] << 4))
            out.append(t[2] | (t[3] << 4))
            out.append(t[4] | (t[5] << 4))
            out.append(t[6] | (t[7] << 4))
    elif k == K_1024:
        for i in range(N // 8):
            var t = InlineArray[UInt8, 8](fill=0)
            for j in range(8):
                var u = a.coeffs[8 * i + j]
                u += (u >> 15) & Int16(Q)
                var d0 = UInt32(u) << 5
                d0 += 1664
                d0 *= 40318
                d0 >>= 27
                t[j] = UInt8(d0) & 0x1F
            out.append((t[0] >> 0) | (t[1] << 5))
            out.append((t[1] >> 3) | (t[2] << 2) | (t[3] << 7))
            out.append((t[3] >> 1) | (t[4] << 4))
            out.append((t[4] >> 4) | (t[5] << 1) | (t[6] << 6))
            out.append((t[6] >> 2) | (t[7] << 3))
    else:
        raise Error("ML-KEM poly_compress invalid k")


def poly_compress_stack(mut out: StackBuffer[UInt8, CIPHERTEXTBYTES_MAX], ref a: Poly, k: Int) raises:
    if k == K_512 or k == K_768:
        for i in range(N // 8):
            var t = InlineArray[UInt8, 8](fill=0)
            for j in range(8):
                var u = a.coeffs[8 * i + j]
                u += (u >> 15) & Int16(Q)
                var d0 = UInt32(u) << 4
                d0 += 1665
                d0 *= 80635
                d0 >>= 28
                t[j] = UInt8(d0) & 0x0F
            out.push_unchecked(t[0] | (t[1] << 4))
            out.push_unchecked(t[2] | (t[3] << 4))
            out.push_unchecked(t[4] | (t[5] << 4))
            out.push_unchecked(t[6] | (t[7] << 4))
    elif k == K_1024:
        for i in range(N // 8):
            var t = InlineArray[UInt8, 8](fill=0)
            for j in range(8):
                var u = a.coeffs[8 * i + j]
                u += (u >> 15) & Int16(Q)
                var d0 = UInt32(u) << 5
                d0 += 1664
                d0 *= 40318
                d0 >>= 27
                t[j] = UInt8(d0) & 0x1F
            out.push_unchecked((t[0] >> 0) | (t[1] << 5))
            out.push_unchecked((t[1] >> 3) | (t[2] << 2) | (t[3] << 7))
            out.push_unchecked((t[3] >> 1) | (t[4] << 4))
            out.push_unchecked((t[4] >> 4) | (t[5] << 1) | (t[6] << 6))
            out.push_unchecked((t[6] >> 2) | (t[7] << 3))
    else:
        raise Error("ML-KEM poly_compress invalid k")


def poly_decompress(mut r: Poly, a: Span[UInt8, ...], k: Int) raises:
    if k == K_512 or k == K_768:
        if len(a) != POLYCOMPRESSEDBYTES_512:
            raise Error("ML-KEM poly_decompress invalid buffer length")
        for i in range(N // 2):
            r.coeffs[2 * i] = Int16(((UInt16(a[i] & 15) * Q) + 8) >> 4)
            r.coeffs[2 * i + 1] = Int16(((UInt16(a[i] >> 4) * Q) + 8) >> 4)
    elif k == K_1024:
        if len(a) != POLYCOMPRESSEDBYTES_1024:
            raise Error("ML-KEM poly_decompress invalid buffer length")
        for i in range(N // 8):
            var off = 5 * i
            var t0 = a[off + 0] >> 0
            var t1 = (a[off + 0] >> 5) | (a[off + 1] << 3)
            var t2 = a[off + 1] >> 2
            var t3 = (a[off + 1] >> 7) | (a[off + 2] << 1)
            var t4 = (a[off + 2] >> 4) | (a[off + 3] << 4)
            var t5 = a[off + 3] >> 1
            var t6 = (a[off + 3] >> 6) | (a[off + 4] << 2)
            var t7 = a[off + 4] >> 3
            r.coeffs[8 * i + 0] = Int16((UInt32(t0 & 31) * Q + 16) >> 5)
            r.coeffs[8 * i + 1] = Int16((UInt32(t1 & 31) * Q + 16) >> 5)
            r.coeffs[8 * i + 2] = Int16((UInt32(t2 & 31) * Q + 16) >> 5)
            r.coeffs[8 * i + 3] = Int16((UInt32(t3 & 31) * Q + 16) >> 5)
            r.coeffs[8 * i + 4] = Int16((UInt32(t4 & 31) * Q + 16) >> 5)
            r.coeffs[8 * i + 5] = Int16((UInt32(t5 & 31) * Q + 16) >> 5)
            r.coeffs[8 * i + 6] = Int16((UInt32(t6 & 31) * Q + 16) >> 5)
            r.coeffs[8 * i + 7] = Int16((UInt32(t7 & 31) * Q + 16) >> 5)
    else:
        raise Error("ML-KEM poly_decompress invalid k")


def poly_compressed_bytes(k: Int) -> Int:
    if k == K_512:
        return POLYCOMPRESSEDBYTES_512
    if k == K_768:
        return POLYCOMPRESSEDBYTES_768
    if k == K_1024:
        return POLYCOMPRESSEDBYTES_1024
    return 0


def polyvec_byte_size(k: Int) -> Int:
    if k == K_512 or k == K_768 or k == K_1024:
        return k * POLYBYTES
    return 0


def polyvec_compressed_byte_size(k: Int) -> Int:
    if k == K_512:
        return POLYVECCOMPRESSEDBYTES_512
    if k == K_768:
        return POLYVECCOMPRESSEDBYTES_768
    if k == K_1024:
        return POLYVECCOMPRESSEDBYTES_1024
    return 0


def polyvec_reduce(mut r: Polyvec, k: Int):
    for i in range(k):
        poly_reduce(r.vec[i])


def polyvec_reduce_k[k: Int](mut r: Polyvec):
    comptime assert k == K_512 or k == K_768 or k == K_1024, "invalid ML-KEM k"
    comptime for i in range(k):
        poly_reduce(r.vec[i])


def polyvec_ntt(mut r: Polyvec, k: Int):
    for i in range(k):
        poly_ntt(r.vec[i])


def polyvec_ntt_k[k: Int](mut r: Polyvec):
    comptime assert k == K_512 or k == K_768 or k == K_1024, "invalid ML-KEM k"
    comptime for i in range(k):
        poly_ntt(r.vec[i])


def polyvec_invntt_tomont(mut r: Polyvec, k: Int):
    for i in range(k):
        poly_invntt_tomont(r.vec[i])


def polyvec_invntt_tomont_k[k: Int](mut r: Polyvec):
    comptime assert k == K_512 or k == K_768 or k == K_1024, "invalid ML-KEM k"
    comptime for i in range(k):
        poly_invntt_tomont(r.vec[i])


def polyvec_basemul_acc_montgomery(mut r: Poly, ref a: Polyvec, ref b: Polyvec, k: Int):
    var t = Poly()
    poly_basemul_montgomery(r, a.vec[0], b.vec[0])
    for i in range(1, k):
        poly_basemul_montgomery(t, a.vec[i], b.vec[i])
        poly_add_inplace(r, t)
    poly_reduce(r)


def polyvec_basemul_acc_montgomery_k[k: Int](mut r: Poly, ref a: Polyvec, ref b: Polyvec):
    comptime assert k == K_512 or k == K_768 or k == K_1024, "invalid ML-KEM k"
    var t = Poly()
    poly_basemul_montgomery(r, a.vec[0], b.vec[0])
    comptime for i in range(1, k):
        poly_basemul_montgomery(t, a.vec[i], b.vec[i])
        poly_add_inplace(r, t)
    poly_reduce(r)


def prf(key: Span[UInt8, ...], iv: UInt8, out_len: Int) raises -> List[UInt8]:
    if len(key) != SYMBYTES:
        raise Error("ML-KEM prf key must be 32 bytes")
    var input = StackBuffer[UInt8, SYMBYTES + 1]()
    for i in range(SYMBYTES):
        input.push_unchecked(key[i])
    input.push_unchecked(iv)
    return shake256(Span[UInt8, ...](ptr=input.ptr(), length=input.len()), out_len)


def prf_into(mut out: StackBuffer[UInt8, ...], key: Span[UInt8, ...], iv: UInt8, out_len: Int) raises:
    if len(key) != SYMBYTES:
        raise Error("ML-KEM prf key must be 32 bytes")
    var input = StackBuffer[UInt8, SYMBYTES + 1]()
    for i in range(SYMBYTES):
        input.push_unchecked(key[i])
    input.push_unchecked(iv)
    shake256_into(out, Span[UInt8, ...](ptr=input.ptr(), length=input.len()), out_len)


def rkprf(key: Span[UInt8, ...], input: Span[UInt8, ...]) raises -> List[UInt8]:
    if len(key) != SYMBYTES:
        raise Error("ML-KEM rkprf key must be 32 bytes")
    if len(input) > CIPHERTEXTBYTES_MAX:
        raise Error("ML-KEM rkprf input too long")
    var buf = StackBuffer[UInt8, SYMBYTES + CIPHERTEXTBYTES_MAX]()
    for i in range(SYMBYTES):
        buf.push_unchecked(key[i])
    for i in range(len(input)):
        buf.push_unchecked(input[i])
    return shake256(Span[UInt8, ...](ptr=buf.ptr(), length=buf.len()), SYMBYTES)


def rkprf_into(mut out: StackBuffer[UInt8, SYMBYTES], key: Span[UInt8, ...], input: Span[UInt8, ...]) raises:
    if len(key) != SYMBYTES:
        raise Error("ML-KEM rkprf key must be 32 bytes")
    if len(input) > CIPHERTEXTBYTES_MAX:
        raise Error("ML-KEM rkprf input too long")
    var buf = StackBuffer[UInt8, SYMBYTES + CIPHERTEXTBYTES_MAX]()
    for i in range(SYMBYTES):
        buf.push_unchecked(key[i])
    for i in range(len(input)):
        buf.push_unchecked(input[i])
    shake256_into(out, Span[UInt8, ...](ptr=buf.ptr(), length=buf.len()), SYMBYTES)


def hash_h_into(mut out: StackBuffer[UInt8, SYMBYTES], input: Span[UInt8, ...]):
    sha3_256_into(out, input)


def hash_g_into(mut out: StackBuffer[UInt8, 2 * SYMBYTES], input: Span[UInt8, ...]):
    sha3_512_into(out, input)


def xof(seed: Span[UInt8, ...], x: UInt8, y: UInt8, out_len: Int) raises -> List[UInt8]:
    if len(seed) != SYMBYTES:
        raise Error("ML-KEM xof seed must be 32 bytes")
    var extseed = StackBuffer[UInt8, SYMBYTES + 2]()
    for i in range(SYMBYTES):
        extseed.push_unchecked(seed[i])
    extseed.push_unchecked(x)
    extseed.push_unchecked(y)
    return shake128(Span[UInt8, ...](ptr=extseed.ptr(), length=extseed.len()), out_len)


def rej_uniform(mut r: Poly, start: Int, buf: Span[UInt8, ...]) -> Int:
    var ctr = start
    var pos = 0
    while ctr < N and pos + 3 <= len(buf):
        var val0 = (UInt16(buf[pos]) | (UInt16(buf[pos + 1]) << 8)) & 0xFFF
        var val1 = (UInt16(buf[pos + 1] >> 4) | (UInt16(buf[pos + 2]) << 4)) & 0xFFF
        pos += 3
        if val0 < UInt16(Q):
            r.coeffs[ctr] = Int16(val0)
            ctr += 1
        if ctr < N and val1 < UInt16(Q):
            r.coeffs[ctr] = Int16(val1)
            ctr += 1
    return ctr - start

def sample_ntt_into(mut out: Poly, seed: Span[UInt8, ...], x: UInt8, y: UInt8) raises:
    if len(seed) != SYMBYTES:
        raise Error("ML-KEM xof seed must be 32 bytes")

    var extseed = StackBuffer[UInt8, SYMBYTES + 2]()
    for i in range(SYMBYTES):
        extseed.push_unchecked(seed[i])
    extseed.push_unchecked(x)
    extseed.push_unchecked(y)

    var ctx = SHA3Context(1344)
    sha3_update(ctx, Span[UInt8, ...](ptr=extseed.ptr(), length=extseed.len()))
    shake_finalize(ctx)

    var block = StackBuffer[UInt8, 504]()
    var ctr = 0
    while ctr < N:
        shake_squeeze_prefix_into(ctx, block, 504)
        ctr += rej_uniform(out, ctr, Span[UInt8, ...](ptr=block.ptr(), length=block.len()))
        if ctr < N:
            shake_advance(ctx)


def poly_getnoise_eta1_512(mut r: Poly, seed: Span[UInt8, ...], iv: UInt8) raises:
    var buf = StackBuffer[UInt8, ETA1_512 * N // 4]()
    prf_into(buf, seed, iv, ETA1_512 * N // 4)
    poly_cbd_eta1_512(r, Span[UInt8, ...](ptr=buf.ptr(), length=buf.len()))


def poly_getnoise_eta1(mut r: Poly, seed: Span[UInt8, ...], iv: UInt8) raises:
    var buf = StackBuffer[UInt8, ETA1 * N // 4]()
    prf_into(buf, seed, iv, ETA1 * N // 4)
    poly_cbd_eta1(r, Span[UInt8, ...](ptr=buf.ptr(), length=buf.len()))


def poly_getnoise_eta2(mut r: Poly, seed: Span[UInt8, ...], iv: UInt8) raises:
    var buf = StackBuffer[UInt8, ETA2 * N // 4]()
    prf_into(buf, seed, iv, ETA2 * N // 4)
    poly_cbd_eta2(r, Span[UInt8, ...](ptr=buf.ptr(), length=buf.len()))


def gen_matrix(mut a: InlineArray[Polyvec, K_MAX], seed: Span[UInt8, ...], transposed: Bool, k: Int) raises:
    for i in range(k):
        for j in range(k):
            if transposed:
                sample_ntt_into(a[i].vec[j], seed, UInt8(i), UInt8(j))
            else:
                sample_ntt_into(a[i].vec[j], seed, UInt8(j), UInt8(i))


def gen_matrix_k_static[k: Int, transposed: Bool](mut a: InlineArray[Polyvec, K_MAX], seed: Span[UInt8, ...]) raises:
    comptime assert k == K_512 or k == K_768 or k == K_1024, "invalid ML-KEM k"
    comptime for i in range(k):
        comptime for j in range(k):
            comptime if transposed:
                sample_ntt_into(a[i].vec[j], seed, UInt8(i), UInt8(j))
            else:
                sample_ntt_into(a[i].vec[j], seed, UInt8(j), UInt8(i))


struct KPKEEncryptionKey(Copyable, Movable):
    var pv: Polyvec
    var p: InlineArray[UInt8, SYMBYTES]
    var k: Int

    def __init__(out self):
        self.pv = Polyvec()
        self.p = InlineArray[UInt8, SYMBYTES](fill=0)
        self.k = 0


struct KPKEDecapsulationKey(Copyable, Movable):
    var pv: Polyvec
    var k: Int

    def __init__(out self):
        self.pv = Polyvec()
        self.k = 0


struct EncapsulationKey(Copyable, Movable):
    var pke_ek: KPKEEncryptionKey
    var raw_bytes: InlineArray[UInt8, INDCPA_PUBLICKEYBYTES_MAX]
    var h: InlineArray[UInt8, SYMBYTES]

    def __init__(out self):
        self.pke_ek = KPKEEncryptionKey()
        self.raw_bytes = InlineArray[UInt8, INDCPA_PUBLICKEYBYTES_MAX](fill=0)
        self.h = InlineArray[UInt8, SYMBYTES](fill=0)


struct DecapsulationKey(Copyable, Movable):
    var pke_dk: KPKEDecapsulationKey
    var ek: EncapsulationKey
    var z: InlineArray[UInt8, SYMBYTES]

    def __init__(out self):
        self.pke_dk = KPKEDecapsulationKey()
        self.ek = EncapsulationKey()
        self.z = InlineArray[UInt8, SYMBYTES](fill=0)

    def __del__(deinit self):
        for row in range(K_MAX):
            var ptr = self.pke_dk.pv.vec[row].coeffs.unsafe_ptr()
            for i in range(N):
                ptr.store[volatile=True](i, Int16(0))
        var z_ptr = self.z.unsafe_ptr()
        for i in range(SYMBYTES):
            z_ptr.store[volatile=True](i, UInt8(0))


def pack_pk_stack(mut out: StackBuffer[UInt8, ...], ref pk: Polyvec, seed: InlineArray[UInt8, SYMBYTES], k: Int) -> Bool:
    if polyvec_byte_size(k) == 0:
        return False
    polyvec_tobytes_stack(out, pk, k)
    for i in range(SYMBYTES):
        out.push_unchecked(seed[i])
    return True


def unpack_pk(mut pk: KPKEEncryptionKey, input: Span[UInt8, ...], k: Int) raises -> Bool:
    var pk_len = polyvec_byte_size(k)
    if pk_len == 0 or len(input) != pk_len + SYMBYTES:
        return False
    if not polyvec_frombytes(pk.pv, input[0:pk_len], k):
        return False
    for i in range(SYMBYTES):
        pk.p[i] = input[pk_len + i]
    pk.k = k
    return True


def pack_ciphertext_stack(mut out: StackBuffer[UInt8, CIPHERTEXTBYTES_MAX], ref b: Polyvec, ref v: Poly, k: Int) raises -> Bool:
    if polyvec_compressed_byte_size(k) == 0 or poly_compressed_bytes(k) == 0:
        return False
    polyvec_compress_stack(out, b, k)
    poly_compress_stack(out, v, k)
    return True


def unpack_ciphertext(mut b: Polyvec, mut v: Poly, c: Span[UInt8, ...], k: Int) raises -> Bool:
    var b_len = polyvec_compressed_byte_size(k)
    var v_len = poly_compressed_bytes(k)
    if b_len == 0 or v_len == 0 or len(c) != b_len + v_len:
        return False
    polyvec_decompress(b, c[0:b_len], k)
    poly_decompress(v, c[b_len:b_len + v_len], k)
    return True


def k_pke_keygen(mut ek: KPKEEncryptionKey, mut dk: KPKEDecapsulationKey, d: Span[UInt8, ...], k: Int) raises:
    if len(d) != SYMBYTES:
        raise Error("ML-KEM K-PKE keygen d must be 32 bytes")
    if k != K_512 and k != K_768 and k != K_1024:
        raise Error("ML-KEM invalid k")

    var g_input = StackBuffer[UInt8, SYMBYTES + 1]()
    for i in range(SYMBYTES):
        g_input.push_unchecked(d[i])
    g_input.push_unchecked(UInt8(k))
    var g = StackBuffer[UInt8, 2 * SYMBYTES]()
    hash_g_into(g, Span[UInt8, ...](ptr=g_input.ptr(), length=g_input.len()))
    var rho = Span[UInt8, ...](ptr=g.ptr(), length=SYMBYTES)
    var sigma = Span[UInt8, ...](ptr=g.ptr() + SYMBYTES, length=SYMBYTES)

    var a = InlineArray[Polyvec, K_MAX](fill=Polyvec())
    gen_matrix(a, Span[UInt8, ...](rho), False, k)

    var nonce = UInt8(0)
    for i in range(k):
        if k == K_512:
            poly_getnoise_eta1_512(dk.pv.vec[i], Span[UInt8, ...](sigma), nonce)
        else:
            poly_getnoise_eta1(dk.pv.vec[i], Span[UInt8, ...](sigma), nonce)
        nonce += 1

    var e = Polyvec()
    for i in range(k):
        if k == K_512:
            poly_getnoise_eta1_512(e.vec[i], Span[UInt8, ...](sigma), nonce)
        else:
            poly_getnoise_eta1(e.vec[i], Span[UInt8, ...](sigma), nonce)
        nonce += 1

    polyvec_ntt(dk.pv, k)
    polyvec_ntt(e, k)

    for i in range(k):
        polyvec_basemul_acc_montgomery(ek.pv.vec[i], a[i], dk.pv, k)
        poly_tomont(ek.pv.vec[i])

    for i in range(k):
        poly_add_inplace(ek.pv.vec[i], e.vec[i])
    polyvec_reduce(ek.pv, k)

    for i in range(SYMBYTES):
        ek.p[i] = rho[i]

    dk.k = k
    ek.k = k


def k_pke_keygen_k[k: Int](mut ek: KPKEEncryptionKey, mut dk: KPKEDecapsulationKey, d: Span[UInt8, ...]) raises:
    comptime assert k == K_512 or k == K_768 or k == K_1024, "invalid ML-KEM k"
    if len(d) != SYMBYTES:
        raise Error("ML-KEM K-PKE keygen d must be 32 bytes")

    var g_input = StackBuffer[UInt8, SYMBYTES + 1]()
    for i in range(SYMBYTES):
        g_input.push_unchecked(d[i])
    g_input.push_unchecked(UInt8(k))
    var g = StackBuffer[UInt8, 2 * SYMBYTES]()
    hash_g_into(g, Span[UInt8, ...](ptr=g_input.ptr(), length=g_input.len()))
    var rho = Span[UInt8, ...](ptr=g.ptr(), length=SYMBYTES)
    var sigma = Span[UInt8, ...](ptr=g.ptr() + SYMBYTES, length=SYMBYTES)

    var a = InlineArray[Polyvec, K_MAX](fill=Polyvec())
    gen_matrix_k_static[k, False](a, Span[UInt8, ...](rho))

    var nonce = UInt8(0)
    comptime for i in range(k):
        comptime if k == K_512:
            poly_getnoise_eta1_512(dk.pv.vec[i], Span[UInt8, ...](sigma), nonce)
        else:
            poly_getnoise_eta1(dk.pv.vec[i], Span[UInt8, ...](sigma), nonce)
        nonce += 1

    var e = Polyvec()
    comptime for i in range(k):
        comptime if k == K_512:
            poly_getnoise_eta1_512(e.vec[i], Span[UInt8, ...](sigma), nonce)
        else:
            poly_getnoise_eta1(e.vec[i], Span[UInt8, ...](sigma), nonce)
        nonce += 1

    polyvec_ntt_k[k](dk.pv)
    polyvec_ntt_k[k](e)

    comptime for i in range(k):
        polyvec_basemul_acc_montgomery_k[k](ek.pv.vec[i], a[i], dk.pv)
        poly_tomont(ek.pv.vec[i])

    comptime for i in range(k):
        poly_add_inplace(ek.pv.vec[i], e.vec[i])
    polyvec_reduce_k[k](ek.pv)

    for i in range(SYMBYTES):
        ek.p[i] = rho[i]

    dk.k = k
    ek.k = k


def k_pke_encrypt_into(mut ciphertext: StackBuffer[UInt8, CIPHERTEXTBYTES_MAX], ref ek: KPKEEncryptionKey, m: Span[UInt8, ...], r: Span[UInt8, ...]) raises -> Bool:
    if len(m) != INDCPA_MSGBYTES or len(r) != SYMBYTES:
        return False
    var k = ek.k
    if k != K_512 and k != K_768 and k != K_1024:
        return False

    var kay = Poly()
    var epp = Poly()
    var v = Poly()
    var at = InlineArray[Polyvec, K_MAX](fill=Polyvec())
    var sp = Polyvec()
    var ep = Polyvec()
    var b = Polyvec()

    poly_frommsg(kay, m)
    gen_matrix(at, ek.p, True, k)

    var nonce = UInt8(0)
    for i in range(k):
        if k == K_512:
            poly_getnoise_eta1_512(sp.vec[i], r, nonce)
        else:
            poly_getnoise_eta1(sp.vec[i], r, nonce)
        nonce += 1
    for i in range(k):
        poly_getnoise_eta2(ep.vec[i], r, nonce)
        nonce += 1
    poly_getnoise_eta2(epp, r, nonce)

    polyvec_ntt(sp, k)

    for i in range(k):
        polyvec_basemul_acc_montgomery(b.vec[i], at[i], sp, k)

    polyvec_basemul_acc_montgomery(v, ek.pv, sp, k)

    polyvec_invntt_tomont(b, k)
    poly_invntt_tomont(v)

    for i in range(k):
        poly_add_inplace(b.vec[i], ep.vec[i])
    poly_add_inplace(v, epp)
    poly_add_inplace(v, kay)
    polyvec_reduce(b, k)
    poly_reduce(v)

    return pack_ciphertext_stack(ciphertext, b, v, k)


def k_pke_encrypt_into_k[k: Int](mut ciphertext: StackBuffer[UInt8, CIPHERTEXTBYTES_MAX], ref ek: KPKEEncryptionKey, m: Span[UInt8, ...], r: Span[UInt8, ...]) raises -> Bool:
    comptime assert k == K_512 or k == K_768 or k == K_1024, "invalid ML-KEM k"
    if len(m) != INDCPA_MSGBYTES or len(r) != SYMBYTES:
        return False
    if ek.k != k:
        return False

    var kay = Poly()
    var epp = Poly()
    var v = Poly()
    var at = InlineArray[Polyvec, K_MAX](fill=Polyvec())
    var sp = Polyvec()
    var ep = Polyvec()
    var b = Polyvec()

    poly_frommsg(kay, m)
    gen_matrix_k_static[k, True](at, ek.p)

    var nonce = UInt8(0)
    comptime for i in range(k):
        comptime if k == K_512:
            poly_getnoise_eta1_512(sp.vec[i], r, nonce)
        else:
            poly_getnoise_eta1(sp.vec[i], r, nonce)
        nonce += 1
    comptime for i in range(k):
        poly_getnoise_eta2(ep.vec[i], r, nonce)
        nonce += 1
    poly_getnoise_eta2(epp, r, nonce)

    polyvec_ntt_k[k](sp)

    comptime for i in range(k):
        polyvec_basemul_acc_montgomery_k[k](b.vec[i], at[i], sp)

    polyvec_basemul_acc_montgomery_k[k](v, ek.pv, sp)

    polyvec_invntt_tomont_k[k](b)
    poly_invntt_tomont(v)

    comptime for i in range(k):
        poly_add_inplace(b.vec[i], ep.vec[i])
    poly_add_inplace(v, epp)
    poly_add_inplace(v, kay)
    polyvec_reduce_k[k](b)
    poly_reduce(v)

    return pack_ciphertext_stack(ciphertext, b, v, k)


def k_pke_decrypt_msg(mut plaintext: StackBuffer[UInt8, SYMBYTES], ref dk: KPKEDecapsulationKey, c: Span[UInt8, ...]) raises -> Bool:
    var k = dk.k
    if k != K_512 and k != K_768 and k != K_1024:
        return False

    var b = Polyvec()
    var v = Poly()
    var mp = Poly()
    if not unpack_ciphertext(b, v, c, k):
        return False

    polyvec_ntt(b, k)
    polyvec_basemul_acc_montgomery(mp, dk.pv, b, k)
    poly_invntt_tomont(mp)

    poly_sub_from(mp, v)
    poly_reduce(mp)
    poly_tomsg_stack(plaintext, mp)
    return True


def k_pke_decrypt_msg_k[k: Int](mut plaintext: StackBuffer[UInt8, SYMBYTES], ref dk: KPKEDecapsulationKey, c: Span[UInt8, ...]) raises -> Bool:
    comptime assert k == K_512 or k == K_768 or k == K_1024, "invalid ML-KEM k"
    if dk.k != k:
        return False

    var b = Polyvec()
    var v = Poly()
    var mp = Poly()
    if not unpack_ciphertext(b, v, c, k):
        return False

    polyvec_ntt_k[k](b)
    polyvec_basemul_acc_montgomery_k[k](mp, dk.pv, b)
    poly_invntt_tomont(mp)

    poly_sub_from(mp, v)
    poly_reduce(mp)
    poly_tomsg_stack(plaintext, mp)
    return True


def kem_keygen_internal(seed: Span[UInt8, ...], k: Int) raises -> DecapsulationKey:
    if len(seed) != 2 * SYMBYTES:
        raise Error("ML-KEM keygen seed must be d || z")
    var dk = DecapsulationKey()
    var d = seed[0:SYMBYTES]
    var z = seed[SYMBYTES:2 * SYMBYTES]
    k_pke_keygen(dk.ek.pke_ek, dk.pke_dk, d, k)

    var ek_bytes = StackBuffer[UInt8, INDCPA_PUBLICKEYBYTES_MAX]()
    if not pack_pk_stack(ek_bytes, dk.ek.pke_ek.pv, dk.ek.pke_ek.p, k):
        raise Error("ML-KEM failed to pack public key")
    for i in range(ek_bytes.len()):
        dk.ek.raw_bytes[i] = ek_bytes[i]
    var h = StackBuffer[UInt8, SYMBYTES]()
    hash_h_into(h, Span[UInt8, ...](ptr=ek_bytes.ptr(), length=ek_bytes.len()))
    for i in range(SYMBYTES):
        dk.ek.h[i] = h[i]
        dk.z[i] = z[i]
    return dk^


def kem_keygen_internal_k[k: Int](seed: Span[UInt8, ...]) raises -> DecapsulationKey:
    comptime assert k == K_512 or k == K_768 or k == K_1024, "invalid ML-KEM k"
    if len(seed) != 2 * SYMBYTES:
        raise Error("ML-KEM keygen seed must be d || z")
    var dk = DecapsulationKey()
    var d = seed[0:SYMBYTES]
    var z = seed[SYMBYTES:2 * SYMBYTES]
    k_pke_keygen_k[k](dk.ek.pke_ek, dk.pke_dk, d)

    var ek_bytes = StackBuffer[UInt8, INDCPA_PUBLICKEYBYTES_MAX]()
    if not pack_pk_stack(ek_bytes, dk.ek.pke_ek.pv, dk.ek.pke_ek.p, k):
        raise Error("ML-KEM failed to pack public key")
    for i in range(ek_bytes.len()):
        dk.ek.raw_bytes[i] = ek_bytes[i]
    var h = StackBuffer[UInt8, SYMBYTES]()
    hash_h_into(h, Span[UInt8, ...](ptr=ek_bytes.ptr(), length=ek_bytes.len()))
    for i in range(SYMBYTES):
        dk.ek.h[i] = h[i]
        dk.z[i] = z[i]
    return dk^


def encapsulation_key_bytes_into(mut out: StackBuffer[UInt8, INDCPA_PUBLICKEYBYTES_MAX], ref dk: DecapsulationKey) -> Bool:
    out.clear()
    var ek_len = polyvec_byte_size(dk.pke_dk.k) + SYMBYTES
    if ek_len == 0:
        return False
    for i in range(ek_len):
        out.push_unchecked(dk.ek.raw_bytes[i])
    return True


def decapsulation_key_expanded_bytes_into(mut out: StackBuffer[UInt8, DECAPSKEYBYTES_MAX], ref dk: DecapsulationKey) -> Bool:
    out.clear()
    var k = dk.pke_dk.k
    var dk_len = _decapsulation_key_size(k)
    if dk_len == 0:
        return False
    polyvec_tobytes_stack(out, dk.pke_dk.pv, k)
    var ek_len = polyvec_byte_size(k) + SYMBYTES
    for i in range(ek_len):
        out.push_unchecked(dk.ek.raw_bytes[i])
    for i in range(SYMBYTES):
        out.push_unchecked(dk.ek.h[i])
    for i in range(SYMBYTES):
        out.push_unchecked(dk.z[i])
    return True


def _parameter_set_k(parameter_set: String) raises -> Int:
    if parameter_set == "ML-KEM-512":
        return K_512
    if parameter_set == "ML-KEM-768":
        return K_768
    if parameter_set == "ML-KEM-1024":
        return K_1024
    raise Error("ML-KEM unsupported parameter set")


def _ciphertext_size(k: Int) -> Int:
    if k == K_512:
        return CIPHERTEXTBYTES_512
    if k == K_768:
        return CIPHERTEXTBYTES_768
    if k == K_1024:
        return CIPHERTEXTBYTES_1024
    return 0


def _decapsulation_key_size(k: Int) -> Int:
    if k == K_512:
        return DECAPSKEYBYTES_512
    if k == K_768:
        return DECAPSKEYBYTES_768
    if k == K_1024:
        return DECAPSKEYBYTES_1024
    return 0


def _bytes_diff(a: Span[UInt8, ...], b: Span[UInt8, ...]) -> UInt8:
    var diff = UInt8(0)
    if len(a) != len(b):
        diff = 1
    var n = len(a)
    if len(b) < n:
        n = len(b)
    for i in range(n):
        diff |= a[i] ^ b[i]
    return diff


@always_inline
def _ct_is_zero_u8(x: UInt8) -> UInt8:
    var y = UInt32(x)
    return UInt8(((y | (UInt32(0) - y)) >> 31) ^ 1)


@always_inline
def _ct_select_u8(a: UInt8, b: UInt8, choice: UInt8) -> UInt8:
    var mask = UInt8(0) - (choice & 1)
    return a ^ (mask & (a ^ b))


def _zero_list(mut data: List[UInt8]):
    var ptr = data.unsafe_ptr()
    for i in range(len(data)):
        ptr.store[volatile=True](i, UInt8(0))



def decapsulation_key_decode(mut dk: DecapsulationKey, input: Span[UInt8, ...], k: Int) raises -> Bool:
    var dk_len = _decapsulation_key_size(k)
    var sk_len = polyvec_byte_size(k)
    var ek_len = polyvec_byte_size(k) + SYMBYTES
    if dk_len == 0 or len(input) != dk_len:
        return False
    if not polyvec_frombytes(dk.pke_dk.pv, input[0:sk_len], k):
        return False
    dk.pke_dk.k = k
    if not unpack_pk(dk.ek.pke_ek, input[sk_len:sk_len + ek_len], k):
        return False
    for i in range(ek_len):
        dk.ek.raw_bytes[i] = input[sk_len + i]
    var h = StackBuffer[UInt8, SYMBYTES]()
    hash_h_into(h, input[sk_len:sk_len + ek_len])
    var h_diff = UInt8(0)
    for i in range(SYMBYTES):
        dk.ek.h[i] = input[sk_len + ek_len + i]
        dk.z[i] = input[sk_len + ek_len + SYMBYTES + i]
        h_diff |= dk.ek.h[i] ^ h[i]
    if h_diff != 0:
        return False
    return True


def mlkem_keygen_seed_into(mut ek_out: StackBuffer[UInt8, INDCPA_PUBLICKEYBYTES_MAX], mut dk_out: StackBuffer[UInt8, DECAPSKEYBYTES_MAX], seed: Span[UInt8, ...], parameter_set: String) raises -> Bool:
    ek_out.clear()
    dk_out.clear()
    var k = _parameter_set_k(parameter_set)
    var dk = kem_keygen_internal(seed, k)
    if not encapsulation_key_bytes_into(ek_out, dk):
        return False
    if not decapsulation_key_expanded_bytes_into(dk_out, dk):
        zero_stack_u8(ek_out)
        return False
    return True


def mlkem_keygen_seed_into_k[k: Int](mut ek_out: StackBuffer[UInt8, INDCPA_PUBLICKEYBYTES_MAX], mut dk_out: StackBuffer[UInt8, DECAPSKEYBYTES_MAX], seed: Span[UInt8, ...]) raises -> Bool:
    comptime assert k == K_512 or k == K_768 or k == K_1024, "invalid ML-KEM k"
    ek_out.clear()
    dk_out.clear()
    var dk = kem_keygen_internal_k[k](seed)
    if not encapsulation_key_bytes_into(ek_out, dk):
        return False
    if not decapsulation_key_expanded_bytes_into(dk_out, dk):
        zero_stack_u8(ek_out)
        return False
    return True


def mlkem_keygen_seed(seed: Span[UInt8, ...], parameter_set: String) raises -> Tuple[List[UInt8], List[UInt8]]:
    var ek_buf = StackBuffer[UInt8, INDCPA_PUBLICKEYBYTES_MAX]()
    var dk_buf = StackBuffer[UInt8, DECAPSKEYBYTES_MAX]()
    if not mlkem_keygen_seed_into(ek_buf, dk_buf, seed, parameter_set):
        return (List[UInt8](), List[UInt8]())

    var ek = List[UInt8](capacity=ek_buf.len())
    for i in range(ek_buf.len()):
        ek.append(ek_buf[i])
    var dk = List[UInt8](capacity=dk_buf.len())
    for i in range(dk_buf.len()):
        dk.append(dk_buf[i])
    zero_stack_u8(ek_buf)
    zero_stack_u8(dk_buf)
    return (ek^, dk^)


# FIPS 203 ML-KEM.KeyGen(): fresh d || z, then deterministic expansion.
def mlkem_keygen(parameter_set: String) raises -> Tuple[List[UInt8], List[UInt8]]:
    var seed = random_bytes(2 * SYMBYTES)
    var result = mlkem_keygen_seed(Span[UInt8, ...](seed), parameter_set)
    _zero_list(seed)
    return result^


def mlkem512_keygen() raises -> Tuple[List[UInt8], List[UInt8]]:
    var seed = random_bytes(2 * SYMBYTES)
    var ek_buf = StackBuffer[UInt8, INDCPA_PUBLICKEYBYTES_MAX]()
    var dk_buf = StackBuffer[UInt8, DECAPSKEYBYTES_MAX]()
    _ = mlkem_keygen_seed_into_k[K_512](ek_buf, dk_buf, Span[UInt8, ...](seed))
    _zero_list(seed)
    var ek = List[UInt8](capacity=ek_buf.len())
    for i in range(ek_buf.len()):
        ek.append(ek_buf[i])
    var dk = List[UInt8](capacity=dk_buf.len())
    for i in range(dk_buf.len()):
        dk.append(dk_buf[i])
    zero_stack_u8(ek_buf)
    zero_stack_u8(dk_buf)
    return (ek^, dk^)


def mlkem768_keygen() raises -> Tuple[List[UInt8], List[UInt8]]:
    var seed = random_bytes(2 * SYMBYTES)
    var ek_buf = StackBuffer[UInt8, INDCPA_PUBLICKEYBYTES_MAX]()
    var dk_buf = StackBuffer[UInt8, DECAPSKEYBYTES_MAX]()
    _ = mlkem_keygen_seed_into_k[K_768](ek_buf, dk_buf, Span[UInt8, ...](seed))
    _zero_list(seed)
    var ek = List[UInt8](capacity=ek_buf.len())
    for i in range(ek_buf.len()):
        ek.append(ek_buf[i])
    var dk = List[UInt8](capacity=dk_buf.len())
    for i in range(dk_buf.len()):
        dk.append(dk_buf[i])
    zero_stack_u8(ek_buf)
    zero_stack_u8(dk_buf)
    return (ek^, dk^)


def mlkem1024_keygen() raises -> Tuple[List[UInt8], List[UInt8]]:
    var seed = random_bytes(2 * SYMBYTES)
    var ek_buf = StackBuffer[UInt8, INDCPA_PUBLICKEYBYTES_MAX]()
    var dk_buf = StackBuffer[UInt8, DECAPSKEYBYTES_MAX]()
    _ = mlkem_keygen_seed_into_k[K_1024](ek_buf, dk_buf, Span[UInt8, ...](seed))
    _zero_list(seed)
    var ek = List[UInt8](capacity=ek_buf.len())
    for i in range(ek_buf.len()):
        ek.append(ek_buf[i])
    var dk = List[UInt8](capacity=dk_buf.len())
    for i in range(dk_buf.len()):
        dk.append(dk_buf[i])
    zero_stack_u8(ek_buf)
    zero_stack_u8(dk_buf)
    return (ek^, dk^)


# FIPS 203 ML-KEM.Encaps(): fresh m, returns (ciphertext, shared_secret, ok).
def mlkem_encaps(ek_bytes: Span[UInt8, ...], parameter_set: String) raises -> Tuple[List[UInt8], List[UInt8], Bool]:
    var m = random_bytes(SYMBYTES)
    var result = mlkem_encaps_seed(ek_bytes, Span[UInt8, ...](m), parameter_set)
    _zero_list(m)
    if not result[2]:
        return (List[UInt8](), List[UInt8](), False)
    return (result[0].copy(), result[1].copy(), True)


def mlkem512_encaps(ek_bytes: Span[UInt8, ...]) raises -> Tuple[List[UInt8], List[UInt8], Bool]:
    var m = random_bytes(SYMBYTES)
    var shared_buf = StackBuffer[UInt8, SYMBYTES]()
    var ciphertext_buf = StackBuffer[UInt8, CIPHERTEXTBYTES_MAX]()
    var ok = mlkem_encaps_seed_into_k[K_512](ciphertext_buf, shared_buf, ek_bytes, Span[UInt8, ...](m))
    _zero_list(m)
    if not ok:
        return (List[UInt8](), List[UInt8](), False)
    var ciphertext = List[UInt8](capacity=ciphertext_buf.len())
    for i in range(ciphertext_buf.len()):
        ciphertext.append(ciphertext_buf[i])
    var shared = List[UInt8](capacity=SYMBYTES)
    for i in range(SYMBYTES):
        shared.append(shared_buf[i])
    zero_stack_u8(shared_buf)
    zero_stack_u8(ciphertext_buf)
    return (ciphertext^, shared^, True)


def mlkem768_encaps(ek_bytes: Span[UInt8, ...]) raises -> Tuple[List[UInt8], List[UInt8], Bool]:
    var m = random_bytes(SYMBYTES)
    var shared_buf = StackBuffer[UInt8, SYMBYTES]()
    var ciphertext_buf = StackBuffer[UInt8, CIPHERTEXTBYTES_MAX]()
    var ok = mlkem_encaps_seed_into_k[K_768](ciphertext_buf, shared_buf, ek_bytes, Span[UInt8, ...](m))
    _zero_list(m)
    if not ok:
        return (List[UInt8](), List[UInt8](), False)
    var ciphertext = List[UInt8](capacity=ciphertext_buf.len())
    for i in range(ciphertext_buf.len()):
        ciphertext.append(ciphertext_buf[i])
    var shared = List[UInt8](capacity=SYMBYTES)
    for i in range(SYMBYTES):
        shared.append(shared_buf[i])
    zero_stack_u8(shared_buf)
    zero_stack_u8(ciphertext_buf)
    return (ciphertext^, shared^, True)


def mlkem1024_encaps(ek_bytes: Span[UInt8, ...]) raises -> Tuple[List[UInt8], List[UInt8], Bool]:
    var m = random_bytes(SYMBYTES)
    var shared_buf = StackBuffer[UInt8, SYMBYTES]()
    var ciphertext_buf = StackBuffer[UInt8, CIPHERTEXTBYTES_MAX]()
    var ok = mlkem_encaps_seed_into_k[K_1024](ciphertext_buf, shared_buf, ek_bytes, Span[UInt8, ...](m))
    _zero_list(m)
    if not ok:
        return (List[UInt8](), List[UInt8](), False)
    var ciphertext = List[UInt8](capacity=ciphertext_buf.len())
    for i in range(ciphertext_buf.len()):
        ciphertext.append(ciphertext_buf[i])
    var shared = List[UInt8](capacity=SYMBYTES)
    for i in range(SYMBYTES):
        shared.append(shared_buf[i])
    zero_stack_u8(shared_buf)
    zero_stack_u8(ciphertext_buf)
    return (ciphertext^, shared^, True)


def mlkem_encaps_seed_into(mut ciphertext_out: StackBuffer[UInt8, CIPHERTEXTBYTES_MAX], mut shared_out: StackBuffer[UInt8, SYMBYTES], ek_bytes: Span[UInt8, ...], m: Span[UInt8, ...], parameter_set: String) raises -> Bool:
    ciphertext_out.clear()
    shared_out.clear()
    var k = _parameter_set_k(parameter_set)
    if len(m) != SYMBYTES:
        return False

    var ek = KPKEEncryptionKey()
    if not unpack_pk(ek, ek_bytes, k):
        return False

    var h = StackBuffer[UInt8, SYMBYTES]()
    hash_h_into(h, ek_bytes)
    var g_input = StackBuffer[UInt8, 2 * SYMBYTES]()
    for i in range(SYMBYTES):
        g_input.push_unchecked(m[i])
    for i in range(SYMBYTES):
        g_input.push_unchecked(h[i])
    var g = StackBuffer[UInt8, 2 * SYMBYTES]()
    hash_g_into(g, Span[UInt8, ...](ptr=g_input.ptr(), length=g_input.len()))
    zero_stack_u8(g_input)
    for i in range(SYMBYTES):
        shared_out.push_unchecked(g[i])
    if not k_pke_encrypt_into(ciphertext_out, ek, m, Span[UInt8, ...](ptr=g.ptr() + SYMBYTES, length=SYMBYTES)):
        zero_stack_u8(g)
        zero_stack_u8(shared_out)
        zero_stack_u8(ciphertext_out)
        return False
    zero_stack_u8(g)
    return True


def mlkem_encaps_seed_into_k[k: Int](mut ciphertext_out: StackBuffer[UInt8, CIPHERTEXTBYTES_MAX], mut shared_out: StackBuffer[UInt8, SYMBYTES], ek_bytes: Span[UInt8, ...], m: Span[UInt8, ...]) raises -> Bool:
    comptime assert k == K_512 or k == K_768 or k == K_1024, "invalid ML-KEM k"
    ciphertext_out.clear()
    shared_out.clear()
    if len(m) != SYMBYTES:
        return False

    var ek = KPKEEncryptionKey()
    if not unpack_pk(ek, ek_bytes, k):
        return False

    var h = StackBuffer[UInt8, SYMBYTES]()
    hash_h_into(h, ek_bytes)
    var g_input = StackBuffer[UInt8, 2 * SYMBYTES]()
    for i in range(SYMBYTES):
        g_input.push_unchecked(m[i])
    for i in range(SYMBYTES):
        g_input.push_unchecked(h[i])
    var g = StackBuffer[UInt8, 2 * SYMBYTES]()
    hash_g_into(g, Span[UInt8, ...](ptr=g_input.ptr(), length=g_input.len()))
    zero_stack_u8(g_input)
    for i in range(SYMBYTES):
        shared_out.push_unchecked(g[i])
    if not k_pke_encrypt_into_k[k](ciphertext_out, ek, m, Span[UInt8, ...](ptr=g.ptr() + SYMBYTES, length=SYMBYTES)):
        zero_stack_u8(g)
        zero_stack_u8(shared_out)
        zero_stack_u8(ciphertext_out)
        return False
    zero_stack_u8(g)
    return True


def mlkem_encaps_seed_vector_order(ek_bytes: Span[UInt8, ...], m: Span[UInt8, ...], parameter_set: String) raises -> Tuple[List[UInt8], List[UInt8], Bool]:
    # KAT/vector order: (shared_secret, ciphertext, ok).
    # Use mlkem_encaps_seed() for the FIPS/RFC external order.
    var shared_buf = StackBuffer[UInt8, SYMBYTES]()
    var ciphertext_buf = StackBuffer[UInt8, CIPHERTEXTBYTES_MAX]()
    if not mlkem_encaps_seed_into(ciphertext_buf, shared_buf, ek_bytes, m, parameter_set):
        return (List[UInt8](), List[UInt8](), False)

    var shared = List[UInt8](capacity=SYMBYTES)
    for i in range(SYMBYTES):
        shared.append(shared_buf[i])
    var ciphertext = List[UInt8](capacity=ciphertext_buf.len())
    for i in range(ciphertext_buf.len()):
        ciphertext.append(ciphertext_buf[i])
    zero_stack_u8(shared_buf)
    zero_stack_u8(ciphertext_buf)
    return (shared^, ciphertext^, True)


def mlkem_encaps_seed_vector(ek_bytes: Span[UInt8, ...], m: Span[UInt8, ...], parameter_set: String) raises -> Tuple[List[UInt8], List[UInt8], Bool]:
    return mlkem_encaps_seed_vector_order(ek_bytes, m, parameter_set)


def mlkem_encaps_seed(ek_bytes: Span[UInt8, ...], m: Span[UInt8, ...], parameter_set: String) raises -> Tuple[List[UInt8], List[UInt8], Bool]:
    # FIPS/RFC order: (ciphertext, shared_secret, ok).
    var result = mlkem_encaps_seed_vector_order(ek_bytes, m, parameter_set)
    if not result[2]:
        return (List[UInt8](), List[UInt8](), False)
    return (result[1].copy(), result[0].copy(), True)


def mlkem_decaps_into(mut shared_out: StackBuffer[UInt8, SYMBYTES], dk_bytes: Span[UInt8, ...], ciphertext: Span[UInt8, ...], parameter_set: String) raises -> Bool:
    shared_out.clear()
    var k = _parameter_set_k(parameter_set)
    if len(ciphertext) != _ciphertext_size(k):
        return False

    var dk = DecapsulationKey()
    if not decapsulation_key_decode(dk, dk_bytes, k):
        return False

    var m = StackBuffer[UInt8, SYMBYTES]()
    if not k_pke_decrypt_msg(m, dk.pke_dk, ciphertext):
        zero_stack_u8(m)
        return False

    var g_input = StackBuffer[UInt8, 2 * SYMBYTES]()
    for i in range(SYMBYTES):
        g_input.push_unchecked(m[i])
    for i in range(SYMBYTES):
        g_input.push_unchecked(dk.ek.h[i])
    var g = StackBuffer[UInt8, 2 * SYMBYTES]()
    hash_g_into(g, Span[UInt8, ...](ptr=g_input.ptr(), length=g_input.len()))
    zero_stack_u8(g_input)

    var ct_check = StackBuffer[UInt8, CIPHERTEXTBYTES_MAX]()
    if not k_pke_encrypt_into(ct_check, dk.ek.pke_ek, Span[UInt8, ...](ptr=m.ptr(), length=m.len()), Span[UInt8, ...](ptr=g.ptr() + SYMBYTES, length=SYMBYTES)):
        zero_stack_u8(m)
        zero_stack_u8(g)
        zero_stack_u8(ct_check)
        return False

    var rejection = StackBuffer[UInt8, SYMBYTES]()
    rkprf_into(rejection, Span[UInt8, ...](dk.z), ciphertext)
    var equal = _ct_is_zero_u8(_bytes_diff(Span[UInt8, ...](ptr=ct_check.ptr(), length=ct_check.len()), ciphertext))
    for i in range(SYMBYTES):
        shared_out.push_unchecked(_ct_select_u8(rejection[i], g[i], equal))

    zero_stack_u8(m)
    zero_stack_u8(g)
    zero_stack_u8(ct_check)
    zero_stack_u8(rejection)
    return True


def mlkem_decaps_into_k[k: Int](mut shared_out: StackBuffer[UInt8, SYMBYTES], dk_bytes: Span[UInt8, ...], ciphertext: Span[UInt8, ...]) raises -> Bool:
    comptime assert k == K_512 or k == K_768 or k == K_1024, "invalid ML-KEM k"
    shared_out.clear()
    if len(ciphertext) != _ciphertext_size(k):
        return False

    var dk = DecapsulationKey()
    if not decapsulation_key_decode(dk, dk_bytes, k):
        return False

    var m = StackBuffer[UInt8, SYMBYTES]()
    if not k_pke_decrypt_msg_k[k](m, dk.pke_dk, ciphertext):
        zero_stack_u8(m)
        return False

    var g_input = StackBuffer[UInt8, 2 * SYMBYTES]()
    for i in range(SYMBYTES):
        g_input.push_unchecked(m[i])
    for i in range(SYMBYTES):
        g_input.push_unchecked(dk.ek.h[i])
    var g = StackBuffer[UInt8, 2 * SYMBYTES]()
    hash_g_into(g, Span[UInt8, ...](ptr=g_input.ptr(), length=g_input.len()))
    zero_stack_u8(g_input)

    var ct_check = StackBuffer[UInt8, CIPHERTEXTBYTES_MAX]()
    if not k_pke_encrypt_into_k[k](ct_check, dk.ek.pke_ek, Span[UInt8, ...](ptr=m.ptr(), length=m.len()), Span[UInt8, ...](ptr=g.ptr() + SYMBYTES, length=SYMBYTES)):
        zero_stack_u8(m)
        zero_stack_u8(g)
        zero_stack_u8(ct_check)
        return False

    var rejection = StackBuffer[UInt8, SYMBYTES]()
    rkprf_into(rejection, Span[UInt8, ...](dk.z), ciphertext)
    var equal = _ct_is_zero_u8(_bytes_diff(Span[UInt8, ...](ptr=ct_check.ptr(), length=ct_check.len()), ciphertext))
    for i in range(SYMBYTES):
        shared_out.push_unchecked(_ct_select_u8(rejection[i], g[i], equal))

    zero_stack_u8(m)
    zero_stack_u8(g)
    zero_stack_u8(ct_check)
    zero_stack_u8(rejection)
    return True


def mlkem_decaps(dk_bytes: Span[UInt8, ...], ciphertext: Span[UInt8, ...], parameter_set: String) raises -> Tuple[List[UInt8], Bool]:
    var shared_buf = StackBuffer[UInt8, SYMBYTES]()
    if not mlkem_decaps_into(shared_buf, dk_bytes, ciphertext, parameter_set):
        zero_stack_u8(shared_buf)
        return (List[UInt8](), False)

    var shared = List[UInt8](capacity=SYMBYTES)
    for i in range(SYMBYTES):
        shared.append(shared_buf[i])
    zero_stack_u8(shared_buf)
    return (shared^, True)


def mlkem512_decaps(dk_bytes: Span[UInt8, ...], ciphertext: Span[UInt8, ...]) raises -> Tuple[List[UInt8], Bool]:
    var shared_buf = StackBuffer[UInt8, SYMBYTES]()
    if not mlkem_decaps_into_k[K_512](shared_buf, dk_bytes, ciphertext):
        zero_stack_u8(shared_buf)
        return (List[UInt8](), False)
    var shared = List[UInt8](capacity=SYMBYTES)
    for i in range(SYMBYTES):
        shared.append(shared_buf[i])
    zero_stack_u8(shared_buf)
    return (shared^, True)


def mlkem768_decaps(dk_bytes: Span[UInt8, ...], ciphertext: Span[UInt8, ...]) raises -> Tuple[List[UInt8], Bool]:
    var shared_buf = StackBuffer[UInt8, SYMBYTES]()
    if not mlkem_decaps_into_k[K_768](shared_buf, dk_bytes, ciphertext):
        zero_stack_u8(shared_buf)
        return (List[UInt8](), False)
    var shared = List[UInt8](capacity=SYMBYTES)
    for i in range(SYMBYTES):
        shared.append(shared_buf[i])
    zero_stack_u8(shared_buf)
    return (shared^, True)


def mlkem1024_decaps(dk_bytes: Span[UInt8, ...], ciphertext: Span[UInt8, ...]) raises -> Tuple[List[UInt8], Bool]:
    var shared_buf = StackBuffer[UInt8, SYMBYTES]()
    if not mlkem_decaps_into_k[K_1024](shared_buf, dk_bytes, ciphertext):
        zero_stack_u8(shared_buf)
        return (List[UInt8](), False)
    var shared = List[UInt8](capacity=SYMBYTES)
    for i in range(SYMBYTES):
        shared.append(shared_buf[i])
    zero_stack_u8(shared_buf)
    return (shared^, True)
