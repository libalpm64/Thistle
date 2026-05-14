# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Libalpm64, Lostlab Technologies.

"""
By Libalpm64
Broken code for now.
"""
from std.builtin.dtype import DType
from std.builtin.simd import SIMD
from std.collections import List
from std.memory import bitcast
from .curve25519 import FieldElement51
from .sha2 import sha512_hash
from .utils import StackInlineArray

comptime L_LIMBS = SIMD[DType.uint64, 5](
    0x0002631a5cf5d3ed,
    0x000dea2f79cd6581,
    0x000000000014def9,
    0x0000000000000000,
    0x0000100000000000,
)
comptime LFACTOR: UInt64 = 0x51da312547e1b

comptime R_LIMBS = SIMD[DType.uint64, 5](
    0x000f48bd6721e6ed,
    0x0003bab5ac67e45a,
    0x000fffffeb35e51b,
    0x000fffffffffffff,
    0x00000fffffffffff,
)

comptime RR_LIMBS = SIMD[DType.uint64, 5](
    0x0009d265e952d13b,
    0x000d63c715bea69f,
    0x0005be65cb687604,
    0x0003dceec73d217f,
    0x000009411b7c309a,
)

comptime ED25519_D_LIMBS = SIMD[DType.uint64, 5](
    0x34dca135978a3,
    0x001a8283b156ebd,
    0x005e7a26001c029,
    0x00739c663a03cbb,
    0x0052036cee2b6ff,
)

comptime ED25519_D2_LIMBS = SIMD[DType.uint64, 5](
    0x69b9426b2f159,
    0x00351050762add,
    0x00bcf4c4c003805,
    0x00e738cc740797,
    0x002480db2752dbe,
)

comptime POW2_256_LIMBS = SIMD[DType.uint64, 5](
    0x0009f4e532df7449,
    0x000da9f725df7382,
    0x000f5be65cc244cc,
    0x000a3dceec73d217,
    0x0000099411b7c309,
)

comptime L_BYTES = SIMD[DType.uint8, 32](
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
)

@always_inline
def _s_lt_l(s: Span[UInt8, ...]) -> Bool:
    # Little endian lexicographic compare from MSB
    for i in range(31, -1, -1):
        var li = L_BYTES[i]
        if s[i] < li:
            return True
        if s[i] > li:
            return False
    return False

def _pack_limbs(limbs: SIMD[DType.uint64, 5]) -> List[UInt8]:
    var words = SIMD[DType.uint64, 4](0, 0, 0, 0)
    words[0] = limbs[0] | (limbs[1] << 52)
    words[1] = (limbs[1] >> 12) | (limbs[2] << 40)
    words[2] = (limbs[2] >> 24) | (limbs[3] << 28)
    words[3] = (limbs[3] >> 36) | (limbs[4] << 16)
    var bytes = bitcast[DType.uint8, 32](words)
    var out = List[UInt8](capacity=32)
    for i in range(32):
        out.append(bytes[i])
    return out^

def _unpack_limbs(bytes: Span[UInt8, ...]) -> SIMD[DType.uint64, 5]:
    var words = bytes.unsafe_ptr().bitcast[UInt64]().load[width=4]()
    comptime MASK = (UInt64(1) << 52) - 1
    comptime TOP_MASK = (UInt64(1) << 48) - 1
    var s = SIMD[DType.uint64, 5](0, 0, 0, 0, 0)
    s[0] = words[0] & MASK
    s[1] = ((words[0] >> UInt64(52)) | (words[1] << UInt64(12))) & MASK
    s[2] = ((words[1] >> UInt64(40)) | (words[2] << UInt64(24))) & MASK
    s[3] = ((words[2] >> UInt64(28)) | (words[3] << UInt64(36))) & MASK
    s[4] = (words[3] >> UInt64(16)) & TOP_MASK
    return s

def _from_512_raw(bytes: Span[UInt8, ...]) -> SIMD[DType.uint64, 5]:
    var ptr = bytes.unsafe_ptr()
    var lo_span = Span[UInt8, ...](ptr=ptr, length=32)
    var hi_span = Span[UInt8, ...](ptr=ptr + 32, length=32)
    var lo = Scalar.from_bytes(lo_span)
    var hi = Scalar.from_bytes(hi_span)
    var pow2_256 = Scalar(POW2_256_LIMBS)
    var res = lo + hi * pow2_256
    return res.limbs

@always_inline
def ed25519_d() -> FieldElement51:
    return FieldElement51(ED25519_D_LIMBS)

@always_inline
def ed25519_d2() -> FieldElement51:
    return ed25519_d() * FieldElement51(2, 0, 0, 0, 0)

def ed25519_base_point() -> EdwardsPoint:
    var X_bytes: List[UInt8] = [
        0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9,
        0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c, 0x69,
        0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0,
        0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21
    ]
    var X = fe_from_bytes(Span[UInt8, ...](X_bytes))
    var Y_bytes: List[UInt8] = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
    ]
    var Y = fe_from_bytes(Span[UInt8, ...](Y_bytes))
    return EdwardsPoint(X, Y, FieldElement51.ONE(), X * Y)


struct Scalar(Movable, Copyable, ImplicitlyCopyable):
    var limbs: SIMD[DType.uint64, 5]

    @always_inline
    def __init__(out self):
        self.limbs = SIMD[DType.uint64, 5](0, 0, 0, 0, 0)

    @always_inline
    def __init__(out self, limbs: SIMD[DType.uint64, 5]):
        self.limbs = limbs

    @always_inline
    def __copyinit__(out self, copy: Self):
        self.limbs = copy.limbs

    @always_inline
    def __moveinit__(out self, deinit take: Self):
        self.limbs = take.limbs

    @staticmethod
    def from_bytes(bytes: Span[UInt8, ...]) -> Scalar:
        var raw = _unpack_limbs(bytes)
        return Scalar(raw)._montgomery_mul(Scalar(RR_LIMBS))

    def to_bytes(self) -> List[UInt8]:
        var raw = self._montgomery_mul(Scalar(SIMD[DType.uint64, 5](1, 0, 0, 0, 0)))
        return _pack_limbs(raw.limbs)

    @staticmethod
    def from_bytes_wide(bytes: Span[UInt8, ...]) -> Scalar:
        var limbs = _from_512_raw(bytes)
        return Scalar(limbs)

    @staticmethod
    def from_bytes_clamped(bytes: Span[UInt8, ...]) -> Scalar:
        var s = List[UInt8](capacity=32)
        for i in range(32):
            s.append(bytes[i])
        s[0] &= 0xF8
        s[31] &= 0x7F
        s[31] |= 0x40
        return Scalar.from_bytes(Span[UInt8, ...](s))

    def __add__(self, other: Scalar) -> Scalar:
        comptime MASK = (UInt64(1) << 52) - 1
        var sum = SIMD[DType.uint64, 5](0, 0, 0, 0, 0)
        var carry: UInt64 = 0
        for i in range(5):
            carry = self.limbs[i] + other.limbs[i] + (carry >> 52)
            sum[i] = carry & MASK
        return Scalar(sum)._sub(Scalar(L_LIMBS))

    def __sub__(self, other: Scalar) -> Scalar:
        return self._sub(other)

    def __neg__(self) -> Scalar:
        return Scalar(L_LIMBS)._sub(self)

    def __mul__(self, other: Scalar) -> Scalar:
        return self._montgomery_mul(other)

    @staticmethod
    def _montgomery_mul_raw(a: SIMD[DType.uint64, 5], b: SIMD[DType.uint64, 5]) -> SIMD[DType.uint64, 5]:
        var z = StackInlineArray[UInt128, 9](uninitialized=True)
        for i in range(9): z[i] = 0
        for i in range(5):
            for j in range(5):
                z[i + j] += UInt128(a[i]) * UInt128(b[j])
        var carry: UInt128 = 0
        var n = StackInlineArray[UInt64, 5](uninitialized=True)
        for i in range(5):
            var sum = carry + z[i]
            for j in range(i):
                sum += UInt128(n[j]) * UInt128(L_LIMBS[i - j])
            var p = (UInt64(sum.cast[DType.uint64]() * LFACTOR)) & ((UInt64(1) << 52) - 1)
            n[i] = p
            carry = (sum + UInt128(p) * UInt128(L_LIMBS[0])) >> 52
        var r = SIMD[DType.uint64, 5](0, 0, 0, 0, 0)
        for i in range(4):
            var sum = carry + z[5 + i]
            for j in range(i + 1, 5):
                sum += UInt128(n[j]) * UInt128(L_LIMBS[5 + i - j])
            r[i] = (sum.cast[DType.uint64]()) & ((UInt64(1) << 52) - 1)
            carry = sum >> 52
        r[4] = carry.cast[DType.uint64]()
        return r

    def _montgomery_mul(self, other: Scalar) -> Scalar:
        var r = Scalar._montgomery_mul_raw(self.limbs, other.limbs)
        return Scalar(r)._sub(Scalar(L_LIMBS))

    def _sub(self, other: Scalar) -> Scalar:
        comptime MASK = (UInt64(1) << 52) - 1
        var diff = SIMD[DType.uint64, 5](0, 0, 0, 0, 0)
        var borrow: UInt64 = 0
        for i in range(5):
            var x = other.limbs[i] + borrow
            if self.limbs[i] < x:
                diff[i] = (self.limbs[i] + (UInt64(1) << 52)) - x
                borrow = 1
            else:
                diff[i] = self.limbs[i] - x
                borrow = 0
        if borrow != 0:
            var carry: UInt64 = 0
            for i in range(5):
                carry = diff[i] + L_LIMBS[i] + (carry >> 52)
                diff[i] = carry & MASK
        return Scalar(diff)


struct EdwardsPoint(Movable, Copyable, ImplicitlyCopyable):
    var X: FieldElement51
    var Y: FieldElement51
    var Z: FieldElement51
    var T: FieldElement51

    @always_inline
    def __init__(out self):
        self.X = FieldElement51.ZERO()
        self.Y = FieldElement51.ONE()
        self.Z = FieldElement51.ONE()
        self.T = FieldElement51.ZERO()

    @always_inline
    def __init__(out self, X: FieldElement51, Y: FieldElement51, Z: FieldElement51, T: FieldElement51):
        self.X = X; self.Y = Y; self.Z = Z; self.T = T

    @always_inline
    def __copyinit__(out self, copy: Self):
        self.X = copy.X; self.Y = copy.Y; self.Z = copy.Z; self.T = copy.T

    @always_inline
    def __moveinit__(out self, deinit take: Self):
        self.X = take.X^; self.Y = take.Y^; self.Z = take.Z^; self.T = take.T^

struct DecodeResult(Movable, Copyable, ImplicitlyCopyable):
    var ok: Bool
    var p: EdwardsPoint

    @always_inline
    def __init__(out self):
        self.ok = False
        self.p = EdwardsPoint()

    @always_inline
    def __init__(out self, ok: Bool, p: EdwardsPoint):
        self.ok = ok
        self.p = p

def edwards_add(p: EdwardsPoint, q: EdwardsPoint) -> EdwardsPoint:
    var d2 = FieldElement51(ED25519_D2_LIMBS)
    return _edwards_add_d2(p, q, d2)

def edwards_double(p: EdwardsPoint) -> EdwardsPoint:
    return _edwards_double_standalone(p)

def edwards_negate(p: EdwardsPoint) -> EdwardsPoint:
    return EdwardsPoint(FieldElement51.ZERO() - p.X, p.Y, p.Z, FieldElement51.ZERO() - p.T)

@no_inline
def _edwards_add_d2(p: EdwardsPoint, q: EdwardsPoint, d2: FieldElement51) -> EdwardsPoint:
    var A = (p.Y - p.X) * (q.Y - q.X)
    var B = (p.Y + p.X) * (q.Y + q.X)
    var C = p.T * q.T * d2
    var D = p.Z * q.Z * FieldElement51(2, 0, 0, 0, 0)
    var E = B - A
    var F = D - C
    var G = D + C
    var H = B + A
    return EdwardsPoint(E * F, G * H, F * G, E * H)

@no_inline
def _edwards_double_standalone(p: EdwardsPoint) -> EdwardsPoint:
    var A = p.X.square()
    var B = p.Y.square()
    var C = p.Z.square() * FieldElement51(2, 0, 0, 0, 0)
    var D = FieldElement51.ZERO() - A
    var E = (p.X + p.Y).square() - A - B
    var G = D + B
    var F = G - C
    var H = D - B
    return EdwardsPoint(E * F, G * H, F * G, E * H)


def fe_to_bytes(fe: FieldElement51) -> List[UInt8]:
    var canonical = fe._reduce(fe.limbs)
    var l = canonical.limbs
    var MASK = UInt64(0x7FFFFFFFFFFFF)
    var r0 = l[0] + 19
    var r1 = l[1] + (r0 >> 51); r0 &= MASK
    var r2 = l[2] + (r1 >> 51); r1 &= MASK
    var r3 = l[3] + (r2 >> 51); r2 &= MASK
    var r4 = l[4] + (r3 >> 51); r3 &= MASK
    if (r4 >> 51) == 1:
        l[0] = r0; l[1] = r1; l[2] = r2; l[3] = r3; l[4] = r4 & MASK
    var bytes = List[UInt8](capacity=32)
    bytes.append(UInt8(l[0] & 0xFF))
    bytes.append(UInt8((l[0] >> 8) & 0xFF))
    bytes.append(UInt8((l[0] >> 16) & 0xFF))
    bytes.append(UInt8((l[0] >> 24) & 0xFF))
    bytes.append(UInt8((l[0] >> 32) & 0xFF))
    bytes.append(UInt8((l[0] >> 40) & 0xFF))
    bytes.append(UInt8(((l[0] >> 48) | (l[1] << UInt64(3))) & 0xFF))
    bytes.append(UInt8((l[1] >> 5) & 0xFF))
    bytes.append(UInt8((l[1] >> 13) & 0xFF))
    bytes.append(UInt8((l[1] >> 21) & 0xFF))
    bytes.append(UInt8((l[1] >> 29) & 0xFF))
    bytes.append(UInt8((l[1] >> 37) & 0xFF))
    bytes.append(UInt8(((l[1] >> 45) | (l[2] << UInt64(6))) & 0xFF))
    bytes.append(UInt8((l[2] >> 2) & 0xFF))
    bytes.append(UInt8((l[2] >> 10) & 0xFF))
    bytes.append(UInt8((l[2] >> 18) & 0xFF))
    bytes.append(UInt8((l[2] >> 26) & 0xFF))
    bytes.append(UInt8((l[2] >> 34) & 0xFF))
    bytes.append(UInt8((l[2] >> 42) & 0xFF))
    bytes.append(UInt8(((l[2] >> 50) | (l[3] << UInt64(1))) & 0xFF))
    bytes.append(UInt8((l[3] >> 7) & 0xFF))
    bytes.append(UInt8((l[3] >> 15) & 0xFF))
    bytes.append(UInt8((l[3] >> 23) & 0xFF))
    bytes.append(UInt8((l[3] >> 31) & 0xFF))
    bytes.append(UInt8((l[3] >> 39) & 0xFF))
    bytes.append(UInt8(((l[3] >> 47) | (l[4] << UInt64(4))) & 0xFF))
    bytes.append(UInt8((l[4] >> 4) & 0xFF))
    bytes.append(UInt8((l[4] >> 12) & 0xFF))
    bytes.append(UInt8((l[4] >> 20) & 0xFF))
    bytes.append(UInt8((l[4] >> 28) & 0xFF))
    bytes.append(UInt8((l[4] >> 36) & 0xFF))
    bytes.append(UInt8((l[4] >> 44) & 0xFF))
    return bytes^

@no_inline
def fe_from_bytes(bytes: Span[UInt8, ...]) -> FieldElement51:
    def load8(ptr: UnsafePointer[UInt8, _]) -> UInt64:
        var v: UInt64 = 0
        for j in range(8):
            v |= UInt64(ptr[j]) << UInt64(j * 8)
        return v
    var ptr = bytes.unsafe_ptr()
    var MASK = UInt64(0x7FFFFFFFFFFFF)
    var l0 = load8(ptr) & MASK
    var l1 = (load8(ptr + 6) >> UInt64(3)) & MASK
    var l2 = (load8(ptr + 12) >> UInt64(6)) & MASK
    var l3 = (load8(ptr + 19) >> UInt64(1)) & MASK
    var l4 = (load8(ptr + 24) >> UInt64(12)) & MASK
    return FieldElement51(l0, l1, l2, l3, l4)

@no_inline
def edwards_encode(p: EdwardsPoint) -> List[UInt8]:
    var z_inv = p.Z.invert()
    var x = p.X * z_inv
    var y = p.Y * z_inv
    var out = fe_to_bytes(y)
    var x_fe = fe_to_bytes(x)
    var x_parity = x_fe[0] & 1
    out[31] = out[31] | (x_parity << 7)
    return out^

@no_inline
def edwards_decode(data: Span[UInt8, ...], strict: Bool = True) -> DecodeResult:
    var y_bytes = List[UInt8](capacity=32)
    for i in range(32):
        y_bytes.append(data[i])
    var sign = (y_bytes[31] >> 7) & 1
    y_bytes[31] &= 0x7F
    var y = fe_from_bytes(Span[UInt8, ...](y_bytes))

    var y2 = y.square()
    var u = y2 - FieldElement51.ONE()
    var v = y2 * ed25519_d() + FieldElement51.ONE()

    var x_opt = sqrt_ratio_checked(u, v)
    if not x_opt:
        return DecodeResult(False, EdwardsPoint())
    var x = x_opt.value()

    var x_try = x
    if (x_try.to_bytes()[0] & 1) != sign:
        x_try = FieldElement51.ZERO() - x_try

    var chk = x_try.square() * v - u
    var chk_bytes = chk.to_bytes()
    var ok = True
    for i in range(32):
        if chk_bytes[i] != 0:
            ok = False

    if ok:
        return DecodeResult(True, EdwardsPoint(x_try, y, FieldElement51.ONE(), x_try * y))

    if not strict:
        var x_alt = FieldElement51.ZERO() - x_try
        var chk2 = x_alt.square() * v - u
        var chk2_bytes = chk2.to_bytes()
        var ok2 = True
        for i in range(32):
            if chk2_bytes[i] != 0:
                ok2 = False
        if ok2:
            return DecodeResult(True, EdwardsPoint(x_alt, y, FieldElement51.ONE(), x_alt * y))

    return DecodeResult(False, EdwardsPoint())

@no_inline
def edwards_decode_checked(data: Span[UInt8, ...]) -> DecodeResult:
    return edwards_decode(data, strict=True)

def edwards_decode_verify_compatible(data: Span[UInt8, ...]) -> DecodeResult:
    return edwards_decode(data, strict=False)

@no_inline
def edwards_decode_canonical(data: Span[UInt8, ...]) -> EdwardsPoint:
    var p = edwards_decode_checked(data)
    if p.ok:
        return p.p
    return EdwardsPoint()

@no_inline
def sqrt_ratio_checked(u: FieldElement51, v: FieldElement51) -> Optional[FieldElement51]:
    @always_inline
    def _pow_p58(a: FieldElement51) -> FieldElement51:
        var acc = FieldElement51.ONE()
        for i in range(251, -1, -1):
            acc = acc.square()
            var bit = True
            if i == 1:
                bit = False
            if bit:
                acc = acc * a
        return acc

    var v2 = v.square()
    var v3 = v2 * v
    var v7 = v3 * v2.square()
    var r = u * v7
    var z = _pow_p58(r)

    var x = u * v3 * z
    var vx2 = x.square() * v
    var diff = vx2 - u
    var diff2 = vx2 + u
    var diff_bytes = diff.to_bytes()
    var diff2_bytes = diff2.to_bytes()
    var is_zero = True
    var is_zero2 = True
    for i in range(32):
        if diff_bytes[i] != 0:
            is_zero = False
        if diff2_bytes[i] != 0:
            is_zero2 = False
    if is_zero:
        return Optional[FieldElement51](x)
    if is_zero2:
        var sqrtm1 = FieldElement51(
            1718705420411056, 234908883556509,
            2233514472574048, 2117202627021982, 765476049583133)
        return Optional[FieldElement51](x * sqrtm1)
    return None

@no_inline
def sqrt_ratio(u: FieldElement51, v: FieldElement51) -> FieldElement51:
    var x = sqrt_ratio_checked(u, v)
    if x:
        return x.value()
    return FieldElement51.ZERO()

@no_inline
def _scalar_mult(k: Span[UInt8, ...], p: EdwardsPoint) -> EdwardsPoint:
    # ARM64 COMPILER BUG: Group homomorphism fails under composition.
    # 8*SB != 8*(R + kA) (affine equivalence fails)
    # Decoding and isolated ops pass. Composition corrupts.
    var d2 = ed25519_d() * FieldElement51(2, 0, 0, 0, 0)
    var base = EdwardsPoint(
        FieldElement51(p.X.limbs),
        FieldElement51(p.Y.limbs),
        FieldElement51(p.Z.limbs),
        FieldElement51(p.T.limbs),
    )
    var r = EdwardsPoint()
    @always_inline
    def _bit_at(bytes: Span[UInt8, ...], bit_index: Int) -> UInt8:
        if bit_index < 0:
            return 0
        var byte_idx = bit_index // 8
        if byte_idx < 0 or byte_idx >= len(bytes):
            return 0
        var shift = bit_index % 8
        if shift < 0:
            return 0
        if shift > 7:
            shift = 7
        var byte_val: UInt8 = bytes[byte_idx]
        return (byte_val >> UInt8(shift)) & UInt8(1)

    for i in range(255, -1, -1):
        r = _edwards_double_standalone(r)
        if _bit_at(k, i) == 1:
            r = _edwards_add_d2(r, base, FieldElement51(d2.limbs))
    return r

def _scalar_mult_base(k: Span[UInt8, ...]) -> EdwardsPoint:
    var bp = ed25519_base_point()
    return _scalar_mult(k, bp)

def ed25519_generate_public_key(private_key: Span[UInt8, ...]) -> List[UInt8]:
    var hash = sha512_hash(private_key)
    var s = Scalar.from_bytes_clamped(Span[UInt8, ...](hash))
    var pub_point = _scalar_mult_base(s.to_bytes())
    return edwards_encode(pub_point)

def ed25519_sign(private_key: Span[UInt8, ...], message: Span[UInt8, ...]) -> List[UInt8]:
    var hash = sha512_hash(private_key)
    var s_scalar = Scalar.from_bytes_clamped(Span[UInt8, ...](hash))

    var prefix = List[UInt8](capacity=32)
    for i in range(32):
        prefix.append(hash[32 + i])

    var A_point = _scalar_mult_base(s_scalar.to_bytes())
    var A_enc = edwards_encode(A_point)

    var r_in = List[UInt8](capacity=32 + len(message))
    r_in.extend(prefix.copy())
    r_in.extend(message)
    var r_hash = sha512_hash(Span[UInt8, ...](r_in))

    var r_hash_span = Span[UInt8, ...](r_hash)
    var r_scalar = Scalar.from_bytes_wide(r_hash_span)
    _ = r_hash

    var r_bytes = r_scalar.to_bytes()
    var r_bytes_span = Span[UInt8, ...](r_bytes)
    var R_point = _scalar_mult_base(r_bytes_span)
    _ = r_bytes_span
    _ = r_bytes
    var R_enc = edwards_encode(R_point)

    var k_in = List[UInt8](capacity=64 + len(message))
    k_in.extend(R_enc.copy())
    k_in.extend(A_enc.copy())
    k_in.extend(message)
    var k_hash = sha512_hash(Span[UInt8, ...](k_in))

    var k_hash_span = Span[UInt8, ...](k_hash)
    var k_scalar = Scalar.from_bytes_wide(k_hash_span)
    _ = k_hash

    var S_scalar = r_scalar + k_scalar * s_scalar
    var S_bytes = S_scalar.to_bytes()

    var sig = List[UInt8](capacity=64)
    for i in range(32): sig.append(R_enc[i])
    for i in range(32): sig.append(S_bytes[i])
    return sig^

def ed25519_verify(public_key: Span[UInt8, ...], message: Span[UInt8, ...], signature: Span[UInt8, ...]) -> Bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    var A_res = edwards_decode_verify_compatible(public_key)
    if not A_res.ok:
        return False
    var A = A_res.p

    var R_enc = List[UInt8](capacity=32)
    for i in range(32): R_enc.append(signature[i])
    var R_enc_span = Span[UInt8, ...](R_enc)
    _ = R_enc_span

    var S_bytes = List[UInt8](capacity=32)
    for i in range(32): S_bytes.append(signature[32 + i])
    var S_bytes_span = Span[UInt8, ...](S_bytes)
    if not _s_lt_l(S_bytes_span):
        return False

    var k_in = List[UInt8](capacity=64 + len(message))
    k_in.extend(R_enc.copy())
    k_in.extend(public_key)
    k_in.extend(message)
    var k_hash = sha512_hash(Span[UInt8, ...](k_in))

    var k_hash_span = Span[UInt8, ...](k_hash)
    var k_scalar = Scalar.from_bytes_wide(k_hash_span)
    _ = k_hash

    var SB = _scalar_mult(S_bytes_span, ed25519_base_point())
    _ = S_bytes

    var k_bytes = k_scalar.to_bytes()
    var k_bytes_span = Span[UInt8, ...](k_bytes)
    var kA = _scalar_mult(k_bytes_span, A)
    _ = k_bytes

    var P = edwards_add(SB, edwards_negate(kA))
    for _ in range(3):
        P = _edwards_double_standalone(P)
    var P_enc = edwards_encode(P)
    var R_res = edwards_decode_verify_compatible(Span[UInt8, ...](R_enc))
    if not R_res.ok:
        return False
    var R_point = R_res.p
    for _ in range(3):
        R_point = _edwards_double_standalone(R_point)
    var R8_enc = edwards_encode(R_point)
    for i in range(32):
        if P_enc[i] != R8_enc[i]:
            return False
    return True