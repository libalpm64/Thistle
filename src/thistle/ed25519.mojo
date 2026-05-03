# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Libalpm64, Lostlab Technologies.

"""
By Libalpm64
Non-Production code
Do note use on ARM because of a stack aliasing bug.
"""
from std.builtin.dtype import DType
from std.builtin.simd import SIMD
from std.collections import List
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

fn _pack_limbs(limbs: SIMD[DType.uint64, 5]) -> List[UInt8]:
    var words = SIMD[DType.uint64, 4](0, 0, 0, 0)
    words[0] = limbs[0] | (limbs[1] << UInt64(52))
    words[1] = (limbs[1] >> UInt64(12)) | (limbs[2] << UInt64(40))
    words[2] = (limbs[2] >> UInt64(24)) | (limbs[3] << UInt64(28))
    words[3] = (limbs[3] >> UInt64(36)) | (limbs[4] << UInt64(16))
    var out = List[UInt8](capacity=32)
    for i in range(4):
        for j in range(8):
            out.append(UInt8(words[i] >> UInt64(j * 8)) & 0xFF)
    return out^

fn bytes_to_hex(bytes: List[UInt8]) -> String:
    var r = String(capacity=len(bytes)*2)
    for i in range(len(bytes)):
        var hi = Int(bytes[i] >> 4)
        var lo = Int(bytes[i] & 15)
        r += chr(hi + 48 if hi < 10 else hi - 10 + 97)
        r += chr(lo + 48 if lo < 10 else lo - 10 + 97)
    return r

fn _unpack_limbs(bytes: Span[UInt8, ...]) -> SIMD[DType.uint64, 5]:
    var words = SIMD[DType.uint64, 4](0, 0, 0, 0)
    for i in range(4):
        for j in range(8):
            words[i] |= UInt64(bytes[i * 8 + j]) << UInt64(j * 8)
    comptime MASK = (UInt64(1) << 52) - 1
    comptime TOP_MASK = (UInt64(1) << 48) - 1
    var s = SIMD[DType.uint64, 5](0, 0, 0, 0, 0)
    s[0] = words[0] & MASK
    s[1] = ((words[0] >> UInt64(52)) | (words[1] << UInt64(12))) & MASK
    s[2] = ((words[1] >> UInt64(40)) | (words[2] << UInt64(24))) & MASK
    s[3] = ((words[2] >> UInt64(28)) | (words[3] << UInt64(36))) & MASK
    s[4] = (words[3] >> UInt64(16)) & TOP_MASK
    return s

fn _from_512_raw(bytes: Span[UInt8, ...]) -> SIMD[DType.uint64, 5]:
    var ptr = bytes.unsafe_ptr()
    var lo_span = Span[UInt8, ...](ptr=ptr, length=32)
    var hi_span = Span[UInt8, ...](ptr=ptr + 32, length=32)
    var lo = Scalar.from_bytes(lo_span)
    var hi = Scalar.from_bytes(hi_span)
    var pow2_256 = Scalar(POW2_256_LIMBS)
    var res = lo + hi * pow2_256
    return res.limbs

@always_inline
fn ed25519_d() -> FieldElement51:
    return FieldElement51(ED25519_D_LIMBS)

@always_inline
fn ed25519_d2() -> FieldElement51:
    return ed25519_d() * FieldElement51(2, 0, 0, 0, 0)

fn ed25519_base_point() -> EdwardsPoint:
    var x_bytes = List[UInt8](capacity=32)
    x_bytes.append(0x1a); x_bytes.append(0xd5); x_bytes.append(0x25); x_bytes.append(0x8f)
    x_bytes.append(0x60); x_bytes.append(0x2d); x_bytes.append(0x56); x_bytes.append(0xc9)
    x_bytes.append(0xb2); x_bytes.append(0xa7); x_bytes.append(0x25); x_bytes.append(0x95)
    x_bytes.append(0x60); x_bytes.append(0xc7); x_bytes.append(0x2c); x_bytes.append(0x69)
    x_bytes.append(0x5c); x_bytes.append(0xdc); x_bytes.append(0xd6); x_bytes.append(0xfd)
    x_bytes.append(0x31); x_bytes.append(0xe2); x_bytes.append(0xa4); x_bytes.append(0xc0)
    x_bytes.append(0xfe); x_bytes.append(0x53); x_bytes.append(0x6e); x_bytes.append(0xcd)
    x_bytes.append(0xd3); x_bytes.append(0x36); x_bytes.append(0x69); x_bytes.append(0x21)
    var x_span = Span[UInt8, ...](x_bytes)
    var X = fe_from_bytes(x_span)
    _ = x_bytes
    var y_bytes = List[UInt8](capacity=32)
    y_bytes.append(0x58); y_bytes.append(0x66); y_bytes.append(0x66); y_bytes.append(0x66)
    y_bytes.append(0x66); y_bytes.append(0x66); y_bytes.append(0x66); y_bytes.append(0x66)
    y_bytes.append(0x66); y_bytes.append(0x66); y_bytes.append(0x66); y_bytes.append(0x66)
    y_bytes.append(0x66); y_bytes.append(0x66); y_bytes.append(0x66); y_bytes.append(0x66)
    y_bytes.append(0x66); y_bytes.append(0x66); y_bytes.append(0x66); y_bytes.append(0x66)
    y_bytes.append(0x66); y_bytes.append(0x66); y_bytes.append(0x66); y_bytes.append(0x66)
    y_bytes.append(0x66); y_bytes.append(0x66); y_bytes.append(0x66); y_bytes.append(0x66)
    y_bytes.append(0x66); y_bytes.append(0x66); y_bytes.append(0x66); y_bytes.append(0x66)
    var y_span = Span[UInt8, ...](y_bytes)
    var Y = fe_from_bytes(y_span)
    _ = y_bytes
    var T = X * Y
    return EdwardsPoint(X, Y, FieldElement51.ONE(), T)


struct Scalar(Movable, Copyable, ImplicitlyCopyable):
    var limbs: SIMD[DType.uint64, 5]

    @always_inline
    fn __init__(out self):
        self.limbs = SIMD[DType.uint64, 5](0, 0, 0, 0, 0)

    @always_inline
    fn __init__(out self, limbs: SIMD[DType.uint64, 5]):
        self.limbs = limbs

    @always_inline
    fn __copyinit__(out self, copy: Self):
        self.limbs = copy.limbs

    @always_inline
    fn __moveinit__(out self, deinit take: Self):
        self.limbs = take.limbs

    @staticmethod
    fn from_bytes(bytes: Span[UInt8, ...]) -> Scalar:
        var raw = _unpack_limbs(bytes)
        return Scalar(raw)._montgomery_mul(Scalar(RR_LIMBS))

    fn to_bytes(self) -> List[UInt8]:
        var raw = self._montgomery_mul(Scalar(SIMD[DType.uint64, 5](1, 0, 0, 0, 0)))
        return _pack_limbs(raw.limbs)

    @staticmethod
    fn from_bytes_wide(bytes: Span[UInt8, ...]) -> Scalar:
        var limbs = _from_512_raw(bytes)
        return Scalar(limbs)

    fn __add__(self, other: Scalar) -> Scalar:
        comptime MASK = (UInt64(1) << 52) - 1
        var sum = SIMD[DType.uint64, 5](0, 0, 0, 0, 0)
        var carry: UInt64 = 0
        for i in range(5):
            carry = self.limbs[i] + other.limbs[i] + (carry >> 52)
            sum[i] = carry & MASK
        return Scalar(sum)._sub(Scalar(L_LIMBS))

    fn __sub__(self, other: Scalar) -> Scalar:
        return self._sub(other)

    fn __neg__(self) -> Scalar:
        return Scalar(L_LIMBS)._sub(self)

    fn __mul__(self, other: Scalar) -> Scalar:
        return self._montgomery_mul(other)

    @staticmethod
    fn _montgomery_mul_raw(a: SIMD[DType.uint64, 5], b: SIMD[DType.uint64, 5]) -> SIMD[DType.uint64, 5]:
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

    fn _montgomery_mul(self, other: Scalar) -> Scalar:
        var r = Scalar._montgomery_mul_raw(self.limbs, other.limbs)
        return Scalar(r)._sub(Scalar(L_LIMBS))

    fn _sub(self, other: Scalar) -> Scalar:
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
    fn __init__(out self):
        self.X = FieldElement51.ZERO()
        self.Y = FieldElement51.ONE()
        self.Z = FieldElement51.ONE()
        self.T = FieldElement51.ZERO()

    @always_inline
    fn __init__(out self, X: FieldElement51, Y: FieldElement51, Z: FieldElement51, T: FieldElement51):
        self.X = X; self.Y = Y; self.Z = Z; self.T = T

    @always_inline
    fn __copyinit__(out self, copy: Self):
        self.X = copy.X; self.Y = copy.Y; self.Z = copy.Z; self.T = copy.T

    @always_inline
    fn __moveinit__(out self, deinit take: Self):
        self.X = take.X^; self.Y = take.Y^; self.Z = take.Z^; self.T = take.T^


fn edwards_add(p: EdwardsPoint, q: EdwardsPoint) -> EdwardsPoint:
    var d2 = FieldElement51(ED25519_D2_LIMBS)
    var A = (p.Y - p.X) * (q.Y - q.X)
    var B = (p.Y + p.X) * (q.Y + q.X)
    var C = p.T * q.T * d2
    var D = p.Z * q.Z * FieldElement51(2, 0, 0, 0, 0)
    var E = B - A
    var F = D - C
    var G = D + C
    var H = B + A
    return EdwardsPoint(E * F, G * H, F * G, E * H)

fn edwards_double(p: EdwardsPoint) -> EdwardsPoint:
    var A = p.X.square()
    var B = p.Y.square()
    var C = p.Z.square() * FieldElement51(2, 0, 0, 0, 0)
    var H = A + B
    var E = H - (p.X + p.Y).square()
    var G = A - B
    var F = C + G
    return EdwardsPoint(E * F, G * H, F * G, E * H)

fn edwards_negate(p: EdwardsPoint) -> EdwardsPoint:
    return EdwardsPoint(FieldElement51.ZERO() - p.X, p.Y, p.Z, FieldElement51.ZERO() - p.T)

# stack aliasing bug on ARM64 that occurs when ed25519_d2()
# is called inside a loop that also modifies EdwardsPoint values.
# COMPILER-BUG (will never sort)
@no_inline
fn _edwards_add_d2(p: EdwardsPoint, q: EdwardsPoint, d2: FieldElement51) -> EdwardsPoint:
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
fn _edwards_double_standalone(p: EdwardsPoint) -> EdwardsPoint:
    var A = p.X.square()
    var B = p.Y.square()
    var C = p.Z.square() * FieldElement51(2, 0, 0, 0, 0)
    var H = A + B
    var E = H - (p.X + p.Y).square()
    var G = A - B
    var F = C + G
    return EdwardsPoint(E * F, G * H, F * G, E * H)


fn fe_to_bytes(fe: FieldElement51) -> List[UInt8]:
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
fn fe_from_bytes(bytes: Span[UInt8, ...]) -> FieldElement51:
    fn load8(ptr: UnsafePointer[UInt8, _]) -> UInt64:
        return ptr.bitcast[UInt64]().load()
    var ptr = bytes.unsafe_ptr()
    var MASK = UInt64(0x7FFFFFFFFFFFF)
    var l0 = load8(ptr) & MASK
    var l1 = (load8(ptr + 6) >> UInt64(3)) & MASK
    var l2 = (load8(ptr + 12) >> UInt64(6)) & MASK
    var l3 = (load8(ptr + 19) >> UInt64(1)) & MASK
    var l4 = (load8(ptr + 24) >> UInt64(12)) & MASK
    return FieldElement51(l0, l1, l2, l3, l4)

@no_inline
fn edwards_encode(p: EdwardsPoint) -> List[UInt8]:
    var z_inv = p.Z.invert()
    var x = p.X * z_inv
    var y = p.Y * z_inv
    var out = fe_to_bytes(y)
    var x_fe = fe_to_bytes(x)
    var x_parity = x_fe[0] & 1
    out[31] = out[31] | (x_parity << 7)
    return out^

@no_inline
fn edwards_decode(data: Span[UInt8, ...]) -> EdwardsPoint:
    var y_bytes = List[UInt8](capacity=32)
    for i in range(32):
        y_bytes.append(data[i])
    y_bytes[31] = y_bytes[31] & 0x7F
    var y_span = Span[UInt8, ...](y_bytes)
    var y = fe_from_bytes(y_span)
    _ = y_bytes
    var y2 = y.square()
    var u = y2 - FieldElement51.ONE()
    var v = y2 * ed25519_d() + FieldElement51.ONE()
    var x = sqrt_ratio(u, v)
    var x_bytes = x.to_bytes()
    var sign = (data[31] >> 7) & 1
    if (x_bytes[0] & 1) != sign:
        x = FieldElement51.ZERO() - x
    var t = x * y
    return EdwardsPoint(x, y, FieldElement51.ONE(), t)

@no_inline
fn sqrt_ratio(u: FieldElement51, v: FieldElement51) -> FieldElement51:
    var v_sq = v.square()
    var v3 = v_sq * v
    var v4 = v_sq.square()
    var v7 = v4 * v3
    var c = u * v7
    var t = c.square()
    t = t * c
    t = t.square()
    var tv = t * c
    t = tv.pow2k(3)
    t = t * tv
    t = t.square()
    tv = t * c
    t = tv.pow2k(7)
    t = t * tv
    t = t.square()
    tv = t * c
    t = tv.pow2k(15)
    t = t * tv
    t = t.square()
    tv = t * c
    t = tv.pow2k(31)
    tv = t * tv
    t = tv.pow2k(62)
    t = t * tv
    t = t.square()
    tv = t * c
    t = tv.pow2k(125)
    t = t * tv
    t = t.square()
    t = t.square()
    t = t * c
    var x = t * u
    x = x * v3
    var diff = x.square() * v - u
    var diff_bytes = diff.to_bytes()
    var is_zero = True
    for i in range(32):
        if diff_bytes[i] != 0:
            is_zero = False
    if is_zero:
        return x
    var sqrtm1 = FieldElement51(
        1718705420411056, 234908883556509,
        2233514472574048, 2117202627021982, 765476049583133)
    x = x * sqrtm1
    return x


@no_inline
fn _scalar_mult(k: Span[UInt8, ...], p: EdwardsPoint) -> EdwardsPoint:
	# ARM COMPILER-BUG
    # ed25519_d2() inside the loop corrupts the accumulator r.
	# two _scalar_mult_base calls corrupt each other.
    var d2 = ed25519_d() * FieldElement51(2, 0, 0, 0, 0)
    var bX = FieldElement51(p.X.limbs)
    var bY = FieldElement51(p.Y.limbs)
    var bZ = FieldElement51(p.Z.limbs)
    var bT = FieldElement51(p.T.limbs)
    var r = EdwardsPoint()
    for i in range(255, -1, -1):
        r = _edwards_double_standalone(r)
        if (Int(k[i // 8]) >> (i % 8)) & 1:
            var q = EdwardsPoint(
                FieldElement51(bX.limbs),
                FieldElement51(bY.limbs),
                FieldElement51(bZ.limbs),
                FieldElement51(bT.limbs),
            )
            r = _edwards_add_d2(r, q, FieldElement51(d2.limbs))
    return r

fn _scalar_mult_base(k: Span[UInt8, ...]) -> EdwardsPoint:
    var bp = ed25519_base_point()
    return _scalar_mult(k, bp)

fn ed25519_generate_public_key(private_key: Span[UInt8, ...]) -> List[UInt8]:
    var hash = sha512_hash(private_key)
    var s = List[UInt8](capacity=32)
    for i in range(32):
        s.append(hash[i])
    s[0] = s[0] & 0xF8
    s[31] = s[31] & 0x7F
    s[31] = s[31] | 0x40
    var s_span = Span[UInt8, ...](s)
    var pub_point = _scalar_mult_base(s_span)
    _ = s
    return edwards_encode(pub_point)

fn ed25519_sign(private_key: Span[UInt8, ...], message: Span[UInt8, ...]) -> List[UInt8]:
    var hash = sha512_hash(private_key)

    var s = List[UInt8](capacity=32)
    for i in range(32):
        s.append(hash[i])
    s[0] = s[0] & 0xF8; s[31] = s[31] & 0x7F; s[31] = s[31] | 0x40

    var prefix = List[UInt8](capacity=32)
    for i in range(32):
        prefix.append(hash[32 + i])

    var s_span = Span[UInt8, ...](s)
    var A_point = _scalar_mult_base(s_span)
    _ = s_span
    var A_enc = edwards_encode(A_point)

    var r_in = List[UInt8](capacity=32 + len(message))
    for i in range(32):
        r_in.append(prefix[i])
    for i in range(len(message)):
        r_in.append(message[i])
    var r_in_span = Span[UInt8, ...](r_in)
    var r_hash = sha512_hash(r_in_span)
    _ = r_in

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
    for i in range(32): k_in.append(R_enc[i])
    for i in range(32): k_in.append(A_enc[i])
    for i in range(len(message)): k_in.append(message[i])
    var k_in_span = Span[UInt8, ...](k_in)
    var k_hash = sha512_hash(k_in_span)
    _ = k_in

    var k_hash_span = Span[UInt8, ...](k_hash)
    var k_scalar = Scalar.from_bytes_wide(k_hash_span)
    _ = k_hash

    var s2 = List[UInt8](capacity=32)
    for i in range(32):
        s2.append(hash[i])
    s2[0] = s2[0] & 0xF8; s2[31] = s2[31] & 0x7F; s2[31] = s2[31] | 0x40
    var s2_span = Span[UInt8, ...](s2)
    var s_scalar = Scalar.from_bytes(s2_span)
    _ = s2

    var S_scalar = r_scalar + k_scalar * s_scalar
    var S_bytes = S_scalar.to_bytes()

    var sig = List[UInt8](capacity=64)
    for i in range(32): sig.append(R_enc[i])
    for i in range(32): sig.append(S_bytes[i])
    return sig^

fn ed25519_verify(public_key: Span[UInt8, ...], message: Span[UInt8, ...], signature: Span[UInt8, ...]) -> Bool:
    var A = edwards_decode(public_key)

    var R_enc = List[UInt8](capacity=32)
    for i in range(32): R_enc.append(signature[i])
    var R_enc_span = Span[UInt8, ...](R_enc)
    _ = R_enc_span

    var S_bytes = List[UInt8](capacity=32)
    for i in range(32): S_bytes.append(signature[32 + i])

    var k_in = List[UInt8](capacity=64 + len(message))
    for i in range(32): k_in.append(R_enc[i])
    for i in range(32): k_in.append(public_key[i])
    for i in range(len(message)): k_in.append(message[i])
    var k_in_span = Span[UInt8, ...](k_in)
    var k_hash = sha512_hash(k_in_span)
    _ = k_in

    var k_hash_span = Span[UInt8, ...](k_hash)
    var k_scalar = Scalar.from_bytes_wide(k_hash_span)
    _ = k_hash

    var S_bytes_span = Span[UInt8, ...](S_bytes)
    var SB = _scalar_mult(S_bytes_span, ed25519_base_point())
    _ = S_bytes

    var k_bytes = k_scalar.to_bytes()
    var k_bytes_span = Span[UInt8, ...](k_bytes)
    var kA = _scalar_mult(k_bytes_span, A)
    _ = k_bytes

    var P = edwards_add(SB, edwards_negate(kA))
    var P_enc = edwards_encode(P)
    for i in range(32):
        if P_enc[i] != R_enc[i]:
            return False
    return True
