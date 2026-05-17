# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Libalpm64, Lostlab Technologies.

"""
Ed25519 implementation
By Libalpm64, no attribution required.
"""
from std.builtin.dtype import DType
from std.builtin.simd import SIMD
from std.memory import bitcast
from .curve25519 import FieldElement51
from .sha2 import SHA512Context, sha512_update, sha512_final_to_buffer
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

comptime FIELD_P_BYTES = SIMD[DType.uint8, 32](
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
)

@always_inline
def _s_lt_l(s: Span[UInt8, ...]) -> Bool:
    # RFC 8032 5.1.7 / 8.4: verification requires S < L; this prevents
    # scalar malleability from S + n*L.
    for i in range(31, -1, -1):
        var li = L_BYTES[i]
        if s[i] < li:
            return True
        if s[i] > li:
            return False
    return False

@always_inline
def _encoded_y_lt_p(y: Span[UInt8, ...]) -> Bool:
    # RFC 8032 5.1.3: strict decoding rejects y >= p.
    # Caller must clear the x-parity bit before this check.
    var lt: UInt8 = 0
    var gt: UInt8 = 0
    for i in range(31, -1, -1):
        var yi = y[i]
        var pi = FIELD_P_BYTES[i]
        if yi < pi and gt == 0:
            lt = 1
        if yi > pi and lt == 0:
            gt = 1
    return lt == 1

def _pack_limbs_into(limbs: SIMD[DType.uint64, 5], output: UnsafePointer[UInt8, MutAnyOrigin]):
    var words = SIMD[DType.uint64, 4](0, 0, 0, 0)
    words[0] = limbs[0] | (limbs[1] << 52)
    words[1] = (limbs[1] >> 12) | (limbs[2] << 40)
    words[2] = (limbs[2] >> 24) | (limbs[3] << 28)
    words[3] = (limbs[3] >> 36) | (limbs[4] << 16)
    var bytes = bitcast[DType.uint8, 32](words)
    for i in range(32):
        output[i] = bytes[i]

def _unpack_limbs(bytes: Span[UInt8, ...]) -> SIMD[DType.uint64, 5]:
    # Input may be byte-aligned; use alignment=1 for the UInt64 wide load.
    var words = bytes.unsafe_ptr().bitcast[UInt64]().load[width=4, alignment=1]()
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
    # RFC 8032 5.1.6: reduce 64-byte SHA-512 output modulo L.
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
    var X = FieldElement51(
        1738742601995546, 1146398526822698, 2070867633025821,
        562264141797630, 587772402128613,
    )
    var Y = FieldElement51(
        1801439850948184, 1351079888211148, 450359962737049,
        900719925474099, 1801439850948198,
    )
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
        # Reduces input modulo L. Callers requiring canonical encodings must
        # range-check first.
        var raw = _unpack_limbs(bytes)
        return Scalar(raw)._montgomery_mul(Scalar(RR_LIMBS))

    def to_bytes_into(self, output: UnsafePointer[UInt8, MutAnyOrigin]):
        var raw = self._montgomery_mul(Scalar(SIMD[DType.uint64, 5](1, 0, 0, 0, 0)))
        _pack_limbs_into(raw.limbs, output)

    @staticmethod
    def from_bytes_wide(bytes: Span[UInt8, ...]) -> Scalar:
        var limbs = _from_512_raw(bytes)
        return Scalar(limbs)

    @staticmethod
    def from_bytes_clamped(bytes: Span[UInt8, ...]) -> Scalar:
        # RFC 8032 5.1.5: prune SHA512(secret)[0..31] into the secret scalar.
        var s = StackInlineArray[UInt8, 32](uninitialized=True)
        for i in range(32):
            s[i] = bytes[i]
        s[0] &= 0xF8
        s[31] &= 0x7F
        s[31] |= 0x40
        return Scalar.from_bytes(Span[UInt8, ...](ptr=s.unsafe_ptr(), length=32))

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
        # Montgomery multiplication modulo L.
        var r = Scalar._montgomery_mul_raw(self.limbs, other.limbs)
        return Scalar(r)._sub(Scalar(L_LIMBS))

    def _sub(self, other: Scalar) -> Scalar:
        # Branchless subtract modulo L; used on secret scalar paths.
        comptime MASK = (UInt64(1) << 52) - 1
        var diff = SIMD[DType.uint64, 5](0, 0, 0, 0, 0)
        var borrow: UInt64 = 0
        for i in range(5):
            var x = other.limbs[i] + borrow
            var underflow = UInt64((self.limbs[i] < x).__bool__())
            diff[i] = (self.limbs[i] + (underflow << 52)) - x
            borrow = underflow

        var add_mask = UInt64(0) - borrow
        var carry: UInt64 = 0
        for i in range(5):
            carry = diff[i] + (L_LIMBS[i] & add_mask) + (carry >> 52)
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
    var d2 = ed25519_d2()
    return _edwards_add_d2(p, q, d2)

def edwards_double(p: EdwardsPoint) -> EdwardsPoint:
    return _edwards_double_standalone(p)

def edwards_negate(p: EdwardsPoint) -> EdwardsPoint:
    return EdwardsPoint(FieldElement51.ZERO() - p.X, p.Y, p.Z, FieldElement51.ZERO() - p.T)

@always_inline
def _ct_select_fe(a: FieldElement51, b: FieldElement51, choice: UInt8) -> FieldElement51:
    # Constant-time select: returns choice ? b : a using XOR/mask.
    # Todo: Verify optimized backend code for release targets.
    var mask = UInt64(0) - UInt64(choice)
    var limbs = SIMD[DType.uint64, 5](0, 0, 0, 0, 0)
    for i in range(5):
        limbs[i] = a.limbs[i] ^ (mask & (a.limbs[i] ^ b.limbs[i]))
    return FieldElement51(limbs)

@always_inline
def _ct_select_point(a: EdwardsPoint, b: EdwardsPoint, choice: UInt8) -> EdwardsPoint:
    return EdwardsPoint(
        _ct_select_fe(a.X, b.X, choice),
        _ct_select_fe(a.Y, b.Y, choice),
        _ct_select_fe(a.Z, b.Z, choice),
        _ct_select_fe(a.T, b.T, choice),
    )

@no_inline
def _edwards_add_d2(p: EdwardsPoint, q: EdwardsPoint, d2: FieldElement51) -> EdwardsPoint:
    # RFC 8032 5.1.4: complete extended Edwards addition, a = -1.
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
    # RFC 8032 5.1.4: extended Edwards doubling.
    var A = p.X.square()
    var B = p.Y.square()
    var C = p.Z.square() * FieldElement51(2, 0, 0, 0, 0)
    var D = FieldElement51.ZERO() - A
    var E = (p.X + p.Y).square() - A - B
    var G = D + B
    var F = G - C
    var H = D - B
    return EdwardsPoint(E * F, G * H, F * G, E * H)


@no_inline
def fe_from_bytes(bytes: Span[UInt8, ...]) -> FieldElement51:
    # Decode 255-bit little-endian field element; caller clears x-parity bit.
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
def edwards_encode_into(p: EdwardsPoint, output: UnsafePointer[UInt8, MutAnyOrigin]):
    # RFC 8032 5.1.2: encode y and store x parity in bit 255.
    var z_inv = p.Z.invert()
    var x = p.X * z_inv
    var y = p.Y * z_inv
    y.to_bytes_into(output)
    var x_bytes = StackInlineArray[UInt8, 32](uninitialized=True)
    x.to_bytes_into(x_bytes.unsafe_ptr())
    var x_parity = x_bytes[0] & 1
    output[31] = output[31] | (x_parity << 7)

@no_inline
def edwards_decode(data: Span[UInt8, ...], strict: Bool = True) -> DecodeResult:
    # RFC 8032 5.1.3: strict point decoding.
    # Reject y >= p, invalid square roots, and x == 0 with sign bit set.
    var y_bytes = StackInlineArray[UInt8, 32](uninitialized=True)
    for i in range(32):
        y_bytes[i] = data[i]
    var sign = (y_bytes[31] >> 7) & 1
    y_bytes[31] &= 0x7F
    if strict and not _encoded_y_lt_p(Span[UInt8, ...](ptr=y_bytes.unsafe_ptr(), length=32)):
        return DecodeResult(False, EdwardsPoint())
    var y = fe_from_bytes(Span[UInt8, ...](ptr=y_bytes.unsafe_ptr(), length=32))

    var y2 = y.square()
    var u = y2 - FieldElement51.ONE()
    var v = y2 * ed25519_d() + FieldElement51.ONE()

    var x_opt = sqrt_ratio_checked(u, v)
    if not x_opt:
        return DecodeResult(False, EdwardsPoint())
    var x = x_opt.unsafe_value()

    # x = 0 has no odd/negative alternate root.
    var x_zero_bytes = StackInlineArray[UInt8, 32](uninitialized=True)
    x.to_bytes_into(x_zero_bytes.unsafe_ptr())
    var x_is_zero = True
    for i in range(32):
        if x_zero_bytes[i] != 0:
            x_is_zero = False
    if x_is_zero and sign == 1:
        return DecodeResult(False, EdwardsPoint())

    var x_try = x
    var x_try_bytes = StackInlineArray[UInt8, 32](uninitialized=True)
    x_try.to_bytes_into(x_try_bytes.unsafe_ptr())
    if (x_try_bytes[0] & 1) != sign:
        # Choose the root matching the encoded x parity.
        x_try = FieldElement51.ZERO() - x_try

    var chk = x_try.square() * v - u
    var chk_bytes = StackInlineArray[UInt8, 32](uninitialized=True)
    chk.to_bytes_into(chk_bytes.unsafe_ptr())
    var ok = True
    for i in range(32):
        if chk_bytes[i] != 0:
            ok = False

    if ok:
        return DecodeResult(True, EdwardsPoint(x_try, y, FieldElement51.ONE(), x_try * y))

    return DecodeResult(False, EdwardsPoint())

@no_inline
def edwards_decode_checked(data: Span[UInt8, ...]) -> DecodeResult:
    return edwards_decode(data, strict=True)

def edwards_decode_verify_compatible(data: Span[UInt8, ...]) -> DecodeResult:
    # RFC verification decode, no ZIP-215 decoding (relaxed decoding not allowed under RFC strictnes).
    return edwards_decode(data, strict=True)

@no_inline
def edwards_decode_canonical(data: Span[UInt8, ...]) -> EdwardsPoint:
    var p = edwards_decode_checked(data)
    if p.ok:
        return p.p
    return EdwardsPoint()

@no_inline
def sqrt_ratio_checked(u: FieldElement51, v: FieldElement51) -> Optional[FieldElement51]:
    # RFC 8032 5.1.3: compute sqrt(u/v) using
    # x = u*v^3*(u*v^7)^((p-5)/8). Public decoding only.
    # Branches on validity; do not use for secret-dependent values.
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
    var diff_bytes = StackInlineArray[UInt8, 32](uninitialized=True)
    var diff2_bytes = StackInlineArray[UInt8, 32](uninitialized=True)
    diff.to_bytes_into(diff_bytes.unsafe_ptr())
    diff2.to_bytes_into(diff2_bytes.unsafe_ptr())
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
        return x.unsafe_value()
    return FieldElement51.ZERO()

@no_inline
def _scalar_mult(k: Span[UInt8, ...], p: EdwardsPoint) -> EdwardsPoint:
    # Secret-scalar loop: always double/add/select; no scalar-bit branch.
    var d2 = ed25519_d2()
    var base = EdwardsPoint(
        FieldElement51(p.X.limbs),
        FieldElement51(p.Y.limbs),
        FieldElement51(p.Z.limbs),
        FieldElement51(p.T.limbs),
    )
    var r = EdwardsPoint()
    @always_inline
    def _bit_at(bytes: Span[UInt8, ...], bit_index: Int) -> UInt8:
        return (bytes[bit_index >> 3] >> UInt8(bit_index & 7)) & UInt8(1)

    for i in range(255, -1, -1):
        r = _edwards_double_standalone(r)
        var added = _edwards_add_d2(r, base, d2)
        r = _ct_select_point(r, added, _bit_at(k, i))
    return r

def _scalar_mult_base(k: Span[UInt8, ...]) -> EdwardsPoint:
    var bp = ed25519_base_point()
    return _scalar_mult(k, bp)

def ed25519_generate_public_key(private_key: Span[UInt8, ...], output: UnsafePointer[UInt8, MutAnyOrigin]):
    # RFC 8032 5.1.5: public key A = [pruned SHA512(secret)]B.
    var hash = StackInlineArray[UInt8, 64](uninitialized=True)
    var ctx = SHA512Context()
    sha512_update(ctx, private_key)
    sha512_final_to_buffer(ctx, hash.unsafe_ptr())
    var s = Scalar.from_bytes_clamped(Span[UInt8, ...](ptr=hash.unsafe_ptr(), length=32))
    var s_bytes = StackInlineArray[UInt8, 32](uninitialized=True)
    s.to_bytes_into(s_bytes.unsafe_ptr())
    var pub_point = _scalar_mult_base(Span[UInt8, ...](ptr=s_bytes.unsafe_ptr(), length=32))
    edwards_encode_into(pub_point, output)

def ed25519_sign(private_key: Span[UInt8, ...], message: Span[UInt8, ...], output: UnsafePointer[UInt8, MutAnyOrigin]):
    # RFC 8032 5.1.6 pure Ed25519:
    # r = SHA512(prefix || M), R = [r]B,
    # k = SHA512(R || A || M), S = r + k*s mod L.
    var hash = StackInlineArray[UInt8, 64](uninitialized=True)
    var ctx = SHA512Context()
    sha512_update(ctx, private_key)
    sha512_final_to_buffer(ctx, hash.unsafe_ptr())
    var s_scalar = Scalar.from_bytes_clamped(Span[UInt8, ...](ptr=hash.unsafe_ptr(), length=32))

    var s_bytes = StackInlineArray[UInt8, 32](uninitialized=True)
    s_scalar.to_bytes_into(s_bytes.unsafe_ptr())
    var A_point = _scalar_mult_base(Span[UInt8, ...](ptr=s_bytes.unsafe_ptr(), length=32))
    var A_enc = StackInlineArray[UInt8, 32](uninitialized=True)
    edwards_encode_into(A_point, A_enc.unsafe_ptr())

    var r_hash = StackInlineArray[UInt8, 64](uninitialized=True)
    var r_ctx = SHA512Context()
    sha512_update(r_ctx, Span[UInt8, ...](ptr=hash.unsafe_ptr() + 32, length=32))
    sha512_update(r_ctx, message)
    sha512_final_to_buffer(r_ctx, r_hash.unsafe_ptr())

    var r_scalar = Scalar.from_bytes_wide(Span[UInt8, ...](ptr=r_hash.unsafe_ptr(), length=64))
    var r_bytes = StackInlineArray[UInt8, 32](uninitialized=True)
    r_scalar.to_bytes_into(r_bytes.unsafe_ptr())
    var R_point = _scalar_mult_base(Span[UInt8, ...](ptr=r_bytes.unsafe_ptr(), length=32))
    var R_enc = StackInlineArray[UInt8, 32](uninitialized=True)
    edwards_encode_into(R_point, R_enc.unsafe_ptr())

    var k_hash = StackInlineArray[UInt8, 64](uninitialized=True)
    var k_ctx = SHA512Context()
    sha512_update(k_ctx, Span[UInt8, ...](ptr=R_enc.unsafe_ptr(), length=32))
    sha512_update(k_ctx, Span[UInt8, ...](ptr=A_enc.unsafe_ptr(), length=32))
    sha512_update(k_ctx, message)
    sha512_final_to_buffer(k_ctx, k_hash.unsafe_ptr())

    var k_scalar = Scalar.from_bytes_wide(Span[UInt8, ...](ptr=k_hash.unsafe_ptr(), length=64))
    var S_scalar = r_scalar + k_scalar * s_scalar
    var S_bytes = StackInlineArray[UInt8, 32](uninitialized=True)
    S_scalar.to_bytes_into(S_bytes.unsafe_ptr())

    for i in range(32): output[i] = R_enc[i]
    for i in range(32): output[32 + i] = S_bytes[i]

def ed25519_verify(public_key: Span[UInt8, ...], message: Span[UInt8, ...], signature: Span[UInt8, ...]) -> Bool:
    # RFC 8032 5.1.7 strict Ed25519 verification.
    # Requires canonical A/R, S < L, and checks [S]B == R + [k]A.
    # Not ZIP-215-compatible.
    if len(public_key) != 32 or len(signature) != 64:
        return False
    var A_res = edwards_decode_verify_compatible(public_key)
    if not A_res.ok:
        return False
    var A = A_res.p

    var R_enc = StackInlineArray[UInt8, 32](uninitialized=True)
    for i in range(32): R_enc[i] = signature[i]

    var S_bytes = StackInlineArray[UInt8, 32](uninitialized=True)
    for i in range(32): S_bytes[i] = signature[32 + i]
    var S_bytes_span = Span[UInt8, ...](ptr=S_bytes.unsafe_ptr(), length=32)
    if not _s_lt_l(S_bytes_span):
        return False

    var k_hash = StackInlineArray[UInt8, 64](uninitialized=True)
    var k_ctx = SHA512Context()
    sha512_update(k_ctx, Span[UInt8, ...](ptr=R_enc.unsafe_ptr(), length=32))
    sha512_update(k_ctx, public_key)
    sha512_update(k_ctx, message)
    sha512_final_to_buffer(k_ctx, k_hash.unsafe_ptr())

    var k_hash_span = Span[UInt8, ...](ptr=k_hash.unsafe_ptr(), length=64)
    var k_scalar = Scalar.from_bytes_wide(k_hash_span)

    var SB = _scalar_mult(S_bytes_span, ed25519_base_point())

    var k_bytes = StackInlineArray[UInt8, 32](uninitialized=True)
    k_scalar.to_bytes_into(k_bytes.unsafe_ptr())
    var k_bytes_span = Span[UInt8, ...](ptr=k_bytes.unsafe_ptr(), length=32)
    var kA = _scalar_mult(k_bytes_span, A)

    var R_res = edwards_decode_verify_compatible(Span[UInt8, ...](ptr=R_enc.unsafe_ptr(), length=32))
    if not R_res.ok:
        return False
    var P = edwards_add(R_res.p, kA)
    var P_enc = StackInlineArray[UInt8, 32](uninitialized=True)
    var SB_enc = StackInlineArray[UInt8, 32](uninitialized=True)
    edwards_encode_into(P, P_enc.unsafe_ptr())
    edwards_encode_into(SB, SB_enc.unsafe_ptr())
    for i in range(32):
        if P_enc[i] != SB_enc[i]:
            return False
    return True