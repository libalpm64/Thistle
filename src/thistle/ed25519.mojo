"""
Ed25519 implementation
"""
from std.builtin.dtype import DType
from std.builtin.simd import SIMD
from std.memory import bitcast
from .curve25519 import FieldElement51
from .ed25519_table import ed25519_base_table, ed25519_b_odd_table
from .sha2 import SHA512Context, sha512_update, sha512_final_to_buffer


comptime L_LIMBS = SIMD[DType.uint64, 8](
    0x0002631a5cf5d3ed,
    0x000dea2f79cd6581,
    0x000000000014def9,
    0x0000000000000000,
    0x0000100000000000,
    0, 0, 0,
)
comptime LFACTOR: UInt64 = 0x51da312547e1b

comptime RR_LIMBS = SIMD[DType.uint64, 8](
    0x0009d265e952d13b,
    0x000d63c715bea69f,
    0x0005be65cb687604,
    0x0003dceec73d217f,
    0x000009411b7c309a,
    0, 0, 0,
)

comptime ED25519_D_LIMBS = SIMD[DType.uint64, 8](
    0x34dca135978a3,
    0x001a8283b156ebd,
    0x005e7a26001c029,
    0x00739c663a03cbb,
    0x0052036cee2b6ff,
    0, 0, 0,
)

comptime POW2_256_LIMBS = SIMD[DType.uint64, 8](
    0x0009f4e532df7449,
    0x000da9f725df7382,
    0x000f5be65cc244cc,
    0x000a3dceec73d217,
    0x0000099411b7c309,
    0, 0, 0,
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

def _pack_limbs_into(limbs: SIMD[DType.uint64, 8], output: Pointer[mut=True, UInt8, _, address_space=_]):
    var words = SIMD[DType.uint64, 4](0, 0, 0, 0)
    words[0] = limbs[0] | (limbs[1] << 52)
    words[1] = (limbs[1] >> 12) | (limbs[2] << 40)
    words[2] = (limbs[2] >> 24) | (limbs[3] << 28)
    words[3] = (limbs[3] >> 36) | (limbs[4] << 16)
    var bytes = bitcast[DType.uint8, 32](words)
    for i in range(32):
        output[unsafe_offset=i] = bytes[i]

def _unpack_limbs(bytes: Span[UInt8, ...]) -> SIMD[DType.uint64, 8]:
    # Input may be byte-aligned; use alignment=1 for the UInt64 wide load.
    var words = bytes.unsafe_ptr().unsafe_bitcast[UInt64]().unsafe_load[width=4, alignment=1]()
    comptime MASK = (UInt64(1) << 52) - 1
    comptime TOP_MASK = (UInt64(1) << 48) - 1
    var s = SIMD[DType.uint64, 8](0)
    s[0] = words[0] & MASK
    s[1] = ((words[0] >> UInt64(52)) | (words[1] << UInt64(12))) & MASK
    s[2] = ((words[1] >> UInt64(40)) | (words[2] << UInt64(24))) & MASK
    s[3] = ((words[2] >> UInt64(28)) | (words[3] << UInt64(36))) & MASK
    s[4] = (words[3] >> UInt64(16)) & TOP_MASK
    return s

def _from_512_raw(bytes: Span[UInt8, ...]) -> SIMD[DType.uint64, 8]:
    # RFC 8032 5.1.6: reduce 64-byte SHA-512 output modulo L.
    var ptr = bytes.unsafe_ptr()
    var lo_span = Span[UInt8, ...](unsafe_ptr=ptr, length=32)
    var hi_span = Span[UInt8, ...](unsafe_ptr=ptr.unsafe_offset(32), length=32)
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
    var limbs: SIMD[DType.uint64, 8]

    @always_inline
    def __init__(out self):
        self.limbs = SIMD[DType.uint64, 8](0)

    @always_inline
    def __init__(out self, limbs: SIMD[DType.uint64, 8]):
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

    def to_bytes_into(self, output: Pointer[mut=True, UInt8, _, address_space=_]):
        var raw = self._montgomery_mul(
            Scalar(SIMD[DType.uint64, 8](1, 0, 0, 0, 0, 0, 0, 0))
        )
        _pack_limbs_into(raw.limbs, output)

    @staticmethod
    def from_bytes_wide(bytes: Span[UInt8, ...]) -> Scalar:
        var limbs = _from_512_raw(bytes)
        return Scalar(limbs)

    @staticmethod
    def from_bytes_clamped(bytes: Span[UInt8, ...]) -> Scalar:
        # RFC 8032 5.1.5: prune SHA512(secret)[0..31] into the secret scalar.
        var s = InlineArray[UInt8, 32](fill=0)
        for i in range(32):
            s[i] = bytes[i]
        s[0] &= 0xF8
        s[31] &= 0x7F
        s[31] |= 0x40
        return Scalar.from_bytes(Span[UInt8, ...](unsafe_ptr=s.unsafe_ptr(), length=32))

    def __add__(self, other: Scalar) -> Scalar:
        comptime MASK = (UInt64(1) << 52) - 1
        var sum = SIMD[DType.uint64, 8](0)
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
    def _montgomery_mul_raw(a: SIMD[DType.uint64, 8], b: SIMD[DType.uint64, 8]) -> SIMD[DType.uint64, 8]:
        var z = InlineArray[UInt128, 9](fill=0)
        for i in range(9): z[i] = 0
        for i in range(5):
            for j in range(5):
                z[i + j] += UInt128(a[i]) * UInt128(b[j])
        var carry: UInt128 = 0
        var n = InlineArray[UInt64, 5](fill=0)
        for i in range(5):
            var sum = carry + z[i]
            for j in range(i):
                sum += UInt128(n[j]) * UInt128(L_LIMBS[i - j])
            var p = (UInt64(sum.cast[DType.uint64]() * LFACTOR)) & ((UInt64(1) << 52) - 1)
            n[i] = p
            carry = (sum + UInt128(p) * UInt128(L_LIMBS[0])) >> 52
        var r = SIMD[DType.uint64, 8](0)
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

    def wipe(mut self):
        Pointer(to=self.limbs).unsafe_bitcast[UInt64]().unsafe_store[volatile=True](
            0, SIMD[DType.uint64, 8](0)
        )

    def _sub(self, other: Scalar) -> Scalar:
        # Branchless subtract modulo L; used on secret scalar paths.
        comptime MASK = (UInt64(1) << 52) - 1
        var diff = SIMD[DType.uint64, 8](0)
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
    # constant-time select via mask
    var mask = UInt64(0) - UInt64(choice)
    var limbs = SIMD[DType.uint64, 8](0)
    for i in range(5):
        limbs[i] = a.limbs[i] ^ (mask & (a.limbs[i] ^ b.limbs[i]))
    return FieldElement51(limbs)

@no_inline
def _edwards_add_d2(p: EdwardsPoint, q: EdwardsPoint, d2: FieldElement51) -> EdwardsPoint:
    # RFC 8032 5.1.4: complete extended Edwards addition, a = -1.
    var A = (p.Y - p.X) * (q.Y - q.X)
    var B = (p.Y + p.X) * (q.Y + q.X)
    var C = p.T * q.T * d2
    var ZZ = p.Z * q.Z
    var D = ZZ + ZZ
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
    var ZZ = p.Z.square()
    var C = ZZ + ZZ
    var D = FieldElement51.ZERO() - A
    var E = (p.X + p.Y).square() - A - B
    var G = D + B
    var F = G - C
    var H = D - B
    return EdwardsPoint(E * F, G * H, F * G, E * H)


@no_inline
def fe_from_bytes(bytes: Span[UInt8, ...]) -> FieldElement51:
    # Decode 255-bit little-endian field element; caller clears x-parity bit.
    def load8(ptr: Pointer[mut=False, UInt8, _, address_space=_]) -> UInt64:
        var v: UInt64 = 0
        for j in range(8):
            v |= UInt64(ptr[unsafe_offset=j]) << UInt64(j * 8)
        return v
    var ptr = bytes.unsafe_ptr()
    var MASK = UInt64(0x7FFFFFFFFFFFF)
    var l0 = load8(ptr) & MASK
    var l1 = (load8(ptr.unsafe_offset(6)) >> UInt64(3)) & MASK
    var l2 = (load8(ptr.unsafe_offset(12)) >> UInt64(6)) & MASK
    var l3 = (load8(ptr.unsafe_offset(19)) >> UInt64(1)) & MASK
    var l4 = (load8(ptr.unsafe_offset(24)) >> UInt64(12)) & MASK
    return FieldElement51(l0, l1, l2, l3, l4)

@no_inline
def edwards_encode_into(p: EdwardsPoint, output: Pointer[mut=True, UInt8, _, address_space=_]):
    # RFC 8032 5.1.2: encode y and store x parity in bit 255.
    _edwards_encode_with_zinv(p, p.Z.invert(), output)

@no_inline
def _edwards_encode_with_zinv(p: EdwardsPoint, z_inv: FieldElement51, output: Pointer[mut=True, UInt8, _, address_space=_]):
    var x = p.X * z_inv
    var y = p.Y * z_inv
    y.to_bytes_into(output)
    var x_bytes = InlineArray[UInt8, 32](fill=0)
    x.to_bytes_into(x_bytes.unsafe_ptr())
    var x_parity = x_bytes[0] & 1
    output[unsafe_offset=31] = output[unsafe_offset=31] | (x_parity << 7)

@no_inline
def edwards_decode(data: Span[UInt8, ...], strict: Bool = True) -> DecodeResult:
    # RFC 8032 5.1.3: strict point decoding.
    # Reject y >= p, invalid square roots, and x == 0 with sign bit set.
    var y_bytes = InlineArray[UInt8, 32](fill=0)
    for i in range(32):
        y_bytes[i] = data[i]
    var sign = (y_bytes[31] >> 7) & 1
    y_bytes[31] &= 0x7F
    if strict and not _encoded_y_lt_p(Span[UInt8, ...](unsafe_ptr=y_bytes.unsafe_ptr(), length=32)):
        return DecodeResult(False, EdwardsPoint())
    var y = fe_from_bytes(Span[UInt8, ...](unsafe_ptr=y_bytes.unsafe_ptr(), length=32))

    var y2 = y.square()
    var u = y2 - FieldElement51.ONE()
    var v = y2 * ed25519_d() + FieldElement51.ONE()

    var x_opt = sqrt_ratio_checked(u, v)
    if not x_opt:
        return DecodeResult(False, EdwardsPoint())
    var x = x_opt.unsafe_value()

    # x = 0 has no odd/negative alternate root.
    var x_zero_bytes = InlineArray[UInt8, 32](fill=0)
    x.to_bytes_into(x_zero_bytes.unsafe_ptr())
    var x_is_zero = True
    for i in range(32):
        if x_zero_bytes[i] != 0:
            x_is_zero = False
    if x_is_zero and sign == 1:
        return DecodeResult(False, EdwardsPoint())

    var x_try = x
    var x_try_bytes = InlineArray[UInt8, 32](fill=0)
    x_try.to_bytes_into(x_try_bytes.unsafe_ptr())
    if (x_try_bytes[0] & 1) != sign:
        # Choose the root matching the encoded x parity.
        x_try = FieldElement51.ZERO() - x_try

    var chk = x_try.square() * v - u
    var chk_bytes = InlineArray[UInt8, 32](fill=0)
    chk.to_bytes_into(chk_bytes.unsafe_ptr())
    var ok = True
    for i in range(32):
        if chk_bytes[i] != 0:
            ok = False

    if ok:
        return DecodeResult(True, EdwardsPoint(x_try, y, FieldElement51.ONE(), x_try * y))

    return DecodeResult(False, EdwardsPoint())

def edwards_decode_verify_compatible(data: Span[UInt8, ...]) -> DecodeResult:
    # strict RFC decoding only, no ZIP-215
    return edwards_decode(data, strict=True)


def _is_small_order(p: EdwardsPoint) -> Bool:
    var q = _edwards_double_standalone(p)
    q = _edwards_double_standalone(q)
    q = _edwards_double_standalone(q)
    var x = InlineArray[UInt8, 32](fill=0)
    var yz = InlineArray[UInt8, 32](fill=0)
    q.X.to_bytes_into(x.unsafe_ptr())
    (q.Y - q.Z).to_bytes_into(yz.unsafe_ptr())
    var diff = UInt8(0)
    for i in range(32):
        diff |= x[i] | yz[i]
    return diff == 0

@no_inline
def sqrt_ratio_checked(u: FieldElement51, v: FieldElement51) -> Optional[FieldElement51]:
    # RFC 8032 5.1.3: compute sqrt(u/v) using
    # x = u*v^3*(u*v^7)^((p-5)/8). Public decoding only.
    # Branches on validity; do not use for secret-dependent values.
    var v2 = v.square()
    var v3 = v2 * v
    var v7 = v3 * v2.square()
    var r = u * v7
    var z = r.pow_p58()

    var x = u * v3 * z
    var vx2 = x.square() * v
    var diff = vx2 - u
    var diff2 = vx2 + u
    var diff_bytes = InlineArray[UInt8, 32](fill=0)
    var diff2_bytes = InlineArray[UInt8, 32](fill=0)
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

struct AffineNielsPoint(Movable, Copyable, ImplicitlyCopyable):
    var y_plus_x: FieldElement51
    var y_minus_x: FieldElement51
    var xy2d: FieldElement51

    @always_inline
    def __init__(out self, y_plus_x: FieldElement51, y_minus_x: FieldElement51, xy2d: FieldElement51):
        self.y_plus_x = y_plus_x
        self.y_minus_x = y_minus_x
        self.xy2d = xy2d

    @always_inline
    def __copyinit__(out self, copy: Self):
        self.y_plus_x = copy.y_plus_x
        self.y_minus_x = copy.y_minus_x
        self.xy2d = copy.xy2d

    @always_inline
    def __moveinit__(out self, deinit take: Self):
        self.y_plus_x = take.y_plus_x^
        self.y_minus_x = take.y_minus_x^
        self.xy2d = take.xy2d^


struct ProjectiveNielsPoint(Movable, Copyable, ImplicitlyCopyable):
    var Y_plus_X: FieldElement51
    var Y_minus_X: FieldElement51
    var Z: FieldElement51
    var T2d: FieldElement51

    @always_inline
    def __init__(out self):
        self.Y_plus_X = FieldElement51()
        self.Y_minus_X = FieldElement51()
        self.Z = FieldElement51()
        self.T2d = FieldElement51()

    @always_inline
    def __init__(out self, Y_plus_X: FieldElement51, Y_minus_X: FieldElement51, Z: FieldElement51, T2d: FieldElement51):
        self.Y_plus_X = Y_plus_X
        self.Y_minus_X = Y_minus_X
        self.Z = Z
        self.T2d = T2d

    @always_inline
    def __copyinit__(out self, copy: Self):
        self.Y_plus_X = copy.Y_plus_X
        self.Y_minus_X = copy.Y_minus_X
        self.Z = copy.Z
        self.T2d = copy.T2d

    @always_inline
    def __moveinit__(out self, deinit take: Self):
        self.Y_plus_X = take.Y_plus_X^
        self.Y_minus_X = take.Y_minus_X^
        self.Z = take.Z^
        self.T2d = take.T2d^


@always_inline
def _to_projective_niels(p: EdwardsPoint, d2: FieldElement51) -> ProjectiveNielsPoint:
    return ProjectiveNielsPoint(p.Y + p.X, p.Y - p.X, p.Z, p.T * d2)

@always_inline
def _add_affine_niels(p: EdwardsPoint, q: AffineNielsPoint) -> EdwardsPoint:
    var PP = (p.Y + p.X) * q.y_plus_x
    var MM = (p.Y - p.X) * q.y_minus_x
    var Txy = p.T * q.xy2d
    var Z2 = p.Z + p.Z
    var X3 = PP - MM
    var Y3 = PP + MM
    var Z3 = Z2 + Txy
    var T3 = Z2 - Txy
    return EdwardsPoint(X3 * T3, Y3 * Z3, Z3 * T3, X3 * Y3)

@always_inline
def _sub_affine_niels(p: EdwardsPoint, q: AffineNielsPoint) -> EdwardsPoint:
    var PM = (p.Y + p.X) * q.y_minus_x
    var MP = (p.Y - p.X) * q.y_plus_x
    var Txy = p.T * q.xy2d
    var Z2 = p.Z + p.Z
    var X3 = PM - MP
    var Y3 = PM + MP
    var Z3 = Z2 - Txy
    var T3 = Z2 + Txy
    return EdwardsPoint(X3 * T3, Y3 * Z3, Z3 * T3, X3 * Y3)

@always_inline
def _add_projective_niels(p: EdwardsPoint, n: ProjectiveNielsPoint) -> EdwardsPoint:
    var PP = (p.Y + p.X) * n.Y_plus_X
    var MM = (p.Y - p.X) * n.Y_minus_X
    var TT2d = p.T * n.T2d
    var ZZ = p.Z * n.Z
    var ZZ2 = ZZ + ZZ
    var X3 = PP - MM
    var Y3 = PP + MM
    var Z3 = ZZ2 + TT2d
    var T3 = ZZ2 - TT2d
    return EdwardsPoint(X3 * T3, Y3 * Z3, Z3 * T3, X3 * Y3)

@always_inline
def _sub_projective_niels(p: EdwardsPoint, n: ProjectiveNielsPoint) -> EdwardsPoint:
    var PM = (p.Y + p.X) * n.Y_minus_X
    var MP = (p.Y - p.X) * n.Y_plus_X
    var TT2d = p.T * n.T2d
    var ZZ = p.Z * n.Z
    var ZZ2 = ZZ + ZZ
    var X3 = PM - MP
    var Y3 = PM + MP
    var Z3 = ZZ2 - TT2d
    var T3 = ZZ2 + TT2d
    return EdwardsPoint(X3 * T3, Y3 * Z3, Z3 * T3, X3 * Y3)

@always_inline
def _radix16_digits(scalar: Span[UInt8, ...]) -> InlineArray[Int, 64]:
    var digits = InlineArray[Int, 64](fill=0)
    for i in range(32):
        digits[2 * i] = Int(scalar[i] & 15)
        digits[2 * i + 1] = Int((scalar[i] >> 4) & 15)
    for i in range(63):
        var carry = (digits[i] + 8) >> 4
        digits[i] -= carry << 4
        digits[i + 1] += carry
    return digits^

@always_inline
def _base_table_lookup(ptr: Pointer[UInt64, _], j: Int, digit: Int) -> AffineNielsPoint:
    var d = Int64(digit)
    var sign = d >> 63
    var absv = ((d ^ sign) - sign).cast[DType.uint64]()
    var acc = SIMD[DType.uint64, 16](0)
    acc[0] = 1
    acc[5] = 1
    var base = ptr.unsafe_offset(j * 128)
    for k in range(1, 9):
        var cand = (base.unsafe_offset((k - 1) * 16)).unsafe_load[width=16, alignment=8]()
        var diff = absv ^ UInt64(k)
        var m = UInt64(0) - ((diff - 1) >> 63)
        acc = acc ^ ((acc ^ cand) & SIMD[DType.uint64, 16](m))
    var sm = sign.cast[DType.uint64]()
    var yp = SIMD[DType.uint64, 8](acc[0], acc[1], acc[2], acc[3], acc[4], 0, 0, 0)
    var ym = SIMD[DType.uint64, 8](acc[5], acc[6], acc[7], acc[8], acc[9], 0, 0, 0)
    var swap = (yp ^ ym) & SIMD[DType.uint64, 8](sm)
    yp ^= swap
    ym ^= swap
    var xy = FieldElement51(acc[10], acc[11], acc[12], acc[13], acc[14])
    var xy_neg = FieldElement51.ZERO() - xy
    var xy_sel = _ct_select_fe(xy, xy_neg, UInt8(sm & 1))
    return AffineNielsPoint(FieldElement51(yp), FieldElement51(ym), xy_sel)

@no_inline
def _mul_base_ct(scalar: Span[UInt8, ...]) -> EdwardsPoint:
    var table = ed25519_base_table()
    var tptr = table.unsafe_ptr()
    var digits = _radix16_digits(scalar)
    var P = EdwardsPoint()
    for i in range(1, 64, 2):
        P = _add_affine_niels(P, _base_table_lookup(tptr, i >> 1, digits[i]))
    P = _edwards_double_standalone(P)
    P = _edwards_double_standalone(P)
    P = _edwards_double_standalone(P)
    P = _edwards_double_standalone(P)
    for i in range(0, 64, 2):
        P = _add_affine_niels(P, _base_table_lookup(tptr, i >> 1, digits[i]))
    var dptr = digits.unsafe_ptr().unsafe_bitcast[UInt64]()
    for i in range(64):
        dptr.unsafe_store[volatile=True](i, UInt64(0))
    return P

def _naf5(scalar: Span[UInt8, ...]) -> InlineArray[Int, 256]:
    var naf = InlineArray[Int, 256](fill=0)
    var words = InlineArray[UInt64, 5](fill=0)
    words[4] = 0
    var ptr = scalar.unsafe_ptr()
    for w in range(4):
        words[w] = (ptr.unsafe_offset(8 * w)).unsafe_bitcast[UInt64]().unsafe_load[width=1, alignment=1]()
    var pos = 0
    var carry: UInt64 = 0
    while pos < 256:
        var idx = pos >> 6
        var bit = UInt64(pos & 63)
        var bit_buf: UInt64 = words[idx] >> bit
        if bit > 59:
            bit_buf |= words[idx + 1] << (UInt64(64) - bit)
        var window = carry + (bit_buf & 31)
        if (window & 1) == 0:
            pos += 1
            continue
        if window < 16:
            carry = 0
            naf[pos] = Int(window)
        else:
            carry = 1
            naf[pos] = Int(window) - 32
        pos += 5
    return naf^

@always_inline
def _b_odd_entry(ptr: Pointer[UInt64, _], k: Int) -> AffineNielsPoint:
    var base = ptr.unsafe_offset(k * 16)
    return AffineNielsPoint(
        FieldElement51(base[unsafe_offset=0], base[unsafe_offset=1], base[unsafe_offset=2], base[unsafe_offset=3], base[unsafe_offset=4]),
        FieldElement51(base[unsafe_offset=5], base[unsafe_offset=6], base[unsafe_offset=7], base[unsafe_offset=8], base[unsafe_offset=9]),
        FieldElement51(base[unsafe_offset=10], base[unsafe_offset=11], base[unsafe_offset=12], base[unsafe_offset=13], base[unsafe_offset=14]),
    )

@no_inline
def _double_scalar_mult_vartime(a: Span[UInt8, ...], A: EdwardsPoint, b: Span[UInt8, ...]) -> EdwardsPoint:
    var naf_a = _naf5(a)
    var naf_b = _naf5(b)
    var d2 = ed25519_d2()
    var A2n = _to_projective_niels(_edwards_double_standalone(A), d2)
    var Ai = InlineArray[ProjectiveNielsPoint, 8](fill=ProjectiveNielsPoint())
    var cur = A
    Ai[0] = _to_projective_niels(A, d2)
    for k in range(1, 8):
        cur = _add_projective_niels(cur, A2n)
        Ai[k] = _to_projective_niels(cur, d2)
    var btable = ed25519_b_odd_table()
    var bptr = btable.unsafe_ptr()
    var start = 255
    while start > 0 and naf_a[start] == 0 and naf_b[start] == 0:
        start -= 1
    var Q = EdwardsPoint()
    for i in range(start, -1, -1):
        Q = _edwards_double_standalone(Q)
        var da = naf_a[i]
        if da > 0:
            Q = _add_projective_niels(Q, Ai[(da - 1) >> 1])
        elif da < 0:
            Q = _sub_projective_niels(Q, Ai[(-da - 1) >> 1])
        var db = naf_b[i]
        if db > 0:
            Q = _add_affine_niels(Q, _b_odd_entry(bptr, (db - 1) >> 1))
        elif db < 0:
            Q = _sub_affine_niels(Q, _b_odd_entry(bptr, (-db - 1) >> 1))
    return Q

@no_inline
def ed25519_generate_public_key(
    private_key: Span[UInt8, ...], output: Span[mut=True, UInt8, ...]
) raises:
    # RFC 8032 5.1.5: public key A = [pruned SHA512(secret)]B.
    if len(private_key) != 32:
        raise Error("Ed25519 private key must be 32 bytes")
    if len(output) < 32:
        raise Error("Ed25519 public-key output must be at least 32 bytes")
    var output_ptr = output.unsafe_ptr()
    var hash = InlineArray[UInt8, 64](fill=0)
    var ctx = SHA512Context()
    sha512_update(ctx, private_key)
    sha512_final_to_buffer(ctx, hash.unsafe_ptr())
    var s = Scalar.from_bytes_clamped(Span[UInt8, ...](unsafe_ptr=hash.unsafe_ptr(), length=32))
    var s_bytes = InlineArray[UInt8, 32](fill=0)
    s.to_bytes_into(s_bytes.unsafe_ptr())
    var pub_point = _mul_base_ct(Span[UInt8, ...](unsafe_ptr=s_bytes.unsafe_ptr(), length=32))
    edwards_encode_into(pub_point, output_ptr)
    ctx.wipe()
    s.wipe()
    var hash_ptr = hash.unsafe_ptr()
    var s_ptr = s_bytes.unsafe_ptr()
    for i in range(64):
        hash_ptr.unsafe_store[volatile=True](i, UInt8(0))
    for i in range(32):
        s_ptr.unsafe_store[volatile=True](i, UInt8(0))

@no_inline
def ed25519_sign(
    private_key: Span[UInt8, ...],
    message: Span[UInt8, ...],
    output: Span[mut=True, UInt8, ...],
) raises:
    # RFC 8032 5.1.6 pure Ed25519:
    # r = SHA512(prefix || M), R = [r]B,
    # k = SHA512(R || A || M), S = r + k*s mod L.
    if len(private_key) != 32:
        raise Error("Ed25519 private key must be 32 bytes")
    if len(output) < 64:
        raise Error("Ed25519 signature output must be at least 64 bytes")
    var output_ptr = output.unsafe_ptr()
    var hash = InlineArray[UInt8, 64](fill=0)
    var ctx = SHA512Context()
    sha512_update(ctx, private_key)
    sha512_final_to_buffer(ctx, hash.unsafe_ptr())
    var s_scalar = Scalar.from_bytes_clamped(Span[UInt8, ...](unsafe_ptr=hash.unsafe_ptr(), length=32))

    var s_bytes = InlineArray[UInt8, 32](fill=0)
    s_scalar.to_bytes_into(s_bytes.unsafe_ptr())
    var A_point = _mul_base_ct(Span[UInt8, ...](unsafe_ptr=s_bytes.unsafe_ptr(), length=32))

    var r_hash = InlineArray[UInt8, 64](fill=0)
    var r_ctx = SHA512Context()
    sha512_update(r_ctx, Span[UInt8, ...](unsafe_ptr=hash.unsafe_ptr().unsafe_offset(32), length=32))
    sha512_update(r_ctx, message)
    sha512_final_to_buffer(r_ctx, r_hash.unsafe_ptr())

    var r_scalar = Scalar.from_bytes_wide(Span[UInt8, ...](unsafe_ptr=r_hash.unsafe_ptr(), length=64))
    var r_bytes = InlineArray[UInt8, 32](fill=0)
    r_scalar.to_bytes_into(r_bytes.unsafe_ptr())
    var R_point = _mul_base_ct(Span[UInt8, ...](unsafe_ptr=r_bytes.unsafe_ptr(), length=32))

    var zz_inv = (A_point.Z * R_point.Z).invert()
    var A_enc = InlineArray[UInt8, 32](fill=0)
    var R_enc = InlineArray[UInt8, 32](fill=0)
    _edwards_encode_with_zinv(A_point, zz_inv * R_point.Z, A_enc.unsafe_ptr())
    _edwards_encode_with_zinv(R_point, zz_inv * A_point.Z, R_enc.unsafe_ptr())

    var k_hash = InlineArray[UInt8, 64](fill=0)
    var k_ctx = SHA512Context()
    sha512_update(k_ctx, Span[UInt8, ...](unsafe_ptr=R_enc.unsafe_ptr(), length=32))
    sha512_update(k_ctx, Span[UInt8, ...](unsafe_ptr=A_enc.unsafe_ptr(), length=32))
    sha512_update(k_ctx, message)
    sha512_final_to_buffer(k_ctx, k_hash.unsafe_ptr())

    var k_scalar = Scalar.from_bytes_wide(Span[UInt8, ...](unsafe_ptr=k_hash.unsafe_ptr(), length=64))
    var S_scalar = r_scalar + k_scalar * s_scalar
    var S_bytes = InlineArray[UInt8, 32](fill=0)
    S_scalar.to_bytes_into(S_bytes.unsafe_ptr())

    for i in range(32): output_ptr[unsafe_offset=i] = R_enc[i]
    for i in range(32): output_ptr[unsafe_offset=32 + i] = S_bytes[i]
    ctx.wipe()
    r_ctx.wipe()
    s_scalar.wipe()
    r_scalar.wipe()
    var hash_ptr = hash.unsafe_ptr()
    var s_ptr = s_bytes.unsafe_ptr()
    var r_ptr = r_hash.unsafe_ptr()
    var r_bytes_ptr = r_bytes.unsafe_ptr()
    var k_ptr = k_hash.unsafe_ptr()
    var S_ptr = S_bytes.unsafe_ptr()
    for i in range(64):
        hash_ptr.unsafe_store[volatile=True](i, UInt8(0))
        r_ptr.unsafe_store[volatile=True](i, UInt8(0))
        k_ptr.unsafe_store[volatile=True](i, UInt8(0))
    for i in range(32):
        s_ptr.unsafe_store[volatile=True](i, UInt8(0))
        r_bytes_ptr.unsafe_store[volatile=True](i, UInt8(0))
        S_ptr.unsafe_store[volatile=True](i, UInt8(0))

struct Ed25519SigningKey(Copyable, Movable):
    var _s: Scalar
    var _prefix: InlineArray[UInt8, 32]
    var _a_enc: InlineArray[UInt8, 32]

    def __init__(out self, private_key: Span[UInt8, ...]) raises:
        if len(private_key) != 32:
            raise Error("Ed25519 private key must be 32 bytes")
        var hash = InlineArray[UInt8, 64](fill=0)
        var ctx = SHA512Context()
        sha512_update(ctx, private_key)
        sha512_final_to_buffer(ctx, hash.unsafe_ptr())
        self._s = Scalar.from_bytes_clamped(Span[UInt8, ...](unsafe_ptr=hash.unsafe_ptr(), length=32))

        self._prefix = InlineArray[UInt8, 32](fill=0)
        for i in range(32):
            self._prefix[i] = hash[32 + i]

        var s_bytes = InlineArray[UInt8, 32](fill=0)
        self._s.to_bytes_into(s_bytes.unsafe_ptr())
        var A_point = _mul_base_ct(Span[UInt8, ...](unsafe_ptr=s_bytes.unsafe_ptr(), length=32))
        self._a_enc = InlineArray[UInt8, 32](fill=0)
        edwards_encode_into(A_point, self._a_enc.unsafe_ptr())

        ctx.wipe()
        var hash_ptr = hash.unsafe_ptr()
        var s_ptr = s_bytes.unsafe_ptr()
        for i in range(64):
            hash_ptr.unsafe_store[volatile=True](i, UInt8(0))
        for i in range(32):
            s_ptr.unsafe_store[volatile=True](i, UInt8(0))

    def __deinit__(deinit self):
        self._s.wipe()
        var p = self._prefix.unsafe_ptr()
        for i in range(32):
            p.unsafe_store[volatile=True](i, UInt8(0))

    def public_key_into(self, output: Span[mut=True, UInt8, ...]) -> Bool:
        if len(output) < 32:
            return False
        for i in range(32):
            output[i] = self._a_enc[i]
        return True

    @no_inline
    def sign(
        self, message: Span[UInt8, ...], output: Span[mut=True, UInt8, ...]
    ) raises:
        if len(output) < 64:
            raise Error("Ed25519 signature output must be at least 64 bytes")
        var r_hash = InlineArray[UInt8, 64](fill=0)
        var r_ctx = SHA512Context()
        sha512_update(r_ctx, Span[UInt8, ...](unsafe_ptr=self._prefix.unsafe_ptr(), length=32))
        sha512_update(r_ctx, message)
        sha512_final_to_buffer(r_ctx, r_hash.unsafe_ptr())

        var r_scalar = Scalar.from_bytes_wide(Span[UInt8, ...](unsafe_ptr=r_hash.unsafe_ptr(), length=64))
        var r_bytes = InlineArray[UInt8, 32](fill=0)
        r_scalar.to_bytes_into(r_bytes.unsafe_ptr())
        var R_point = _mul_base_ct(Span[UInt8, ...](unsafe_ptr=r_bytes.unsafe_ptr(), length=32))

        var R_enc = InlineArray[UInt8, 32](fill=0)
        edwards_encode_into(R_point, R_enc.unsafe_ptr())

        var k_hash = InlineArray[UInt8, 64](fill=0)
        var k_ctx = SHA512Context()
        sha512_update(k_ctx, Span[UInt8, ...](unsafe_ptr=R_enc.unsafe_ptr(), length=32))
        sha512_update(k_ctx, Span[UInt8, ...](unsafe_ptr=self._a_enc.unsafe_ptr(), length=32))
        sha512_update(k_ctx, message)
        sha512_final_to_buffer(k_ctx, k_hash.unsafe_ptr())

        var k_scalar = Scalar.from_bytes_wide(Span[UInt8, ...](unsafe_ptr=k_hash.unsafe_ptr(), length=64))
        var S_scalar = r_scalar + k_scalar * self._s
        var S_bytes = InlineArray[UInt8, 32](fill=0)
        S_scalar.to_bytes_into(S_bytes.unsafe_ptr())

        for i in range(32):
            output[i] = R_enc[i]
        for i in range(32):
            output[32 + i] = S_bytes[i]

        r_ctx.wipe()
        r_scalar.wipe()
        var r_ptr = r_hash.unsafe_ptr()
        var k_ptr = k_hash.unsafe_ptr()
        var r_bytes_ptr = r_bytes.unsafe_ptr()
        var S_ptr = S_bytes.unsafe_ptr()
        for i in range(64):
            r_ptr.unsafe_store[volatile=True](i, UInt8(0))
            k_ptr.unsafe_store[volatile=True](i, UInt8(0))
        for i in range(32):
            r_bytes_ptr.unsafe_store[volatile=True](i, UInt8(0))
            S_ptr.unsafe_store[volatile=True](i, UInt8(0))


@no_inline
def ed25519_verify(public_key: Span[UInt8, ...], message: Span[UInt8, ...], signature: Span[UInt8, ...]) -> Bool:
    # Uses canonical decoding, S < L, and the uncofactored equation.
    # Low-order public keys are rejected by library policy.
    if len(public_key) != 32 or len(signature) != 64:
        return False
    var A_res = edwards_decode_verify_compatible(public_key)
    if not A_res.ok:
        return False
    var A = A_res.p
    if _is_small_order(A):
        return False

    var R_enc = InlineArray[UInt8, 32](fill=0)
    for i in range(32): R_enc[i] = signature[i]

    var S_bytes = InlineArray[UInt8, 32](fill=0)
    for i in range(32): S_bytes[i] = signature[32 + i]
    var S_bytes_span = Span[UInt8, ...](unsafe_ptr=S_bytes.unsafe_ptr(), length=32)
    if not _s_lt_l(S_bytes_span):
        return False

    var k_hash = InlineArray[UInt8, 64](fill=0)
    var k_ctx = SHA512Context()
    sha512_update(k_ctx, Span[UInt8, ...](unsafe_ptr=R_enc.unsafe_ptr(), length=32))
    sha512_update(k_ctx, public_key)
    sha512_update(k_ctx, message)
    sha512_final_to_buffer(k_ctx, k_hash.unsafe_ptr())

    var k_hash_span = Span[UInt8, ...](unsafe_ptr=k_hash.unsafe_ptr(), length=64)
    var k_scalar = Scalar.from_bytes_wide(k_hash_span)

    var k_bytes = InlineArray[UInt8, 32](fill=0)
    k_scalar.to_bytes_into(k_bytes.unsafe_ptr())
    var k_bytes_span = Span[UInt8, ...](unsafe_ptr=k_bytes.unsafe_ptr(), length=32)

    var Q = _double_scalar_mult_vartime(k_bytes_span, edwards_negate(A), S_bytes_span)
    var Q_enc = InlineArray[UInt8, 32](fill=0)
    edwards_encode_into(Q, Q_enc.unsafe_ptr())
    for i in range(32):
        if Q_enc[i] != R_enc[i]:
            return False
    return True
