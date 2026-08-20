"""
Camellia block cipher implementation per RFC 3713
"""

from std.memory import bitcast, UnsafePointer
from std.bit import byte_swap, rotate_bits_left
from std.collections import InlineArray
from std.sys import llvm_intrinsic
from std.utils import StaticTuple
from .aes import _ct_sbox, _ct_ortho, _ctr_write_block
from .utils import transpose8x8
from .aes_ni import (
    _aese,
    _mm_aesenclast_si128,
    has_arm_crypto,
    has_x86_aes_ni,
)


comptime SIGMA1 = 0xA09E667F3BCC908B
comptime SIGMA2 = 0xB67AE8584CAA73B2
comptime SIGMA3 = 0xC6EF372FE94F82BE
comptime SIGMA4 = 0x54FF53A5F1D36F1C
comptime SIGMA5 = 0x10E527FADE682D1D
comptime SIGMA6 = 0xB05688C2B3E6C1FD


comptime _CAM_Q = StaticTuple[UInt8, 8](
    0x08, 0x57, 0xFF, 0x66, 0x06, 0xDD, 0x04, 0xF2
)
comptime _CAM_P = StaticTuple[UInt8, 8](
    0x18, 0x7A, 0xCD, 0xE5, 0x54, 0x51, 0xC7, 0xAB
)
comptime _CAM_IC: UInt8 = 0x01
comptime _CAM_OC: UInt8 = 0x9A


comptime _U8x16 = SIMD[DType.uint8, 16]

# y = LO[x & 15] ^ HI[x >> 4], constant LO side only.
# s2 = rotl1(s1), s3 = rotr1(s1) fold rotated POST copies;
# s4 = s1(rotl1(x)) folds rotl1 into pre matrix.
def _mk_tbl(
    cols: StaticTuple[UInt8, 8],
    add: UInt8,
    hi: Bool,
    in_rotl1: Bool,
    out_rot: Int,
) -> _U8x16:
    var t = _U8x16(0)
    for n in range(16):
        var x = UInt8(n << 4) if hi else UInt8(n)
        if in_rotl1:
            x = (x << 1) | (x >> 7)
        var y = UInt8(0) if hi else add
        for j in range(8):
            if ((x >> UInt8(j)) & 1) == 1:
                y ^= cols[j]
        if out_rot == 1:
            y = (y << 1) | (y >> 7)
        elif out_rot == -1:
            y = (y >> 1) | (y << 7)
        t[n] = y
    return t


comptime _PRE_LO = _mk_tbl(_CAM_Q, _CAM_IC, False, False, 0)
comptime _PRE_HI = _mk_tbl(_CAM_Q, 0, True, False, 0)
comptime _POST_LO = _mk_tbl(_CAM_P, _CAM_OC, False, False, 0)
comptime _POST_HI = _mk_tbl(_CAM_P, 0, True, False, 0)
comptime _POST2_LO = _mk_tbl(_CAM_P, _CAM_OC, False, False, 1)
comptime _POST2_HI = _mk_tbl(_CAM_P, 0, True, False, 1)
comptime _POST3_LO = _mk_tbl(_CAM_P, _CAM_OC, False, False, -1)
comptime _POST3_HI = _mk_tbl(_CAM_P, 0, True, False, -1)
comptime _PRE4_LO = _mk_tbl(_CAM_Q, _CAM_IC, False, True, 0)
comptime _PRE4_HI = _mk_tbl(_CAM_Q, 0, True, True, 0)


@always_inline
def _has_hw_sbox() -> Bool:
    return has_arm_crypto() or has_x86_aes_ni()


@always_inline
def _tbl16(table: _U8x16, idx: _U8x16) -> _U8x16:
    comptime if has_arm_crypto():
        return llvm_intrinsic[
            "llvm.aarch64.neon.tbl1.v16i8", _U8x16, has_side_effect=False
        ](table, idx)
    elif has_x86_aes_ni():
        return llvm_intrinsic[
            "llvm.x86.ssse3.pshuf.b.128", _U8x16, has_side_effect=False
        ](table, idx)
    else:
        return _U8x16(0)


@always_inline
def _aes_sub16(t: _U8x16) -> _U8x16:
    # AESE/AESENCLAST compute SubBytes(ShiftRows(x)).
	# Lane 16 bytes per blocks.
	# pre-shuffling with InvShiftRows cancels which is required for no lane movement
    var s = t.shuffle[0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3]()
    comptime if has_arm_crypto():
        return _aese(s, _U8x16(0))
    else:
        return bitcast[DType.uint8, 16](
            _mm_aesenclast_si128(
                bitcast[DType.uint64, 2](s), SIMD[DType.uint64, 2](0)
            )
        )


@always_inline
def _sbox_bs_post[pos: Int](t0: _U8x16) -> _U8x16:
    var t = _aes_sub16(t0)
    comptime if pos == 1 or pos == 4:
        return _tbl16(_POST2_LO, t & 0x0F) ^ _tbl16(_POST2_HI, t >> 4)
    elif pos == 2 or pos == 5:
        return _tbl16(_POST3_LO, t & 0x0F) ^ _tbl16(_POST3_HI, t >> 4)
    else:
        return _tbl16(_POST_LO, t & 0x0F) ^ _tbl16(_POST_HI, t >> 4)


@always_inline
def _sbox_bs[pos: Int](x: _U8x16) -> _U8x16:
    # tbl/AES/tbl.
    comptime if pos == 3 or pos == 6:
        return _sbox_bs_post[pos](
            _tbl16(_PRE4_LO, x & 0x0F) ^ _tbl16(_PRE4_HI, x >> 4)
        )
    else:
        return _sbox_bs_post[pos](
            _tbl16(_PRE_LO, x & 0x0F) ^ _tbl16(_PRE_HI, x >> 4)
        )


comptime _LANES_D: UInt64 = 0x00000000FFFFFFFF
comptime _LANES_S2: UInt64 = (UInt64(0xFF) << 8) | (UInt64(0xFF) << 32)
comptime _LANES_S3: UInt64 = (UInt64(0xFF) << 16) | (UInt64(0xFF) << 40)
comptime _LANES_S4: UInt64 = (UInt64(0xFF) << 24) | (UInt64(0xFF) << 48)


@always_inline
def _slice_subkey(k: UInt64) -> InlineArray[UInt64, 8]:
    var out = InlineArray[UInt64, 8](fill=0)
    var lanes = byte_swap(k) 
    for kk in range(8):
        var p: UInt64 = 0
        for i in range(8):
            p |= (((lanes >> UInt64(8 * i + kk)) & 1) * UInt64(0xFF)) << UInt64(8 * i)
        out[kk] = p
    return out^


@always_inline
def _f_planes[W: Int](
    left: InlineArray[SIMD[DType.uint64, W], 8],
    mut right: InlineArray[SIMD[DType.uint64, W], 8],
    kp: InlineArray[UInt64, 192],
    base: Int,
):
    var a = InlineArray[SIMD[DType.uint64, W], 8](fill=0)
    comptime for k in range(8):
        a[k] = left[k] ^ kp[base + k]

    var b = InlineArray[SIMD[DType.uint64, W], 8](fill=0)
    comptime for k in range(8):
        b[k] = (a[k] & ~_LANES_S4) | (a[(k + 7) % 8] & _LANES_S4)

    var c = InlineArray[SIMD[DType.uint64, W], 8](fill=0)
    comptime for k in range(8):
        var acc = SIMD[DType.uint64, W](0)
        comptime for j in range(8):
            comptime if (Int(_CAM_Q[j]) >> k) & 1:
                acc ^= b[j]
        c[k] = acc
    c[0] = c[0] ^ SIMD[DType.uint64, W](0xFFFFFFFFFFFFFFFF)

    _ct_sbox(c)

    var d = InlineArray[SIMD[DType.uint64, W], 8](fill=0)
    comptime for k in range(8):
        var acc = SIMD[DType.uint64, W](0)
        comptime for j in range(8):
            comptime if (Int(_CAM_P[j]) >> k) & 1:
                acc ^= c[j]
        comptime if (Int(_CAM_OC) >> k) & 1:
            acc ^= SIMD[DType.uint64, W](0xFFFFFFFFFFFFFFFF)
        d[k] = acc

    comptime m23: UInt64 = _LANES_S2 | _LANES_S3
    var e = InlineArray[SIMD[DType.uint64, W], 8](fill=0)
    comptime for k in range(8):
        e[k] = (
            (d[k] & ~m23)
            | (d[(k + 7) % 8] & _LANES_S2)
            | (d[(k + 1) % 8] & _LANES_S3)
        )

    comptime for k in range(8):
        var p = e[k]
        var x32 = bitcast[DType.uint32, 2 * W](p)
        var r16 = x32 ^ ((x32 << 16) | (x32 >> 16))
        var s32 = r16 ^ ((r16 >> 8) | (r16 << 24))
        var d8 = bitcast[DType.uint64, W]((x32 >> 8) | (x32 << 24))
        var s = bitcast[DType.uint64, W](s32)
        var u = (s ^ p) >> 32
        var lo = (s ^ d8 ^ u) & _LANES_D
        var hi = (lo ^ s ^ p) << 32
        right[k] ^= lo | hi


@always_inline
def _fl_planes[inv: Bool, W: Int](
    mut x: InlineArray[SIMD[DType.uint64, W], 8],
    kep: InlineArray[UInt64, 48],
    base: Int,
):
    comptime if inv:
        comptime for k in range(8):
            x[k] ^= (x[k] | kep[base + k]) >> 32
    var t = InlineArray[SIMD[DType.uint64, W], 8](fill=0)
    comptime for k in range(8):
        t[k] = x[k] & kep[base + k] & _LANES_D
    x[0] ^= (((t[7] >> 8) | (t[7] << 24)) & _LANES_D) << 32
    comptime for k in range(1, 8):
        x[k] ^= t[k - 1] << 32
    comptime if not inv:
        comptime for k in range(8):
            x[k] ^= (x[k] | kep[base + k]) >> 32


@always_inline
def rotl128[n: Int](high: UInt64, low: UInt64) -> SIMD[DType.uint64, 2]:
    comptime shift = n % 128

    comptime if shift == 0:
        return SIMD[DType.uint64, 2](high, low)
    else:
        comptime if shift == 64:
            return SIMD[DType.uint64, 2](low, high)
        else:
            comptime if shift < 64:
                comptime s = UInt64(shift)
                return SIMD[DType.uint64, 2](
                    (high << s) | (low >> (UInt64(64) - s)),
                    (low << s) | (high >> (UInt64(64) - s)),
                )
            else:
                comptime s = UInt64(shift - 64)
                return SIMD[DType.uint64, 2](
                    (low << s) | (high >> (UInt64(64) - s)),
                    (high << s) | (low >> (UInt64(64) - s)),
                )


comptime _BIT0_OF_EACH_BYTE: UInt64 = 0x0101010101010101
comptime _ONE_VALUE_LANES: UInt64 = 0xFF


@always_inline
def _wipe_u64(ptr: UnsafePointer[mut=True, UInt64, _, address_space=_], count: Int):
    for i in range(count):
        ptr.store[volatile=True](i, UInt64(0))


@always_inline
def _p_tail(sout0: UInt64) -> UInt64:
    var sout = sout0
    var ol = ((sout << 1) & ~_BIT0_OF_EACH_BYTE) | ((sout >> 7) & _BIT0_OF_EACH_BYTE)
    var orr = ((sout >> 1) & ~(_BIT0_OF_EACH_BYTE << 7)) | (
        (sout << 7) & (_BIT0_OF_EACH_BYTE << 7)
    )
    sout = (
        (sout & ~(_LANES_S2 | _LANES_S3))
        | (ol & _LANES_S2)
        | (orr & _LANES_S3)
    )

    var dw = UInt32(sout & 0xFFFFFFFF)
    var uw = UInt32(sout >> 32)
    var dr = rotate_bits_left[24](dw)
    var da = dw ^ rotate_bits_left[16](dw)
    var all_d = da ^ rotate_bits_left[24](da)
    var ua = uw ^ rotate_bits_left[16](uw)
    var uc = (ua ^ rotate_bits_left[24](ua)) ^ uw
    var y14 = all_d ^ dr ^ uc
    var y58 = dw ^ dr ^ uc

    return byte_swap(UInt64(y14) | (UInt64(y58) << 32))


@always_inline
def _f_hw(f_in: UInt64, ke: UInt64) -> UInt64:
    var pin = byte_swap(f_in ^ ke)
    var rol1 = ((pin << 1) & ~_BIT0_OF_EACH_BYTE) | ((pin >> 7) & _BIT0_OF_EACH_BYTE)
    pin = (pin & ~_LANES_S4) | (rol1 & _LANES_S4)

    var x = bitcast[DType.uint8, 16](SIMD[DType.uint64, 2](pin, 0))
    var t = _tbl16(_PRE_LO, x & 0x0F) ^ _tbl16(_PRE_HI, x >> 4)
    t = _aes_sub16(t)
    var y = _tbl16(_POST_LO, t & 0x0F) ^ _tbl16(_POST_HI, t >> 4)
    return _p_tail(bitcast[DType.uint64, 2](y)[0])


@always_inline
def _f_scalar(f_in: UInt64, ke: UInt64) -> UInt64:
    var x = f_in ^ ke

    var pin = byte_swap(x)

    var rol1 = ((pin << 1) & ~_BIT0_OF_EACH_BYTE) | ((pin >> 7) & _BIT0_OF_EACH_BYTE)
    pin = (pin & ~_LANES_S4) | (rol1 & _LANES_S4)

    var xt = transpose8x8(pin)
    var q = InlineArray[SIMD[DType.uint64, 1], 8](fill=0)
    comptime for k in range(8):
        q[k] = (xt >> UInt64(8 * k)) & 0xFF

    var a = InlineArray[SIMD[DType.uint64, 1], 8](fill=0)
    comptime for k in range(8):
        var acc: UInt64 = 0
        comptime for j in range(8):
            comptime if (Int(_CAM_Q[j]) >> k) & 1:
                acc ^= UInt64(q[j])
        a[k] = acc
    a[0] = UInt64(a[0]) ^ _ONE_VALUE_LANES

    _ct_sbox[1](a)

    var b = InlineArray[SIMD[DType.uint64, 1], 8](fill=0)
    comptime for k in range(8):
        var acc: UInt64 = 0
        comptime for j in range(8):
            comptime if (Int(_CAM_P[j]) >> k) & 1:
                acc ^= UInt64(a[j])
        comptime if (Int(_CAM_OC) >> k) & 1:
            acc ^= _ONE_VALUE_LANES
        b[k] = acc

    var packed: UInt64 = 0
    comptime for k in range(8):
        packed |= (UInt64(b[k]) & 0xFF) << UInt64(8 * k)
    return _p_tail(transpose8x8(packed))


@always_inline
def _f_one(x: UInt64, k: UInt64) -> UInt64:
    comptime if _has_hw_sbox():
        return _f_hw(x, k)
    else:
        return _f_scalar(x, k)



comptime _M_S4V = _U8x16(
    0, 0, 0, 0xFF, 0, 0, 0xFF, 0, 0, 0, 0, 0xFF, 0, 0, 0xFF, 0
)

comptime _AES_SR_INV = StaticTuple[UInt8, 16](
    0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3
)

comptime _P_SRC = StaticTuple[StaticTuple[UInt8, 6], 8](
    StaticTuple[UInt8, 6](0, 2, 3, 5, 6, 7),
    StaticTuple[UInt8, 6](0, 1, 3, 4, 6, 7),
    StaticTuple[UInt8, 6](0, 1, 2, 4, 5, 7),
    StaticTuple[UInt8, 6](1, 2, 3, 4, 5, 6),
    StaticTuple[UInt8, 6](0, 1, 5, 6, 7, 255),
    StaticTuple[UInt8, 6](1, 2, 4, 6, 7, 255),
    StaticTuple[UInt8, 6](2, 3, 4, 5, 7, 255),
    StaticTuple[UInt8, 6](0, 3, 4, 5, 6, 255),
)


def _mk_p_cls_idx(vec: Int, slot: Int, a_to_b: Bool) -> _U8x16:
    var t = _U8x16(255)
    for i in range(8):
        var count = 0
        for m in range(6):
            var src = _P_SRC[i][m]
            if src == 255:
                continue
            var cls = 0
            if src == 1 or src == 4:
                cls = 1
            elif src == 2 or src == 5:
                cls = 2
            if cls != vec:
                continue
            if count == slot:
                var srcl = Int(src) if a_to_b else Int(src) + 8
                t[(8 + i) if a_to_b else i] = _AES_SR_INV[srcl]
            count += 1
    return t


def _mk_fl_idx(base: Int, rot: Bool, down: Bool) -> _U8x16:
    var t = _U8x16(255)
    for i in range(4):
        if down:
            t[base + i] = UInt8(base + 4 + i)
        elif rot:
            t[base + 4 + i] = UInt8(base + ((i + 1) % 4))
        else:
            t[base + 4 + i] = UInt8(base + i)
    return t


comptime _FL_SH_A = _mk_fl_idx(0, False, False)
comptime _FL_SH2_A = _mk_fl_idx(0, True, False)
comptime _FL_DOWN_A = _mk_fl_idx(0, False, True)
comptime _FL_SH_B = _mk_fl_idx(8, False, False)
comptime _FL_SH2_B = _mk_fl_idx(8, True, False)
comptime _FL_DOWN_B = _mk_fl_idx(8, False, True)

@always_inline
def _kv_a(k: UInt64) -> _U8x16:
    return bitcast[DType.uint8, 16](SIMD[DType.uint64, 2](k, 0))


@always_inline
def _kv_b(k: UInt64) -> _U8x16:
    return bitcast[DType.uint8, 16](SIMD[DType.uint64, 2](0, k))


@always_inline
def _aes_sub16_raw(t: _U8x16) -> _U8x16:
    comptime if has_arm_crypto():
        return _aese(t, _U8x16(0))
    else:
        return bitcast[DType.uint8, 16](
            _mm_aesenclast_si128(
                bitcast[DType.uint64, 2](t), SIMD[DType.uint64, 2](0)
            )
        )


@always_inline
def _round_simd[a_to_b: Bool](mut v: _U8x16, kvec: _U8x16):
    var x = v ^ kvec
    var lo = x & 0x0F
    var hi = x >> 4
    var t = _tbl16(_PRE_LO, lo) ^ _tbl16(_PRE_HI, hi)
    var t4 = _tbl16(_PRE4_LO, lo) ^ _tbl16(_PRE4_HI, hi)
    t = (t & ~_M_S4V) | (t4 & _M_S4V)
    var s = _aes_sub16_raw(t)
    var slo = s & 0x0F
    var shi = s >> 4
    var yb = _tbl16(_POST_LO, slo) ^ _tbl16(_POST_HI, shi)
    var y2 = _tbl16(_POST2_LO, slo) ^ _tbl16(_POST2_HI, shi)
    var y3 = _tbl16(_POST3_LO, slo) ^ _tbl16(_POST3_HI, shi)
    var acc = _U8x16(0)
    comptime for m in range(4):
        comptime IDXB = _mk_p_cls_idx(0, m, a_to_b)
        acc = acc ^ _tbl16(yb, IDXB)
    comptime for m in range(2):
        comptime IDX2 = _mk_p_cls_idx(1, m, a_to_b)
        comptime IDX3 = _mk_p_cls_idx(2, m, a_to_b)
        acc = acc ^ (_tbl16(y2, IDX2) ^ _tbl16(y3, IDX3))
    v = v ^ acc


@always_inline
def _fl_simd[inv: Bool, half_b: Bool](mut v: _U8x16, ke: UInt64):
    var keb = byte_swap(ke)
    var k1v = _kv_b(keb) if half_b else _kv_a(keb)
    comptime if inv:
        comptime if half_b:
            v = v ^ _tbl16(v | k1v, _FL_DOWN_B)
        else:
            v = v ^ _tbl16(v | k1v, _FL_DOWN_A)
    var t = v & k1v
    comptime if half_b:
        t = t & ~_mask_x2_b()
        v = v ^ (_tbl16(t << 1, _FL_SH_B) | _tbl16(t >> 7, _FL_SH2_B))
    else:
        t = t & ~_mask_x2_a()
        v = v ^ (_tbl16(t << 1, _FL_SH_A) | _tbl16(t >> 7, _FL_SH2_A))
    comptime if not inv:
        comptime if half_b:
            v = v ^ _tbl16(v | k1v, _FL_DOWN_B)
        else:
            v = v ^ _tbl16(v | k1v, _FL_DOWN_A)


@always_inline
def _mask_x2_a() -> _U8x16:
    return _U8x16(
        0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0
    )


@always_inline
def _mask_x2_b() -> _U8x16:
    return _U8x16(
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF
    )


@always_inline
def _six_rounds_simd[forward: Bool](
    mut v: _U8x16, cipher: CamelliaCipher, base: Int
):
    comptime for r in range(6):
        var k = cipher.khw[base + (r if forward else 5 - r)]
        comptime if r % 2 == 0:
            _round_simd[True](v, _kv_a(k))
        else:
            _round_simd[False](v, _kv_b(k))


@always_inline
def _fl_scalar(x: UInt64, ke: UInt64) -> UInt64:
    var x1 = UInt32(x >> 32)
    var x2 = UInt32(x & 0xFFFFFFFF)
    x2 ^= rotate_bits_left[1](x1 & UInt32(ke >> 32))
    x1 ^= x2 | UInt32(ke & 0xFFFFFFFF)
    return (UInt64(x1) << 32) | UInt64(x2)


@always_inline
def _flinv_scalar(y: UInt64, ke: UInt64) -> UInt64:
    var y1 = UInt32(y >> 32)
    var y2 = UInt32(y & 0xFFFFFFFF)
    y1 ^= y2 | UInt32(ke & 0xFFFFFFFF)
    y2 ^= rotate_bits_left[1](y1 & UInt32(ke >> 32))
    return (UInt64(y1) << 32) | UInt64(y2)


struct CamelliaCipher:
    var kw: SIMD[DType.uint64, 4]
    var k: InlineArray[UInt64, 24]
    var ke: InlineArray[UInt64, 6]
    var kp: InlineArray[UInt64, 192]
    var kep: InlineArray[UInt64, 48]
    var khw: InlineArray[UInt64, 24]
    var kwhw: InlineArray[UInt64, 4]
    var is_128: Bool

    def __init__(out self, key: Span[UInt8, ...]) raises:
        self.kw = SIMD[DType.uint64, 4](0)
        self.k = InlineArray[UInt64, 24](fill=0)
        self.ke = InlineArray[UInt64, 6](fill=0)
        self.kp = InlineArray[UInt64, 192](fill=0)
        self.kep = InlineArray[UInt64, 48](fill=0)
        self.khw = InlineArray[UInt64, 24](fill=0)
        self.kwhw = InlineArray[UInt64, 4](fill=0)
        self.is_128 = len(key) == 16

        if self.is_128:
            self._key_schedule_128(key)
        elif len(key) == 24 or len(key) == 32:
            self._key_schedule_192_256(key)
        else:
            raise Error("Camellia key must be 16, 24, or 32 bytes")

        for r in range(24):
            var planes = _slice_subkey(self.k[r])
            for kk in range(8):
                self.kp[r * 8 + kk] = planes[kk]
        for r in range(6):
            var planes = _slice_subkey(self.ke[r])
            for kk in range(8):
                self.kep[r * 8 + kk] = planes[kk]
        for r in range(24):
            self.khw[r] = byte_swap(self.k[r])
        for r in range(4):
            self.kwhw[r] = byte_swap(self.kw[r])

    def wipe(mut self):
        _wipe_u64(UnsafePointer(to=self.kw).bitcast[UInt64](), 4)
        _wipe_u64(self.k.unsafe_ptr(), 24)
        _wipe_u64(self.ke.unsafe_ptr(), 6)
        _wipe_u64(self.kp.unsafe_ptr(), 192)
        _wipe_u64(self.kep.unsafe_ptr(), 48)
        _wipe_u64(self.khw.unsafe_ptr(), 24)
        _wipe_u64(self.kwhw.unsafe_ptr(), 4)

    def __del__(deinit self):
        _wipe_u64(UnsafePointer(to=self.kw).bitcast[UInt64](), 4)
        _wipe_u64(self.k.unsafe_ptr(), 24)
        _wipe_u64(self.ke.unsafe_ptr(), 6)
        _wipe_u64(self.kp.unsafe_ptr(), 192)
        _wipe_u64(self.kep.unsafe_ptr(), 48)
        _wipe_u64(self.khw.unsafe_ptr(), 24)
        _wipe_u64(self.kwhw.unsafe_ptr(), 4)

    @always_inline
    def _bytes_to_u64_be(ref self, b: Span[UInt8, ...]) -> UInt64:
        return byte_swap(
            bitcast[DType.uint64, 1](
                b.unsafe_ptr().load[width=8, alignment=1](0)
            )[0]
        )

    @always_inline
    def _set_k2[n: Int](mut self, i: Int, h: UInt64, l: UInt64):
        var rot = rotl128[n](h, l)
        self.k[i] = rot[0]
        self.k[i + 1] = rot[1]

    @always_inline
    def _set_ke2[n: Int](mut self, i: Int, h: UInt64, l: UInt64):
        var rot = rotl128[n](h, l)
        self.ke[i] = rot[0]
        self.ke[i + 1] = rot[1]

    @always_inline
    def _set_kw2[n: Int](mut self, h: UInt64, l: UInt64):
        var rot = rotl128[n](h, l)
        self.kw[2] = rot[0]
        self.kw[3] = rot[1]

    def _key_schedule_128(mut self, key: Span[UInt8, ...]):
        var kl_h = self._bytes_to_u64_be(key[0:8])
        var kl_l = self._bytes_to_u64_be(key[8:16])
        var kr_h: UInt64 = 0
        var kr_l: UInt64 = 0

        var d1 = kl_h ^ kr_h
        var d2 = kl_l ^ kr_l
        d2 ^= _f_scalar(d1, SIGMA1)
        d1 ^= _f_scalar(d2, SIGMA2)
        d1 ^= kl_h
        d2 ^= kl_l
        d2 ^= _f_scalar(d1, SIGMA3)
        d1 ^= _f_scalar(d2, SIGMA4)
        var ka_h = d1
        var ka_l = d2

        self.kw[0] = kl_h
        self.kw[1] = kl_l
        self.k[0] = ka_h
        self.k[1] = ka_l

        self._set_k2[15](2, kl_h, kl_l)
        self._set_k2[15](4, ka_h, ka_l)
        self._set_ke2[30](0, ka_h, ka_l)
        self._set_k2[45](6, kl_h, kl_l)
        self.k[8] = rotl128[45](ka_h, ka_l)[0]
        self.k[9] = rotl128[60](kl_h, kl_l)[1]
        self._set_k2[60](10, ka_h, ka_l)
        self._set_ke2[77](2, kl_h, kl_l)
        self._set_k2[94](12, kl_h, kl_l)
        self._set_k2[94](14, ka_h, ka_l)
        self._set_k2[111](16, kl_h, kl_l)
        self._set_kw2[111](ka_h, ka_l)

    def _key_schedule_192_256(mut self, key: Span[UInt8, ...]):
        var kl_h = self._bytes_to_u64_be(key[0:8])
        var kl_l = self._bytes_to_u64_be(key[8:16])
        var kr_h: UInt64
        var kr_l: UInt64

        if len(key) == 32:
            kr_h = self._bytes_to_u64_be(key[16:24])
            kr_l = self._bytes_to_u64_be(key[24:32])
        else:
            kr_h = self._bytes_to_u64_be(key[16:24])
            kr_l = ~kr_h

        var d1 = kl_h ^ kr_h
        var d2 = kl_l ^ kr_l
        d2 ^= _f_scalar(d1, SIGMA1)
        d1 ^= _f_scalar(d2, SIGMA2)
        d1 ^= kl_h
        d2 ^= kl_l
        d2 ^= _f_scalar(d1, SIGMA3)
        d1 ^= _f_scalar(d2, SIGMA4)
        var ka_h = d1
        var ka_l = d2

        d1 = ka_h ^ kr_h
        d2 = ka_l ^ kr_l
        d2 ^= _f_scalar(d1, SIGMA5)
        d1 ^= _f_scalar(d2, SIGMA6)
        var kb_h = d1
        var kb_l = d2

        self.kw[0] = kl_h
        self.kw[1] = kl_l
        self.k[0] = kb_h
        self.k[1] = kb_l

        self._set_k2[15](2, kr_h, kr_l)
        self._set_k2[15](4, ka_h, ka_l)
        self._set_ke2[30](0, kr_h, kr_l)
        self._set_k2[30](6, kb_h, kb_l)
        self._set_k2[45](8, kl_h, kl_l)
        self._set_k2[45](10, ka_h, ka_l)
        self._set_ke2[60](2, kl_h, kl_l)
        self._set_k2[60](12, kr_h, kr_l)
        self._set_k2[60](14, kb_h, kb_l)
        self._set_k2[77](16, kl_h, kl_l)
        self._set_ke2[77](4, ka_h, ka_l)
        self._set_k2[94](18, kr_h, kr_l)
        self._set_k2[94](20, ka_h, ka_l)
        self._set_k2[111](22, kl_h, kl_l)
        self._set_kw2[111](kb_h, kb_l)


@always_inline
def _load_half[W: Int](
    buf: UnsafePointer[mut=True, UInt8, _, address_space=_], off: Int, kw: UInt64
) -> InlineArray[SIMD[DType.uint64, W], 8]:
    var q = InlineArray[SIMD[DType.uint64, W], 8](fill=0)
    var kwl = byte_swap(kw)
    comptime for e in range(W):
        comptime for j in range(8):
            var base = (e * 8 + j) * 16 + off
            q[j][e] = (
                bitcast[DType.uint64, 1](
                    buf.load[width=8, alignment=1](base)
                )[0]
                ^ kwl
            )
    _ct_ortho[W](q)
    return q^


@always_inline
def _store_half[W: Int](
    buf: UnsafePointer[mut=True, UInt8, _, address_space=_],
    off: Int,
    mut q: InlineArray[SIMD[DType.uint64, W], 8],
    kw: UInt64,
):
    _ct_ortho(q)
    var kwl = byte_swap(kw)
    comptime for e in range(W):
        comptime for j in range(8):
            var base = (e * 8 + j) * 16 + off
            buf.store[alignment=1](
                base,
                bitcast[DType.uint8, 8](
                    SIMD[DType.uint64, 1](q[j][e] ^ kwl)
                ),
            )


@always_inline
def _six_rounds[forward: Bool, W: Int](
    mut a: InlineArray[SIMD[DType.uint64, W], 8],
    mut b: InlineArray[SIMD[DType.uint64, W], 8],
    kp: InlineArray[UInt64, 192],
    kbase: Int,
):
    comptime for r in range(6):
        comptime off = 8 * (r if forward else 5 - r)
        comptime if (r % 2 == 0) == forward:
            _f_planes(a, b, kp, kbase + off)
        else:
            _f_planes(b, a, kp, kbase + off)


@always_inline
def _encrypt_batch[W: Int](
    cipher: CamelliaCipher, buf: UnsafePointer[mut=True, UInt8, _, address_space=_]
):
    var a = _load_half[W](buf, 0, cipher.kw[0])
    var b = _load_half[W](buf, 8, cipher.kw[1])

    _six_rounds[True](a, b, cipher.kp, 0)
    _fl_planes[False](a, cipher.kep, 0)
    _fl_planes[True](b, cipher.kep, 8)
    _six_rounds[True](a, b, cipher.kp, 48)
    _fl_planes[False](a, cipher.kep, 16)
    _fl_planes[True](b, cipher.kep, 24)
    _six_rounds[True](a, b, cipher.kp, 96)
    if not cipher.is_128:
        _fl_planes[False](a, cipher.kep, 32)
        _fl_planes[True](b, cipher.kep, 40)
        _six_rounds[True](a, b, cipher.kp, 144)

    _store_half[W](buf, 0, b, cipher.kw[2])
    _store_half[W](buf, 8, a, cipher.kw[3])


@always_inline
def _decrypt_batch[W: Int](
    cipher: CamelliaCipher, buf: UnsafePointer[mut=True, UInt8, _, address_space=_]
):
    var b = _load_half[W](buf, 0, cipher.kw[2])
    var a = _load_half[W](buf, 8, cipher.kw[3])

    if not cipher.is_128:
        _six_rounds[False](a, b, cipher.kp, 144)
        _fl_planes[True](a, cipher.kep, 32)
        _fl_planes[False](b, cipher.kep, 40)
    _six_rounds[False](a, b, cipher.kp, 96)
    _fl_planes[True](a, cipher.kep, 16)
    _fl_planes[False](b, cipher.kep, 24)
    _six_rounds[False](a, b, cipher.kp, 48)
    _fl_planes[True](a, cipher.kep, 0)
    _fl_planes[False](b, cipher.kep, 8)
    _six_rounds[False](a, b, cipher.kp, 0)

    _store_half[W](buf, 0, a, cipher.kw[0])
    _store_half[W](buf, 8, b, cipher.kw[1])


@always_inline
def _batch[encrypt: Bool, W: Int](
    cipher: CamelliaCipher, buf: UnsafePointer[mut=True, UInt8, _, address_space=_]
):
    comptime if encrypt:
        _encrypt_batch[W](cipher, buf)
    else:
        _decrypt_batch[W](cipher, buf)


# FL/FLINV BE words, bounce via scalar registers (1/6 rounds)
# 16 blocks transposed j holds byte positon of j of all 16 blocks
# The AES round instruction computes 16 blocks worth of one S-Box pos
# S2/S3/S4 rotations go to per positon tables P functiions register XORS
# ZIP network byte positon j row _BITREV4[j] block b in row _BITREV[B]
comptime _BITREV4 = StaticTuple[Int, 16](
    0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15
)

@always_inline
def _transpose16(mut m: InlineArray[_U8x16, 16]):
    # 16x16 byte matrix transpose setup 4 zip stages.
    var t = InlineArray[_U8x16, 16](fill=_U8x16(0))
    comptime for i in range(8):
        var il = m[2 * i].interleave(m[2 * i + 1])
        t[i] = il.slice[16]()
        t[i + 8] = il.slice[16, offset=16]()
    comptime for i in range(8):
        var il = bitcast[DType.uint16, 8](t[2 * i]).interleave(
            bitcast[DType.uint16, 8](t[2 * i + 1])
        )
        m[i] = bitcast[DType.uint8, 16](il.slice[8]())
        m[i + 8] = bitcast[DType.uint8, 16](il.slice[8, offset=8]())
    comptime for i in range(8):
        var il = bitcast[DType.uint32, 4](m[2 * i]).interleave(
            bitcast[DType.uint32, 4](m[2 * i + 1])
        )
        t[i] = bitcast[DType.uint8, 16](il.slice[4]())
        t[i + 8] = bitcast[DType.uint8, 16](il.slice[4, offset=4]())
    comptime for i in range(8):
        var il = bitcast[DType.uint64, 2](t[2 * i]).interleave(
            bitcast[DType.uint64, 2](t[2 * i + 1])
        )
        m[i] = bitcast[DType.uint8, 16](il.slice[2]())
        m[i + 8] = bitcast[DType.uint8, 16](il.slice[2, offset=2]())


@always_inline
def _splat_byte(k: UInt64, j: Int) -> _U8x16:
    return _U8x16(UInt8((k >> UInt64(8 * j)) & 0xFF))


@always_inline
def _f_bs(
    l: InlineArray[_U8x16, 8],
    mut r: InlineArray[_U8x16, 8],
    k: UInt64,
):
    # Byte-sliced F on 16 blocks, k is the pre-byte-swapped subkey
    # (byte j = t_{j+1}). P-function in CSE form:
    # y_{4+i} = a_{i,i+1} ^ (s ^ x_{5+i}), y_i = x_i ^ a_{i+2,i+3} ^ ...
    var y = InlineArray[_U8x16, 8](fill=_U8x16(0))
    comptime for j in range(8):
        y[j] = _sbox_bs[j](l[j] ^ _splat_byte(k, j))

    var a12 = y[0] ^ y[1]
    var a23 = y[1] ^ y[2]
    var a34 = y[2] ^ y[3]
    var a41 = y[3] ^ y[0]
    var s = (y[4] ^ y[5]) ^ (y[6] ^ y[7])
    var s5 = s ^ y[4]
    var s6 = s ^ y[5]
    var s7 = s ^ y[6]
    var s8 = s ^ y[7]
    r[0] ^= y[0] ^ a34 ^ s5
    r[1] ^= y[1] ^ a41 ^ s6
    r[2] ^= y[2] ^ a12 ^ s7
    r[3] ^= y[3] ^ a23 ^ s8
    r[4] ^= a12 ^ s5
    r[5] ^= a23 ^ s6
    r[6] ^= a34 ^ s7
    r[7] ^= a41 ^ s8


@always_inline
def _fl_rot_bs(mut h: InlineArray[_U8x16, 8], ke: UInt64):
    # FL step x2 ^= rotl1(x1 & k1). Layout: h[0..3] = x1 bytes MSB first,
    # h[4..7] = x2; ke is big-endian, k1 = ke bytes 7..4, k2 = 3..0.
    # rotl1 32-bit word t0t1t2t3 splits pb register
    # out_i = (t_i << 1) | (t_{i+1 mod 4} >> 7), t3 wraps t0.
    var t0 = h[0] & _splat_byte(ke, 7)
    var t1 = h[1] & _splat_byte(ke, 6)
    var t2 = h[2] & _splat_byte(ke, 5)
    var t3 = h[3] & _splat_byte(ke, 4)
    h[4] ^= (t0 << 1) | (t1 >> 7)
    h[5] ^= (t1 << 1) | (t2 >> 7)
    h[6] ^= (t2 << 1) | (t3 >> 7)
    h[7] ^= (t3 << 1) | (t0 >> 7)


@always_inline
def _fl_bs[inv: Bool](mut h: InlineArray[_U8x16, 8], ke: UInt64):
    # x2 ^= rotl1(x1 & k1), x1 ^= (x2 | k2)
    comptime if inv:
        comptime for j in range(4):
            h[j] ^= h[4 + j] | _splat_byte(ke, 3 - j)
        _fl_rot_bs(h, ke)
    else:
        _fl_rot_bs(h, ke)
        comptime for j in range(4):
            h[j] ^= h[4 + j] | _splat_byte(ke, 3 - j)


@always_inline
def _six_rounds_bs[forward: Bool](
    mut a: InlineArray[_U8x16, 8],
    mut b: InlineArray[_U8x16, 8],
    cipher: CamelliaCipher,
    kbase: Int,
):
    comptime for r in range(6):
        comptime off = r if forward else 5 - r
        comptime if (r % 2 == 0) == forward:
            _f_bs(a, b, cipher.khw[kbase + off])
        else:
            _f_bs(b, a, cipher.khw[kbase + off])


@always_inline
def _batch16_hw[encrypt: Bool](
    cipher: CamelliaCipher, buf: UnsafePointer[mut=True, UInt8, _, address_space=_]
):
    var m = InlineArray[_U8x16, 16](fill=_U8x16(0))
    comptime for i in range(16):
        m[i] = buf.load[width=16, alignment=1](i * 16)
    _transpose16(m)

    var a = InlineArray[_U8x16, 8](fill=_U8x16(0))
    var b = InlineArray[_U8x16, 8](fill=_U8x16(0))

    comptime if encrypt:
        comptime for j in range(8):
            a[j] = m[_BITREV4[j]] ^ _splat_byte(cipher.kwhw[0], j)
            b[j] = m[_BITREV4[j + 8]] ^ _splat_byte(cipher.kwhw[1], j)
        _six_rounds_bs[True](a, b, cipher, 0)
        _fl_bs[False](a, cipher.ke[0])
        _fl_bs[True](b, cipher.ke[1])
        _six_rounds_bs[True](a, b, cipher, 6)
        _fl_bs[False](a, cipher.ke[2])
        _fl_bs[True](b, cipher.ke[3])
        _six_rounds_bs[True](a, b, cipher, 12)
        if not cipher.is_128:
            _fl_bs[False](a, cipher.ke[4])
            _fl_bs[True](b, cipher.ke[5])
            _six_rounds_bs[True](a, b, cipher, 18)
        comptime for j in range(8):
            m[j] = b[j] ^ _splat_byte(cipher.kwhw[2], j)
            m[j + 8] = a[j] ^ _splat_byte(cipher.kwhw[3], j)
    else:
        comptime for j in range(8):
            b[j] = m[_BITREV4[j]] ^ _splat_byte(cipher.kwhw[2], j)
            a[j] = m[_BITREV4[j + 8]] ^ _splat_byte(cipher.kwhw[3], j)
        if not cipher.is_128:
            _six_rounds_bs[False](a, b, cipher, 18)
            _fl_bs[True](a, cipher.ke[4])
            _fl_bs[False](b, cipher.ke[5])
        _six_rounds_bs[False](a, b, cipher, 12)
        _fl_bs[True](a, cipher.ke[2])
        _fl_bs[False](b, cipher.ke[3])
        _six_rounds_bs[False](a, b, cipher, 6)
        _fl_bs[True](a, cipher.ke[0])
        _fl_bs[False](b, cipher.ke[1])
        _six_rounds_bs[False](a, b, cipher, 0)
        comptime for j in range(8):
            m[j] = a[j] ^ _splat_byte(cipher.kwhw[0], j)
            m[j + 8] = b[j] ^ _splat_byte(cipher.kwhw[1], j)

    _transpose16(m)
    comptime for blk in range(16):
        buf.store[alignment=1](blk * 16, m[_BITREV4[blk]])


@always_inline
def _six_rounds_one[forward: Bool](
    mut d1: UInt64, mut d2: UInt64, cipher: CamelliaCipher, base: Int
):
    comptime for r in range(6):
        var k = cipher.k[base + (r if forward else 5 - r)]
        comptime if r % 2 == 0:
            d2 ^= _f_one(d1, k)
        else:
            d1 ^= _f_one(d2, k)


def _camellia_block_hw[encrypt: Bool](
    cipher: CamelliaCipher, block: SIMD[DType.uint8, 16]
) -> SIMD[DType.uint8, 16]:
    var v = block

    comptime if encrypt:
        v = v ^ bitcast[DType.uint8, 16](
            SIMD[DType.uint64, 2](cipher.kwhw[0], cipher.kwhw[1])
        )
        _six_rounds_simd[True](v, cipher, 0)
        _fl_simd[False, False](v, cipher.ke[0])
        _fl_simd[True, True](v, cipher.ke[1])
        _six_rounds_simd[True](v, cipher, 6)
        _fl_simd[False, False](v, cipher.ke[2])
        _fl_simd[True, True](v, cipher.ke[3])
        _six_rounds_simd[True](v, cipher, 12)
        if not cipher.is_128:
            _fl_simd[False, False](v, cipher.ke[4])
            _fl_simd[True, True](v, cipher.ke[5])
            _six_rounds_simd[True](v, cipher, 18)
        return v.shuffle[
            8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7
        ]() ^ bitcast[DType.uint8, 16](
            SIMD[DType.uint64, 2](cipher.kwhw[2], cipher.kwhw[3])
        )
    else:
        v = v ^ bitcast[DType.uint8, 16](
            SIMD[DType.uint64, 2](cipher.kwhw[2], cipher.kwhw[3])
        )
        if not cipher.is_128:
            _six_rounds_simd[False](v, cipher, 18)
            _fl_simd[False, False](v, cipher.ke[5])
            _fl_simd[True, True](v, cipher.ke[4])
        _six_rounds_simd[False](v, cipher, 12)
        _fl_simd[False, False](v, cipher.ke[3])
        _fl_simd[True, True](v, cipher.ke[2])
        _six_rounds_simd[False](v, cipher, 6)
        _fl_simd[False, False](v, cipher.ke[1])
        _fl_simd[True, True](v, cipher.ke[0])
        _six_rounds_simd[False](v, cipher, 0)
        return v.shuffle[
            8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7
        ]() ^ bitcast[DType.uint8, 16](
            SIMD[DType.uint64, 2](cipher.kwhw[0], cipher.kwhw[1])
        )


def _camellia_block[encrypt: Bool](
    cipher: CamelliaCipher, block: SIMD[DType.uint8, 16]
) -> SIMD[DType.uint8, 16]:
    comptime if _has_hw_sbox():
        return _camellia_block_hw[encrypt](cipher, block)

    var w = bitcast[DType.uint64, 2](block)
    var d1 = byte_swap(w[0])
    var d2 = byte_swap(w[1])

    comptime if encrypt:
        d1 ^= cipher.kw[0]
        d2 ^= cipher.kw[1]
        _six_rounds_one[True](d1, d2, cipher, 0)
        d1 = _fl_scalar(d1, cipher.ke[0])
        d2 = _flinv_scalar(d2, cipher.ke[1])
        _six_rounds_one[True](d1, d2, cipher, 6)
        d1 = _fl_scalar(d1, cipher.ke[2])
        d2 = _flinv_scalar(d2, cipher.ke[3])
        _six_rounds_one[True](d1, d2, cipher, 12)
        if not cipher.is_128:
            d1 = _fl_scalar(d1, cipher.ke[4])
            d2 = _flinv_scalar(d2, cipher.ke[5])
            _six_rounds_one[True](d1, d2, cipher, 18)
        return bitcast[DType.uint8, 16](
            SIMD[DType.uint64, 2](
                byte_swap(d2 ^ cipher.kw[2]), byte_swap(d1 ^ cipher.kw[3])
            )
        )
    else:
        d1 ^= cipher.kw[2]
        d2 ^= cipher.kw[3]
        if not cipher.is_128:
            _six_rounds_one[False](d1, d2, cipher, 18)
            d1 = _fl_scalar(d1, cipher.ke[5])
            d2 = _flinv_scalar(d2, cipher.ke[4])
        _six_rounds_one[False](d1, d2, cipher, 12)
        d1 = _fl_scalar(d1, cipher.ke[3])
        d2 = _flinv_scalar(d2, cipher.ke[2])
        _six_rounds_one[False](d1, d2, cipher, 6)
        d1 = _fl_scalar(d1, cipher.ke[1])
        d2 = _flinv_scalar(d2, cipher.ke[0])
        _six_rounds_one[False](d1, d2, cipher, 0)
        return bitcast[DType.uint8, 16](
            SIMD[DType.uint64, 2](
                byte_swap(d2 ^ cipher.kw[0]), byte_swap(d1 ^ cipher.kw[1])
            )
        )


def _camellia_blocks[encrypt: Bool](
    cipher: CamelliaCipher,
    data: UnsafePointer[mut=True, UInt8, _, address_space=_],
    num_blocks: Int,
):
    comptime if _has_hw_sbox():
        var i = 0
        while i + 16 <= num_blocks:
            _batch16_hw[encrypt](cipher, data + i * 16)
            i += 16
        if i < num_blocks:
            var scratch = InlineArray[UInt8, 256](fill=0)
            var sp = scratch.unsafe_ptr()
            for j in range((num_blocks - i) * 16):
                sp[j] = data[i * 16 + j]
            _batch16_hw[encrypt](cipher, sp)
            for j in range((num_blocks - i) * 16):
                data[i * 16 + j] = sp[j]
    else:
        var i = 0
        while i + 32 <= num_blocks:
            _batch[encrypt, 4](cipher, data + i * 16)
            i += 32
        while i + 8 <= num_blocks:
            _batch[encrypt, 1](cipher, data + i * 16)
            i += 8
        if i < num_blocks:
            var scratch = InlineArray[UInt8, 128](fill=0)
            var sp = scratch.unsafe_ptr()
            for j in range((num_blocks - i) * 16):
                sp[j] = data[i * 16 + j]
            _batch[encrypt, 1](cipher, sp)
            for j in range((num_blocks - i) * 16):
                data[i * 16 + j] = sp[j]


def camellia_encrypt_block(
    cipher: CamelliaCipher, block: SIMD[DType.uint8, 16]
) -> SIMD[DType.uint8, 16]:
    return _camellia_block[True](cipher, block)


def camellia_decrypt_block(
    cipher: CamelliaCipher, block: SIMD[DType.uint8, 16]
) -> SIMD[DType.uint8, 16]:
    return _camellia_block[False](cipher, block)


def camellia_encrypt_blocks(
    cipher: CamelliaCipher,
    data: UnsafePointer[mut=True, UInt8, _, address_space=_],
    num_blocks: Int,
):
    _camellia_blocks[True](cipher, data, num_blocks)


def camellia_decrypt_blocks(
    cipher: CamelliaCipher,
    data: UnsafePointer[mut=True, UInt8, _, address_space=_],
    num_blocks: Int,
):
    _camellia_blocks[False](cipher, data, num_blocks)


def camellia_cbc_encrypt_kernel(
    input_ptr: UnsafePointer[mut=True, UInt8, _, address_space=_],
    output_ptr: UnsafePointer[mut=True, UInt8, _, address_space=_],
    cipher: CamelliaCipher,
    num_blocks: Int,
    iv_ptr: UnsafePointer[mut=True, UInt8, _, address_space=_],
):
    var prev = iv_ptr.load[width=16, alignment=1](0)
    for i in range(num_blocks):
        var x = input_ptr.load[width=16, alignment=1](i * 16) ^ prev
        prev = camellia_encrypt_block(cipher, x)
        output_ptr.store[alignment=1](i * 16, prev)


def camellia_cbc_decrypt_kernel(
    input_ptr: UnsafePointer[mut=True, UInt8, _, address_space=_],
    output_ptr: UnsafePointer[mut=True, UInt8, _, address_space=_],
    cipher: CamelliaCipher,
    num_blocks: Int,
    iv_ptr: UnsafePointer[mut=True, UInt8, _, address_space=_],
):
    var ct = InlineArray[UInt8, 1024](fill=0)
    var pt = InlineArray[UInt8, 1024](fill=0)
    var ctp = ct.unsafe_ptr()
    var ptp = pt.unsafe_ptr()
    var prev = iv_ptr.load[width=16, alignment=1](0)
    var i = 0
    while i < num_blocks:
        var n = num_blocks - i
        if n > 64:
            n = 64
        for b in range(n):
            var v = input_ptr.load[width=16, alignment=1]((i + b) * 16)
            ctp.store[alignment=1](b * 16, v)
            ptp.store[alignment=1](b * 16, v)
        camellia_decrypt_blocks(cipher, ptp, n)
        for b in range(n):
            var out = ptp.load[width=16, alignment=1](b * 16) ^ prev
            output_ptr.store[alignment=1]((i + b) * 16, out)
            prev = ctp.load[width=16, alignment=1](b * 16)
        i += n


def camellia_ctr_kernel(
    input_ptr: UnsafePointer[mut=True, UInt8, _, address_space=_],
    output_ptr: UnsafePointer[mut=True, UInt8, _, address_space=_],
    cipher: CamelliaCipher,
    num_blocks: Int,
    nonce_ptr: UnsafePointer[mut=True, UInt8, _, address_space=_],
):
    var ks = InlineArray[UInt8, 512](fill=0)
    var kp = ks.unsafe_ptr()
    var i = 0
    comptime if _has_hw_sbox():
        while i + 16 <= num_blocks:
            for k in range(16):
                _ctr_write_block(kp + k * 16, nonce_ptr, i + k)
            _batch16_hw[True](cipher, kp)
            for b in range(16):
                var off = (i + b) * 16
                output_ptr.store[alignment=1](
                    off,
                    input_ptr.load[width=16, alignment=1](off)
                    ^ kp.load[width=16, alignment=1](b * 16),
                )
            i += 16
        while i < num_blocks:
            var n = num_blocks - i
            for k in range(16):
                _ctr_write_block(
                    kp + k * 16, nonce_ptr, i + (k if k < n else 0)
                )
            _batch16_hw[True](cipher, kp)
            for b in range(n):
                var off = (i + b) * 16
                output_ptr.store[alignment=1](
                    off,
                    input_ptr.load[width=16, alignment=1](off)
                    ^ kp.load[width=16, alignment=1](b * 16),
                )
            i += n
    else:
        while i + 32 <= num_blocks:
            for k in range(32):
                _ctr_write_block(kp + k * 16, nonce_ptr, i + k)
            _encrypt_batch[4](cipher, kp)
            for b in range(32):
                var off = (i + b) * 16
                output_ptr.store[alignment=1](
                    off,
                    input_ptr.load[width=16, alignment=1](off)
                    ^ kp.load[width=16, alignment=1](b * 16),
                )
            i += 32
        while i < num_blocks:
            var n = num_blocks - i
            if n > 8:
                n = 8
            for k in range(8):
                _ctr_write_block(
                    kp + k * 16, nonce_ptr, i + (k if k < n else 0)
                )
            _encrypt_batch[1](cipher, kp)
            for b in range(n):
                var off = (i + b) * 16
                output_ptr.store[alignment=1](
                    off,
                    input_ptr.load[width=16, alignment=1](off)
                    ^ kp.load[width=16, alignment=1](b * 16),
                )
            i += n
