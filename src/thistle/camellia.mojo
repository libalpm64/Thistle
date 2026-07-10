"""
Camellia block cipher implementation per RFC 3713
"""

from std.memory import bitcast, UnsafePointer
from std.bit import byte_swap, rotate_bits_left
from std.collections import InlineArray
from std.utils import StaticTuple
from .aes import _ct_sbox, _ct_ortho, _ctr_write_block


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
    return out


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
def _wipe_u64(ptr: UnsafePointer[UInt64, MutAnyOrigin], count: Int):
    for i in range(count):
        ptr.store[volatile=True](i, UInt64(0))


@always_inline
def _transpose8x8(x0: UInt64) -> UInt64:
    var x = x0
    var t = (x ^ (x >> 7)) & 0x00AA00AA00AA00AA
    x ^= t ^ (t << 7)
    t = (x ^ (x >> 14)) & 0x0000CCCC0000CCCC
    x ^= t ^ (t << 14)
    t = (x ^ (x >> 28)) & 0x00000000F0F0F0F0
    x ^= t ^ (t << 28)
    return x


@always_inline
def _f_scalar(f_in: UInt64, ke: UInt64) -> UInt64:
    var x = f_in ^ ke

    var pin = byte_swap(x)

    var rol1 = ((pin << 1) & ~_BIT0_OF_EACH_BYTE) | ((pin >> 7) & _BIT0_OF_EACH_BYTE)
    pin = (pin & ~_LANES_S4) | (rol1 & _LANES_S4)

    var xt = _transpose8x8(pin)
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

    _ct_sbox(a)

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
    var sout = _transpose8x8(packed)

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


struct CamelliaCipher:
    var kw: SIMD[DType.uint64, 4]
    var k: InlineArray[UInt64, 24]
    var ke: InlineArray[UInt64, 6]
    var kp: InlineArray[UInt64, 192]
    var kep: InlineArray[UInt64, 48]
    var is_128: Bool

    def __init__(out self, key: Span[UInt8, ...]) raises:
        self.kw = SIMD[DType.uint64, 4](0)
        self.k = InlineArray[UInt64, 24](fill=0)
        self.ke = InlineArray[UInt64, 6](fill=0)
        self.kp = InlineArray[UInt64, 192](fill=0)
        self.kep = InlineArray[UInt64, 48](fill=0)
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

    def wipe(mut self):
        _wipe_u64(UnsafePointer(to=self.kw).bitcast[UInt64](), 4)
        _wipe_u64(self.k.unsafe_ptr(), 24)
        _wipe_u64(self.ke.unsafe_ptr(), 6)
        _wipe_u64(self.kp.unsafe_ptr(), 192)
        _wipe_u64(self.kep.unsafe_ptr(), 48)

    def __del__(deinit self):
        _wipe_u64(UnsafePointer(to=self.kw).bitcast[UInt64](), 4)
        _wipe_u64(self.k.unsafe_ptr(), 24)
        _wipe_u64(self.ke.unsafe_ptr(), 6)
        _wipe_u64(self.kp.unsafe_ptr(), 192)
        _wipe_u64(self.kep.unsafe_ptr(), 48)

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
    buf: UnsafePointer[UInt8, MutAnyOrigin], off: Int, kw: UInt64
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
    _ct_ortho(q)
    return q


@always_inline
def _store_half[W: Int](
    buf: UnsafePointer[UInt8, MutAnyOrigin],
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
    cipher: CamelliaCipher, buf: UnsafePointer[UInt8, MutAnyOrigin]
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
    cipher: CamelliaCipher, buf: UnsafePointer[UInt8, MutAnyOrigin]
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
    cipher: CamelliaCipher, buf: UnsafePointer[UInt8, MutAnyOrigin]
):
    comptime if encrypt:
        _encrypt_batch[W](cipher, buf)
    else:
        _decrypt_batch[W](cipher, buf)


def _camellia_block[encrypt: Bool](
    cipher: CamelliaCipher, block: SIMD[DType.uint8, 16]
) -> SIMD[DType.uint8, 16]:
    var buf = InlineArray[UInt8, 128](fill=0)
    var bp = buf.unsafe_ptr()
    bp.store[alignment=1](0, block)
    _batch[encrypt, 1](cipher, bp)
    return bp.load[width=16, alignment=1](0)


def _camellia_blocks[encrypt: Bool](
    cipher: CamelliaCipher,
    data: UnsafePointer[UInt8, MutAnyOrigin],
    num_blocks: Int,
):
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
    data: UnsafePointer[UInt8, MutAnyOrigin],
    num_blocks: Int,
):
    _camellia_blocks[True](cipher, data, num_blocks)


def camellia_decrypt_blocks(
    cipher: CamelliaCipher,
    data: UnsafePointer[UInt8, MutAnyOrigin],
    num_blocks: Int,
):
    _camellia_blocks[False](cipher, data, num_blocks)


def camellia_cbc_encrypt_kernel(
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    cipher: CamelliaCipher,
    num_blocks: Int,
    iv_ptr: UnsafePointer[UInt8, MutAnyOrigin],
):
    var prev = iv_ptr.load[width=16, alignment=1](0)
    for i in range(num_blocks):
        var x = input_ptr.load[width=16, alignment=1](i * 16) ^ prev
        prev = camellia_encrypt_block(cipher, x)
        output_ptr.store[alignment=1](i * 16, prev)


def camellia_cbc_decrypt_kernel(
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    cipher: CamelliaCipher,
    num_blocks: Int,
    iv_ptr: UnsafePointer[UInt8, MutAnyOrigin],
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
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    cipher: CamelliaCipher,
    num_blocks: Int,
    nonce_ptr: UnsafePointer[UInt8, MutAnyOrigin],
):
    var ks = InlineArray[UInt8, 512](fill=0)
    var kp = ks.unsafe_ptr()
    var i = 0
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
            _ctr_write_block(kp + k * 16, nonce_ptr, i + (k if k < n else 0))
        _encrypt_batch[1](cipher, kp)
        for b in range(n):
            var off = (i + b) * 16
            output_ptr.store[alignment=1](
                off,
                input_ptr.load[width=16, alignment=1](off)
                ^ kp.load[width=16, alignment=1](b * 16),
            )
        i += n
