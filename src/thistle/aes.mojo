"""
AES CPU implementation
"""

from std.bit import byte_swap
from std.memory import alloc, memset_zero
from std.utils import StaticTuple
from .utils import StackBuffer

comptime AESError = Error
comptime ROUNDS_128: Int = 10
comptime BLOCK_SIZE: Int = 16

@always_inline
def _ct_encrypt1(
    block: UnsafePointer[UInt8, MutAnyOrigin],
    skey: List[UInt64],
    rounds: Int,
) -> None:
    var buf = InlineArray[UInt8, 64](fill=0)
    var bp = buf.unsafe_ptr()
    for i in range(16):
        bp[i] = block[i]
    cpu_aes_ct_encrypt4(bp, skey, rounds)
    for i in range(16):
        block[i] = bp[i]

@always_inline
def cpu_aes_encrypt(
    pt_bytes: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
) -> None:
    cpu_aes_encrypt(pt_bytes, round_keys, 10)

@always_inline
def cpu_aes_encrypt(
    pt_bytes: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
    rounds: Int,
) -> None:
    var skey = cpu_aes_ct_skey(round_keys, rounds)
    _ct_encrypt1(pt_bytes, skey, rounds)

@always_inline
def cpu_aes_ecb_kernel(
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
    num_blocks: Int,
    rounds: Int
) -> None:
    var skey = cpu_aes_ct_skey(round_keys, rounds)
    var scratch = InlineArray[UInt8, 256](fill=0)
    var sp = scratch.unsafe_ptr()
    var i = 0
    while i < num_blocks:
        var n = num_blocks - i
        if n > 16:
            n = 16
        for j in range(n * 16):
            sp[j] = input_ptr[i * 16 + j]
        cpu_aes_ct_encrypt16(sp, skey, rounds)
        for j in range(n * 16):
            output_ptr[i * 16 + j] = sp[j]
        i += n

@always_inline
def cpu_aes_cbc_kernel(
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
    num_blocks: Int,
    iv_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    rounds: Int
) -> None:
    var skey = cpu_aes_ct_skey(round_keys, rounds)
    var prev_block = StaticTuple[UInt8, 16](
        iv_ptr[0], iv_ptr[1], iv_ptr[2], iv_ptr[3],
        iv_ptr[4], iv_ptr[5], iv_ptr[6], iv_ptr[7],
        iv_ptr[8], iv_ptr[9], iv_ptr[10], iv_ptr[11],
        iv_ptr[12], iv_ptr[13], iv_ptr[14], iv_ptr[15]
    )

    var i = 0
    while i < num_blocks:
        var block_ptr = input_ptr + i * 16
        var out_ptr = output_ptr + i * 16

        for j in range(16):
            out_ptr.store(j, block_ptr.load(j) ^ prev_block[j])

        _ct_encrypt1(out_ptr, skey, rounds)

        for j in range(16):
            prev_block[j] = out_ptr.load(j)

        i += 1

@always_inline
def _ctr_write_block(
    dst: UnsafePointer[UInt8, MutAnyOrigin],
    nonce_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    offset: Int,
) -> None:
    for j in range(16):
        dst.store(j, nonce_ptr[j])
    var carry = UInt64(offset)
    for j in range(15, -1, -1):
        if carry == 0:
            break
        var total = UInt64(dst.load(j)) + (carry & 0xFF)
        dst.store(j, UInt8(total & 0xFF))
        carry = (carry >> 8) + (total >> 8)


@always_inline
def cpu_aes_ctr_kernel(
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
    num_blocks: Int,
    nonce_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    rounds: Int
) -> None:
    var skey = cpu_aes_ct_skey(round_keys, rounds)
    var ks = InlineArray[UInt8, 256](fill=0)
    var kp = ks.unsafe_ptr()
    var i = 0
    while i < num_blocks:
        var n = num_blocks - i
        if n > 16:
            n = 16
        for k in range(16):
            _ctr_write_block(kp + k * 16, nonce_ptr, i + (k if k < n else 0))
        cpu_aes_ct_encrypt16(kp, skey, rounds)
        for k in range(n):
            var in_block = input_ptr + (i + k) * 16
            var out_block = output_ptr + (i + k) * 16
            for j in range(16):
                out_block.store(j, in_block.load(j) ^ kp.load(k * 16 + j))
        i += n

@always_inline
def cpu_xts_mul_alpha_inplace(tweak_ptr: UnsafePointer[UInt8, MutAnyOrigin]) -> None:
    var carry = (tweak_ptr.load(15) & 0x80) != 0
    for i in range(15, 0, -1):
        tweak_ptr.store(i, (tweak_ptr.load(i) << UInt8(1)) | (tweak_ptr.load(i - 1) >> UInt8(7)))
    var t0 = tweak_ptr.load(0) << UInt8(1)
    if carry:
        t0 = t0 ^ UInt8(0x87)
    tweak_ptr.store(0, t0)

@always_inline
def cpu_aes_xts_kernel(
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys1: UnsafePointer[UInt32, MutAnyOrigin],
    round_keys2: UnsafePointer[UInt32, MutAnyOrigin],
    num_blocks: Int,
    tweak_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    rounds: Int
) -> None:
    var skey1 = cpu_aes_ct_skey(round_keys1, rounds)
    var skey2 = cpu_aes_ct_skey(round_keys2, rounds)
    var tweak = StackBuffer[UInt8, 16]()
    var wp = tweak.ptr()
    for j in range(16):
        wp.store(j, tweak_ptr[j])

    _ct_encrypt1(wp, skey2, rounds)

    var i = 0
    while i < num_blocks:
        var in_block = input_ptr + i * 16
        var out_block = output_ptr + i * 16

        var xored = StackBuffer[UInt8, 16]()
        var xp = xored.ptr()
        for j in range(16):
            xp.store(j, in_block.load(j) ^ wp.load(j))

        _ct_encrypt1(xp, skey1, rounds)

        for j in range(16):
            out_block.store(j, xp.load(j) ^ wp.load(j))

        cpu_xts_mul_alpha_inplace(wp)
        i += 1

@always_inline
def sub_word(w: UInt32) -> UInt32:
    var blk = InlineArray[UInt8, 16](fill=0)
    var bp = blk.unsafe_ptr()
    bp[0] = UInt8((w >> 24) & 0xff)
    bp[1] = UInt8((w >> 16) & 0xff)
    bp[2] = UInt8((w >> 8) & 0xff)
    bp[3] = UInt8(w & 0xff)
    var q = InlineArray[SIMD[DType.uint64, 1], 8](fill=0)
    var pair = _ct_interleave_in[1](_ct_le32(bp, 0), 0, 0, 0)
    q[0] = pair[0]
    q[4] = pair[1]
    _ct_ortho(q)
    _ct_sbox(q)
    _ct_ortho(q)
    var ws = _ct_interleave_out(q[0], q[4])
    var v = UInt64(ws[0])
    return (
        (UInt32(v & 0xFF) << 24) | (UInt32((v >> 8) & 0xFF) << 16)
        | (UInt32((v >> 16) & 0xFF) << 8) | UInt32((v >> 24) & 0xFF)
    )

comptime RCON: StaticTuple[UInt8, 11] = StaticTuple[UInt8, 11](
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c
)

def expand_key_128_into(
    key_bytes: UnsafePointer[UInt8, MutAnyOrigin],
    w: UnsafePointer[UInt32, MutAnyOrigin],
) raises -> None:
    for i in range(4):
        var key_val: UInt32 = 0
        for j in range(4):
            key_val |= UInt32(key_bytes.load(i * 4 + j)) << UInt32((3 - j) * 8)
        w.store(i, key_val)
    for i in range(4, 44):
        var temp = w.load(i - 1)
        if i % 4 == 0:
            var rotated = (temp >> 24) | ((temp << 8) & 0xffffffff)
            temp = sub_word(rotated)
            temp ^= UInt32(RCON._unsafe_ref(i // 4 - 1)) << 24
        w.store(i, w.load(i - 4) ^ temp)

def expand_key_192_into(
    key_bytes: UnsafePointer[UInt8, MutAnyOrigin],
    w: UnsafePointer[UInt32, MutAnyOrigin],
) raises -> None:
    for i in range(6):
        var key_val: UInt32 = 0
        for j in range(4):
            key_val |= UInt32(key_bytes.load(i * 4 + j)) << UInt32((3 - j) * 8)
        w.store(i, key_val)
    for i in range(6, 52):
        var temp = w.load(i - 1)
        if i % 6 == 0:
            var rotated = (temp >> 24) | ((temp << 8) & 0xffffffff)
            temp = sub_word(rotated)
            temp ^= UInt32(RCON._unsafe_ref(i // 6 - 1)) << 24
        w.store(i, w.load(i - 6) ^ temp)

def expand_key_256_into(
    key_bytes: UnsafePointer[UInt8, MutAnyOrigin],
    w: UnsafePointer[UInt32, MutAnyOrigin],
) raises -> None:
    for i in range(8):
        var key_val: UInt32 = 0
        for j in range(4):
            key_val |= UInt32(key_bytes.load(i * 4 + j)) << UInt32((3 - j) * 8)
        w.store(i, key_val)
    for i in range(8, 60):
        var temp = w.load(i - 1)
        if i % 8 == 0:
            var rotated = (temp >> 24) | ((temp << 8) & 0xffffffff)
            temp = sub_word(rotated)
            temp ^= UInt32(RCON._unsafe_ref(i // 8 - 1)) << 24
        elif i % 8 == 4:
            temp = sub_word(temp)
        w.store(i, w.load(i - 8) ^ temp)

def expand_key_128(key_bytes: UnsafePointer[UInt8, MutAnyOrigin]) raises -> UnsafePointer[UInt32, MutAnyOrigin]:
    var w = alloc[UInt32](44)
    expand_key_128_into(key_bytes, w)
    return w

def expand_key_192(key_bytes: UnsafePointer[UInt8, MutAnyOrigin]) raises -> UnsafePointer[UInt32, MutAnyOrigin]:
    var w = alloc[UInt32](52)
    expand_key_192_into(key_bytes, w)
    return w

def expand_key_256(key_bytes: UnsafePointer[UInt8, MutAnyOrigin]) raises -> UnsafePointer[UInt32, MutAnyOrigin]:
    var w = alloc[UInt32](60)
    expand_key_256_into(key_bytes, w)
    return w

struct AESKey:
    var _data: StackBuffer[UInt8, 16]
    var _round_keys: StackBuffer[UInt32, 44]
    
    def __init__(out self, key: StaticTuple[UInt8, 16]) raises:
        self._data = StackBuffer[UInt8, 16]()
        for i in range(16):
            self._data.ptr().store(i, key[i])
        self._round_keys = StackBuffer[UInt32, 44]()
        expand_key_128_into(self._data.ptr(), self._round_keys.ptr())
    
    def __del__(deinit self):
        memset_zero(self._data.ptr(), 16)
        memset_zero(self._round_keys.ptr(), 44)

    def round_keys(mut self) -> UnsafePointer[UInt32, MutAnyOrigin]:
        return self._round_keys.ptr()


@always_inline
def _ct_interleave_in[W: Int](
    w0: SIMD[DType.uint64, W], w1: SIMD[DType.uint64, W],
    w2: SIMD[DType.uint64, W], w3: SIMD[DType.uint64, W],
) -> Tuple[SIMD[DType.uint64, W], SIMD[DType.uint64, W]]:
    var x0 = w0
    var x1 = w1
    var x2 = w2
    var x3 = w3
    x0 |= x0 << 16
    x1 |= x1 << 16
    x2 |= x2 << 16
    x3 |= x3 << 16
    x0 &= 0x0000FFFF0000FFFF
    x1 &= 0x0000FFFF0000FFFF
    x2 &= 0x0000FFFF0000FFFF
    x3 &= 0x0000FFFF0000FFFF
    x0 |= x0 << 8
    x1 |= x1 << 8
    x2 |= x2 << 8
    x3 |= x3 << 8
    x0 &= 0x00FF00FF00FF00FF
    x1 &= 0x00FF00FF00FF00FF
    x2 &= 0x00FF00FF00FF00FF
    x3 &= 0x00FF00FF00FF00FF
    return (x0 | (x2 << 8), x1 | (x3 << 8))


@always_inline
def _ct_interleave_out[W: Int](
    q0: SIMD[DType.uint64, W], q1: SIMD[DType.uint64, W]
) -> Tuple[
    SIMD[DType.uint64, W], SIMD[DType.uint64, W],
    SIMD[DType.uint64, W], SIMD[DType.uint64, W],
]:
    var x0 = q0 & 0x00FF00FF00FF00FF
    var x1 = q1 & 0x00FF00FF00FF00FF
    var x2 = (q0 >> 8) & 0x00FF00FF00FF00FF
    var x3 = (q1 >> 8) & 0x00FF00FF00FF00FF
    x0 |= x0 >> 8
    x1 |= x1 >> 8
    x2 |= x2 >> 8
    x3 |= x3 >> 8
    x0 &= 0x0000FFFF0000FFFF
    x1 &= 0x0000FFFF0000FFFF
    x2 &= 0x0000FFFF0000FFFF
    x3 &= 0x0000FFFF0000FFFF
    x0 |= x0 >> 16
    x1 |= x1 >> 16
    x2 |= x2 >> 16
    x3 |= x3 >> 16
    return (
        x0 & 0xFFFFFFFF, x1 & 0xFFFFFFFF, x2 & 0xFFFFFFFF, x3 & 0xFFFFFFFF
    )


@always_inline
def _ct_swapn[W: Int](
    cl: UInt64, s: Int, x: SIMD[DType.uint64, W], y: SIMD[DType.uint64, W]
) -> Tuple[SIMD[DType.uint64, W], SIMD[DType.uint64, W]]:
    var sv = SIMD[DType.uint64, W](s)
    return (
        (x & cl) | ((y & cl) << sv),
        ((x & ~cl) >> sv) | (y & ~cl),
    )


@always_inline
def _ct_ortho[W: Int](mut q: InlineArray[SIMD[DType.uint64, W], 8]):
    var p01 = _ct_swapn(0x5555555555555555, 1, q[0], q[1])
    var p23 = _ct_swapn(0x5555555555555555, 1, q[2], q[3])
    var p45 = _ct_swapn(0x5555555555555555, 1, q[4], q[5])
    var p67 = _ct_swapn(0x5555555555555555, 1, q[6], q[7])
    var p02 = _ct_swapn(0x3333333333333333, 2, p01[0], p23[0])
    var p13 = _ct_swapn(0x3333333333333333, 2, p01[1], p23[1])
    var p46 = _ct_swapn(0x3333333333333333, 2, p45[0], p67[0])
    var p57 = _ct_swapn(0x3333333333333333, 2, p45[1], p67[1])
    var p04 = _ct_swapn(0x0F0F0F0F0F0F0F0F, 4, p02[0], p46[0])
    var p15 = _ct_swapn(0x0F0F0F0F0F0F0F0F, 4, p13[0], p57[0])
    var p26 = _ct_swapn(0x0F0F0F0F0F0F0F0F, 4, p02[1], p46[1])
    var p37 = _ct_swapn(0x0F0F0F0F0F0F0F0F, 4, p13[1], p57[1])
    q[0] = p04[0]
    q[1] = p15[0]
    q[2] = p26[0]
    q[3] = p37[0]
    q[4] = p04[1]
    q[5] = p15[1]
    q[6] = p26[1]
    q[7] = p37[1]


@always_inline
def _ct_sbox[W: Int](mut q: InlineArray[SIMD[DType.uint64, W], 8]):
    var x0 = q[7]
    var x1 = q[6]
    var x2 = q[5]
    var x3 = q[4]
    var x4 = q[3]
    var x5 = q[2]
    var x6 = q[1]
    var x7 = q[0]

    var y14 = x3 ^ x5
    var y13 = x0 ^ x6
    var y9 = x0 ^ x3
    var y8 = x0 ^ x5
    var t0 = x1 ^ x2
    var y1 = t0 ^ x7
    var y4 = y1 ^ x3
    var y12 = y13 ^ y14
    var y2 = y1 ^ x0
    var y5 = y1 ^ x6
    var y3 = y5 ^ y8
    var t1 = x4 ^ y12
    var y15 = t1 ^ x5
    var y20 = t1 ^ x1
    var y6 = y15 ^ x7
    var y10 = y15 ^ t0
    var y11 = y20 ^ y9
    var y7 = x7 ^ y11
    var y17 = y10 ^ y11
    var y19 = y10 ^ y8
    var y16 = t0 ^ y11
    var y21 = y13 ^ y16
    var y18 = x0 ^ y16

    var t2 = y12 & y15
    var t3 = y3 & y6
    var t4 = t3 ^ t2
    var t5 = y4 & x7
    var t6 = t5 ^ t2
    var t7 = y13 & y16
    var t8 = y5 & y1
    var t9 = t8 ^ t7
    var t10 = y2 & y7
    var t11 = t10 ^ t7
    var t12 = y9 & y11
    var t13 = y14 & y17
    var t14 = t13 ^ t12
    var t15 = y8 & y10
    var t16 = t15 ^ t12
    var t17 = t4 ^ t14
    var t18 = t6 ^ t16
    var t19 = t9 ^ t14
    var t20 = t11 ^ t16
    var t21 = t17 ^ y20
    var t22 = t18 ^ y19
    var t23 = t19 ^ y21
    var t24 = t20 ^ y18

    var t25 = t21 ^ t22
    var t26 = t21 & t23
    var t27 = t24 ^ t26
    var t28 = t25 & t27
    var t29 = t28 ^ t22
    var t30 = t23 ^ t24
    var t31 = t22 ^ t26
    var t32 = t31 & t30
    var t33 = t32 ^ t24
    var t34 = t23 ^ t33
    var t35 = t27 ^ t33
    var t36 = t24 & t35
    var t37 = t36 ^ t34
    var t38 = t27 ^ t36
    var t39 = t29 & t38
    var t40 = t25 ^ t39

    var t41 = t40 ^ t37
    var t42 = t29 ^ t33
    var t43 = t29 ^ t40
    var t44 = t33 ^ t37
    var t45 = t42 ^ t41
    var z0 = t44 & y15
    var z1 = t37 & y6
    var z2 = t33 & x7
    var z3 = t43 & y16
    var z4 = t40 & y1
    var z5 = t29 & y7
    var z6 = t42 & y11
    var z7 = t45 & y17
    var z8 = t41 & y10
    var z9 = t44 & y12
    var z10 = t37 & y3
    var z11 = t33 & y4
    var z12 = t43 & y13
    var z13 = t40 & y5
    var z14 = t29 & y2
    var z15 = t42 & y9
    var z16 = t45 & y14
    var z17 = t41 & y8

    var t46 = z15 ^ z16
    var t47 = z10 ^ z11
    var t48 = z5 ^ z13
    var t49 = z9 ^ z10
    var t50 = z2 ^ z12
    var t51 = z2 ^ z5
    var t52 = z7 ^ z8
    var t53 = z0 ^ z3
    var t54 = z6 ^ z7
    var t55 = z16 ^ z17
    var t56 = z12 ^ t48
    var t57 = t50 ^ t53
    var t58 = z4 ^ t46
    var t59 = z3 ^ t54
    var t60 = t46 ^ t57
    var t61 = z14 ^ t57
    var t62 = t52 ^ t58
    var t63 = t49 ^ t58
    var t64 = z4 ^ t59
    var t65 = t61 ^ t62
    var t66 = z1 ^ t63
    var s0 = t59 ^ t63
    var s6 = t56 ^ ~t62
    var s7 = t48 ^ ~t60
    var t67 = t64 ^ t65
    var s3 = t53 ^ t66
    var s4 = t51 ^ t66
    var s5 = t47 ^ t65
    var s1 = t64 ^ ~s3
    var s2 = t55 ^ ~t67

    q[7] = s0
    q[6] = s1
    q[5] = s2
    q[4] = s3
    q[3] = s4
    q[2] = s5
    q[1] = s6
    q[0] = s7


@always_inline
def _ct_shift_rows[W: Int](mut q: InlineArray[SIMD[DType.uint64, W], 8]):
    comptime for i in range(8):
        var x = q[i]
        q[i] = (
            (x & 0x000000000000FFFF)
            | ((x & 0x00000000FFF00000) >> 4)
            | ((x & 0x00000000000F0000) << 12)
            | ((x & 0x0000FF0000000000) >> 8)
            | ((x & 0x000000FF00000000) << 8)
            | ((x & 0xF000000000000000) >> 12)
            | ((x & 0x0FFF000000000000) << 4)
        )


@always_inline
def _ct_rotr32[W: Int](x: SIMD[DType.uint64, W]) -> SIMD[DType.uint64, W]:
    return (x << 32) | (x >> 32)


@always_inline
def _ct_mix_columns[W: Int](mut q: InlineArray[SIMD[DType.uint64, W], 8]):
    var q0 = q[0]
    var q1 = q[1]
    var q2 = q[2]
    var q3 = q[3]
    var q4 = q[4]
    var q5 = q[5]
    var q6 = q[6]
    var q7 = q[7]
    var r0 = (q0 >> 16) | (q0 << 48)
    var r1 = (q1 >> 16) | (q1 << 48)
    var r2 = (q2 >> 16) | (q2 << 48)
    var r3 = (q3 >> 16) | (q3 << 48)
    var r4 = (q4 >> 16) | (q4 << 48)
    var r5 = (q5 >> 16) | (q5 << 48)
    var r6 = (q6 >> 16) | (q6 << 48)
    var r7 = (q7 >> 16) | (q7 << 48)

    q[0] = q7 ^ r7 ^ r0 ^ _ct_rotr32(q0 ^ r0)
    q[1] = q0 ^ r0 ^ q7 ^ r7 ^ r1 ^ _ct_rotr32(q1 ^ r1)
    q[2] = q1 ^ r1 ^ r2 ^ _ct_rotr32(q2 ^ r2)
    q[3] = q2 ^ r2 ^ q7 ^ r7 ^ r3 ^ _ct_rotr32(q3 ^ r3)
    q[4] = q3 ^ r3 ^ q7 ^ r7 ^ r4 ^ _ct_rotr32(q4 ^ r4)
    q[5] = q4 ^ r4 ^ r5 ^ _ct_rotr32(q5 ^ r5)
    q[6] = q5 ^ r5 ^ r6 ^ _ct_rotr32(q6 ^ r6)
    q[7] = q6 ^ r6 ^ r7 ^ _ct_rotr32(q7 ^ r7)


def cpu_aes_ct_skey(
    round_keys: UnsafePointer[UInt32, MutAnyOrigin], rounds: Int
) -> List[UInt64]:
    var skey = List[UInt64](capacity=(rounds + 1) * 8)
    for r in range(rounds + 1):
        var w0 = SIMD[DType.uint64, 1](UInt64(byte_swap(round_keys.load(r * 4))))
        var w1 = SIMD[DType.uint64, 1](UInt64(byte_swap(round_keys.load(r * 4 + 1))))
        var w2 = SIMD[DType.uint64, 1](UInt64(byte_swap(round_keys.load(r * 4 + 2))))
        var w3 = SIMD[DType.uint64, 1](UInt64(byte_swap(round_keys.load(r * 4 + 3))))
        var q = InlineArray[SIMD[DType.uint64, 1], 8](fill=0)
        for i in range(4):
            var pair = _ct_interleave_in(w0, w1, w2, w3)
            q[i] = pair[0]
            q[i + 4] = pair[1]
        _ct_ortho(q)
        for i in range(8):
            skey.append(UInt64(q[i]))
    return skey^


@always_inline
def _ct_le32(p: UnsafePointer[UInt8, MutAnyOrigin], off: Int) -> UInt64:
    return (
        UInt64(p.load(off))
        | (UInt64(p.load(off + 1)) << 8)
        | (UInt64(p.load(off + 2)) << 16)
        | (UInt64(p.load(off + 3)) << 24)
    )


@always_inline
def _ct_store_le32(p: UnsafePointer[UInt8, MutAnyOrigin], off: Int, w: UInt64):
    p.store(off, UInt8(w & 0xFF))
    p.store(off + 1, UInt8((w >> 8) & 0xFF))
    p.store(off + 2, UInt8((w >> 16) & 0xFF))
    p.store(off + 3, UInt8((w >> 24) & 0xFF))


@always_inline
def _ct_encrypt_blocks[W: Int](
    blocks: UnsafePointer[UInt8, MutAnyOrigin],
    skp: UnsafePointer[UInt64, ImmutAnyOrigin],
    rounds: Int,
) -> None:
    var q = InlineArray[SIMD[DType.uint64, W], 8](fill=0)
    for i in range(4):
        var w0 = SIMD[DType.uint64, W](0)
        var w1 = SIMD[DType.uint64, W](0)
        var w2 = SIMD[DType.uint64, W](0)
        var w3 = SIMD[DType.uint64, W](0)
        comptime for l in range(W):
            var base = (i + 4 * l) * 16
            w0[l] = _ct_le32(blocks, base)
            w1[l] = _ct_le32(blocks, base + 4)
            w2[l] = _ct_le32(blocks, base + 8)
            w3[l] = _ct_le32(blocks, base + 12)
        var pair = _ct_interleave_in(w0, w1, w2, w3)
        q[i] = pair[0]
        q[i + 4] = pair[1]
    _ct_ortho(q)

    comptime for i in range(8):
        q[i] ^= SIMD[DType.uint64, W](skp[i])
    for r in range(1, rounds):
        _ct_sbox(q)
        _ct_shift_rows(q)
        _ct_mix_columns(q)
        comptime for i in range(8):
            q[i] ^= SIMD[DType.uint64, W](skp[r * 8 + i])
    _ct_sbox(q)
    _ct_shift_rows(q)
    comptime for i in range(8):
        q[i] ^= SIMD[DType.uint64, W](skp[rounds * 8 + i])

    _ct_ortho(q)
    for i in range(4):
        var ws = _ct_interleave_out(q[i], q[i + 4])
        comptime for l in range(W):
            var base = (i + 4 * l) * 16
            _ct_store_le32(blocks, base, UInt64(ws[0][l]))
            _ct_store_le32(blocks, base + 4, UInt64(ws[1][l]))
            _ct_store_le32(blocks, base + 8, UInt64(ws[2][l]))
            _ct_store_le32(blocks, base + 12, UInt64(ws[3][l]))


def cpu_aes_ct_encrypt4(
    blocks: UnsafePointer[UInt8, MutAnyOrigin],
    skey: List[UInt64],
    rounds: Int,
) -> None:
    _ct_encrypt_blocks[1](blocks, skey.unsafe_ptr(), rounds)


def cpu_aes_ct_encrypt16(
    blocks: UnsafePointer[UInt8, MutAnyOrigin],
    skey: List[UInt64],
    rounds: Int,
) -> None:
    _ct_encrypt_blocks[4](blocks, skey.unsafe_ptr(), rounds)


def cpu_aes_ct_encrypt(
    pt_bytes: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
    rounds: Int = 10,
) -> None:
    var skey = cpu_aes_ct_skey(round_keys, rounds)
    var buf = InlineArray[UInt8, 64](fill=0)
    var bp = buf.unsafe_ptr()
    for i in range(16):
        bp[i] = pt_bytes[i]
    cpu_aes_ct_encrypt4(bp, skey, rounds)
    for i in range(16):
        pt_bytes[i] = bp[i]
