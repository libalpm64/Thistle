"""
AES CPU implementation
"""

from std.builtin.globals import global_constant
from std.memory import alloc, memset_zero
from std.utils import StaticTuple
from .utils import StackBuffer

comptime AESError = Error
comptime ROUNDS_128: Int = 10
comptime BLOCK_SIZE: Int = 16

@always_inline
def gf_mul2(a: UInt8) -> UInt8:
    return (a << UInt8(1)) ^ (UInt8(0x1b) & (UInt8(0) - (a >> UInt8(7))))

@always_inline
def sbox_lookup(idx: UInt8) -> UInt8:
    ref sbox = global_constant[SBOX]()
    return sbox._unsafe_ref(Int(idx))

comptime TE0: InlineArray[UInt32, 256] = [
    0xc66363a5, 0xf87c7c84, 0xee777799, 0xf67b7b8d, 0xfff2f20d, 0xd66b6bbd, 0xde6f6fb1, 0x91c5c554,
    0x60303050, 0x02010103, 0xce6767a9, 0x562b2b7d, 0xe7fefe19, 0xb5d7d762, 0x4dababe6, 0xec76769a,
    0x8fcaca45, 0x1f82829d, 0x89c9c940, 0xfa7d7d87, 0xeffafa15, 0xb25959eb, 0x8e4747c9, 0xfbf0f00b,
    0x41adadec, 0xb3d4d467, 0x5fa2a2fd, 0x45afafea, 0x239c9cbf, 0x53a4a4f7, 0xe4727296, 0x9bc0c05b,
    0x75b7b7c2, 0xe1fdfd1c, 0x3d9393ae, 0x4c26266a, 0x6c36365a, 0x7e3f3f41, 0xf5f7f702, 0x83cccc4f,
    0x6834345c, 0x51a5a5f4, 0xd1e5e534, 0xf9f1f108, 0xe2717193, 0xabd8d873, 0x62313153, 0x2a15153f,
    0x0804040c, 0x95c7c752, 0x46232365, 0x9dc3c35e, 0x30181828, 0x379696a1, 0x0a05050f, 0x2f9a9ab5,
    0x0e070709, 0x24121236, 0x1b80809b, 0xdfe2e23d, 0xcdebeb26, 0x4e272769, 0x7fb2b2cd, 0xea75759f,
    0x1209091b, 0x1d83839e, 0x582c2c74, 0x341a1a2e, 0x361b1b2d, 0xdc6e6eb2, 0xb45a5aee, 0x5ba0a0fb,
    0xa45252f6, 0x763b3b4d, 0xb7d6d661, 0x7db3b3ce, 0x5229297b, 0xdde3e33e, 0x5e2f2f71, 0x13848497,
    0xa65353f5, 0xb9d1d168, 0x00000000, 0xc1eded2c, 0x40202060, 0xe3fcfc1f, 0x79b1b1c8, 0xb65b5bed,
    0xd46a6abe, 0x8dcbcb46, 0x67bebed9, 0x7239394b, 0x944a4ade, 0x984c4cd4, 0xb05858e8, 0x85cfcf4a,
    0xbbd0d06b, 0xc5efef2a, 0x4faaaae5, 0xedfbfb16, 0x864343c5, 0x9a4d4dd7, 0x66333355, 0x11858594,
    0x8a4545cf, 0xe9f9f910, 0x04020206, 0xfe7f7f81, 0xa05050f0, 0x783c3c44, 0x259f9fba, 0x4ba8a8e3,
    0xa25151f3, 0x5da3a3fe, 0x804040c0, 0x058f8f8a, 0x3f9292ad, 0x219d9dbc, 0x70383848, 0xf1f5f504,
    0x63bcbcdf, 0x77b6b6c1, 0xafdada75, 0x42212163, 0x20101030, 0xe5ffff1a, 0xfdf3f30e, 0xbfd2d26d,
    0x81cdcd4c, 0x180c0c14, 0x26131335, 0xc3ecec2f, 0xbe5f5fe1, 0x359797a2, 0x884444cc, 0x2e171739,
    0x93c4c457, 0x55a7a7f2, 0xfc7e7e82, 0x7a3d3d47, 0xc86464ac, 0xba5d5de7, 0x3219192b, 0xe6737395,
    0xc06060a0, 0x19818198, 0x9e4f4fd1, 0xa3dcdc7f, 0x44222266, 0x542a2a7e, 0x3b9090ab, 0x0b888883,
    0x8c4646ca, 0xc7eeee29, 0x6bb8b8d3, 0x2814143c, 0xa7dede79, 0xbc5e5ee2, 0x160b0b1d, 0xaddbdb76,
    0xdbe0e03b, 0x64323256, 0x743a3a4e, 0x140a0a1e, 0x924949db, 0x0c06060a, 0x4824246c, 0xb85c5ce4,
    0x9fc2c25d, 0xbdd3d36e, 0x43acacef, 0xc46262a6, 0x399191a8, 0x319595a4, 0xd3e4e437, 0xf279798b,
    0xd5e7e732, 0x8bc8c843, 0x6e373759, 0xda6d6db7, 0x018d8d8c, 0xb1d5d564, 0x9c4e4ed2, 0x49a9a9e0,
    0xd86c6cb4, 0xac5656fa, 0xf3f4f407, 0xcfeaea25, 0xca6565af, 0xf47a7a8e, 0x47aeaee9, 0x10080818,
    0x6fbabad5, 0xf0787888, 0x4a25256f, 0x5c2e2e72, 0x381c1c24, 0x57a6a6f1, 0x73b4b4c7, 0x97c6c651,
    0xcbe8e823, 0xa1dddd7c, 0xe874749c, 0x3e1f1f21, 0x964b4bdd, 0x61bdbddc, 0x0d8b8b86, 0x0f8a8a85,
    0xe0707090, 0x7c3e3e42, 0x71b5b5c4, 0xcc6666aa, 0x904848d8, 0x06030305, 0xf7f6f601, 0x1c0e0e12,
    0xc26161a3, 0x6a35355f, 0xae5757f9, 0x69b9b9d0, 0x17868691, 0x99c1c158, 0x3a1d1d27, 0x279e9eb9,
    0xd9e1e138, 0xebf8f813, 0x2b9898b3, 0x22111133, 0xd26969bb, 0xa9d9d970, 0x078e8e89, 0x339494a7,
    0x2d9b9bb6, 0x3c1e1e22, 0x15878792, 0xc9e9e920, 0x87cece49, 0xaa5555ff, 0x50282878, 0xa5dfdf7a,
    0x038c8c8f, 0x59a1a1f8, 0x09898980, 0x1a0d0d17, 0x65bfbfda, 0xd7e6e631, 0x844242c6, 0xd06868b8,
    0x824141c3, 0x299999b0, 0x5a2d2d77, 0x1e0f0f11, 0x7bb0b0cb, 0xa85454fc, 0x6dbbbbd6, 0x2c16163a
]

@always_inline
def _te(idx: UInt32) -> UInt32:
    ref t = global_constant[TE0]()
    return t.unsafe_ptr()[Int(idx)]

@always_inline
def _rotr[n: Int](x: UInt32) -> UInt32:
    return (x >> UInt32(n)) | (x << UInt32(32 - n))

@always_inline
def _sb(idx: UInt32) -> UInt32:
    return UInt32(sbox_lookup(UInt8(idx)))

@always_inline
def _cpu_aes_encrypt[rounds: Int](
    pt_bytes: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
) -> None:
    var c0 = (
        (UInt32(pt_bytes.load(0)) << 24) | (UInt32(pt_bytes.load(1)) << 16)
        | (UInt32(pt_bytes.load(2)) << 8) | UInt32(pt_bytes.load(3))
    ) ^ round_keys.load(0)
    var c1 = (
        (UInt32(pt_bytes.load(4)) << 24) | (UInt32(pt_bytes.load(5)) << 16)
        | (UInt32(pt_bytes.load(6)) << 8) | UInt32(pt_bytes.load(7))
    ) ^ round_keys.load(1)
    var c2 = (
        (UInt32(pt_bytes.load(8)) << 24) | (UInt32(pt_bytes.load(9)) << 16)
        | (UInt32(pt_bytes.load(10)) << 8) | UInt32(pt_bytes.load(11))
    ) ^ round_keys.load(2)
    var c3 = (
        (UInt32(pt_bytes.load(12)) << 24) | (UInt32(pt_bytes.load(13)) << 16)
        | (UInt32(pt_bytes.load(14)) << 8) | UInt32(pt_bytes.load(15))
    ) ^ round_keys.load(3)

    comptime for r in range(1, rounds):
        var rk = round_keys + r * 4
        var t0 = (
            _te(c0 >> 24) ^ _rotr[8](_te((c1 >> 16) & 0xFF))
            ^ _rotr[16](_te((c2 >> 8) & 0xFF)) ^ _rotr[24](_te(c3 & 0xFF))
        ) ^ rk.load(0)
        var t1 = (
            _te(c1 >> 24) ^ _rotr[8](_te((c2 >> 16) & 0xFF))
            ^ _rotr[16](_te((c3 >> 8) & 0xFF)) ^ _rotr[24](_te(c0 & 0xFF))
        ) ^ rk.load(1)
        var t2 = (
            _te(c2 >> 24) ^ _rotr[8](_te((c3 >> 16) & 0xFF))
            ^ _rotr[16](_te((c0 >> 8) & 0xFF)) ^ _rotr[24](_te(c1 & 0xFF))
        ) ^ rk.load(2)
        var t3 = (
            _te(c3 >> 24) ^ _rotr[8](_te((c0 >> 16) & 0xFF))
            ^ _rotr[16](_te((c1 >> 8) & 0xFF)) ^ _rotr[24](_te(c2 & 0xFF))
        ) ^ rk.load(3)
        c0 = t0
        c1 = t1
        c2 = t2
        c3 = t3

    var frk = round_keys + rounds * 4
    var o0 = (
        (_sb(c0 >> 24) << 24) | (_sb((c1 >> 16) & 0xFF) << 16)
        | (_sb((c2 >> 8) & 0xFF) << 8) | _sb(c3 & 0xFF)
    ) ^ frk.load(0)
    var o1 = (
        (_sb(c1 >> 24) << 24) | (_sb((c2 >> 16) & 0xFF) << 16)
        | (_sb((c3 >> 8) & 0xFF) << 8) | _sb(c0 & 0xFF)
    ) ^ frk.load(1)
    var o2 = (
        (_sb(c2 >> 24) << 24) | (_sb((c3 >> 16) & 0xFF) << 16)
        | (_sb((c0 >> 8) & 0xFF) << 8) | _sb(c1 & 0xFF)
    ) ^ frk.load(2)
    var o3 = (
        (_sb(c3 >> 24) << 24) | (_sb((c0 >> 16) & 0xFF) << 16)
        | (_sb((c1 >> 8) & 0xFF) << 8) | _sb(c2 & 0xFF)
    ) ^ frk.load(3)

    pt_bytes.store(0, UInt8(o0 >> 24))
    pt_bytes.store(1, UInt8((o0 >> 16) & 0xFF))
    pt_bytes.store(2, UInt8((o0 >> 8) & 0xFF))
    pt_bytes.store(3, UInt8(o0 & 0xFF))
    pt_bytes.store(4, UInt8(o1 >> 24))
    pt_bytes.store(5, UInt8((o1 >> 16) & 0xFF))
    pt_bytes.store(6, UInt8((o1 >> 8) & 0xFF))
    pt_bytes.store(7, UInt8(o1 & 0xFF))
    pt_bytes.store(8, UInt8(o2 >> 24))
    pt_bytes.store(9, UInt8((o2 >> 16) & 0xFF))
    pt_bytes.store(10, UInt8((o2 >> 8) & 0xFF))
    pt_bytes.store(11, UInt8(o2 & 0xFF))
    pt_bytes.store(12, UInt8(o3 >> 24))
    pt_bytes.store(13, UInt8((o3 >> 16) & 0xFF))
    pt_bytes.store(14, UInt8((o3 >> 8) & 0xFF))
    pt_bytes.store(15, UInt8(o3 & 0xFF))

@always_inline
# Not Constant Time
def cpu_aes_encrypt(
    pt_bytes: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
) -> None:
    _cpu_aes_encrypt[10](pt_bytes, round_keys)

@always_inline
def cpu_aes_encrypt(
    pt_bytes: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
    rounds: Int,
) -> None:
    if rounds == 10:
        _cpu_aes_encrypt[10](pt_bytes, round_keys)
    elif rounds == 12:
        _cpu_aes_encrypt[12](pt_bytes, round_keys)
    else:
        _cpu_aes_encrypt[14](pt_bytes, round_keys)

@always_inline
def cpu_aes_ecb_kernel(
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
    num_blocks: Int,
    rounds: Int
) -> None:
    var i = 0
    while i < num_blocks:
        var block_ptr = input_ptr + i * 16
        var out_ptr = output_ptr + i * 16

        for j in range(16):
            out_ptr.store(j, block_ptr.load(j))

        if rounds == 10:
            _cpu_aes_encrypt[10](out_ptr, round_keys)
        elif rounds == 12:
            _cpu_aes_encrypt[12](out_ptr, round_keys)
        else:
            _cpu_aes_encrypt[14](out_ptr, round_keys)

        i += 1

@always_inline
def cpu_aes_cbc_kernel(
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
    num_blocks: Int,
    iv_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    rounds: Int
) -> None:
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

        if rounds == 10:
            _cpu_aes_encrypt[10](out_ptr, round_keys)
        elif rounds == 12:
            _cpu_aes_encrypt[12](out_ptr, round_keys)
        else:
            _cpu_aes_encrypt[14](out_ptr, round_keys)

        for j in range(16):
            prev_block[j] = out_ptr.load(j)

        i += 1

@always_inline
def cpu_aes_ctr_kernel(
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
    num_blocks: Int,
    nonce_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    rounds: Int
) -> None:
    var i = 0
    while i < num_blocks:
        var temp_block = StackBuffer[UInt8, 16]()
        var tp = temp_block.ptr()
        for j in range(16):
            tp.store(j, nonce_ptr[j])

        var carry = UInt64(i)
        for j in range(15, -1, -1):
            if carry == 0:
                break
            var total = UInt64(tp.load(j)) + (carry & 0xFF)
            tp.store(j, UInt8(total & 0xFF))
            carry = (carry >> 8) + (total >> 8)

        if rounds == 10:
            _cpu_aes_encrypt[10](tp, round_keys)
        elif rounds == 12:
            _cpu_aes_encrypt[12](tp, round_keys)
        else:
            _cpu_aes_encrypt[14](tp, round_keys)

        var in_block = input_ptr + i * 16
        var out_block = output_ptr + i * 16
        for j in range(16):
            out_block.store(j, in_block.load(j) ^ tp.load(j))
        i += 1

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
    var tweak = StackBuffer[UInt8, 16]()
    var wp = tweak.ptr()
    for j in range(16):
        wp.store(j, tweak_ptr[j])

    if rounds == 10:
        _cpu_aes_encrypt[10](wp, round_keys2)
    elif rounds == 12:
        _cpu_aes_encrypt[12](wp, round_keys2)
    else:
        _cpu_aes_encrypt[14](wp, round_keys2)

    var i = 0
    while i < num_blocks:
        var in_block = input_ptr + i * 16
        var out_block = output_ptr + i * 16

        var xored = StackBuffer[UInt8, 16]()
        var xp = xored.ptr()
        for j in range(16):
            xp.store(j, in_block.load(j) ^ wp.load(j))

        if rounds == 10:
            _cpu_aes_encrypt[10](xp, round_keys1)
        elif rounds == 12:
            _cpu_aes_encrypt[12](xp, round_keys1)
        else:
            _cpu_aes_encrypt[14](xp, round_keys1)

        for j in range(16):
            out_block.store(j, xp.load(j) ^ wp.load(j))

        cpu_xts_mul_alpha_inplace(wp)
        i += 1

@always_inline
def sub_word(w: UInt32) -> UInt32:
    var b0 = UInt32(sbox_lookup(UInt8((w >> 24) & 0xff)))
    var b1 = UInt32(sbox_lookup(UInt8((w >> 16) & 0xff)))
    var b2 = UInt32(sbox_lookup(UInt8((w >> 8) & 0xff)))
    var b3 = UInt32(sbox_lookup(UInt8(w & 0xff)))
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3

comptime SBOX: StaticTuple[UInt8, 256] = StaticTuple[UInt8, 256](
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
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
