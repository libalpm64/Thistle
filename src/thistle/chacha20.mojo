# ChaCha20 stream cipher per RFC 7539.

from std.memory import bitcast
from std.memory.unsafe_pointer import UnsafePointer
from std.bit import rotate_bits_left

comptime CHACHA_CONSTANTS = SIMD[DType.uint32, 4](
    0x61707865, 0x3320646E, 0x79622D32, 0x6B206574,
)


@always_inline
def _rotl[shift: Int, W: Int](x: SIMD[DType.uint32, W]) -> SIMD[DType.uint32, W]:
    comptime if shift == 16:
        var h = bitcast[DType.uint16, 2 * W](x)
        comptime if W == 4:
            return bitcast[DType.uint32, W](
                h.shuffle[1, 0, 3, 2, 5, 4, 7, 6]()
            )
        elif W == 16:
            return bitcast[DType.uint32, W](
                h.shuffle[
                    1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14,
                    17, 16, 19, 18, 21, 20, 23, 22, 25, 24, 27, 26, 29, 28,
                    31, 30,
                ]()
            )
        else:
            return rotate_bits_left[shift](x)
    elif shift == 8:
        var b = bitcast[DType.uint8, 4 * W](x)
        comptime if W == 4:
            return bitcast[DType.uint32, W](
                b.shuffle[3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14]()
            )
        elif W == 16:
            return bitcast[DType.uint32, W](
                b.shuffle[
                    3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14,
                    19, 16, 17, 18, 23, 20, 21, 22, 27, 24, 25, 26, 31, 28,
                    29, 30, 35, 32, 33, 34, 39, 36, 37, 38, 43, 40, 41, 42,
                    47, 44, 45, 46, 51, 48, 49, 50, 55, 52, 53, 54, 59, 56,
                    57, 58, 63, 60, 61, 62,
                ]()
            )
        else:
            return rotate_bits_left[shift](x)
    else:
        return rotate_bits_left[shift](x)

@always_inline
def simd_quarter_round(
    a: SIMD[DType.uint32, 4],
    b: SIMD[DType.uint32, 4],
    c: SIMD[DType.uint32, 4],
    d: SIMD[DType.uint32, 4],
) -> Tuple[SIMD[DType.uint32, 4], SIMD[DType.uint32, 4], SIMD[DType.uint32, 4], SIMD[DType.uint32, 4]]:
    
    var aa = a
    var bb = b
    var cc = c
    var dd = d

    aa = aa + bb
    dd = dd ^ aa
    dd = _rotl[16, dd.size](dd)

    cc = cc + dd
    bb = bb ^ cc
    bb = rotate_bits_left[shift=12](bb)

    aa = aa + bb
    dd = dd ^ aa
    dd = _rotl[8, dd.size](dd)

    cc = cc + dd
    bb = bb ^ cc
    bb = rotate_bits_left[shift=7](bb)

    return Tuple(aa, bb, cc, dd)


@always_inline
def shuffle_for_diagonal(
    row0: SIMD[DType.uint32, 4],
    row1: SIMD[DType.uint32, 4],
    row2: SIMD[DType.uint32, 4],
    row3: SIMD[DType.uint32, 4],
) -> Tuple[SIMD[DType.uint32, 4], SIMD[DType.uint32, 4], SIMD[DType.uint32, 4], SIMD[DType.uint32, 4]]:

    var a = row0
    var b = row1.rotate_left[1]()
    var c = row2.rotate_left[2]()
    var d = row3.rotate_left[3]()
    
    return Tuple(a, b, c, d)


@always_inline
def unshuffle_from_diagonal(
    a: SIMD[DType.uint32, 4],
    b: SIMD[DType.uint32, 4],
    c: SIMD[DType.uint32, 4],
    d: SIMD[DType.uint32, 4],
) -> Tuple[SIMD[DType.uint32, 4], SIMD[DType.uint32, 4], SIMD[DType.uint32, 4], SIMD[DType.uint32, 4]]:

    var row0 = a
    var row1 = b.rotate_right[1]()
    var row2 = c.rotate_right[2]()
    var row3 = d.rotate_right[3]()

    return Tuple(row0, row1, row2, row3)


@always_inline
def simd_double_round(
    row0: SIMD[DType.uint32, 4],
    row1: SIMD[DType.uint32, 4],
    row2: SIMD[DType.uint32, 4],
    row3: SIMD[DType.uint32, 4],
) -> Tuple[SIMD[DType.uint32, 4], SIMD[DType.uint32, 4], SIMD[DType.uint32, 4], SIMD[DType.uint32, 4]]:

    var rr0 = row0
    var rr1 = row1
    var rr2 = row2
    var rr3 = row3

    var qr = simd_quarter_round(rr0, rr1, rr2, rr3)
    rr0 = qr[0]; rr1 = qr[1]; rr2 = qr[2]; rr3 = qr[3]
    
    var shuffled = shuffle_for_diagonal(rr0, rr1, rr2, rr3)
    var diag_a = shuffled[0]; var diag_b = shuffled[1]
    var diag_c = shuffled[2]; var diag_d = shuffled[3]
    
    qr = simd_quarter_round(diag_a, diag_b, diag_c, diag_d)
    diag_a = qr[0]; diag_b = qr[1]; diag_c = qr[2]; diag_d = qr[3]
    
    return unshuffle_from_diagonal(diag_a, diag_b, diag_c, diag_d)

@always_inline
def _qr16(
    mut a: SIMD[DType.uint32, 16],
    mut b: SIMD[DType.uint32, 16],
    mut c: SIMD[DType.uint32, 16],
    mut d: SIMD[DType.uint32, 16],
):
    a = a + b
    d = _rotl[16, 16](d ^ a)
    c = c + d
    b = rotate_bits_left[shift=12](b ^ c)
    a = a + b
    d = _rotl[8, 16](d ^ a)
    c = c + d
    b = rotate_bits_left[shift=7](b ^ c)


@always_inline
def simd_double_round_16x(
    mut row0: SIMD[DType.uint32, 16],
    mut row1: SIMD[DType.uint32, 16],
    mut row2: SIMD[DType.uint32, 16],
    mut row3: SIMD[DType.uint32, 16],
):
    _qr16(row0, row1, row2, row3)

    row1 = row1.shuffle[
        1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12
    ]()
    row2 = row2.shuffle[
        2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13
    ]()
    row3 = row3.shuffle[
        3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14
    ]()

    _qr16(row0, row1, row2, row3)

    row1 = row1.shuffle[
        3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14
    ]()
    row2 = row2.shuffle[
        2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13
    ]()
    row3 = row3.shuffle[
        1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12
    ]()


@always_inline
def _quad_block(
    row0: SIMD[DType.uint32, 16],
    row1: SIMD[DType.uint32, 16],
    row2: SIMD[DType.uint32, 16],
    row3: SIMD[DType.uint32, 16],
    blk: Int,
) -> SIMD[DType.uint32, 16]:
    var out = SIMD[DType.uint32, 16]()
    if blk == 0:
        out = out.insert[offset=0](row0.slice[4, offset=0]())
        out = out.insert[offset=4](row1.slice[4, offset=0]())
        out = out.insert[offset=8](row2.slice[4, offset=0]())
        out = out.insert[offset=12](row3.slice[4, offset=0]())
    elif blk == 1:
        out = out.insert[offset=0](row0.slice[4, offset=4]())
        out = out.insert[offset=4](row1.slice[4, offset=4]())
        out = out.insert[offset=8](row2.slice[4, offset=4]())
        out = out.insert[offset=12](row3.slice[4, offset=4]())
    elif blk == 2:
        out = out.insert[offset=0](row0.slice[4, offset=8]())
        out = out.insert[offset=4](row1.slice[4, offset=8]())
        out = out.insert[offset=8](row2.slice[4, offset=8]())
        out = out.insert[offset=12](row3.slice[4, offset=8]())
    else:
        out = out.insert[offset=0](row0.slice[4, offset=12]())
        out = out.insert[offset=4](row1.slice[4, offset=12]())
        out = out.insert[offset=8](row2.slice[4, offset=12]())
        out = out.insert[offset=12](row3.slice[4, offset=12]())
    return out


comptime _CTR_INC4 = SIMD[DType.uint32, 16](
    4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0
)


@always_inline
def _quad_rows_init(
    key: SIMD[DType.uint32, 8],
    counter: UInt32,
    nonce: SIMD[DType.uint32, 3],
) -> Tuple[
    SIMD[DType.uint32, 16],
    SIMD[DType.uint32, 16],
    SIMD[DType.uint32, 16],
    SIMD[DType.uint32, 16],
]:
    comptime CONST16 = SIMD[DType.uint32, 16](
        0x61707865, 0x3320646E, 0x79622D32, 0x6B206574,
        0x61707865, 0x3320646E, 0x79622D32, 0x6B206574,
        0x61707865, 0x3320646E, 0x79622D32, 0x6B206574,
        0x61707865, 0x3320646E, 0x79622D32, 0x6B206574,
    )
    var row1 = SIMD[DType.uint32, 16](
        key[0], key[1], key[2], key[3], key[0], key[1], key[2], key[3],
        key[0], key[1], key[2], key[3], key[0], key[1], key[2], key[3],
    )
    var row2 = SIMD[DType.uint32, 16](
        key[4], key[5], key[6], key[7], key[4], key[5], key[6], key[7],
        key[4], key[5], key[6], key[7], key[4], key[5], key[6], key[7],
    )
    var row3 = SIMD[DType.uint32, 16](
        counter, nonce[0], nonce[1], nonce[2],
        counter + 1, nonce[0], nonce[1], nonce[2],
        counter + 2, nonce[0], nonce[1], nonce[2],
        counter + 3, nonce[0], nonce[1], nonce[2],
    )
    return Tuple(CONST16, row1, row2, row3)


@always_inline
def _diag16[back: Bool](
    mut r1: SIMD[DType.uint32, 16],
    mut r2: SIMD[DType.uint32, 16],
    mut r3: SIMD[DType.uint32, 16],
):
    comptime if back:
        r1 = r1.shuffle[3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14]()
        r3 = r3.shuffle[1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12]()
    else:
        r1 = r1.shuffle[1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12]()
        r3 = r3.shuffle[3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14]()
    r2 = r2.shuffle[2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13]()


@always_inline
def chacha20_x12_core_rows(
    init0: SIMD[DType.uint32, 16],
    init1: SIMD[DType.uint32, 16],
    init2: SIMD[DType.uint32, 16],
    init3a: SIMD[DType.uint32, 16],
    init3b: SIMD[DType.uint32, 16],
    init3c: SIMD[DType.uint32, 16],
) -> Tuple[
    SIMD[DType.uint32, 16], SIMD[DType.uint32, 16], SIMD[DType.uint32, 16],
    SIMD[DType.uint32, 16], SIMD[DType.uint32, 16], SIMD[DType.uint32, 16],
    SIMD[DType.uint32, 16], SIMD[DType.uint32, 16], SIMD[DType.uint32, 16],
    SIMD[DType.uint32, 16], SIMD[DType.uint32, 16], SIMD[DType.uint32, 16],
]:
    var a0 = init0
    var a1 = init1
    var a2 = init2
    var a3 = init3a
    var b0 = init0
    var b1 = init1
    var b2 = init2
    var b3 = init3b
    var c0 = init0
    var c1 = init1
    var c2 = init2
    var c3 = init3c

    comptime for _ in range(10):
        _qr16(a0, a1, a2, a3)
        _qr16(b0, b1, b2, b3)
        _qr16(c0, c1, c2, c3)
        _diag16[False](a1, a2, a3)
        _diag16[False](b1, b2, b3)
        _diag16[False](c1, c2, c3)
        _qr16(a0, a1, a2, a3)
        _qr16(b0, b1, b2, b3)
        _qr16(c0, c1, c2, c3)
        _diag16[True](a1, a2, a3)
        _diag16[True](b1, b2, b3)
        _diag16[True](c1, c2, c3)

    a0 = a0 + init0
    a1 = a1 + init1
    a2 = a2 + init2
    a3 = a3 + init3a
    b0 = b0 + init0
    b1 = b1 + init1
    b2 = b2 + init2
    b3 = b3 + init3b
    c0 = c0 + init0
    c1 = c1 + init1
    c2 = c2 + init2
    c3 = c3 + init3c

    return Tuple(
        _quad_block(a0, a1, a2, a3, 0),
        _quad_block(a0, a1, a2, a3, 1),
        _quad_block(a0, a1, a2, a3, 2),
        _quad_block(a0, a1, a2, a3, 3),
        _quad_block(b0, b1, b2, b3, 0),
        _quad_block(b0, b1, b2, b3, 1),
        _quad_block(b0, b1, b2, b3, 2),
        _quad_block(b0, b1, b2, b3, 3),
        _quad_block(c0, c1, c2, c3, 0),
        _quad_block(c0, c1, c2, c3, 1),
        _quad_block(c0, c1, c2, c3, 2),
        _quad_block(c0, c1, c2, c3, 3),
    )


@always_inline
def chacha20_octo_core_rows(
    init0: SIMD[DType.uint32, 16],
    init1: SIMD[DType.uint32, 16],
    init2: SIMD[DType.uint32, 16],
    init3a: SIMD[DType.uint32, 16],
    init3b: SIMD[DType.uint32, 16],
) -> Tuple[
    SIMD[DType.uint32, 16],
    SIMD[DType.uint32, 16],
    SIMD[DType.uint32, 16],
    SIMD[DType.uint32, 16],
    SIMD[DType.uint32, 16],
    SIMD[DType.uint32, 16],
    SIMD[DType.uint32, 16],
    SIMD[DType.uint32, 16],
]:
    var a0 = init0
    var a1 = init1
    var a2 = init2
    var a3 = init3a
    var b0 = init0
    var b1 = init1
    var b2 = init2
    var b3 = init3b

    comptime for _ in range(10):
        _qr16(a0, a1, a2, a3)
        _qr16(b0, b1, b2, b3)
        a1 = a1.shuffle[1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12]()
        a2 = a2.shuffle[2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13]()
        a3 = a3.shuffle[3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14]()
        b1 = b1.shuffle[1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12]()
        b2 = b2.shuffle[2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13]()
        b3 = b3.shuffle[3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14]()
        _qr16(a0, a1, a2, a3)
        _qr16(b0, b1, b2, b3)
        a1 = a1.shuffle[3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14]()
        a2 = a2.shuffle[2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13]()
        a3 = a3.shuffle[1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12]()
        b1 = b1.shuffle[3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14]()
        b2 = b2.shuffle[2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13]()
        b3 = b3.shuffle[1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12]()

    a0 = a0 + init0
    a1 = a1 + init1
    a2 = a2 + init2
    a3 = a3 + init3a
    b0 = b0 + init0
    b1 = b1 + init1
    b2 = b2 + init2
    b3 = b3 + init3b

    return Tuple(
        _quad_block(a0, a1, a2, a3, 0),
        _quad_block(a0, a1, a2, a3, 1),
        _quad_block(a0, a1, a2, a3, 2),
        _quad_block(a0, a1, a2, a3, 3),
        _quad_block(b0, b1, b2, b3, 0),
        _quad_block(b0, b1, b2, b3, 1),
        _quad_block(b0, b1, b2, b3, 2),
        _quad_block(b0, b1, b2, b3, 3),
    )


@always_inline
def chacha20_quad_core_rows(
    init0: SIMD[DType.uint32, 16],
    init1: SIMD[DType.uint32, 16],
    init2: SIMD[DType.uint32, 16],
    init3: SIMD[DType.uint32, 16],
) -> Tuple[
    SIMD[DType.uint32, 16],
    SIMD[DType.uint32, 16],
    SIMD[DType.uint32, 16],
    SIMD[DType.uint32, 16],
]:
    var row0 = init0
    var row1 = init1
    var row2 = init2
    var row3 = init3

    comptime for _ in range(10):
        simd_double_round_16x(row0, row1, row2, row3)

    row0 = row0 + init0
    row1 = row1 + init1
    row2 = row2 + init2
    row3 = row3 + init3

    return Tuple(
        _quad_block(row0, row1, row2, row3, 0),
        _quad_block(row0, row1, row2, row3, 1),
        _quad_block(row0, row1, row2, row3, 2),
        _quad_block(row0, row1, row2, row3, 3),
    )


@always_inline
def _qr_scalar(mut a: UInt32, mut b: UInt32, mut c: UInt32, mut d: UInt32):
    a += b
    d = rotate_bits_left[16](d ^ a)
    c += d
    b = rotate_bits_left[12](b ^ c)
    a += b
    d = rotate_bits_left[8](d ^ a)
    c += d
    b = rotate_bits_left[7](b ^ c)


@always_inline
def chacha20_block_core(
    key: SIMD[DType.uint32, 8],
    counter: UInt32,
    nonce: SIMD[DType.uint32, 3],
) -> SIMD[DType.uint32, 16]:

    var row0 = CHACHA_CONSTANTS
    var row1 = SIMD[DType.uint32, 4](key[0], key[1], key[2], key[3])
    var row2 = SIMD[DType.uint32, 4](key[4], key[5], key[6], key[7])
    var row3 = SIMD[DType.uint32, 4](counter, nonce[0], nonce[1], nonce[2])

    var init0 = row0
    var init1 = row1
    var init2 = row2
    var init3 = row3

    comptime for _ in range(10):
        var dr = simd_double_round(row0, row1, row2, row3)
        row0 = dr[0]; row1 = dr[1]; row2 = dr[2]; row3 = dr[3]

    row0 = row0 + init0
    row1 = row1 + init1
    row2 = row2 + init2
    row3 = row3 + init3

    var result = SIMD[DType.uint32, 16]()
    result = result.insert[offset=0](row0)
    result = result.insert[offset=4](row1)
    result = result.insert[offset=8](row2)
    result = result.insert[offset=12](row3)
    return result


@always_inline
def _chacha20_block_scalar(
    key: SIMD[DType.uint32, 8],
    counter: UInt32,
    nonce: SIMD[DType.uint32, 3],
) -> SIMD[DType.uint32, 16]:
    var x0: UInt32 = 0x61707865
    var x1: UInt32 = 0x3320646E
    var x2: UInt32 = 0x79622D32
    var x3: UInt32 = 0x6B206574
    var x4 = key[0]
    var x5 = key[1]
    var x6 = key[2]
    var x7 = key[3]
    var x8 = key[4]
    var x9 = key[5]
    var x10 = key[6]
    var x11 = key[7]
    var x12 = counter
    var x13 = nonce[0]
    var x14 = nonce[1]
    var x15 = nonce[2]

    comptime for _ in range(10):
        _qr_scalar(x0, x4, x8, x12)
        _qr_scalar(x1, x5, x9, x13)
        _qr_scalar(x2, x6, x10, x14)
        _qr_scalar(x3, x7, x11, x15)
        _qr_scalar(x0, x5, x10, x15)
        _qr_scalar(x1, x6, x11, x12)
        _qr_scalar(x2, x7, x8, x13)
        _qr_scalar(x3, x4, x9, x14)

    var result = SIMD[DType.uint32, 16](
        x0 + 0x61707865, x1 + 0x3320646E, x2 + 0x79622D32, x3 + 0x6B206574,
        x4 + key[0], x5 + key[1], x6 + key[2], x7 + key[3],
        x8 + key[4], x9 + key[5], x10 + key[6], x11 + key[7],
        x12 + counter, x13 + nonce[0], x14 + nonce[1], x15 + nonce[2],
    )
    return result


def chacha20_block(
    key: SIMD[DType.uint8, 32], counter: UInt32, nonce: SIMD[DType.uint8, 12]
) -> SIMD[DType.uint8, 64]:

    var key_words = bitcast[DType.uint32, 8](key)
    var nonce_words = bitcast[DType.uint32, 3](nonce)
    var state = chacha20_block_core(key_words, counter, nonce_words)
    return bitcast[DType.uint8, 64](state)


@always_inline
def _xor_block64(
    src: UnsafePointer[UInt8, MutAnyOrigin],
    dst: UnsafePointer[UInt8, MutAnyOrigin],
    keystream: SIMD[DType.uint32, 16],
    offset: Int,
):
    var ks = bitcast[DType.uint8, 64](keystream)
    var v = (src + offset).load[width=64, alignment=1](0)
    (dst + offset).store[alignment=1](0, v ^ ks)


struct ChaCha20:
    var key: SIMD[DType.uint32, 8]
    var nonce: SIMD[DType.uint32, 3]
    var counter: UInt32

    def __init__(
        out self,
        key_bytes: SIMD[DType.uint8, 32],
        nonce_bytes: SIMD[DType.uint8, 12],
        counter: UInt32 = 1,
    ):
        self.key = bitcast[DType.uint32, 8](key_bytes)
        self.nonce = bitcast[DType.uint32, 3](nonce_bytes)
        self.counter = counter

    def _check_counter_space(self, data_len: Int) raises:
        var blocks_needed = UInt64((data_len + 63) // 64)
        var space = UInt64(0x100000000) - UInt64(self.counter)
        if blocks_needed >= space:
            raise Error("ChaCha20 counter would wrap, use a new nonce")

    @always_inline
    def _stream_xor(
        mut self,
        src: UnsafePointer[UInt8, MutAnyOrigin],
        dst: UnsafePointer[UInt8, MutAnyOrigin],
        length: Int,
    ) raises:
        self._check_counter_space(length)
        var block_idx = 0
        var offset = 0

        if 256 <= length:
            var rows = _quad_rows_init(self.key, self.counter, self.nonce)
            var i3 = rows[3]
            while offset + 768 <= length:
                var o = chacha20_x12_core_rows(
                    rows[0], rows[1], rows[2], i3,
                    i3 + _CTR_INC4, i3 + _CTR_INC4 + _CTR_INC4,
                )
                comptime for j in range(12):
                    _xor_block64(src, dst, o[j], offset + j * 64)
                i3 = i3 + _CTR_INC4 + _CTR_INC4 + _CTR_INC4
                offset += 768
                block_idx += 12
            while offset + 512 <= length:
                var o = chacha20_octo_core_rows(
                    rows[0], rows[1], rows[2], i3, i3 + _CTR_INC4
                )
                comptime for j in range(8):
                    _xor_block64(src, dst, o[j], offset + j * 64)
                i3 = i3 + _CTR_INC4 + _CTR_INC4
                offset += 512
                block_idx += 8
            while offset + 256 <= length:
                var q = chacha20_quad_core_rows(rows[0], rows[1], rows[2], i3)
                comptime for j in range(4):
                    _xor_block64(src, dst, q[j], offset + j * 64)
                i3 = i3 + _CTR_INC4
                offset += 256
                block_idx += 4

        while offset + 64 <= length:
            var keystream = chacha20_block_core(
                self.key, self.counter + UInt32(block_idx), self.nonce
            )
            _xor_block64(src, dst, keystream, offset)
            offset += 64
            block_idx += 1

        if offset < length:
            var keystream = _chacha20_block_scalar(
                self.key, self.counter + UInt32(block_idx), self.nonce
            )
            var ks_u8 = bitcast[DType.uint8, 64](keystream)
            for i in range(length - offset):
                (dst + offset + i).store(0, (src + offset + i).load(0) ^ ks_u8[i])
            block_idx += 1

        self.counter += UInt32(block_idx)

    def encrypt_into[origin: Origin[mut=True]](
        mut self,
        plaintext: Span[UInt8, ...],
        mut ciphertext: Span[mut=True, UInt8, origin],
    ) raises:
        if len(ciphertext) < len(plaintext):
            raise Error("ChaCha20 ciphertext buffer too small")
        self._stream_xor(
            plaintext.unsafe_ptr().unsafe_mut_cast[True]().unsafe_origin_cast[MutAnyOrigin](),
            ciphertext.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin](),
            len(plaintext),
        )

    def decrypt_into[origin: Origin[mut=True]](
        mut self,
        ciphertext: Span[UInt8, ...],
        mut plaintext: Span[mut=True, UInt8, origin],
    ) raises:
        self.encrypt_into(ciphertext, plaintext)

    def encrypt_inplace[origin: Origin[mut=True]](
        mut self, mut data: Span[mut=True, UInt8, origin]
    ) raises:
        var p = data.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin]()
        self._stream_xor(p, p, len(data))
