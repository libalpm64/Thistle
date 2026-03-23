# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Libalpm64, Lostlab Technologies.

"""
ChaCha20 stream cipher implementation per RFC 7539
By Libalpm no attribution required
"""

from memory import bitcast, memcpy
from memory.unsafe_pointer import UnsafePointer, alloc
from builtin.type_aliases import MutExternalOrigin
from bit import rotate_bits_left

comptime CHACHA_CONSTANTS = SIMD[DType.uint32, 4](
    0x61707865, 0x3320646E, 0x79622D32, 0x6B206574,
)

@always_inline
fn simd_quarter_round(
    mut a: SIMD[DType.uint32, 4],
    mut b: SIMD[DType.uint32, 4],
    mut c: SIMD[DType.uint32, 4],
    mut d: SIMD[DType.uint32, 4],
) -> Tuple[SIMD[DType.uint32, 4], SIMD[DType.uint32, 4], SIMD[DType.uint32, 4], SIMD[DType.uint32, 4]]:
    """SIMD vectorized quarter round operating on 4 columns in parallel."""
    a = a + b
    d = d ^ a
    d = rotate_bits_left[shift=16](d)
    
    c = c + d
    b = b ^ c
    b = rotate_bits_left[shift=12](b)
    
    a = a + b
    d = d ^ a
    d = rotate_bits_left[shift=8](d)
    
    c = c + d
    b = b ^ c
    b = rotate_bits_left[shift=7](b)
    
    return Tuple(a, b, c, d)


@always_inline
fn shuffle_for_diagonal(
    row0: SIMD[DType.uint32, 4],
    row1: SIMD[DType.uint32, 4],
    row2: SIMD[DType.uint32, 4],
    row3: SIMD[DType.uint32, 4],
) -> Tuple[SIMD[DType.uint32, 4], SIMD[DType.uint32, 4], SIMD[DType.uint32, 4], SIMD[DType.uint32, 4]]:
    """Rotate rows to align diagonals for simd_quarter_round."""
    var a = row0
    var b = row1.rotate_left[1]()
    var c = row2.rotate_left[2]()
    var d = row3.rotate_left[3]()
    
    return Tuple(a, b, c, d)


@always_inline
fn unshuffle_from_diagonal(
    a: SIMD[DType.uint32, 4],
    b: SIMD[DType.uint32, 4],
    c: SIMD[DType.uint32, 4],
    d: SIMD[DType.uint32, 4],
) -> Tuple[SIMD[DType.uint32, 4], SIMD[DType.uint32, 4], SIMD[DType.uint32, 4], SIMD[DType.uint32, 4]]:
    """Reverse the diagonal shuffle to restore row layout."""
    var row0 = a
    var row1 = b.rotate_right[1]()
    var row2 = c.rotate_right[2]()
    var row3 = d.rotate_right[3]()

    return Tuple(row0, row1, row2, row3)


@always_inline
fn simd_double_round(
    mut row0: SIMD[DType.uint32, 4],
    mut row1: SIMD[DType.uint32, 4],
    mut row2: SIMD[DType.uint32, 4],
    mut row3: SIMD[DType.uint32, 4],
) -> Tuple[SIMD[DType.uint32, 4], SIMD[DType.uint32, 4], SIMD[DType.uint32, 4], SIMD[DType.uint32, 4]]:

    var qr = simd_quarter_round(row0, row1, row2, row3)
    row0 = qr[0]; row1 = qr[1]; row2 = qr[2]; row3 = qr[3]
    
    var shuffled = shuffle_for_diagonal(row0, row1, row2, row3)
    var diag_a = shuffled[0]; var diag_b = shuffled[1]
    var diag_c = shuffled[2]; var diag_d = shuffled[3]
    
    qr = simd_quarter_round(diag_a, diag_b, diag_c, diag_d)
    diag_a = qr[0]; diag_b = qr[1]; diag_c = qr[2]; diag_d = qr[3]
    
    return unshuffle_from_diagonal(diag_a, diag_b, diag_c, diag_d)

@always_inline
fn simd_quarter_round_8x(
    mut a: SIMD[DType.uint32, 8],
    mut b: SIMD[DType.uint32, 8],
    mut c: SIMD[DType.uint32, 8],
    mut d: SIMD[DType.uint32, 8],
) -> Tuple[SIMD[DType.uint32, 8], SIMD[DType.uint32, 8], SIMD[DType.uint32, 8], SIMD[DType.uint32, 8]]:
    """SIMD quarter round for 8-element vectors."""
    a = a + b
    d = d ^ a
    d = rotate_bits_left[shift=16](d)
    
    c = c + d
    b = b ^ c
    b = rotate_bits_left[shift=12](b)
    
    a = a + b
    d = d ^ a
    d = rotate_bits_left[shift=8](d)
    
    c = c + d
    b = b ^ c
    b = rotate_bits_left[shift=7](b)
    
    return Tuple(a, b, c, d)


@always_inline
fn simd_double_round_8x(
    mut row0: SIMD[DType.uint32, 8],
    mut row1: SIMD[DType.uint32, 8],
    mut row2: SIMD[DType.uint32, 8],
    mut row3: SIMD[DType.uint32, 8],
) -> Tuple[SIMD[DType.uint32, 8], SIMD[DType.uint32, 8], SIMD[DType.uint32, 8], SIMD[DType.uint32, 8]]:
    """One ChaCha20 double-round on 2 blocks in parallel using 256-bit SIMD."""
    var qr = simd_quarter_round_8x(row0, row1, row2, row3)
    row0 = qr[0]; row1 = qr[1]; row2 = qr[2]; row3 = qr[3]

    var b = row1.shuffle[1, 2, 3, 0, 5, 6, 7, 4]()
    var c = row2.shuffle[2, 3, 0, 1, 6, 7, 4, 5]()
    var d = row3.shuffle[3, 0, 1, 2, 7, 4, 5, 6]()

    qr = simd_quarter_round_8x(row0, b, c, d)
    var diag_a = qr[0]; var diag_b = qr[1]; var diag_c = qr[2]; var diag_d = qr[3]

    row1 = diag_b.shuffle[3, 0, 1, 2, 7, 4, 5, 6]()
    row2 = diag_c.shuffle[2, 3, 0, 1, 6, 7, 4, 5]()
    row3 = diag_d.shuffle[1, 2, 3, 0, 5, 6, 7, 4]()

    return Tuple(diag_a, row1, row2, row3)


@always_inline
fn chacha20_dual_block_core(
    key: SIMD[DType.uint32, 8],
    counter1: UInt32,
    counter2: UInt32,
    nonce: SIMD[DType.uint32, 3],
) -> Tuple[SIMD[DType.uint32, 16], SIMD[DType.uint32, 16]]:
    """Process 2 ChaCha20 blocks in parallel using 256-bit SIMD."""
    comptime CONST8 = SIMD[DType.uint32, 8](
        0x61707865, 0x3320646E, 0x79622D32, 0x6B206574,
        0x61707865, 0x3320646E, 0x79622D32, 0x6B206574,
    )

    var row0 = CONST8
    var row1 = SIMD[DType.uint32, 8](key[0], key[1], key[2], key[3], key[0], key[1], key[2], key[3])
    var row2 = SIMD[DType.uint32, 8](key[4], key[5], key[6], key[7], key[4], key[5], key[6], key[7])
    var row3 = SIMD[DType.uint32, 8](counter1, nonce[0], nonce[1], nonce[2], counter2, nonce[0], nonce[1], nonce[2])

    var init0 = row0
    var init1 = row1
    var init2 = row2
    var init3 = row3

    for _ in range(10):
        var dr = simd_double_round_8x(row0, row1, row2, row3)
        row0 = dr[0]; row1 = dr[1]; row2 = dr[2]; row3 = dr[3]

    row0 = row0 + init0
    row1 = row1 + init1
    row2 = row2 + init2
    row3 = row3 + init3

    var block1 = SIMD[DType.uint32, 16](
        row0[0], row0[1], row0[2], row0[3],
        row1[0], row1[1], row1[2], row1[3],
        row2[0], row2[1], row2[2], row2[3],
        row3[0], row3[1], row3[2], row3[3],
    )
    var block2 = SIMD[DType.uint32, 16](
        row0[4], row0[5], row0[6], row0[7],
        row1[4], row1[5], row1[6], row1[7],
        row2[4], row2[5], row2[6], row2[7],
        row3[4], row3[5], row3[6], row3[7],
    )

    return Tuple(block1, block2)


@always_inline
fn chacha20_block_core(
    key: SIMD[DType.uint32, 8],
    counter: UInt32,
    nonce: SIMD[DType.uint32, 3],
) -> SIMD[DType.uint32, 16]:
    """ChaCha20 block function. Processes 16-word state as 4 SIMD row vectors."""
    var row0 = CHACHA_CONSTANTS
    var row1 = SIMD[DType.uint32, 4](key[0], key[1], key[2], key[3])
    var row2 = SIMD[DType.uint32, 4](key[4], key[5], key[6], key[7])
    var row3 = SIMD[DType.uint32, 4](counter, nonce[0], nonce[1], nonce[2])

    var init0 = row0
    var init1 = row1
    var init2 = row2
    var init3 = row3

    for _ in range(10):
        var dr = simd_double_round(row0, row1, row2, row3)
        row0 = dr[0]; row1 = dr[1]; row2 = dr[2]; row3 = dr[3]

    row0 = row0 + init0
    row1 = row1 + init1
    row2 = row2 + init2
    row3 = row3 + init3

    return SIMD[DType.uint32, 16](
        row0[0], row0[1], row0[2], row0[3],
        row1[0], row1[1], row1[2], row1[3],
        row2[0], row2[1], row2[2], row2[3],
        row3[0], row3[1], row3[2], row3[3],
    )


fn chacha20_block(
    key: SIMD[DType.uint8, 32], counter: UInt32, nonce: SIMD[DType.uint8, 12]
) -> SIMD[DType.uint8, 64]:
    """ChaCha20 block function for compatibility."""
    var key_words = bitcast[DType.uint32, 8](key)
    var nonce_words = bitcast[DType.uint32, 3](nonce)
    var state = chacha20_block_core(key_words, counter, nonce_words)
    return bitcast[DType.uint8, 64](state)


@always_inline
fn xor_block_simd[
    origin: Origin[mut=True]
](
    mut data: Span[mut=True, UInt8, origin],
    keystream: SIMD[DType.uint32, 16],
    offset: Int,
):
    """XOR 64 bytes in-place with keystream using byte-level SIMD loads."""
    var d0 = SIMD[DType.uint32, 4](
        UInt32(data[offset + 3]) << 24 | UInt32(data[offset + 2]) << 16 | 
        UInt32(data[offset + 1]) << 8 | UInt32(data[offset + 0]),
        UInt32(data[offset + 7]) << 24 | UInt32(data[offset + 6]) << 16 | 
        UInt32(data[offset + 5]) << 8 | UInt32(data[offset + 4]),
        UInt32(data[offset + 11]) << 24 | UInt32(data[offset + 10]) << 16 | 
        UInt32(data[offset + 9]) << 8 | UInt32(data[offset + 8]),
        UInt32(data[offset + 15]) << 24 | UInt32(data[offset + 14]) << 16 | 
        UInt32(data[offset + 13]) << 8 | UInt32(data[offset + 12]),
    )
    
    var d1 = SIMD[DType.uint32, 4](
        UInt32(data[offset + 19]) << 24 | UInt32(data[offset + 18]) << 16 | 
        UInt32(data[offset + 17]) << 8 | UInt32(data[offset + 16]),
        UInt32(data[offset + 23]) << 24 | UInt32(data[offset + 22]) << 16 | 
        UInt32(data[offset + 21]) << 8 | UInt32(data[offset + 20]),
        UInt32(data[offset + 27]) << 24 | UInt32(data[offset + 26]) << 16 | 
        UInt32(data[offset + 25]) << 8 | UInt32(data[offset + 24]),
        UInt32(data[offset + 31]) << 24 | UInt32(data[offset + 30]) << 16 | 
        UInt32(data[offset + 29]) << 8 | UInt32(data[offset + 28]),
    )
    
    var d2 = SIMD[DType.uint32, 4](
        UInt32(data[offset + 35]) << 24 | UInt32(data[offset + 34]) << 16 | 
        UInt32(data[offset + 33]) << 8 | UInt32(data[offset + 32]),
        UInt32(data[offset + 39]) << 24 | UInt32(data[offset + 38]) << 16 | 
        UInt32(data[offset + 37]) << 8 | UInt32(data[offset + 36]),
        UInt32(data[offset + 43]) << 24 | UInt32(data[offset + 42]) << 16 | 
        UInt32(data[offset + 41]) << 8 | UInt32(data[offset + 40]),
        UInt32(data[offset + 47]) << 24 | UInt32(data[offset + 46]) << 16 | 
        UInt32(data[offset + 45]) << 8 | UInt32(data[offset + 44]),
    )
    
    var d3 = SIMD[DType.uint32, 4](
        UInt32(data[offset + 51]) << 24 | UInt32(data[offset + 50]) << 16 | 
        UInt32(data[offset + 49]) << 8 | UInt32(data[offset + 48]),
        UInt32(data[offset + 55]) << 24 | UInt32(data[offset + 54]) << 16 | 
        UInt32(data[offset + 53]) << 8 | UInt32(data[offset + 52]),
        UInt32(data[offset + 59]) << 24 | UInt32(data[offset + 58]) << 16 | 
        UInt32(data[offset + 57]) << 8 | UInt32(data[offset + 56]),
        UInt32(data[offset + 63]) << 24 | UInt32(data[offset + 62]) << 16 | 
        UInt32(data[offset + 61]) << 8 | UInt32(data[offset + 60]),
    )
    
    var k0 = SIMD[DType.uint32, 4](keystream[0], keystream[1], keystream[2], keystream[3])
    var k1 = SIMD[DType.uint32, 4](keystream[4], keystream[5], keystream[6], keystream[7])
    var k2 = SIMD[DType.uint32, 4](keystream[8], keystream[9], keystream[10], keystream[11])
    var k3 = SIMD[DType.uint32, 4](keystream[12], keystream[13], keystream[14], keystream[15])
    
    d0 = d0 ^ k0
    d1 = d1 ^ k1
    d2 = d2 ^ k2
    d3 = d3 ^ k3
    
    for i in range(4):
        var val = d0[i]
        data[offset + i * 4 + 0] = UInt8(val & 0xFF)
        data[offset + i * 4 + 1] = UInt8((val >> 8) & 0xFF)
        data[offset + i * 4 + 2] = UInt8((val >> 16) & 0xFF)
        data[offset + i * 4 + 3] = UInt8((val >> 24) & 0xFF)
    
    for i in range(4):
        var val = d1[i]
        data[offset + 16 + i * 4 + 0] = UInt8(val & 0xFF)
        data[offset + 16 + i * 4 + 1] = UInt8((val >> 8) & 0xFF)
        data[offset + 16 + i * 4 + 2] = UInt8((val >> 16) & 0xFF)
        data[offset + 16 + i * 4 + 3] = UInt8((val >> 24) & 0xFF)
    
    for i in range(4):
        var val = d2[i]
        data[offset + 32 + i * 4 + 0] = UInt8(val & 0xFF)
        data[offset + 32 + i * 4 + 1] = UInt8((val >> 8) & 0xFF)
        data[offset + 32 + i * 4 + 2] = UInt8((val >> 16) & 0xFF)
        data[offset + 32 + i * 4 + 3] = UInt8((val >> 24) & 0xFF)
    
    for i in range(4):
        var val = d3[i]
        data[offset + 48 + i * 4 + 0] = UInt8(val & 0xFF)
        data[offset + 48 + i * 4 + 1] = UInt8((val >> 8) & 0xFF)
        data[offset + 48 + i * 4 + 2] = UInt8((val >> 16) & 0xFF)
        data[offset + 48 + i * 4 + 3] = UInt8((val >> 24) & 0xFF)


@always_inline
fn xor_block(
    dst: UnsafePointer[UInt8, MutExternalOrigin],
    src: Span[UInt8, ...],
    keystream: SIMD[DType.uint32, 16],
    offset: Int,
):
    """XOR 64 bytes of src with keystream, store to dst using uint64 load/store."""
    var ks_u64 = bitcast[DType.uint64, 8](keystream)
    var src_ptr = src.unsafe_ptr()
    var src_u64 = src_ptr.bitcast[UInt64]()
    var dst_u64 = dst.bitcast[UInt64]()
    var base = offset // 8

    (dst_u64 + base + 0).store((src_u64 + base + 0).load[width=1]() ^ ks_u64[0])
    (dst_u64 + base + 1).store((src_u64 + base + 1).load[width=1]() ^ ks_u64[1])
    (dst_u64 + base + 2).store((src_u64 + base + 2).load[width=1]() ^ ks_u64[2])
    (dst_u64 + base + 3).store((src_u64 + base + 3).load[width=1]() ^ ks_u64[3])
    (dst_u64 + base + 4).store((src_u64 + base + 4).load[width=1]() ^ ks_u64[4])
    (dst_u64 + base + 5).store((src_u64 + base + 5).load[width=1]() ^ ks_u64[5])
    (dst_u64 + base + 6).store((src_u64 + base + 6).load[width=1]() ^ ks_u64[6])
    (dst_u64 + base + 7).store((src_u64 + base + 7).load[width=1]() ^ ks_u64[7])


@always_inline
fn xor_block_inplace[origin: Origin[mut=True]](
    data_ptr: UnsafePointer[UInt8, origin],
    keystream: SIMD[DType.uint32, 16],
    offset: Int,
):
    """XOR 64 bytes in-place with keystream using uint64 load/store."""
    var ks_u64 = bitcast[DType.uint64, 8](keystream)
    var data_u64 = data_ptr.bitcast[UInt64]()
    var base = offset // 8

    (data_u64 + base + 0).store((data_u64 + base + 0).load[width=1]() ^ ks_u64[0])
    (data_u64 + base + 1).store((data_u64 + base + 1).load[width=1]() ^ ks_u64[1])
    (data_u64 + base + 2).store((data_u64 + base + 2).load[width=1]() ^ ks_u64[2])
    (data_u64 + base + 3).store((data_u64 + base + 3).load[width=1]() ^ ks_u64[3])
    (data_u64 + base + 4).store((data_u64 + base + 4).load[width=1]() ^ ks_u64[4])
    (data_u64 + base + 5).store((data_u64 + base + 5).load[width=1]() ^ ks_u64[5])
    (data_u64 + base + 6).store((data_u64 + base + 6).load[width=1]() ^ ks_u64[6])
    (data_u64 + base + 7).store((data_u64 + base + 7).load[width=1]() ^ ks_u64[7])


struct ChaCha20:
    """ChaCha20 stream cipher per RFC 7539."""

    var key: SIMD[DType.uint32, 8]
    var nonce: SIMD[DType.uint32, 3]
    var counter: UInt32

    fn __init__(
        out self,
        key_bytes: SIMD[DType.uint8, 32],
        nonce_bytes: SIMD[DType.uint8, 12],
        counter: UInt32 = 1,
    ):
        self.key = bitcast[DType.uint32, 8](key_bytes)
        self.nonce = bitcast[DType.uint32, 3](nonce_bytes)
        self.counter = counter

    fn encrypt(
        mut self, plaintext: Span[UInt8, ...]
    ) -> UnsafePointer[UInt8, MutExternalOrigin]:
        var len_pt = len(plaintext)
        if len_pt == 0:
            var null_ptr: UnsafePointer[UInt8, MutExternalOrigin] = {}
            return null_ptr

        var ciphertext = alloc[UInt8](len_pt)
        var block_idx = 0
        var offset = 0

        while offset + 128 <= len_pt:
            var blocks = chacha20_dual_block_core(
                self.key,
                self.counter + UInt32(block_idx),
                self.counter + UInt32(block_idx + 1),
                self.nonce
            )
            xor_block(ciphertext, plaintext, blocks[0], offset)
            xor_block(ciphertext, plaintext, blocks[1], offset + 64)
            offset += 128
            block_idx += 2

        while offset + 64 <= len_pt:
            var keystream = chacha20_block_core(
                self.key, self.counter + UInt32(block_idx), self.nonce
            )
            xor_block(ciphertext, plaintext, keystream, offset)
            offset += 64
            block_idx += 1

        if offset < len_pt:
            var keystream = chacha20_block_core(
                self.key, self.counter + UInt32(block_idx), self.nonce
            )
            var ks_u8 = bitcast[DType.uint8, 64](keystream)
            var remaining = len_pt - offset

            for i in range(remaining):
                (ciphertext + offset + i).init_pointee_copy(
                    plaintext[offset + i] ^ ks_u8[i]
                )

        return ciphertext

    fn decrypt(
        mut self, ciphertext: Span[UInt8, ...]
    ) -> UnsafePointer[UInt8, MutExternalOrigin]:
        return self.encrypt(ciphertext)

    fn encrypt_inplace[origin: Origin[mut=True]](
        mut self, mut data: Span[mut=True, UInt8, origin]
    ):
        var len_data = len(data)
        var data_ptr = data.unsafe_ptr()
        var block_idx = 0
        var offset = 0

        while offset + 128 <= len_data:
            var blocks = chacha20_dual_block_core(
                self.key,
                self.counter + UInt32(block_idx),
                self.counter + UInt32(block_idx + 1),
                self.nonce
            )
            xor_block_inplace(data_ptr, blocks[0], offset)
            xor_block_inplace(data_ptr, blocks[1], offset + 64)
            offset += 128
            block_idx += 2

        # Process remaining single blocks
        while offset + 64 <= len_data:
            var keystream = chacha20_block_core(
                self.key, self.counter + UInt32(block_idx), self.nonce
            )
            xor_block_inplace(data_ptr, keystream, offset)
            offset += 64
            block_idx += 1

        if offset < len_data:
            var keystream = chacha20_block_core(
                self.key, self.counter + UInt32(block_idx), self.nonce
            )
            var ks_u8 = bitcast[DType.uint8, 64](keystream)
            var remaining = len_data - offset

            for i in range(remaining):
                data[offset + i] = data[offset + i] ^ ks_u8[i]
