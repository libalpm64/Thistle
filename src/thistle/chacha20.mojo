# SPDX-License-Identifier: MIT
#
# Copyright (c) 2026 Libalpm64, Lostlab Technologies.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

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
    """SIMD vectorized quarter round operating on 4 columns in parallel.
    
    ChaCha20 quarter round: a += b; d ^= a; d <<<= 16; c += d; b ^= c; b <<<= 12;
                            a += b; d ^= a; d <<<= 8; c += d; b ^= c; b <<<= 7
    """
    # a += b; d ^= a; d <<<= 16
    a = a + b
    d = d ^ a
    d = rotate_bits_left[shift=16](d)
    
    # c += d; b ^= c; b <<<= 12
    c = c + d
    b = b ^ c
    b = rotate_bits_left[shift=12](b)
    
    # a += b; d ^= a; d <<<= 8
    a = a + b
    d = d ^ a
    d = rotate_bits_left[shift=8](d)
    
    # c += d; b ^= c; b <<<= 7
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
    """Shuffle row vectors for diagonal round processing using SIMD rotate.
    
    Input row vectors:
      row0 = [s0, s1, s2, s3]
      row1 = [s4, s5, s6, s7]
      row2 = [s8, s9, s10, s11]
      row3 = [s12, s13, s14, s15]
    
    Diagonal rounds operate on:
      QR(0,5,10,15): s0, s5, s10, s15 = row0[0], row1[1], row2[2], row3[3]
      QR(1,6,11,12): s1, s6, s11, s12 = row0[1], row1[2], row2[3], row3[0]
      QR(2,7,8,13):  s2, s7, s8, s13  = row0[2], row1[3], row2[0], row3[1]
      QR(3,4,9,14):  s3, s4, s9, s14  = row0[3], row1[0], row2[1], row3[2]
    
    For simd_quarter_round to process these, we need:
      a = [s0, s1, s2, s3] = row0 (no changes)
      b = [s5, s6, s7, s4] = row1.rotate_left[1]()
      c = [s10, s11, s8, s9] = row2.rotate_left[2]()
      d = [s15, s12, s13, s14] = row3.rotate_left[3]()
    """
    var a = row0  # No change needed
    var b = row1.rotate_left[1]()  # SIMD element rotate left by 1
    var c = row2.rotate_left[2]()  # SIMD element rotate left by 2
    var d = row3.rotate_left[3]()  # SIMD element rotate left by 3
    
    return Tuple(a, b, c, d)


@always_inline
fn unshuffle_from_diagonal(
    a: SIMD[DType.uint32, 4],
    b: SIMD[DType.uint32, 4],
    c: SIMD[DType.uint32, 4],
    d: SIMD[DType.uint32, 4],
) -> Tuple[SIMD[DType.uint32, 4], SIMD[DType.uint32, 4], SIMD[DType.uint32, 4], SIMD[DType.uint32, 4]]:
    """Reverse the diagonal shuffle to restore row layout using SIMD rotate.
    
    After diagonal processing:
      a = [s0', s1', s2', s3'] (was row0, unchanged)
      b = [s5', s6', s7', s4'] (was row1 rotated left by 1)
      c = [s10', s11', s8', s9'] (was row2 rotated left by 2)
      d = [s15', s12', s13', s14'] (was row3 rotated left by 3)
    
    Need to restore:
      row0 = [s0', s1', s2', s3'] = a (unchanged)
      row1 = [s4', s5', s6', s7'] = b.rotate_right[1]()
      row2 = [s8', s9', s10', s11'] = c.rotate_right[2]()
      row3 = [s12', s13', s14', s15'] = d.rotate_right[3]()
    """
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
    # a += b; d ^= a; d <<<= 16
    a = a + b
    d = d ^ a
    d = rotate_bits_left[shift=16](d)
    
    # c += d; b ^= c; b <<<= 12
    c = c + d
    b = b ^ c
    b = rotate_bits_left[shift=12](b)
    
    # a += b; d ^= a; d <<<= 8
    a = a + b
    d = d ^ a
    d = rotate_bits_left[shift=8](d)
    
    # c += d; b ^= c; b <<<= 7
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
    # Column rounds
    var qr = simd_quarter_round_8x(row0, row1, row2, row3)
    row0 = qr[0]; row1 = qr[1]; row2 = qr[2]; row3 = qr[3]
    
    # Shuffle for diagonal: rotate within each 4-element half
    var b = row1.shuffle[1, 2, 3, 0, 5, 6, 7, 4]()
    var c = row2.shuffle[2, 3, 0, 1, 6, 7, 4, 5]()
    var d = row3.shuffle[3, 0, 1, 2, 7, 4, 5, 6]()
    
    # Diagonal rounds
    qr = simd_quarter_round_8x(row0, b, c, d)
    var diag_a = qr[0]; var diag_b = qr[1]; var diag_c = qr[2]; var diag_d = qr[3]
    
    # Unshuffle: rotate right within each 4-element half
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
    """Process 2 ChaCha20 blocks in parallel
	Returns two 16-word state blocks.
    """
    # Constants replicated for 8-element vectors
    comptime CONST8 = SIMD[DType.uint32, 8](
        0x61707865, 0x3320646E, 0x79622D32, 0x6B206574,
        0x61707865, 0x3320646E, 0x79622D32, 0x6B206574,
    )
    
    # Initialize state for 2 blocks interleaved
    # row0 = [c0, c1, c2, c3, c0, c1, c2, c3] (constants)
    # row1 = [k0, k1, k2, k3, k0, k1, k2, k3] (key first half)
    # row2 = [k4, k5, k6, k7, k4, k5, k6, k7] (key second half)
    # row3 = [ctr1, n0, n1, n2, ctr2, n0, n1, n2] (counter + nonce)
    var row0 = CONST8
    var row1 = SIMD[DType.uint32, 8](key[0], key[1], key[2], key[3], key[0], key[1], key[2], key[3])
    var row2 = SIMD[DType.uint32, 8](key[4], key[5], key[6], key[7], key[4], key[5], key[6], key[7])
    var row3 = SIMD[DType.uint32, 8](counter1, nonce[0], nonce[1], nonce[2], counter2, nonce[0], nonce[1], nonce[2])
    
    # Store initial state
    var init0 = row0
    var init1 = row1
    var init2 = row2
    var init3 = row3
    
    # 10 double-rounds
    var dr = simd_double_round_8x(row0, row1, row2, row3)
    row0 = dr[0]; row1 = dr[1]; row2 = dr[2]; row3 = dr[3]
    
    dr = simd_double_round_8x(row0, row1, row2, row3)
    row0 = dr[0]; row1 = dr[1]; row2 = dr[2]; row3 = dr[3]
    
    dr = simd_double_round_8x(row0, row1, row2, row3)
    row0 = dr[0]; row1 = dr[1]; row2 = dr[2]; row3 = dr[3]
    
    dr = simd_double_round_8x(row0, row1, row2, row3)
    row0 = dr[0]; row1 = dr[1]; row2 = dr[2]; row3 = dr[3]
    
    dr = simd_double_round_8x(row0, row1, row2, row3)
    row0 = dr[0]; row1 = dr[1]; row2 = dr[2]; row3 = dr[3]
    
    dr = simd_double_round_8x(row0, row1, row2, row3)
    row0 = dr[0]; row1 = dr[1]; row2 = dr[2]; row3 = dr[3]
    
    dr = simd_double_round_8x(row0, row1, row2, row3)
    row0 = dr[0]; row1 = dr[1]; row2 = dr[2]; row3 = dr[3]
    
    dr = simd_double_round_8x(row0, row1, row2, row3)
    row0 = dr[0]; row1 = dr[1]; row2 = dr[2]; row3 = dr[3]
    
    dr = simd_double_round_8x(row0, row1, row2, row3)
    row0 = dr[0]; row1 = dr[1]; row2 = dr[2]; row3 = dr[3]
    
    dr = simd_double_round_8x(row0, row1, row2, row3)
    row0 = dr[0]; row1 = dr[1]; row2 = dr[2]; row3 = dr[3]
    
    # initial states
    row0 = row0 + init0
    row1 = row1 + init1
    row2 = row2 + init2
    row3 = row3 + init3
    
    # Extract block 1 and block 2
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
    """Core ChaCha20 block function using SIMD vectorization.
    
    Organizes the 16-word state into 4 SIMD vectors for parallel processing.
    State layout per RFC 7539:
       0   1   2   3
       4   5   6   7
       8   9  10  11
      12  13  14  15
    
    For SIMD processing, we use row vectors:
      row0 = [s0, s1, s2, s3]
      row1 = [s4, s5, s6, s7]
      row2 = [s8, s9, s10, s11]
      row3 = [s12, s13, s14, s15]
    
    This allows simd_quarter_round(row0, row1, row2, row3) to process:
      - row0[0], row1[0], row2[0], row3[0] = s0, s4, s8, s12 (column 0)
      - row0[1], row1[1], row2[1], row3[1] = s1, s5, s9, s13 (column 1)
      - etc.
    
    """
    # Initialize state vectors
    var row0 = CHACHA_CONSTANTS
    var row1 = SIMD[DType.uint32, 4](key[0], key[1], key[2], key[3])  # s4-s7: key first half
    var row2 = SIMD[DType.uint32, 4](key[4], key[5], key[6], key[7])  # s8-s11: key second half
    var row3 = SIMD[DType.uint32, 4](counter, nonce[0], nonce[1], nonce[2])  # s12-s15: counter + nonce
    
    # Store initial state for final addition
    var init0 = row0
    var init1 = row1
    var init2 = row2
    var init3 = row3
    
	# Double round
    var dr = simd_double_round(row0, row1, row2, row3)
    row0 = dr[0]; row1 = dr[1]; row2 = dr[2]; row3 = dr[3]
    
    dr = simd_double_round(row0, row1, row2, row3)
    row0 = dr[0]; row1 = dr[1]; row2 = dr[2]; row3 = dr[3]
    
    dr = simd_double_round(row0, row1, row2, row3)
    row0 = dr[0]; row1 = dr[1]; row2 = dr[2]; row3 = dr[3]
    
    dr = simd_double_round(row0, row1, row2, row3)
    row0 = dr[0]; row1 = dr[1]; row2 = dr[2]; row3 = dr[3]
    
    dr = simd_double_round(row0, row1, row2, row3)
    row0 = dr[0]; row1 = dr[1]; row2 = dr[2]; row3 = dr[3]
    
    dr = simd_double_round(row0, row1, row2, row3)
    row0 = dr[0]; row1 = dr[1]; row2 = dr[2]; row3 = dr[3]
    
    dr = simd_double_round(row0, row1, row2, row3)
    row0 = dr[0]; row1 = dr[1]; row2 = dr[2]; row3 = dr[3]
    
    dr = simd_double_round(row0, row1, row2, row3)
    row0 = dr[0]; row1 = dr[1]; row2 = dr[2]; row3 = dr[3]
    
    dr = simd_double_round(row0, row1, row2, row3)
    row0 = dr[0]; row1 = dr[1]; row2 = dr[2]; row3 = dr[3]
    
    dr = simd_double_round(row0, row1, row2, row3)
    row0 = dr[0]; row1 = dr[1]; row2 = dr[2]; row3 = dr[3]
    
    # Add initial state
    row0 = row0 + init0
    row1 = row1 + init1
    row2 = row2 + init2
    row3 = row3 + init3
    
    # Output in row-major order
    # row0 = [s0, s1, s2, s3], row1 = [s4, s5, s6, s7], etc.
    return SIMD[DType.uint32, 16](
        row0[0], row0[1], row0[2], row0[3],  # s0, s1, s2, s3
        row1[0], row1[1], row1[2], row1[3],  # s4, s5, s6, s7
        row2[0], row2[1], row2[2], row2[3],  # s8, s9, s10, s11
        row3[0], row3[1], row3[2], row3[3],  # s12, s13, s14, s15
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
    """XOR 64 bytes in-place with keystream"""
    # Load 64 bytes as 16 uint32 values using bitcast
    # We need to load from the span data
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
    
    # Extract keystream chunks
    var k0 = SIMD[DType.uint32, 4](keystream[0], keystream[1], keystream[2], keystream[3])
    var k1 = SIMD[DType.uint32, 4](keystream[4], keystream[5], keystream[6], keystream[7])
    var k2 = SIMD[DType.uint32, 4](keystream[8], keystream[9], keystream[10], keystream[11])
    var k3 = SIMD[DType.uint32, 4](keystream[12], keystream[13], keystream[14], keystream[15])
    
    # XOR with keystream
    d0 = d0 ^ k0
    d1 = d1 ^ k1
    d2 = d2 ^ k2
    d3 = d3 ^ k3
    
    # Store results back (little-endian)
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
    src: Span[UInt8],
    keystream: SIMD[DType.uint32, 16],
    offset: Int,
):
    """XOR 64 bytes of plaintext with keystream using direct SIMD load/store."""
    # Cast keystream to 64-bit chunks for efficient XOR
    var ks_u64 = bitcast[DType.uint64, 8](keystream)
    
    # Get unsafe pointer to source data and bitcast to uint64 pointer
    var src_ptr = src.unsafe_ptr()
    var src_u64 = src_ptr.bitcast[UInt64]()
    
    # Bitcast destination to uint64 pointer for direct SIMD store
    var dst_u64 = dst.bitcast[UInt64]()
    
    # Calculate base offset in uint64 elements
    var base = offset // 8
    
    # 8 load-XOR-store operations
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
    """XOR 64 bytes in-place with keystream using direct SIMD load/store."""
    # Cast keystream to 64-bit chunks
    var ks_u64 = bitcast[DType.uint64, 8](keystream)
    
    # Bitcast to uint64 pointer
    var data_u64 = data_ptr.bitcast[UInt64]()
    
    # Calculate base offset in uint64 elements
    var base = offset // 8
    
    # load-XOR-store operations
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
        mut self, plaintext: Span[UInt8]
    ) -> UnsafePointer[UInt8, MutExternalOrigin]:
        var len_pt = len(plaintext)
        if len_pt == 0:
            var null_ptr: UnsafePointer[UInt8, MutExternalOrigin] = {}
            return null_ptr

        var ciphertext = alloc[UInt8](len_pt)

        var block_idx = 0
        var offset = 0

        # Process 2 blocks (128 bytes) at a time using AVX2 dual-block
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

        # Process remaining single blocks
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
        mut self, ciphertext: Span[UInt8]
    ) -> UnsafePointer[UInt8, MutExternalOrigin]:
        return self.encrypt(ciphertext)

    fn encrypt_inplace[origin: Origin[mut=True]](
        mut self, mut data: Span[mut=True, UInt8, origin]
    ):
        var len_data = len(data)
        
        # Get unsafe pointer once to avoid repeated span access
        var data_ptr = data.unsafe_ptr()
        
        var block_idx = 0
        var offset = 0

        # Process 2 blocks (128 bytes) at a time using AVX2 dual-block
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
