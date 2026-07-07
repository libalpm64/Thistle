"""
ChaCha20 stream cipher implementation per RFC 7539
"""

from std.memory import bitcast
from std.memory.unsafe_pointer import UnsafePointer
from std.builtin.type_aliases import MutUntrackedOrigin
from std.bit import rotate_bits_left

comptime CHACHA_CONSTANTS = SIMD[DType.uint32, 4](
    0x61707865, 0x3320646E, 0x79622D32, 0x6B206574,
)

@always_inline
def simd_quarter_round(
    a: SIMD[DType.uint32, 4],
    b: SIMD[DType.uint32, 4],
    c: SIMD[DType.uint32, 4],
    d: SIMD[DType.uint32, 4],
) -> Tuple[SIMD[DType.uint32, 4], SIMD[DType.uint32, 4], SIMD[DType.uint32, 4], SIMD[DType.uint32, 4]]:
    """SIMD vectorized quarter round operating on 4 columns in parallel."""
    var aa = a
    var bb = b
    var cc = c
    var dd = d

    aa = aa + bb
    dd = dd ^ aa
    dd = rotate_bits_left[shift=16](dd)

    cc = cc + dd
    bb = bb ^ cc
    bb = rotate_bits_left[shift=12](bb)

    aa = aa + bb
    dd = dd ^ aa
    dd = rotate_bits_left[shift=8](dd)

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
    """Rotate rows to align diagonals for simd_quarter_round."""
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
    """Reverse the diagonal shuffle to restore row layout."""
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
def simd_quarter_round_8x(
    a: SIMD[DType.uint32, 8],
    b: SIMD[DType.uint32, 8],
    c: SIMD[DType.uint32, 8],
    d: SIMD[DType.uint32, 8],
) -> Tuple[SIMD[DType.uint32, 8], SIMD[DType.uint32, 8], SIMD[DType.uint32, 8], SIMD[DType.uint32, 8]]:
    """SIMD quarter round for 8-element vectors."""
    var aa = a
    var bb = b
    var cc = c
    var dd = d

    aa = aa + bb
    dd = dd ^ aa
    dd = rotate_bits_left[shift=16](dd)

    cc = cc + dd
    bb = bb ^ cc
    bb = rotate_bits_left[shift=12](bb)

    aa = aa + bb
    dd = dd ^ aa
    dd = rotate_bits_left[shift=8](dd)

    cc = cc + dd
    bb = bb ^ cc
    bb = rotate_bits_left[shift=7](bb)

    return Tuple(aa, bb, cc, dd)


@always_inline
def simd_double_round_8x(
    row0: SIMD[DType.uint32, 8],
    row1: SIMD[DType.uint32, 8],
    row2: SIMD[DType.uint32, 8],
    row3: SIMD[DType.uint32, 8],
) -> Tuple[SIMD[DType.uint32, 8], SIMD[DType.uint32, 8], SIMD[DType.uint32, 8], SIMD[DType.uint32, 8]]:
    """One ChaCha20 double-round on 2 blocks in parallel using 256-bit SIMD."""
    var rr0 = row0
    var rr1 = row1
    var rr2 = row2
    var rr3 = row3

    var qr = simd_quarter_round_8x(rr0, rr1, rr2, rr3)
    rr0 = qr[0]; rr1 = qr[1]; rr2 = qr[2]; rr3 = qr[3]

    var b = rr1.shuffle[1, 2, 3, 0, 5, 6, 7, 4]()
    var c = rr2.shuffle[2, 3, 0, 1, 6, 7, 4, 5]()
    var d = rr3.shuffle[3, 0, 1, 2, 7, 4, 5, 6]()

    qr = simd_quarter_round_8x(rr0, b, c, d)
    var diag_a = qr[0]; var diag_b = qr[1]; var diag_c = qr[2]; var diag_d = qr[3]

    rr1 = diag_b.shuffle[3, 0, 1, 2, 7, 4, 5, 6]()
    rr2 = diag_c.shuffle[2, 3, 0, 1, 6, 7, 4, 5]()
    rr3 = diag_d.shuffle[1, 2, 3, 0, 5, 6, 7, 4]()

    return Tuple(diag_a, rr1, rr2, rr3)


@always_inline
def chacha20_dual_block_core(
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

    comptime for _ in range(10):
        var dr = simd_double_round_8x(row0, row1, row2, row3)
        row0 = dr[0]; row1 = dr[1]; row2 = dr[2]; row3 = dr[3]

    row0 = row0 + init0
    row1 = row1 + init1
    row2 = row2 + init2
    row3 = row3 + init3

    var r0 = row0.split()
    var r1 = row1.split()
    var r2 = row2.split()
    var r3 = row3.split()

    var block1 = SIMD[DType.uint32, 16]()
    block1 = block1.insert[offset=0](r0[0])
    block1 = block1.insert[offset=4](r1[0])
    block1 = block1.insert[offset=8](r2[0])
    block1 = block1.insert[offset=12](r3[0])

    var block2 = SIMD[DType.uint32, 16]()
    block2 = block2.insert[offset=0](r0[1])
    block2 = block2.insert[offset=4](r1[1])
    block2 = block2.insert[offset=8](r2[1])
    block2 = block2.insert[offset=12](r3[1])

    return Tuple(block1, block2)


@always_inline
def chacha20_block_core(
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


def chacha20_block(
    key: SIMD[DType.uint8, 32], counter: UInt32, nonce: SIMD[DType.uint8, 12]
) -> SIMD[DType.uint8, 64]:
    """ChaCha20 block function for compatibility."""
    var key_words = bitcast[DType.uint32, 8](key)
    var nonce_words = bitcast[DType.uint32, 3](nonce)
    var state = chacha20_block_core(key_words, counter, nonce_words)
    return bitcast[DType.uint8, 64](state)


@always_inline
def _store_u64_le[origin: Origin[mut=True]](
    dst: UnsafePointer[UInt8, origin], byte_offset: Int, x: UInt64
):
    dst[byte_offset + 0] = UInt8(x & 0xff)
    dst[byte_offset + 1] = UInt8((x >> UInt64(8)) & 0xff)
    dst[byte_offset + 2] = UInt8((x >> UInt64(16)) & 0xff)
    dst[byte_offset + 3] = UInt8((x >> UInt64(24)) & 0xff)
    dst[byte_offset + 4] = UInt8((x >> UInt64(32)) & 0xff)
    dst[byte_offset + 5] = UInt8((x >> UInt64(40)) & 0xff)
    dst[byte_offset + 6] = UInt8((x >> UInt64(48)) & 0xff)
    dst[byte_offset + 7] = UInt8((x >> UInt64(56)) & 0xff)


@always_inline
def xor_block[origin: Origin[mut=True]](
    dst: UnsafePointer[UInt8, origin],
    src: Span[UInt8, ...],
    keystream: SIMD[DType.uint32, 16],
    offset: Int,
):
    """XOR 64 bytes of src with keystream; src loads are explicitly unaligned."""
    var ks_u64 = bitcast[DType.uint64, 8](keystream)
    var src_u64 = src.unsafe_ptr().bitcast[UInt64]()
    var base = offset // 8

    _store_u64_le(dst, offset + 0,  (src_u64 + base + 0).load[width=1, alignment=1]() ^ ks_u64[0])
    _store_u64_le(dst, offset + 8,  (src_u64 + base + 1).load[width=1, alignment=1]() ^ ks_u64[1])
    _store_u64_le(dst, offset + 16, (src_u64 + base + 2).load[width=1, alignment=1]() ^ ks_u64[2])
    _store_u64_le(dst, offset + 24, (src_u64 + base + 3).load[width=1, alignment=1]() ^ ks_u64[3])
    _store_u64_le(dst, offset + 32, (src_u64 + base + 4).load[width=1, alignment=1]() ^ ks_u64[4])
    _store_u64_le(dst, offset + 40, (src_u64 + base + 5).load[width=1, alignment=1]() ^ ks_u64[5])
    _store_u64_le(dst, offset + 48, (src_u64 + base + 6).load[width=1, alignment=1]() ^ ks_u64[6])
    _store_u64_le(dst, offset + 56, (src_u64 + base + 7).load[width=1, alignment=1]() ^ ks_u64[7])


@always_inline
def xor_block_inplace[origin: Origin[mut=True]](
    data_ptr: UnsafePointer[UInt8, origin],
    keystream: SIMD[DType.uint32, 16],
    offset: Int,
):
    """XOR 64 bytes in-place; loads are explicitly unaligned."""
    var ks_u64 = bitcast[DType.uint64, 8](keystream)
    var data_u64 = data_ptr.bitcast[UInt64]()
    var base = offset // 8

    _store_u64_le(data_ptr, offset + 0,  (data_u64 + base + 0).load[width=1, alignment=1]() ^ ks_u64[0])
    _store_u64_le(data_ptr, offset + 8,  (data_u64 + base + 1).load[width=1, alignment=1]() ^ ks_u64[1])
    _store_u64_le(data_ptr, offset + 16, (data_u64 + base + 2).load[width=1, alignment=1]() ^ ks_u64[2])
    _store_u64_le(data_ptr, offset + 24, (data_u64 + base + 3).load[width=1, alignment=1]() ^ ks_u64[3])
    _store_u64_le(data_ptr, offset + 32, (data_u64 + base + 4).load[width=1, alignment=1]() ^ ks_u64[4])
    _store_u64_le(data_ptr, offset + 40, (data_u64 + base + 5).load[width=1, alignment=1]() ^ ks_u64[5])
    _store_u64_le(data_ptr, offset + 48, (data_u64 + base + 6).load[width=1, alignment=1]() ^ ks_u64[6])
    _store_u64_le(data_ptr, offset + 56, (data_u64 + base + 7).load[width=1, alignment=1]() ^ ks_u64[7])


struct ChaCha20:
    """ChaCha20 stream cipher per RFC 7539."""

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
            raise Error("ChaCha20 counter would wrap; use a new nonce")

    def encrypt_into[origin: Origin[mut=True]](
        mut self,
        plaintext: Span[UInt8, ...],
        mut ciphertext: Span[mut=True, UInt8, origin],
    ) raises:
        """Encrypt plaintext into caller-owned ciphertext storage and advance counter."""
        var len_pt = len(plaintext)
        if len(ciphertext) < len_pt:
            raise Error("ChaCha20 ciphertext buffer too small")
        self._check_counter_space(len_pt)
        var ciphertext_ptr = ciphertext.unsafe_ptr()
        var block_idx = 0
        var offset = 0

        while offset + 128 <= len_pt:
            var blocks = chacha20_dual_block_core(
                self.key,
                self.counter + UInt32(block_idx),
                self.counter + UInt32(block_idx + 1),
                self.nonce
            )
            xor_block(ciphertext_ptr, plaintext, blocks[0], offset)
            xor_block(ciphertext_ptr, plaintext, blocks[1], offset + 64)
            offset += 128
            block_idx += 2

        while offset + 64 <= len_pt:
            var keystream = chacha20_block_core(
                self.key, self.counter + UInt32(block_idx), self.nonce
            )
            xor_block(ciphertext_ptr, plaintext, keystream, offset)
            offset += 64
            block_idx += 1

        if offset < len_pt:
            var keystream = chacha20_block_core(
                self.key, self.counter + UInt32(block_idx), self.nonce
            )
            var ks_u8 = bitcast[DType.uint8, 64](keystream)
            var remaining = len_pt - offset

            for i in range(remaining):
                ciphertext[offset + i] = plaintext[offset + i] ^ ks_u8[i]
            block_idx += 1

        self.counter += UInt32(block_idx)

    def decrypt_into[origin: Origin[mut=True]](
        mut self,
        ciphertext: Span[UInt8, ...],
        mut plaintext: Span[mut=True, UInt8, origin],
    ) raises:
        self.encrypt_into(ciphertext, plaintext)

    def encrypt_inplace[origin: Origin[mut=True]](
        mut self, mut data: Span[mut=True, UInt8, origin]
    ) raises:
        """Encrypt/decrypt in place and advance counter."""
        var len_data = len(data)
        self._check_counter_space(len_data)
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
            block_idx += 1

        self.counter += UInt32(block_idx)
