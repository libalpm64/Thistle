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
BLAKE3 cryptographic hash function

Description:
Blake3 is a cryptographic hash function that is designed to be fast and secure.
It is much faster than SHA-256 and SHA-3 and is highly parallelizable across any number of threads and SIMD.
lanes. Mojo Excels at parallelization and SIMD operations.

Tested With -
0, 1, 1024, 1025, 64 KB, 64 KB+1, 128 KB, and 1 MB.
Blake3 Official Test Vectors (XOF 131-byte extended outputs)
Link: https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json
All test cases pass.

Tested On -
x86_64 AVX2 (Tested)
x86_64 AVX-512 (Not yet tested)
ARM64 NEON (Not yet tested)
ARM64 SVE (Not yet tested)

Valgrind Test:

Result: Definitely Lost: 0 bytes in 0 blocks.
HEAP SUMMARY:
    In use at exit: 78,534 bytes in 7 blocks (Ignore, Mojo Runtime)
    Total usage:    215 allocs, 208 frees, 2,425,015 bytes allocated
    Errors:         0 errors from 0 contexts

Constant Time Test (200,000 trials):
Class A (Fixed) Mean:  324073.3861452671 ns
Class B (Random) Mean: 324140.79993818176 ns
Delta:                -67.41379291465273 ns
T-Statistic:          -0.42135190883592855

"""

from algorithm import parallelize
from memory import UnsafePointer, alloc, bitcast, stack_allocation
from bit import count_trailing_zeros
from std.utils import IndexList
from thistle.utils import StackInlineArray

comptime IV = SIMD[DType.uint32, 8](
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)
"""The BLAKE3 initial chaining value."""

comptime CHUNK_START = UInt8(1 << 0)
"""Flag indicating the start of a chunk."""
comptime CHUNK_END = UInt8(1 << 1)
"""Flag indicating the end of a chunk."""
comptime PARENT = UInt8(1 << 2)
"""Flag indicating a parent node in the hash tree."""
comptime ROOT = UInt8(1 << 3)
"""Flag indicating the root node of the hash tree."""
comptime CHUNK_LEN = 1024
"""The length of a BLAKE3 chunk in bytes."""


# fmt: off
comptime _round_idxes_arr = [
    [(0, 1), (2, 3), (4, 5), (6, 7), (8, 9), (10, 11), (12, 13), (14, 15)],
    [(2, 6), (3, 10), (7, 0), (4, 13), (1, 11), (12, 5), (9, 14), (15, 8)],
    [(3, 4), (10, 12), (13, 2), (7, 14), (6, 5), (9, 0), (11, 15), (8, 1)],
    [(10, 7), (12, 9), (14, 3), (13, 15), (4, 0), (11, 2), (5, 8), (1, 6)],
    [(12, 13), (9, 11), (15, 10), (14, 8), (7, 2), (5, 3), (0, 1), (6, 4)],
    [(9, 14), (11, 5), (8, 12), (15, 1), (13, 3), (0, 10), (2, 6), (4, 7)],
    [(11, 15), (5, 0), (1, 9), (8, 6), (14, 10), (2, 12), (3, 4), (7, 13)],
]
comptime _v_idxes_arr = [
    (0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
    (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)
]
# fmt: on


@always_inline
fn bit_rotr[n: Int, w: Int](v: SIMD[DType.uint32, w]) -> SIMD[DType.uint32, w]:
    """Right-rotate a SIMD vector of 32-bit integers.

    Parameters:
        n: The number of bits to rotate by.
        w: The width of the SIMD vector.

    Args:
        v: The vector to rotate.

    Returns:
        The rotated vector.
    """
    return (v >> n) | (v << (32 - n))


@always_inline
fn g_v_half1[
    w: Int
](
    mut a: SIMD[DType.uint32, w],
    mut b: SIMD[DType.uint32, w],
    mut c: SIMD[DType.uint32, w],
    mut d: SIMD[DType.uint32, w],
    x: SIMD[DType.uint32, w],
):
    a = a + b + x
    d = bit_rotr[16, w](d ^ a)
    c = c + d
    b = bit_rotr[12, w](b ^ c)


@always_inline
fn g_v_half2[
    w: Int
](
    mut a: SIMD[DType.uint32, w],
    mut b: SIMD[DType.uint32, w],
    mut c: SIMD[DType.uint32, w],
    mut d: SIMD[DType.uint32, w],
    y: SIMD[DType.uint32, w],
):
    a = a + b + y
    d = bit_rotr[8, w](d ^ a)
    c = c + d
    b = bit_rotr[7, w](b ^ c)


@always_inline
fn g_v[
    w: Int
](
    mut a: SIMD[DType.uint32, w],
    mut b: SIMD[DType.uint32, w],
    mut c: SIMD[DType.uint32, w],
    mut d: SIMD[DType.uint32, w],
    x: SIMD[DType.uint32, w],
    y: SIMD[DType.uint32, w],
):
    """The BLAKE3 G function, operating on four columns (or one row) of the state.

    Parameters:
        w: The width of the SIMD vectors.

    Args:
        a: State vector a.
        b: State vector b.
        c: State vector c.
        d: State vector d.
        x: Message word x.
        y: Message word y.
    """
    g_v_half1[w](a, b, c, d, x)
    g_v_half2[w](a, b, c, d, y)


@always_inline
fn compress_internal[
    w: Int
](
    cv: SIMD[DType.uint32, 8],
    var m: StackInlineArray[SIMD[DType.uint32, w], 16],
    counter: UInt64,
    blen: UInt8,
    flags: UInt8,
    out_ptr: UnsafePointer[SIMD[DType.uint32, w], MutAnyOrigin],
):
    """The core internal compression function performing 7 rounds of G.

    Parameters:
        w: The width of the SIMD vectors.

    Args:
        cv: The chaining value.
        m: Message words.
        counter: The chunk counter.
        blen: The block length.
        flags: The flag byte.
        out_ptr: The output pointer to store the resulting 16 SIMD vectors.
    """
    # fmt: off
    var v: StackInlineArray[SIMD[DType.uint32, w], 16] = [
        {cv[0]}, {cv[1]}, {cv[2]}, {cv[3]}, {cv[4]}, {cv[5]}, {cv[6]}, {cv[7]},
        {IV[0]}, {IV[1]}, {IV[2]}, {IV[3]},
        {UInt32(counter & 0xFFFFFFFF)},
        {UInt32(counter >> 32)},
        {UInt32(blen)},
        {UInt32(flags)},
    ]
    # fmt: on

    @parameter
    @always_inline
    fn round():
        g_v(v[0], v[4], v[8], v[12], m[0], m[1])
        g_v(v[1], v[5], v[9], v[13], m[2], m[3])
        g_v(v[2], v[6], v[10], v[14], m[4], m[5])
        g_v(v[3], v[7], v[11], v[15], m[6], m[7])
        g_v(v[0], v[5], v[10], v[15], m[8], m[9])
        g_v(v[1], v[6], v[11], v[12], m[10], m[11])
        g_v(v[2], v[7], v[8], v[13], m[12], m[13])
        g_v(v[3], v[4], v[9], v[14], m[14], m[15])
    
    @parameter
    @always_inline
    fn transform():
        # fmt: off
        m = [
            m[2], m[6], m[3], m[10], m[7], m[0], m[4], m[13],
            m[1], m[11], m[12], m[5], m[9], m[14], m[15], m[8],        
        ]
        # fmt: on

    @parameter
    for _ in range(7):
        round()
        transform()

    out_ptr.bitcast[UInt32]().store(
        v.unsafe_ptr().bitcast[UInt32]().load[width=w * 16]()
    )


@always_inline
fn rot[n: Int](v: SIMD[DType.uint32, 8]) -> SIMD[DType.uint32, 8]:
    """Rotate a SIMD vector of 8 32-bit integers.

    Parameters:
        n: The number of bits to rotate by.

    Args:
        v: The vector to rotate.

    Returns:
        The rotated vector.
    """
    return (v >> n) | (v << (32 - n))


@always_inline
fn g_vertical(
    mut a: SIMD[DType.uint32, 8],
    mut b: SIMD[DType.uint32, 8],
    mut c: SIMD[DType.uint32, 8],
    mut d: SIMD[DType.uint32, 8],
    x: SIMD[DType.uint32, 8],
    y: SIMD[DType.uint32, 8],
):
    """Vertical G function for width-8 SIMD types.

    Args:
        a: State vector a.
        b: State vector b.
        c: State vector c.
        d: State vector d.
        x: Message word x.
        y: Message word y.
    """
    a = a + b + x
    d = rot[16](d ^ a)
    c = c + d
    b = rot[12](b ^ c)
    a = a + b + y
    d = rot[8](d ^ a)
    c = c + d
    b = rot[7](b ^ c)


@always_inline
fn compress_core(
    cv: SIMD[DType.uint32, 8],
    block: SIMD[DType.uint32, 16],
    counter: UInt64,
    blen: UInt8,
    flags: UInt8,
) -> SIMD[DType.uint32, 16]:
    """The core compression function for a single block.

    Args:
        cv: The chaining value.
        block: The 64-byte message block.
        counter: The chunk counter.
        blen: The block length.
        flags: The flag byte.

    Returns:
        The resulting 16 words (32 bytes of CV and 32 bytes of output).
    """
    # fmt: off
    var m: StackInlineArray[UInt32, 16] = [
        block[0], block[1], block[2], block[3],
        block[4], block[5], block[6], block[7],
        block[8], block[9], block[10], block[11],
        block[12], block[13], block[14], block[15],
    ]
    # fmt: on

    var res = StackInlineArray[SIMD[DType.uint32, 1], 16](uninitialized=True)
    compress_internal[1](cv, m^, counter, blen, flags, res.unsafe_ptr())
    var final = SIMD[DType.uint32, 16]()

    @parameter
    for i in range(8):
        final[i] = res[i][0] ^ res[i + 8][0]
        final[i + 8] = res[i + 8][0] ^ cv[i]
    return final


@always_inline
fn compress_internal_16way(
    c: StackInlineArray[SIMD[DType.uint32, 16], 8],
    var m: StackInlineArray[SIMD[DType.uint32, 16], 16],
    base_counter: UInt64,
    blen: UInt8,
    flags: UInt8,
    out_ptr: UnsafePointer[mut=True, SIMD[DType.uint32, 16]],
):
    """16-way SIMD internal compression.

    Args:
        c: State vectors.
        m: Message vectors.
        base_counter: Starting counter for the 16-way batch.
        blen: Block length.
        flags: Flag byte.
        out_ptr: The output pointer to store the resulting 8 vectors of 16-way SIMD words.
    """
    # Per-lane sequential counters
    var counters_low = SIMD[DType.uint32, 16](
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    )
    counters_low += UInt32(base_counter & 0xFFFFFFFF)
    # fmt: off
    var v: StackInlineArray[SIMD[DType.uint32, 16], 16] = [
        {c[0]}, {c[1]}, {c[2]}, {c[3]}, {c[4]}, {c[5]}, {c[6]}, {c[7]},
        {IV[0]}, {IV[1]}, {IV[2]}, {IV[3]},
        counters_low,
        {UInt32(base_counter >> 32)},
        {UInt32(blen)},
        {UInt32(flags)},
    ]
    # fmt: on

    @parameter
    @always_inline
    fn round():
        g_v[16](v[0], v[4], v[8], v[12], m[0], m[1])
        g_v[16](v[1], v[5], v[9], v[13], m[2], m[3])
        g_v[16](v[2], v[6], v[10], v[14], m[4], m[5])
        g_v[16](v[3], v[7], v[11], v[15], m[6], m[7])
        g_v[16](v[0], v[5], v[10], v[15], m[8], m[9])
        g_v[16](v[1], v[6], v[11], v[12], m[10], m[11])
        g_v[16](v[2], v[7], v[8], v[13], m[12], m[13])
        g_v[16](v[3], v[4], v[9], v[14], m[14], m[15])

    @parameter
    @always_inline
    fn transform():
        # fmt: off
        m = [
            m[2], m[6], m[3], m[10], m[7], m[0], m[4], m[13],
            m[1], m[11], m[12], m[5], m[9], m[14], m[15], m[8],        
        ]
        # fmt: on

    @parameter
    for _ in range(7):
        round()
        transform()

    out_ptr[0] = v[0] ^ v[8]
    out_ptr[1] = v[1] ^ v[9]
    out_ptr[2] = v[2] ^ v[10]
    out_ptr[3] = v[3] ^ v[11]
    out_ptr[4] = v[4] ^ v[12]
    out_ptr[5] = v[5] ^ v[13]
    out_ptr[6] = v[6] ^ v[14]
    out_ptr[7] = v[7] ^ v[15]


@always_inline
fn compress_parallel_8(
    cv: SIMD[DType.uint32, 8],
    m: UnsafePointer[SIMD[DType.uint32, 8], ImmutAnyOrigin],
    base_counter: UInt64,
    blen: UInt8,
    flags: UInt8,
    out_ptr: UnsafePointer[SIMD[DType.uint32, 8], MutAnyOrigin],
):
    """8-way parallel compression.

    Args:
        cv: The common chaining value for all 8 lanes.
        m: The message words for all 8 lanes.
        base_counter: The starting counter for the 8-way batch.
        blen: The block length.
        flags: The flags.
        out_ptr: The output pointer to store the resulting 8 CVs.
    """
    var counters_low = SIMD[DType.uint32, 8](0, 1, 2, 3, 4, 5, 6, 7) + (
        UInt32(base_counter & 0xFFFFFFFF)
    )
    # fmt: off
    var v: StackInlineArray[SIMD[DType.uint32, 8], 16] = [
        {cv[0]}, {cv[1]}, {cv[2]}, {cv[3]}, {cv[4]}, {cv[5]}, {cv[6]}, {cv[7]},
        {IV[0]}, {IV[1]}, {IV[2]}, {IV[3]},
        counters_low,
        {UInt32(base_counter >> 32)},
        {UInt32(blen)},
        {UInt32(flags)},
    ]
    # fmt: on

    @parameter
    for round_idxes in _round_idxes_arr:

        @parameter
        for v_idx in range(len(_v_idxes_arr)):
            comptime v_i = _v_idxes_arr[v_idx]
            comptime m_i = round_idxes[v_idx]
            g_vertical(
                v[v_i[0]], v[v_i[1]], v[v_i[2]], v[v_i[3]], m[m_i[0]], m[m_i[1]]
            )

    out_ptr[0] = v[0] ^ v[8]
    out_ptr[1] = v[1] ^ v[9]
    out_ptr[2] = v[2] ^ v[10]
    out_ptr[3] = v[3] ^ v[11]
    out_ptr[4] = v[4] ^ v[12]
    out_ptr[5] = v[5] ^ v[13]
    out_ptr[6] = v[6] ^ v[14]
    out_ptr[7] = v[7] ^ v[15]


@always_inline
fn compress_parallel_16_per_lane(
    cv_lanes: UnsafePointer[SIMD[DType.uint32, 8], ImmutAnyOrigin],
    ma: UnsafePointer[SIMD[DType.uint32, 8], ImmutAnyOrigin],
    mb: UnsafePointer[SIMD[DType.uint32, 8], ImmutAnyOrigin],
    base_counter: UInt64,
    blen: UInt8,
    flags: UInt8,
    out_ptr: UnsafePointer[SIMD[DType.uint32, 8], MutAnyOrigin],
):
    """16-way parallel compression with per-lane CVs.

    Args:
        cv_lanes: The 16 chaining values.
        ma: First 8 lanes' message words.
        mb: Next 8 lanes' message words.
        base_counter: Starting counter.
        blen: Block length.
        flags: Flags.
        out_ptr: The output pointer to store the resulting 16 CVs.
    """

    # fmt: off
    comptime transpose_8x8_idxes: IndexList[64] = [
        0, 8, 16, 24, 32, 40, 48, 56,
        1, 9, 17, 25, 33, 41, 49, 57,
        2, 10, 18, 26, 34, 42, 50, 58,
        3, 11, 19, 27, 35, 43, 51, 59,
        4, 12, 20, 28, 36, 44, 52, 60,
        5, 13, 21, 29, 37, 45, 53, 61,
        6, 14, 22, 30, 38, 46, 54, 62,
        7, 15, 23, 31, 39, 47, 55, 63
    ]
    # fmt: on
    var va_vec = cv_lanes.bitcast[UInt32]().load[width=64]()
    var va_t = va_vec.shuffle[mask=transpose_8x8_idxes]()

    var vb_vec = (cv_lanes + 8).bitcast[UInt32]().load[width=64]()
    var vb_t = vb_vec.shuffle[mask=transpose_8x8_idxes]()

    var counters_low = SIMD[DType.uint32, 8](0, 1, 2, 3, 4, 5, 6, 7) + (
        UInt32(base_counter & 0xFFFFFFFF)
    )

    @always_inline
    fn _from_slice(
        vec: SIMD[DType.uint32, 64]
    ) -> StackInlineArray[SIMD[DType.uint32, 8], 16]:
        # fmt: off
        return [
            vec.slice[8, offset=0](),
            vec.slice[8, offset=8](),
            vec.slice[8, offset=2 * 8](),
            vec.slice[8, offset=3 * 8](),
            vec.slice[8, offset=4 * 8](),
            vec.slice[8, offset=5 * 8](),
            vec.slice[8, offset=6 * 8](),
            vec.slice[8, offset=7 * 8](),
            {IV[0]}, {IV[1]}, {IV[2]}, {IV[3]},
            {counters_low},
            {UInt32(base_counter >> 32)},
            {UInt32(blen)},
            {UInt32(flags)},
        ]
        # fmt: on


    var va = _from_slice(va_t)
    var vb = _from_slice(vb_t)

    @parameter
    for round_idxes in _round_idxes_arr:

        @parameter
        for v_idx in range(len(_v_idxes_arr)):
            comptime v = _v_idxes_arr[v_idx]
            comptime m_i = round_idxes[v_idx]
            g_vertical(
                va[v[0]], va[v[1]], va[v[2]], va[v[3]], ma[m_i[0]], ma[m_i[1]]
            )
            g_vertical(
                vb[v[0]], vb[v[1]], vb[v[2]], vb[v[3]], mb[m_i[0]], mb[m_i[1]]
            )

    var res_a: StackInlineArray[SIMD[DType.uint32, 8], 8] = [
        va[0] ^ va[8],
        va[1] ^ va[9],
        va[2] ^ va[10],
        va[3] ^ va[11],
        va[4] ^ va[12],
        va[5] ^ va[13],
        va[6] ^ va[14],
        va[7] ^ va[15],
    ]
    var res_b: StackInlineArray[SIMD[DType.uint32, 8], 8] = [
        vb[0] ^ vb[8],
        vb[1] ^ vb[9],
        vb[2] ^ vb[10],
        vb[3] ^ vb[11],
        vb[4] ^ vb[12],
        vb[5] ^ vb[13],
        vb[6] ^ vb[14],
        vb[7] ^ vb[15],
    ]
    var res_a_t = (
        res_a.unsafe_ptr().bitcast[UInt32]().load[width=64]()
    ).shuffle[mask=transpose_8x8_idxes]()
    var res_b_t = (
        res_b.unsafe_ptr().bitcast[UInt32]().load[width=64]()
    ).shuffle[mask=transpose_8x8_idxes]()

    out_ptr.bitcast[UInt32]().store(res_a_t)
    (out_ptr + 8).bitcast[UInt32]().store(res_b_t)


struct Hasher:
    var key: SIMD[DType.uint32, 8]
    var original_key: SIMD[DType.uint32, 8]
    var cv_stack: StackInlineArray[SIMD[DType.uint32, 8], 54]
    var stack_len: Int
    var buf: StackInlineArray[UInt8, 64]
    var buf_len: Int
    var chunk_counter: UInt64
    var blocks_compressed: Int

    fn __init__(out self):
        self.key = IV
        self.original_key = IV
        self.cv_stack = {uninitialized=True}

        self.stack_len = 0

        self.buf = {uninitialized=True}

        self.buf_len = 0
        self.chunk_counter = 0
        self.blocks_compressed = 0

    fn update(mut self, input: Span[UInt8]):
        var d = input
        while len(d) > 0:
            if self.buf_len == 64:
                # TODO: use simd_width_of[dtype]() and make the functions
                # be more generic based on the width
                var blk = (
                    # Note: Defaults to AVX2 (AVX-512 = Width 32)
                    # Will need to use Sys to set targets any target that dooesn't support AVX2 will spill (ARM)
                    # Sys is just a pain to use at the moment there's like hundreds of targets so it's useless to try and target all cpus.
                    self.buf.unsafe_ptr().bitcast[UInt32]().load[width=16]()
                )

                if self.blocks_compressed == 15:
                    if len(d) > 0:
                        var res = compress_core(
                            self.key,
                            blk,
                            self.chunk_counter,
                            64,
                            (CHUNK_START if self.blocks_compressed == 0 else 0)
                            | CHUNK_END,
                        )
                        var chunk_cv = res.slice[8]()
                        self.add_chunk_cv(chunk_cv, self.chunk_counter)
                        self.key = self.original_key
                        self.chunk_counter += 1
                        self.blocks_compressed = 0
                        self.buf_len = 0
                    else:
                        # finalize() will handle it as ROOT if needed.
                        return
                else:
                    var res = compress_core(
                        self.key,
                        blk,
                        self.chunk_counter,
                        64,
                        (CHUNK_START if self.blocks_compressed == 0 else 0),
                    )
                    self.key = res.slice[8]()
                    self.blocks_compressed += 1
                    self.buf_len = 0

            var take = min(len(d), 64 - self.buf_len)
            for i in range(take):
                self.buf.unsafe_set(self.buf_len + i, d[i])
            self.buf_len += take
            d = d[take:]

    @always_inline
    fn add_chunk_cv(
        mut self, cv_in: SIMD[DType.uint32, 8], total_chunks: UInt64
    ):
        var new_total = total_chunks + 1
        var new_cv = cv_in
        var num_merges = count_trailing_zeros(new_total.cast[DType.int]())
        for _ in range(num_merges):
            if self.stack_len == 0:
                break
            var left = self.cv_stack.unsafe_get((self.stack_len - 1))
            var res = compress_core(
                self.original_key, left.join(new_cv), 0, 64, PARENT
            )
            new_cv = res.slice[8]()
            self.stack_len -= 1
        self.cv_stack.unsafe_set(self.stack_len, new_cv)
        self.stack_len += 1

    @always_inline
    fn add_subtree_cv(mut self, cv_in: SIMD[DType.uint32, 8], height: Int):
        var new_cv = cv_in
        self.chunk_counter += UInt64(1) << height
        var total_at_level = self.chunk_counter >> height

        while (total_at_level & 1) == 0 and self.stack_len > 0:
            var left = self.cv_stack.unsafe_get((self.stack_len - 1))
            var res = compress_core(
                self.original_key, left.join(new_cv), 0, 64, PARENT
            )
            new_cv = res.slice[8]()
            self.stack_len -= 1
            total_at_level >>= 1

        self.cv_stack.unsafe_set(self.stack_len, new_cv)
        self.stack_len += 1

    @always_inline
    fn finalize(
        self, out_ptr: UnsafePointer[UInt8, MutAnyOrigin], out_len: Int
    ):
        """Finalize the hash and write the output.

        Args:
            out_ptr: Pointer to write the resulting hash to.
            out_len: The number of bytes to write.
        """
        var temp_buf = StackInlineArray[UInt8, 64](uninitialized=True)
        # Initialize temp_buf to 0 and copy self.buf
        # TODO: maybe if we have self.buf always have 0 where > self.buf_len
        # we can avoid this entirely. We could also just load the whole
        # vector and mask based on self.buf_len.

        @parameter
        for i in range(64):
            if i < self.buf_len:
                temp_buf[i] = self.buf[i]
            else:
                temp_buf[i] = 0
        
        # TODO: use simd_width_of[dtype]() and make everything more generic
        # Note: Defaults to AVX2 (AVX-512 = Width 32)
        # Will need to use Sys to set targets any target that dooesn't support AVX2 will spill (ARM)
        var blk = temp_buf.unsafe_ptr().bitcast[UInt32]().load[width=16]()

        var flags = (
            CHUNK_START if self.blocks_compressed == 0 else UInt8(0)
        ) | CHUNK_END

        var working_key: SIMD[DType.uint32, 8]
        var working_blk: SIMD[DType.uint32, 16]
        var working_counter: UInt64
        var working_blen: UInt8
        var working_flags: UInt8

        if self.stack_len == 0:
            working_key = self.key
            working_blk = blk
            working_counter = self.chunk_counter
            working_blen = UInt8(self.buf_len)
            working_flags = flags | ROOT
        else:
            var res = compress_core(
                self.key, blk, self.chunk_counter, UInt8(self.buf_len), flags
            )
            var out_cv = res.slice[8]()
            var depth = self.stack_len
            while depth > 1:
                depth -= 1
                var left = self.cv_stack.unsafe_get(depth)
                var p_res = compress_core(
                    self.original_key, left.join(out_cv), 0, 64, PARENT
                )
                out_cv = p_res.slice[8]()

            working_key = self.original_key
            working_blk = self.cv_stack.unsafe_get(0).join(out_cv)
            working_counter = 0
            working_blen = 64
            working_flags = PARENT | ROOT

        var bytes_written = 0
        var block_idx: UInt64 = 0
        while bytes_written < out_len:
            var res = compress_core(
                working_key, working_blk, block_idx, working_blen, working_flags
            )
            var b = bitcast[DType.uint8, 64](res)
            var to_copy = min(64, out_len - bytes_written)

            var t = stack_allocation[64, UInt8]()
            t.bitcast[SIMD[DType.uint8, 64]]()[0] = b
            for i in range(to_copy):
                (out_ptr + bytes_written + i)[] = t[i]

            bytes_written += to_copy
            block_idx += 1


@always_inline
fn blake3_parallel_hash(input: Span[UInt8], out_len: Int = 32) -> List[UInt8]:
    var d = input
    var total_chunks = (len(d) + CHUNK_LEN - 1) // CHUNK_LEN

    if len(d) > 65536:
        comptime BSIZE = 64
        var chunks_to_parallelize = total_chunks - 1
        var num_full_batches = chunks_to_parallelize // BSIZE

        var batch_roots = alloc[SIMD[DType.uint32, 8]](num_full_batches)
        var batch_roots_ptr = batch_roots

        @parameter
        fn process_batch(tid: Int):
            var task_base = tid * BSIZE
            var base_ptr = d.unsafe_ptr().bitcast[UInt32]()
            var local_cvs = StackInlineArray[SIMD[DType.uint32, 8], 64](
                uninitialized=True
            )
            # TODO: I think there is a lot of room for perf improvement here
            # because these transformations are known at compile time, we should
            # be able to vectorize this according to the device's simd_width
            for i in range(0, BSIZE, 16):
                var base = task_base + i
                # fmt: off
                var c: StackInlineArray[SIMD[DType.uint32, 16], 8] = [
                    {IV[0]}, {IV[1]}, {IV[2]}, {IV[3]},
                    {IV[4]}, {IV[5]}, {IV[6]}, {IV[7]},
                ]
                # fmt: on

                for b in range(16):
                    var flags = (CHUNK_START if b == 0 else UInt8(0)) | (
                        CHUNK_END if b == 15 else 0
                    )
                    var ma = StackInlineArray[SIMD[DType.uint32, 8], 16](
                        uninitialized=True
                    )
                    var mb = StackInlineArray[SIMD[DType.uint32, 8], 16](
                        uninitialized=True
                    )

                    for j in range(4):
                        var joff = j * 4

                        @parameter
                        @always_inline
                        fn _load_idx(v: Int) -> SIMD[DType.uint32, 4]:
                            return base_ptr.load[width=4](
                                (base + v) * 256 + b * 16 + joff
                            )

                        var v0a = _load_idx(0).interleave(_load_idx(1))
                        var v1a = _load_idx(2).interleave(_load_idx(3))
                        var v2a = _load_idx(4).interleave(_load_idx(5))
                        var v3a = _load_idx(6).interleave(_load_idx(7))
                        comptime t_01_mask: IndexList[8] = [
                            0, 1, 8, 9, 2, 3, 10, 11
                        ]
                        comptime t_23_mask: IndexList[8] = [
                            4, 5, 12, 13, 6, 7, 14, 15
                        ]
                        comptime mask_even: IndexList[8] = [
                            0, 1, 2, 3, 8, 9, 10, 11
                        ]
                        comptime mask_odd: IndexList[8] = [
                            4, 5, 6, 7, 12, 13, 14, 15
                        ]
                        var t0a = v0a.shuffle[mask=t_01_mask](v1a)
                        var t1a = v2a.shuffle[mask=t_01_mask](v3a)
                        ma.unsafe_set(joff + 0, t0a.shuffle[mask=mask_even](t1a))
                        ma.unsafe_set(joff + 1, t0a.shuffle[mask=mask_odd](t1a))
                        var t2a = v0a.shuffle[mask=t_23_mask](v1a)
                        var t3a = v2a.shuffle[mask=t_23_mask](v3a)
                        ma.unsafe_set(joff + 2, t2a.shuffle[mask=mask_even](t3a))
                        ma.unsafe_set(joff + 3, t2a.shuffle[mask=mask_odd](t3a))

                        var v0b = _load_idx(8).interleave(_load_idx(9))
                        var v1b = _load_idx(10).interleave(_load_idx(11))
                        var v2b = _load_idx(12).interleave(_load_idx(13))
                        var v3b = _load_idx(14).interleave(_load_idx(15))
                        var t0b = v0b.shuffle[mask=t_01_mask](v1b)
                        var t1b = v2b.shuffle[mask=t_01_mask](v3b)
                        mb.unsafe_set(joff + 0, t0b.shuffle[mask=mask_even](t1b))
                        mb.unsafe_set(joff + 1, t0b.shuffle[mask=mask_odd](t1b))
                        var t2b = v0b.shuffle[mask=t_23_mask](v1b)
                        var t3b = v2b.shuffle[mask=t_23_mask](v3b)
                        mb.unsafe_set(joff + 2, t2b.shuffle[mask=mask_even](t3b))
                        mb.unsafe_set(joff + 3, t2b.shuffle[mask=mask_odd](t3b))

                    var am: StackInlineArray[SIMD[DType.uint32, 16], 16] = [
                        ma[0].join(mb[0]),
                        ma[1].join(mb[1]),
                        ma[2].join(mb[2]),
                        ma[3].join(mb[3]),
                        ma[4].join(mb[4]),
                        ma[5].join(mb[5]),
                        ma[6].join(mb[6]),
                        ma[7].join(mb[7]),
                        ma[8].join(mb[8]),
                        ma[9].join(mb[9]),
                        ma[10].join(mb[10]),
                        ma[11].join(mb[11]),
                        ma[12].join(mb[12]),
                        ma[13].join(mb[13]),
                        ma[14].join(mb[14]),
                        ma[15].join(mb[15]),
                    ]

                    var res = StackInlineArray[SIMD[DType.uint32, 16], 8](
                        uninitialized=True
                    )
                    compress_internal_16way(
                        c,
                        am^,
                        UInt64(base),
                        64,
                        flags,
                        res.unsafe_ptr(),
                    )
                    c = res^

                for k in range(16):
                    # fmt: off
                    var vec = SIMD[DType.uint32, 8](
                        c[0][k], c[1][k], c[2][k], c[3][k],
                        c[4][k], c[5][k], c[6][k], c[7][k],
                    )
                    # fmt: on
                    local_cvs.unsafe_set(i + k, vec)

            var current_len = 64
            while current_len > 1:
                current_len >>= 1
                for i in range(current_len):
                    var left = local_cvs.unsafe_get(i * 2)
                    var right = local_cvs.unsafe_get(i * 2 + 1)
                    var combined = compress_core(
                        IV, left.join(right), 0, 64, PARENT
                    )
                    local_cvs.unsafe_set(i, combined.slice[8]())
            batch_roots_ptr[tid] = local_cvs[0]

        parallelize[process_batch](num_full_batches)

        var h = Hasher()
        for i in range(num_full_batches):
            h.add_subtree_cv(batch_roots[i], height=6)
        batch_roots.free()

        h.update(d[num_full_batches * 64 * 1024 :])
        var out_p = List[UInt8](capacity=out_len)
        for _ in range(out_len):
            out_p.append(0)
        h.finalize(out_p.unsafe_ptr().as_any_origin(), out_len)
        return out_p^

    var h = Hasher()
    h.update(d)
    var out = List[UInt8](capacity=out_len)
    for _ in range(out_len):
        out.append(0)
    h.finalize(out.unsafe_ptr().as_any_origin(), out_len)
    return out^


fn blake3_hash(input: Span[UInt8], out_len: Int = 32) -> List[UInt8]:
    return blake3_parallel_hash(input, out_len)
