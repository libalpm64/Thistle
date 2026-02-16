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
    mut m0: SIMD[DType.uint32, w],
    mut m1: SIMD[DType.uint32, w],
    mut m2: SIMD[DType.uint32, w],
    mut m3: SIMD[DType.uint32, w],
    mut m4: SIMD[DType.uint32, w],
    mut m5: SIMD[DType.uint32, w],
    mut m6: SIMD[DType.uint32, w],
    mut m7: SIMD[DType.uint32, w],
    mut m8: SIMD[DType.uint32, w],
    mut m9: SIMD[DType.uint32, w],
    mut m10: SIMD[DType.uint32, w],
    mut m11: SIMD[DType.uint32, w],
    mut m12: SIMD[DType.uint32, w],
    mut m13: SIMD[DType.uint32, w],
    mut m14: SIMD[DType.uint32, w],
    mut m15: SIMD[DType.uint32, w],
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
        m0: Message word 0.
        m1: Message word 1.
        m2: Message word 2.
        m3: Message word 3.
        m4: Message word 4.
        m5: Message word 5.
        m6: Message word 6.
        m7: Message word 7.
        m8: Message word 8.
        m9: Message word 9.
        m10: Message word 10.
        m11: Message word 11.
        m12: Message word 12.
        m13: Message word 13.
        m14: Message word 14.
        m15: Message word 15.
        counter: The chunk counter.
        blen: The block length.
        flags: The flag byte.
        out_ptr: The output pointer to store the resulting 16 SIMD vectors.
    """
    var v0 = SIMD[DType.uint32, w](cv[0])
    var v1 = SIMD[DType.uint32, w](cv[1])
    var v2 = SIMD[DType.uint32, w](cv[2])
    var v3 = SIMD[DType.uint32, w](cv[3])
    var v4 = SIMD[DType.uint32, w](cv[4])
    var v5 = SIMD[DType.uint32, w](cv[5])
    var v6 = SIMD[DType.uint32, w](cv[6])
    var v7 = SIMD[DType.uint32, w](cv[7])
    var v8 = SIMD[DType.uint32, w](IV[0])
    var v9 = SIMD[DType.uint32, w](IV[1])
    var v10 = SIMD[DType.uint32, w](IV[2])
    var v11 = SIMD[DType.uint32, w](IV[3])
    var v12 = SIMD[DType.uint32, w](UInt32(counter & 0xFFFFFFFF))
    var v13 = SIMD[DType.uint32, w](UInt32(counter >> 32))
    var v14 = SIMD[DType.uint32, w](UInt32(blen))
    var v15 = SIMD[DType.uint32, w](UInt32(flags))

    @always_inline
    fn round(
        mut v0: SIMD[DType.uint32, w],
        mut v1: SIMD[DType.uint32, w],
        mut v2: SIMD[DType.uint32, w],
        mut v3: SIMD[DType.uint32, w],
        mut v4: SIMD[DType.uint32, w],
        mut v5: SIMD[DType.uint32, w],
        mut v6: SIMD[DType.uint32, w],
        mut v7: SIMD[DType.uint32, w],
        mut v8: SIMD[DType.uint32, w],
        mut v9: SIMD[DType.uint32, w],
        mut v10: SIMD[DType.uint32, w],
        mut v11: SIMD[DType.uint32, w],
        mut v12: SIMD[DType.uint32, w],
        mut v13: SIMD[DType.uint32, w],
        mut v14: SIMD[DType.uint32, w],
        mut v15: SIMD[DType.uint32, w],
        m0: SIMD[DType.uint32, w],
        m1: SIMD[DType.uint32, w],
        m2: SIMD[DType.uint32, w],
        m3: SIMD[DType.uint32, w],
        m4: SIMD[DType.uint32, w],
        m5: SIMD[DType.uint32, w],
        m6: SIMD[DType.uint32, w],
        m7: SIMD[DType.uint32, w],
        m8: SIMD[DType.uint32, w],
        m9: SIMD[DType.uint32, w],
        m10: SIMD[DType.uint32, w],
        m11: SIMD[DType.uint32, w],
        m12: SIMD[DType.uint32, w],
        m13: SIMD[DType.uint32, w],
        m14: SIMD[DType.uint32, w],
        m15: SIMD[DType.uint32, w],
    ):
        g_v(v0, v4, v8, v12, m0, m1)
        g_v(v1, v5, v9, v13, m2, m3)
        g_v(v2, v6, v10, v14, m4, m5)
        g_v(v3, v7, v11, v15, m6, m7)
        g_v(v0, v5, v10, v15, m8, m9)
        g_v(v1, v6, v11, v12, m10, m11)
        g_v(v2, v7, v8, v13, m12, m13)
        g_v(v3, v4, v9, v14, m14, m15)

    round(
        v0,
        v1,
        v2,
        v3,
        v4,
        v5,
        v6,
        v7,
        v8,
        v9,
        v10,
        v11,
        v12,
        v13,
        v14,
        v15,
        m0,
        m1,
        m2,
        m3,
        m4,
        m5,
        m6,
        m7,
        m8,
        m9,
        m10,
        m11,
        m12,
        m13,
        m14,
        m15,
    )
    var t0 = m2
    var t1 = m6
    var t2 = m3
    var t3 = m10
    var t4 = m7
    var t5 = m0
    var t6 = m4
    var t7 = m13
    var t8 = m1
    var t9 = m11
    var t10 = m12
    var t11 = m5
    var t12 = m9
    var t13 = m14
    var t14 = m15
    var t15 = m8
    round(
        v0,
        v1,
        v2,
        v3,
        v4,
        v5,
        v6,
        v7,
        v8,
        v9,
        v10,
        v11,
        v12,
        v13,
        v14,
        v15,
        t0,
        t1,
        t2,
        t3,
        t4,
        t5,
        t6,
        t7,
        t8,
        t9,
        t10,
        t11,
        t12,
        t13,
        t14,
        t15,
    )
    var u0 = t2
    var u1 = t6
    var u2 = t3
    var u3 = t10
    var u4 = t7
    var u5 = t0
    var u6 = t4
    var u7 = t13
    var u8 = t1
    var u9 = t11
    var u10 = t12
    var u11 = t5
    var u12 = t9
    var u13 = t14
    var u14 = t15
    var u15 = t8
    round(
        v0,
        v1,
        v2,
        v3,
        v4,
        v5,
        v6,
        v7,
        v8,
        v9,
        v10,
        v11,
        v12,
        v13,
        v14,
        v15,
        u0,
        u1,
        u2,
        u3,
        u4,
        u5,
        u6,
        u7,
        u8,
        u9,
        u10,
        u11,
        u12,
        u13,
        u14,
        u15,
    )
    var w0 = u2
    var w1 = u6
    var w2 = u3
    var w3 = u10
    var w4 = u7
    var w5 = u0
    var w6 = u4
    var w7 = u13
    var w8 = u1
    var w9 = u11
    var w10 = u12
    var w11 = u5
    var w12 = u9
    var w13 = u14
    var w14 = u15
    var w15 = u8
    round(
        v0,
        v1,
        v2,
        v3,
        v4,
        v5,
        v6,
        v7,
        v8,
        v9,
        v10,
        v11,
        v12,
        v13,
        v14,
        v15,
        w0,
        w1,
        w2,
        w3,
        w4,
        w5,
        w6,
        w7,
        w8,
        w9,
        w10,
        w11,
        w12,
        w13,
        w14,
        w15,
    )
    var x0 = w2
    var x1 = w6
    var x2 = w3
    var x3 = w10
    var x4 = w7
    var x5 = w0
    var x6 = w4
    var x7 = w13
    var x8 = w1
    var x9 = w11
    var x10 = w12
    var x11 = w5
    var x12 = w9
    var x13 = w14
    var x14 = w15
    var x15 = w8
    round(
        v0,
        v1,
        v2,
        v3,
        v4,
        v5,
        v6,
        v7,
        v8,
        v9,
        v10,
        v11,
        v12,
        v13,
        v14,
        v15,
        x0,
        x1,
        x2,
        x3,
        x4,
        x5,
        x6,
        x7,
        x8,
        x9,
        x10,
        x11,
        x12,
        x13,
        x14,
        x15,
    )
    var y0 = x2
    var y1 = x6
    var y2 = x3
    var y3 = x10
    var y4 = x7
    var y5 = x0
    var y6 = x4
    var y7 = x13
    var y8 = x1
    var y9 = x11
    var y10 = x12
    var y11 = x5
    var y12 = x9
    var y13 = x14
    var y14 = x15
    var y15 = x8
    round(
        v0,
        v1,
        v2,
        v3,
        v4,
        v5,
        v6,
        v7,
        v8,
        v9,
        v10,
        v11,
        v12,
        v13,
        v14,
        v15,
        y0,
        y1,
        y2,
        y3,
        y4,
        y5,
        y6,
        y7,
        y8,
        y9,
        y10,
        y11,
        y12,
        y13,
        y14,
        y15,
    )
    var z0 = y2
    var z1 = y6
    var z2 = y3
    var z3 = y10
    var z4 = y7
    var z5 = y0
    var z6 = y4
    var z7 = y13
    var z8 = y1
    var z9 = y11
    var z10 = y12
    var z11 = y5
    var z12 = y9
    var z13 = y14
    var z14 = y15
    var z15 = y8
    round(
        v0,
        v1,
        v2,
        v3,
        v4,
        v5,
        v6,
        v7,
        v8,
        v9,
        v10,
        v11,
        v12,
        v13,
        v14,
        v15,
        z0,
        z1,
        z2,
        z3,
        z4,
        z5,
        z6,
        z7,
        z8,
        z9,
        z10,
        z11,
        z12,
        z13,
        z14,
        z15,
    )

    out_ptr[0] = v0
    out_ptr[1] = v1
    out_ptr[2] = v2
    out_ptr[3] = v3
    out_ptr[4] = v4
    out_ptr[5] = v5
    out_ptr[6] = v6
    out_ptr[7] = v7
    out_ptr[8] = v8
    out_ptr[9] = v9
    out_ptr[10] = v10
    out_ptr[11] = v11
    out_ptr[12] = v12
    out_ptr[13] = v13
    out_ptr[14] = v14
    out_ptr[15] = v15


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
    var m0 = block[0]
    var m1 = block[1]
    var m2 = block[2]
    var m3 = block[3]
    var m4 = block[4]
    var m5 = block[5]
    var m6 = block[6]
    var m7 = block[7]
    var m8 = block[8]
    var m9 = block[9]
    var m10 = block[10]
    var m11 = block[11]
    var m12 = block[12]
    var m13 = block[13]
    var m14 = block[14]
    var m15 = block[15]

    var res = stack_allocation[16, SIMD[DType.uint32, 1]]()
    compress_internal[1](
        cv,
        m0,
        m1,
        m2,
        m3,
        m4,
        m5,
        m6,
        m7,
        m8,
        m9,
        m10,
        m11,
        m12,
        m13,
        m14,
        m15,
        counter,
        blen,
        flags,
        res,
    )
    var final = SIMD[DType.uint32, 16]()
    for i in range(8):
        final[i] = res[i][0] ^ res[i + 8][0]
        final[i + 8] = res[i + 8][0] ^ cv[i]
    return final


@always_inline
fn compress_internal_16way(
    c0: SIMD[DType.uint32, 16],
    c1: SIMD[DType.uint32, 16],
    c2: SIMD[DType.uint32, 16],
    c3: SIMD[DType.uint32, 16],
    c4: SIMD[DType.uint32, 16],
    c5: SIMD[DType.uint32, 16],
    c6: SIMD[DType.uint32, 16],
    c7: SIMD[DType.uint32, 16],
    mut m0: SIMD[DType.uint32, 16],
    mut m1: SIMD[DType.uint32, 16],
    mut m2: SIMD[DType.uint32, 16],
    mut m3: SIMD[DType.uint32, 16],
    mut m4: SIMD[DType.uint32, 16],
    mut m5: SIMD[DType.uint32, 16],
    mut m6: SIMD[DType.uint32, 16],
    mut m7: SIMD[DType.uint32, 16],
    mut m8: SIMD[DType.uint32, 16],
    mut m9: SIMD[DType.uint32, 16],
    mut m10: SIMD[DType.uint32, 16],
    mut m11: SIMD[DType.uint32, 16],
    mut m12: SIMD[DType.uint32, 16],
    mut m13: SIMD[DType.uint32, 16],
    mut m14: SIMD[DType.uint32, 16],
    mut m15: SIMD[DType.uint32, 16],
    base_counter: UInt64,
    blen: UInt8,
    flags: UInt8,
    out_ptr: UnsafePointer[SIMD[DType.uint32, 16], MutAnyOrigin],
):
    """16-way SIMD internal compression.

    Args:
        c0: State vector 0.
        c1: State vector 1.
        c2: State vector 2.
        c3: State vector 3.
        c4: State vector 4.
        c5: State vector 5.
        c6: State vector 6.
        c7: State vector 7.
        m0: Message vector 0.
        m1: Message vector 1.
        m2: Message vector 2.
        m3: Message vector 3.
        m4: Message vector 4.
        m5: Message vector 5.
        m6: Message vector 6.
        m7: Message vector 7.
        m8: Message vector 8.
        m9: Message vector 9.
        m10: Message vector 10.
        m11: Message vector 11.
        m12: Message vector 12.
        m13: Message vector 13.
        m14: Message vector 14.
        m15: Message vector 15.
        base_counter: Starting counter for the 16-way batch.
        blen: Block length.
        flags: Flag byte.
        out_ptr: The output pointer to store the resulting 8 vectors of 16-way SIMD words.
    """
    var v0 = c0
    var v1 = c1
    var v2 = c2
    var v3 = c3
    var v4 = c4
    var v5 = c5
    var v6 = c6
    var v7 = c7
    var v8 = SIMD[DType.uint32, 16](IV[0])
    var v9 = SIMD[DType.uint32, 16](IV[1])
    var v10 = SIMD[DType.uint32, 16](IV[2])
    var v11 = SIMD[DType.uint32, 16](IV[3])

    # Per-lane sequential counters
    var counters_low = SIMD[DType.uint32, 16](
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    )
    counters_low += UInt32(base_counter & 0xFFFFFFFF)
    var v12 = counters_low
    var v13 = SIMD[DType.uint32, 16](UInt32(base_counter >> 32))
    var v14 = SIMD[DType.uint32, 16](UInt32(blen))
    var v15 = SIMD[DType.uint32, 16](UInt32(flags))

    @always_inline
    fn round(
        mut v0: SIMD[DType.uint32, 16],
        mut v1: SIMD[DType.uint32, 16],
        mut v2: SIMD[DType.uint32, 16],
        mut v3: SIMD[DType.uint32, 16],
        mut v4: SIMD[DType.uint32, 16],
        mut v5: SIMD[DType.uint32, 16],
        mut v6: SIMD[DType.uint32, 16],
        mut v7: SIMD[DType.uint32, 16],
        mut v8: SIMD[DType.uint32, 16],
        mut v9: SIMD[DType.uint32, 16],
        mut v10: SIMD[DType.uint32, 16],
        mut v11: SIMD[DType.uint32, 16],
        mut v12: SIMD[DType.uint32, 16],
        mut v13: SIMD[DType.uint32, 16],
        mut v14: SIMD[DType.uint32, 16],
        mut v15: SIMD[DType.uint32, 16],
        m0: SIMD[DType.uint32, 16],
        m1: SIMD[DType.uint32, 16],
        m2: SIMD[DType.uint32, 16],
        m3: SIMD[DType.uint32, 16],
        m4: SIMD[DType.uint32, 16],
        m5: SIMD[DType.uint32, 16],
        m6: SIMD[DType.uint32, 16],
        m7: SIMD[DType.uint32, 16],
        m8: SIMD[DType.uint32, 16],
        m9: SIMD[DType.uint32, 16],
        m10: SIMD[DType.uint32, 16],
        m11: SIMD[DType.uint32, 16],
        m12: SIMD[DType.uint32, 16],
        m13: SIMD[DType.uint32, 16],
        m14: SIMD[DType.uint32, 16],
        m15: SIMD[DType.uint32, 16],
    ):
        g_v[16](v0, v4, v8, v12, m0, m1)
        g_v[16](v1, v5, v9, v13, m2, m3)
        g_v[16](v2, v6, v10, v14, m4, m5)
        g_v[16](v3, v7, v11, v15, m6, m7)
        g_v[16](v0, v5, v10, v15, m8, m9)
        g_v[16](v1, v6, v11, v12, m10, m11)
        g_v[16](v2, v7, v8, v13, m12, m13)
        g_v[16](v3, v4, v9, v14, m14, m15)

    round(
        v0,
        v1,
        v2,
        v3,
        v4,
        v5,
        v6,
        v7,
        v8,
        v9,
        v10,
        v11,
        v12,
        v13,
        v14,
        v15,
        m0,
        m1,
        m2,
        m3,
        m4,
        m5,
        m6,
        m7,
        m8,
        m9,
        m10,
        m11,
        m12,
        m13,
        m14,
        m15,
    )
    var t0 = m2
    var t1 = m6
    var t2 = m3
    var t3 = m10
    var t4 = m7
    var t5 = m0
    var t6 = m4
    var t7 = m13
    var t8 = m1
    var t9 = m11
    var t10 = m12
    var t11 = m5
    var t12 = m9
    var t13 = m14
    var t14 = m15
    var t15 = m8
    round(
        v0,
        v1,
        v2,
        v3,
        v4,
        v5,
        v6,
        v7,
        v8,
        v9,
        v10,
        v11,
        v12,
        v13,
        v14,
        v15,
        t0,
        t1,
        t2,
        t3,
        t4,
        t5,
        t6,
        t7,
        t8,
        t9,
        t10,
        t11,
        t12,
        t13,
        t14,
        t15,
    )
    var u0 = t2
    var u1 = t6
    var u2 = t3
    var u3 = t10
    var u4 = t7
    var u5 = t0
    var u6 = t4
    var u7 = t13
    var u8 = t1
    var u9 = t11
    var u10 = t12
    var u11 = t5
    var u12 = t9
    var u13 = t14
    var u14 = t15
    var u15 = t8
    round(
        v0,
        v1,
        v2,
        v3,
        v4,
        v5,
        v6,
        v7,
        v8,
        v9,
        v10,
        v11,
        v12,
        v13,
        v14,
        v15,
        u0,
        u1,
        u2,
        u3,
        u4,
        u5,
        u6,
        u7,
        u8,
        u9,
        u10,
        u11,
        u12,
        u13,
        u14,
        u15,
    )
    var w0 = u2
    var w1 = u6
    var w2 = u3
    var w3 = u10
    var w4 = u7
    var w5 = u0
    var w6 = u4
    var w7 = u13
    var w8 = u1
    var w9 = u11
    var w10 = u12
    var w11 = u5
    var w12 = u9
    var w13 = u14
    var w14 = u15
    var w15 = u8
    round(
        v0,
        v1,
        v2,
        v3,
        v4,
        v5,
        v6,
        v7,
        v8,
        v9,
        v10,
        v11,
        v12,
        v13,
        v14,
        v15,
        w0,
        w1,
        w2,
        w3,
        w4,
        w5,
        w6,
        w7,
        w8,
        w9,
        w10,
        w11,
        w12,
        w13,
        w14,
        w15,
    )
    var x0 = w2
    var x1 = w6
    var x2 = w3
    var x3 = w10
    var x4 = w7
    var x5 = w0
    var x6 = w4
    var x7 = w13
    var x8 = w1
    var x9 = w11
    var x10 = w12
    var x11 = w5
    var x12 = w9
    var x13 = w14
    var x14 = w15
    var x15 = w8
    round(
        v0,
        v1,
        v2,
        v3,
        v4,
        v5,
        v6,
        v7,
        v8,
        v9,
        v10,
        v11,
        v12,
        v13,
        v14,
        v15,
        x0,
        x1,
        x2,
        x3,
        x4,
        x5,
        x6,
        x7,
        x8,
        x9,
        x10,
        x11,
        x12,
        x13,
        x14,
        x15,
    )
    var y0 = x2
    var y1 = x6
    var y2 = x3
    var y3 = x10
    var y4 = x7
    var y5 = x0
    var y6 = x4
    var y7 = x13
    var y8 = x1
    var y9 = x11
    var y10 = x12
    var y11 = x5
    var y12 = x9
    var y13 = x14
    var y14 = x15
    var y15 = x8
    round(
        v0,
        v1,
        v2,
        v3,
        v4,
        v5,
        v6,
        v7,
        v8,
        v9,
        v10,
        v11,
        v12,
        v13,
        v14,
        v15,
        y0,
        y1,
        y2,
        y3,
        y4,
        y5,
        y6,
        y7,
        y8,
        y9,
        y10,
        y11,
        y12,
        y13,
        y14,
        y15,
    )
    var z0 = y2
    var z1 = y6
    var z2 = y3
    var z3 = y10
    var z4 = y7
    var z5 = y0
    var z6 = y4
    var z7 = y13
    var z8 = y1
    var z9 = y11
    var z10 = y12
    var z11 = y5
    var z12 = y9
    var z13 = y14
    var z14 = y15
    var z15 = y8
    round(
        v0,
        v1,
        v2,
        v3,
        v4,
        v5,
        v6,
        v7,
        v8,
        v9,
        v10,
        v11,
        v12,
        v13,
        v14,
        v15,
        z0,
        z1,
        z2,
        z3,
        z4,
        z5,
        z6,
        z7,
        z8,
        z9,
        z10,
        z11,
        z12,
        z13,
        z14,
        z15,
    )

    out_ptr[0] = v0 ^ v8
    out_ptr[1] = v1 ^ v9
    out_ptr[2] = v2 ^ v10
    out_ptr[3] = v3 ^ v11
    out_ptr[4] = v4 ^ v12
    out_ptr[5] = v5 ^ v13
    out_ptr[6] = v6 ^ v14
    out_ptr[7] = v7 ^ v15


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
    var v0 = SIMD[DType.uint32, 8](cv[0])
    var v1 = SIMD[DType.uint32, 8](cv[1])
    var v2 = SIMD[DType.uint32, 8](cv[2])
    var v3 = SIMD[DType.uint32, 8](cv[3])
    var v4 = SIMD[DType.uint32, 8](cv[4])
    var v5 = SIMD[DType.uint32, 8](cv[5])
    var v6 = SIMD[DType.uint32, 8](cv[6])
    var v7 = SIMD[DType.uint32, 8](cv[7])
    var v8 = SIMD[DType.uint32, 8](IV[0])
    var v9 = SIMD[DType.uint32, 8](IV[1])
    var v10 = SIMD[DType.uint32, 8](IV[2])
    var v11 = SIMD[DType.uint32, 8](IV[3])
    var v12 = SIMD[DType.uint32, 8](UInt32(base_counter & 0xFFFFFFFF)) + SIMD[
        DType.uint32, 8
    ](0, 1, 2, 3, 4, 5, 6, 7)
    var v13 = SIMD[DType.uint32, 8](UInt32(base_counter >> 32))
    var v14 = SIMD[DType.uint32, 8](UInt32(blen))
    var v15 = SIMD[DType.uint32, 8](UInt32(flags))

    # Round 0
    g_vertical(v0, v4, v8, v12, m[0], m[1])
    g_vertical(v1, v5, v9, v13, m[2], m[3])
    g_vertical(v2, v6, v10, v14, m[4], m[5])
    g_vertical(v3, v7, v11, v15, m[6], m[7])
    g_vertical(v0, v5, v10, v15, m[8], m[9])
    g_vertical(v1, v6, v11, v12, m[10], m[11])
    g_vertical(v2, v7, v8, v13, m[12], m[13])
    g_vertical(v3, v4, v9, v14, m[14], m[15])

    # Round 1
    g_vertical(v0, v4, v8, v12, m[2], m[6])
    g_vertical(v1, v5, v9, v13, m[3], m[10])
    g_vertical(v2, v6, v10, v14, m[7], m[0])
    g_vertical(v3, v7, v11, v15, m[4], m[13])
    g_vertical(v0, v5, v10, v15, m[1], m[11])
    g_vertical(v1, v6, v11, v12, m[12], m[5])
    g_vertical(v2, v7, v8, v13, m[9], m[14])
    g_vertical(v3, v4, v9, v14, m[15], m[8])

    # Round 2
    g_vertical(v0, v4, v8, v12, m[3], m[4])
    g_vertical(v1, v5, v9, v13, m[10], m[12])
    g_vertical(v2, v6, v10, v14, m[13], m[2])
    g_vertical(v3, v7, v11, v15, m[7], m[14])
    g_vertical(v0, v5, v10, v15, m[6], m[5])
    g_vertical(v1, v6, v11, v12, m[9], m[0])
    g_vertical(v2, v7, v8, v13, m[11], m[15])
    g_vertical(v3, v4, v9, v14, m[8], m[1])

    # Round 3
    g_vertical(v0, v4, v8, v12, m[10], m[7])
    g_vertical(v1, v5, v9, v13, m[12], m[9])
    g_vertical(v2, v6, v10, v14, m[14], m[3])
    g_vertical(v3, v7, v11, v15, m[13], m[15])
    g_vertical(v0, v5, v10, v15, m[4], m[0])
    g_vertical(v1, v6, v11, v12, m[11], m[2])
    g_vertical(v2, v7, v8, v13, m[5], m[8])
    g_vertical(v3, v4, v9, v14, m[1], m[6])

    # Round 4
    g_vertical(v0, v4, v8, v12, m[12], m[13])
    g_vertical(v1, v5, v9, v13, m[9], m[11])
    g_vertical(v2, v6, v10, v14, m[15], m[10])
    g_vertical(v3, v7, v11, v15, m[14], m[8])
    g_vertical(v0, v5, v10, v15, m[7], m[2])
    g_vertical(v1, v6, v11, v12, m[5], m[3])
    g_vertical(v2, v7, v8, v13, m[0], m[1])
    g_vertical(v3, v4, v9, v14, m[6], m[4])

    # Round 5
    g_vertical(v0, v4, v8, v12, m[9], m[14])
    g_vertical(v1, v5, v9, v13, m[11], m[5])
    g_vertical(v2, v6, v10, v14, m[8], m[12])
    g_vertical(v3, v7, v11, v15, m[15], m[1])
    g_vertical(v0, v5, v10, v15, m[13], m[3])
    g_vertical(v1, v6, v11, v12, m[0], m[10])
    g_vertical(v2, v7, v8, v13, m[2], m[6])
    g_vertical(v3, v4, v9, v14, m[4], m[7])

    # Round 6
    g_vertical(v0, v4, v8, v12, m[11], m[15])
    g_vertical(v1, v5, v9, v13, m[5], m[0])
    g_vertical(v2, v6, v10, v14, m[1], m[9])
    g_vertical(v3, v7, v11, v15, m[8], m[6])
    g_vertical(v0, v5, v10, v15, m[9], m[10])
    g_vertical(v1, v6, v11, v12, m[14], m[2])
    g_vertical(v2, v7, v8, v13, m[3], m[4])
    g_vertical(v3, v4, v9, v14, m[7], m[13])

    out_ptr[0] = v0 ^ v8
    out_ptr[1] = v1 ^ v9
    out_ptr[2] = v2 ^ v10
    out_ptr[3] = v3 ^ v11
    out_ptr[4] = v4 ^ v12
    out_ptr[5] = v5 ^ v13
    out_ptr[6] = v6 ^ v14
    out_ptr[7] = v7 ^ v15


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
    var va0 = SIMD[DType.uint32, 8]()
    var va1 = SIMD[DType.uint32, 8]()
    var va2 = SIMD[DType.uint32, 8]()
    var va3 = SIMD[DType.uint32, 8]()
    var va4 = SIMD[DType.uint32, 8]()
    var va5 = SIMD[DType.uint32, 8]()
    var va6 = SIMD[DType.uint32, 8]()
    var va7 = SIMD[DType.uint32, 8]()
    for k in range(8):
        va0[k] = cv_lanes[k][0]
        va1[k] = cv_lanes[k][1]
        va2[k] = cv_lanes[k][2]
        va3[k] = cv_lanes[k][3]
        va4[k] = cv_lanes[k][4]
        va5[k] = cv_lanes[k][5]
        va6[k] = cv_lanes[k][6]
        va7[k] = cv_lanes[k][7]

    var vb0 = SIMD[DType.uint32, 8]()
    var vb1 = SIMD[DType.uint32, 8]()
    var vb2 = SIMD[DType.uint32, 8]()
    var vb3 = SIMD[DType.uint32, 8]()
    var vb4 = SIMD[DType.uint32, 8]()
    var vb5 = SIMD[DType.uint32, 8]()
    var vb6 = SIMD[DType.uint32, 8]()
    var vb7 = SIMD[DType.uint32, 8]()
    for k in range(8):
        vb0[k] = cv_lanes[k + 8][0]
        vb1[k] = cv_lanes[k + 8][1]
        vb2[k] = cv_lanes[k + 8][2]
        vb3[k] = cv_lanes[k + 8][3]
        vb4[k] = cv_lanes[k + 8][4]
        vb5[k] = cv_lanes[k + 8][5]
        vb6[k] = cv_lanes[k + 8][6]
        vb7[k] = cv_lanes[k + 8][7]

    var va8 = SIMD[DType.uint32, 8](IV[0])
    var va9 = SIMD[DType.uint32, 8](IV[1])
    var va10 = SIMD[DType.uint32, 8](IV[2])
    var va11 = SIMD[DType.uint32, 8](IV[3])
    var va12 = SIMD[DType.uint32, 8](UInt32(base_counter & 0xFFFFFFFF)) + SIMD[
        DType.uint32, 8
    ](0, 1, 2, 3, 4, 5, 6, 7)
    var va13 = SIMD[DType.uint32, 8](UInt32(base_counter >> 32))
    var va14 = SIMD[DType.uint32, 8](UInt32(blen))
    var va15 = SIMD[DType.uint32, 8](UInt32(flags))

    var vb8 = SIMD[DType.uint32, 8](IV[0])
    var vb9 = SIMD[DType.uint32, 8](IV[1])
    var vb10 = SIMD[DType.uint32, 8](IV[2])
    var vb11 = SIMD[DType.uint32, 8](IV[3])
    var vb12 = SIMD[DType.uint32, 8](UInt32(base_counter & 0xFFFFFFFF)) + SIMD[
        DType.uint32, 8
    ](8, 9, 10, 11, 12, 13, 14, 15)
    var vb13 = SIMD[DType.uint32, 8](UInt32(base_counter >> 32))
    var vb14 = SIMD[DType.uint32, 8](UInt32(blen))
    var vb15 = SIMD[DType.uint32, 8](UInt32(flags))

    # Round 0
    g_vertical(va0, va4, va8, va12, ma[0], ma[1])
    g_vertical(vb0, vb4, vb8, vb12, mb[0], mb[1])
    g_vertical(va1, va5, va9, va13, ma[2], ma[3])
    g_vertical(vb1, vb5, vb9, vb13, mb[2], mb[3])
    g_vertical(va2, va6, va10, va14, ma[4], ma[5])
    g_vertical(vb2, vb6, vb10, vb14, mb[4], mb[5])
    g_vertical(va3, va7, va11, va15, ma[6], ma[7])
    g_vertical(vb3, vb7, vb11, vb15, mb[6], mb[7])
    g_vertical(va0, va5, va10, va15, ma[8], ma[9])
    g_vertical(vb0, vb5, vb10, vb15, mb[8], mb[9])
    g_vertical(va1, va6, va11, va12, ma[10], ma[11])
    g_vertical(vb1, vb6, vb11, vb12, mb[10], mb[11])
    g_vertical(va2, va7, va8, va13, ma[12], ma[13])
    g_vertical(vb2, vb7, vb8, vb13, mb[12], mb[13])
    g_vertical(va3, va4, va9, va14, ma[14], ma[15])
    g_vertical(vb3, vb4, vb9, vb14, mb[14], mb[15])

    # Round 1
    g_vertical(va0, va4, va8, va12, ma[2], ma[6])
    g_vertical(vb0, vb4, vb8, vb12, mb[2], mb[6])
    g_vertical(va1, va5, va9, va13, ma[3], ma[10])
    g_vertical(vb1, vb5, vb9, vb13, mb[3], mb[10])
    g_vertical(va2, va6, va10, va14, ma[7], ma[0])
    g_vertical(vb2, vb6, vb10, vb14, mb[7], mb[0])
    g_vertical(va3, va7, va11, va15, ma[4], ma[13])
    g_vertical(vb3, vb7, vb11, vb15, mb[4], mb[13])
    g_vertical(va0, va5, va10, va15, ma[1], ma[11])
    g_vertical(vb0, vb5, vb10, vb15, mb[1], mb[11])
    g_vertical(va1, va6, va11, va12, ma[12], ma[5])
    g_vertical(vb1, vb6, vb11, vb12, mb[12], mb[5])
    g_vertical(va2, va7, va8, va13, ma[9], ma[14])
    g_vertical(vb2, vb7, vb8, vb13, mb[9], mb[14])
    g_vertical(va3, va4, va9, va14, ma[15], ma[8])
    g_vertical(vb3, vb4, vb9, vb14, mb[15], mb[8])

    # Round 2
    g_vertical(va0, va4, va8, va12, ma[3], ma[4])
    g_vertical(vb0, vb4, vb8, vb12, mb[3], mb[4])
    g_vertical(va1, va5, va9, va13, ma[10], ma[12])
    g_vertical(vb1, vb5, vb9, vb13, mb[10], mb[12])
    g_vertical(va2, va6, va10, va14, ma[13], ma[2])
    g_vertical(vb2, vb6, vb10, vb14, mb[13], mb[2])
    g_vertical(va3, va7, va11, va15, ma[7], ma[14])
    g_vertical(vb3, vb7, vb11, vb15, mb[7], mb[14])
    g_vertical(va0, va5, va10, va15, ma[6], ma[5])
    g_vertical(vb0, vb5, vb10, vb15, mb[6], mb[5])
    g_vertical(va1, va6, va11, va12, ma[9], ma[0])
    g_vertical(vb1, vb6, vb11, vb12, mb[9], mb[0])
    g_vertical(va2, va7, va8, va13, ma[11], ma[15])
    g_vertical(vb2, vb7, vb8, vb13, mb[11], mb[15])
    g_vertical(va3, va4, va9, va14, ma[8], ma[1])
    g_vertical(vb3, vb4, vb9, vb14, mb[8], mb[1])

    # Round 3
    g_vertical(va0, va4, va8, va12, ma[10], ma[7])
    g_vertical(vb0, vb4, vb8, vb12, mb[10], mb[7])
    g_vertical(va1, va5, va9, va13, ma[12], ma[9])
    g_vertical(vb1, vb5, vb9, vb13, mb[12], mb[9])
    g_vertical(va2, va6, va10, va14, ma[14], ma[3])
    g_vertical(vb2, vb6, vb10, vb14, mb[14], mb[3])
    g_vertical(va3, va7, va11, va15, ma[13], ma[15])
    g_vertical(vb3, vb7, vb11, vb15, mb[13], mb[15])
    g_vertical(va0, va5, va10, va15, ma[4], ma[0])
    g_vertical(vb0, vb5, vb10, vb15, mb[4], mb[0])
    g_vertical(va1, va6, va11, va12, ma[11], ma[2])
    g_vertical(vb1, vb6, vb11, vb12, mb[11], mb[2])
    g_vertical(va2, va7, va8, va13, ma[5], ma[8])
    g_vertical(vb2, vb7, vb8, vb13, mb[5], mb[8])
    g_vertical(va3, va4, va9, va14, ma[1], ma[6])
    g_vertical(vb3, vb4, vb9, vb14, mb[1], mb[6])

    # Round 4
    g_vertical(va0, va4, va8, va12, ma[12], ma[13])
    g_vertical(vb0, vb4, vb8, vb12, mb[12], mb[13])
    g_vertical(va1, va5, va9, va13, ma[9], ma[11])
    g_vertical(vb1, vb5, vb9, vb13, mb[9], mb[11])
    g_vertical(va2, va6, va10, va14, ma[15], ma[10])
    g_vertical(vb2, vb6, vb10, vb14, mb[15], mb[10])
    g_vertical(va3, va7, va11, va15, ma[14], ma[8])
    g_vertical(vb3, vb7, vb11, vb15, mb[14], mb[8])
    g_vertical(va0, va5, va10, va15, ma[7], ma[2])
    g_vertical(vb0, vb5, vb10, vb15, mb[7], mb[2])
    g_vertical(va1, va6, va11, va12, ma[5], ma[3])
    g_vertical(vb1, vb6, vb11, vb12, mb[5], mb[3])
    g_vertical(va2, va7, va8, va13, ma[0], ma[1])
    g_vertical(vb2, vb7, vb8, vb13, mb[0], mb[1])
    g_vertical(va3, va4, va9, va14, ma[6], ma[4])
    g_vertical(vb3, vb4, vb9, vb14, mb[6], mb[4])

    # Round 5
    g_vertical(va0, va4, va8, va12, ma[9], ma[14])
    g_vertical(vb0, vb4, vb8, vb12, mb[9], mb[14])
    g_vertical(va1, va5, va9, va13, ma[11], ma[5])
    g_vertical(vb1, vb5, vb9, vb13, mb[11], mb[5])
    g_vertical(va2, va6, va10, va14, ma[8], ma[12])
    g_vertical(vb2, vb6, vb10, vb14, mb[8], mb[12])
    g_vertical(va3, va7, va11, va15, ma[15], ma[1])
    g_vertical(vb3, vb7, vb11, vb15, mb[15], mb[1])
    g_vertical(va0, va5, va10, va15, ma[13], ma[3])
    g_vertical(vb0, vb5, vb10, vb15, mb[13], mb[3])
    g_vertical(va1, va6, va11, va12, ma[0], ma[10])
    g_vertical(vb1, vb6, vb11, vb12, mb[0], mb[10])
    g_vertical(va2, va7, va8, va13, ma[2], ma[6])
    g_vertical(vb2, vb7, vb8, vb13, mb[2], mb[6])
    g_vertical(va3, va4, va9, va14, ma[4], ma[7])
    g_vertical(vb3, vb4, vb9, vb14, mb[4], mb[7])

    # Round 6
    g_vertical(va0, va4, va8, va12, ma[11], ma[15])
    g_vertical(vb0, vb4, vb8, vb12, mb[11], mb[15])
    g_vertical(va1, va5, va9, va13, ma[5], ma[0])
    g_vertical(vb1, vb5, vb9, vb13, mb[5], mb[0])
    g_vertical(va2, va6, va10, va14, ma[1], ma[9])
    g_vertical(vb2, vb6, vb10, vb14, mb[1], mb[9])
    g_vertical(va3, va7, va11, va15, ma[8], ma[6])
    g_vertical(vb3, vb7, vb11, vb15, mb[8], mb[6])
    g_vertical(va0, va5, va10, va15, ma[9], ma[10])
    g_vertical(vb0, vb5, vb10, vb15, mb[9], mb[10])
    g_vertical(va1, va6, va11, va12, ma[14], ma[2])
    g_vertical(vb1, vb6, vb11, vb12, mb[14], mb[2])
    g_vertical(va2, va7, va8, va13, ma[3], ma[4])
    g_vertical(vb2, vb7, vb8, vb13, mb[3], mb[4])
    g_vertical(va3, va4, va9, va14, ma[7], ma[13])
    g_vertical(vb3, vb4, vb9, vb14, mb[7], mb[13])

    var res_a0 = va0 ^ va8
    var res_a1 = va1 ^ va9
    var res_a2 = va2 ^ va10
    var res_a3 = va3 ^ va11
    var res_a4 = va4 ^ va12
    var res_a5 = va5 ^ va13
    var res_a6 = va6 ^ va14
    var res_a7 = va7 ^ va15

    var res_b0 = vb0 ^ vb8
    var res_b1 = vb1 ^ vb9
    var res_b2 = vb2 ^ vb10
    var res_b3 = vb3 ^ vb11
    var res_b4 = vb4 ^ vb12
    var res_b5 = vb5 ^ vb13
    var res_b6 = vb6 ^ vb14
    var res_b7 = vb7 ^ vb15

    # Reverse transpose
    for k in range(8):
        out_ptr[k] = SIMD[DType.uint32, 8](
            res_a0[k],
            res_a1[k],
            res_a2[k],
            res_a3[k],
            res_a4[k],
            res_a5[k],
            res_a6[k],
            res_a7[k],
        )
        out_ptr[k + 8] = SIMD[DType.uint32, 8](
            res_b0[k],
            res_b1[k],
            res_b2[k],
            res_b3[k],
            res_b4[k],
            res_b5[k],
            res_b6[k],
            res_b7[k],
        )


struct Hasher:
    var key: SIMD[DType.uint32, 8]
    var original_key: SIMD[DType.uint32, 8]
    var cv_stack: UnsafePointer[SIMD[DType.uint32, 8], MutExternalOrigin]
    var stack_len: Int
    var buf: UnsafePointer[UInt8, MutExternalOrigin]
    var buf_len: Int
    var chunk_counter: UInt64
    var blocks_compressed: Int

    fn __init__(out self):
        self.key = IV
        self.original_key = IV
        # Allocate space for 54 SIMD8 vectors (UInt32)
        # Currently Mojo OwnedPointer (Heap based) or InlineArray will cause huge bounds checking.
        # When the compiler improves we might switch to InlineArray as it's not that big of a difference in speed.
        self.cv_stack = alloc[SIMD[DType.uint32, 8]](54)

        self.stack_len = 0

        self.buf = alloc[UInt8](64)

        self.buf_len = 0
        self.chunk_counter = 0
        self.blocks_compressed = 0

    fn __deinit__(mut self):
        self.cv_stack.free()
        self.buf.free()

    fn update(mut self, input: Span[UInt8]):
        var d = input
        while len(d) > 0:
            if self.buf_len == 64:
                var blk = (
                    # Note: Defaults to AVX2 (AVX-512 = Width 32)
                    # Will need to use Sys to set targets any target that dooesn't support AVX2 will spill (ARM)
                    # Sys is just a pain to use at the moment there's like hundreds of targets so it's useless to try and target all cpus.
                    self.buf.bitcast[UInt32]().load[width=16]()
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
                        var chunk_cv = SIMD[DType.uint32, 8](
                            res[0],
                            res[1],
                            res[2],
                            res[3],
                            res[4],
                            res[5],
                            res[6],
                            res[7],
                        )
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
                    self.key = SIMD[DType.uint32, 8](
                        res[0],
                        res[1],
                        res[2],
                        res[3],
                        res[4],
                        res[5],
                        res[6],
                        res[7],
                    )
                    self.blocks_compressed += 1
                    self.buf_len = 0

            var take = min(len(d), 64 - self.buf_len)
            for i in range(take):
                (self.buf + self.buf_len + i)[] = d[i]
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
            var left = (self.cv_stack + (self.stack_len - 1))[]
            var res = compress_core(
                self.original_key, left.join(new_cv), 0, 64, PARENT
            )
            new_cv = SIMD[DType.uint32, 8](
                res[0], res[1], res[2], res[3], res[4], res[5], res[6], res[7]
            )
            self.stack_len -= 1
        (self.cv_stack + self.stack_len)[] = new_cv
        self.stack_len += 1

    @always_inline
    fn add_subtree_cv(mut self, cv_in: SIMD[DType.uint32, 8], height: Int):
        var new_cv = cv_in
        self.chunk_counter += UInt64(1) << height
        var total_at_level = self.chunk_counter >> height

        while (total_at_level & 1) == 0 and self.stack_len > 0:
            var left = (self.cv_stack + (self.stack_len - 1))[]
            var res = compress_core(
                self.original_key, left.join(new_cv), 0, 64, PARENT
            )
            new_cv = SIMD[DType.uint32, 8](
                res[0], res[1], res[2], res[3], res[4], res[5], res[6], res[7]
            )
            self.stack_len -= 1
            total_at_level >>= 1

        (self.cv_stack + self.stack_len)[] = new_cv
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
        var temp_buf = stack_allocation[64, UInt8]()
        # Initialize temp_buf to 0 and copy self.buf
        for i in range(64):
            if i < self.buf_len:
                temp_buf[i] = self.buf[i]
            else:
                temp_buf[i] = 0
        # Note: Defaults to AVX2 (AVX-512 = Width 32)
        # Will need to use Sys to set targets any target that dooesn't support AVX2 will spill (ARM)
        var blk = temp_buf.bitcast[UInt32]().load[width=16]()

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
            var out_cv = SIMD[DType.uint32, 8](
                res[0], res[1], res[2], res[3], res[4], res[5], res[6], res[7]
            )
            var depth = self.stack_len
            while depth > 1:
                depth -= 1
                var left = (self.cv_stack + depth)[]
                var p_res = compress_core(
                    self.original_key, left.join(out_cv), 0, 64, PARENT
                )
                out_cv = SIMD[DType.uint32, 8](
                    p_res[0],
                    p_res[1],
                    p_res[2],
                    p_res[3],
                    p_res[4],
                    p_res[5],
                    p_res[6],
                    p_res[7],
                )

            working_key = self.original_key
            working_blk = self.cv_stack[].join(out_cv)
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
            var local_cvs = stack_allocation[64, SIMD[DType.uint32, 8]]()

            for i in range(0, BSIZE, 16):
                var base = task_base + i
                var c0 = SIMD[DType.uint32, 16](IV[0])
                var c1 = SIMD[DType.uint32, 16](IV[1])
                var c2 = SIMD[DType.uint32, 16](IV[2])
                var c3 = SIMD[DType.uint32, 16](IV[3])
                var c4 = SIMD[DType.uint32, 16](IV[4])
                var c5 = SIMD[DType.uint32, 16](IV[5])
                var c6 = SIMD[DType.uint32, 16](IV[6])
                var c7 = SIMD[DType.uint32, 16](IV[7])

                for b in range(16):
                    var flags = (CHUNK_START if b == 0 else UInt8(0)) | (
                        CHUNK_END if b == 15 else 0
                    )
                    var ma = stack_allocation[16, SIMD[DType.uint32, 8]]()
                    var mb = stack_allocation[16, SIMD[DType.uint32, 8]]()

                    for j in range(4):
                        var joff = j * 4
                        var v0a = base_ptr.load[width=4](
                            (base + 0) * 256 + b * 16 + joff
                        ).interleave(
                            base_ptr.load[width=4](
                                (base + 1) * 256 + b * 16 + joff
                            )
                        )
                        var v1a = base_ptr.load[width=4](
                            (base + 2) * 256 + b * 16 + joff
                        ).interleave(
                            base_ptr.load[width=4](
                                (base + 3) * 256 + b * 16 + joff
                            )
                        )
                        var v2a = base_ptr.load[width=4](
                            (base + 4) * 256 + b * 16 + joff
                        ).interleave(
                            base_ptr.load[width=4](
                                (base + 5) * 256 + b * 16 + joff
                            )
                        )
                        var v3a = base_ptr.load[width=4](
                            (base + 6) * 256 + b * 16 + joff
                        ).interleave(
                            base_ptr.load[width=4](
                                (base + 7) * 256 + b * 16 + joff
                            )
                        )
                        var t0a = v0a.shuffle[0, 1, 8, 9, 2, 3, 10, 11](v1a)
                        var t1a = v2a.shuffle[0, 1, 8, 9, 2, 3, 10, 11](v3a)
                        ma[joff + 0] = t0a.shuffle[0, 1, 2, 3, 8, 9, 10, 11](
                            t1a
                        )
                        ma[joff + 1] = t0a.shuffle[4, 5, 6, 7, 12, 13, 14, 15](
                            t1a
                        )
                        var t2a = v0a.shuffle[4, 5, 12, 13, 6, 7, 14, 15](v1a)
                        var t3a = v2a.shuffle[4, 5, 12, 13, 6, 7, 14, 15](v3a)
                        ma[joff + 2] = t2a.shuffle[0, 1, 2, 3, 8, 9, 10, 11](
                            t3a
                        )
                        ma[joff + 3] = t2a.shuffle[4, 5, 6, 7, 12, 13, 14, 15](
                            t3a
                        )

                        var v0b = base_ptr.load[width=4](
                            (base + 8) * 256 + b * 16 + joff
                        ).interleave(
                            base_ptr.load[width=4](
                                (base + 9) * 256 + b * 16 + joff
                            )
                        )
                        var v1b = base_ptr.load[width=4](
                            (base + 10) * 256 + b * 16 + joff
                        ).interleave(
                            base_ptr.load[width=4](
                                (base + 11) * 256 + b * 16 + joff
                            )
                        )
                        var v2b = base_ptr.load[width=4](
                            (base + 12) * 256 + b * 16 + joff
                        ).interleave(
                            base_ptr.load[width=4](
                                (base + 13) * 256 + b * 16 + joff
                            )
                        )
                        var v3b = base_ptr.load[width=4](
                            (base + 14) * 256 + b * 16 + joff
                        ).interleave(
                            base_ptr.load[width=4](
                                (base + 15) * 256 + b * 16 + joff
                            )
                        )
                        var t0b = v0b.shuffle[0, 1, 8, 9, 2, 3, 10, 11](v1b)
                        var t1b = v2b.shuffle[0, 1, 8, 9, 2, 3, 10, 11](v3b)
                        mb[joff + 0] = t0b.shuffle[0, 1, 2, 3, 8, 9, 10, 11](
                            t1b
                        )
                        mb[joff + 1] = t0b.shuffle[4, 5, 6, 7, 12, 13, 14, 15](
                            t1b
                        )
                        var t2b = v0b.shuffle[4, 5, 12, 13, 6, 7, 14, 15](v1b)
                        var t3b = v2b.shuffle[4, 5, 12, 13, 6, 7, 14, 15](v3b)
                        mb[joff + 2] = t2b.shuffle[0, 1, 2, 3, 8, 9, 10, 11](
                            t3b
                        )
                        mb[joff + 3] = t2b.shuffle[4, 5, 6, 7, 12, 13, 14, 15](
                            t3b
                        )

                    var am0 = ma[0].join(mb[0])
                    var am1 = ma[1].join(mb[1])
                    var am2 = ma[2].join(mb[2])
                    var am3 = ma[3].join(mb[3])
                    var am4 = ma[4].join(mb[4])
                    var am5 = ma[5].join(mb[5])
                    var am6 = ma[6].join(mb[6])
                    var am7 = ma[7].join(mb[7])
                    var am8 = ma[8].join(mb[8])
                    var am9 = ma[9].join(mb[9])
                    var am10 = ma[10].join(mb[10])
                    var am11 = ma[11].join(mb[11])
                    var am12 = ma[12].join(mb[12])
                    var am13 = ma[13].join(mb[13])
                    var am14 = ma[14].join(mb[14])
                    var am15 = ma[15].join(mb[15])

                    var res = stack_allocation[8, SIMD[DType.uint32, 16]]()
                    compress_internal_16way(
                        c0,
                        c1,
                        c2,
                        c3,
                        c4,
                        c5,
                        c6,
                        c7,
                        am0,
                        am1,
                        am2,
                        am3,
                        am4,
                        am5,
                        am6,
                        am7,
                        am8,
                        am9,
                        am10,
                        am11,
                        am12,
                        am13,
                        am14,
                        am15,
                        UInt64(base),
                        64,
                        flags,
                        res,
                    )
                    c0 = res[0]
                    c1 = res[1]
                    c2 = res[2]
                    c3 = res[3]
                    c4 = res[4]
                    c5 = res[5]
                    c6 = res[6]
                    c7 = res[7]

                for k in range(16):
                    local_cvs[i + k] = SIMD[DType.uint32, 8](
                        c0[k], c1[k], c2[k], c3[k], c4[k], c5[k], c6[k], c7[k]
                    )

            var current_len = 64
            while current_len > 1:
                current_len >>= 1
                for i in range(current_len):
                    var left = local_cvs[i * 2]
                    var right = local_cvs[i * 2 + 1]
                    var combined = compress_core(
                        IV, left.join(right), 0, 64, PARENT
                    )
                    local_cvs[i] = SIMD[DType.uint32, 8](
                        combined[0],
                        combined[1],
                        combined[2],
                        combined[3],
                        combined[4],
                        combined[5],
                        combined[6],
                        combined[7],
                    )
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
