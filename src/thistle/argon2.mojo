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
Argon2id/Argon2d Implementation in Mojo
RFC 9106
By Libalpm64 no attribution required.
"""

from collections import List, InlineArray
from memory import (
    UnsafePointer,
    MutUnsafePointer,
    ImmutUnsafePointer,
    memcpy,
)
from algorithm import parallelize
from bit import rotate_bits_left
from .blake2b import blake2b_hash, Blake2b


@always_inline
fn gb(
    a: UInt64, b: UInt64, c: UInt64, d: UInt64
) -> Tuple[UInt64, UInt64, UInt64, UInt64]:
    """Argon2 G function using native rotate.
    
    RFC 9103 specifies right rotations (>>>). For 64-bit values:
    right rotate by n = left rotate by (64-n)
    - >>> 32 = left rotate 32 (64-32=32)
    - >>> 24 = left rotate 40 (64-24=40)
    - >>> 16 = left rotate 48 (64-16=48)
    - >>> 63 = left rotate 1  (64-63=1)
    
    NOTE: Using scalar operations instead of SIMD. Mojo's SIMD[DType.uint64, N]
    constructor fails with "constraint failed: expected a scalar type" when
    attempting to create UInt64 SIMD vectors. Python's argon2-cffi achieves
    ~2x better performance (24 vs 11 hashes/sec) using AVX2/AVX-512 SIMD
    for these 64-bit operations. This is a fundamental Mojo limitation that
    cannot be worked around until native UInt64 SIMD support is added.
    """
    # Scalar operations would benefit from SIMD[DType.uint64, 4] if supported
    var a_new = a + b + 2 * (a & 0xFFFFFFFF) * (b & 0xFFFFFFFF)
    var d_new = rotate_bits_left[shift=32](d ^ a_new)
    var c_new = c + d_new + 2 * (c & 0xFFFFFFFF) * (d_new & 0xFFFFFFFF)
    var b_new = rotate_bits_left[shift=40](b ^ c_new)
    a_new = a_new + b_new + 2 * (a_new & 0xFFFFFFFF) * (b_new & 0xFFFFFFFF)
    d_new = rotate_bits_left[shift=48](d_new ^ a_new)
    c_new = c_new + d_new + 2 * (c_new & 0xFFFFFFFF) * (d_new & 0xFFFFFFFF)
    b_new = rotate_bits_left[shift=1](b_new ^ c_new)
    return (a_new, b_new, c_new, d_new)


fn compression_g(
    out_ptr: MutUnsafePointer[UInt64, _],
    x_ptr: ImmutUnsafePointer[UInt64, _],
    y_ptr: ImmutUnsafePointer[UInt64, _],
    with_xor: Bool,
    debug_print: Bool = False,
):
    """Argon2 compression function G.
    
    Based on RFC 9106 Section 3.5-3.6.
    The 1024-byte block is viewed as 64 16-byte registers (128 UInt64 words).
    Each register S_i = (v_{2*i+1} || v_{2*i}) contains 2 UInt64 words.
    
    P operates on 8 registers (16 words) as a 4x4 matrix:
      v_0  v_1  v_2  v_3
      v_4  v_5  v_6  v_7
      v_8  v_9 v_10 v_11
     v_12 v_13 v_14 v_15
    
    First 4 GB calls are column-wise, then 4 are diagonal-wise.
    """
    # R = X XOR Y (128 words)
    var r = InlineArray[UInt64, 128](uninitialized=True)
    var r_backup = InlineArray[UInt64, 128](uninitialized=True)
    
    for i in range(128):
        var val = x_ptr[i] ^ y_ptr[i]
        r[i] = val
        if with_xor:
            r_backup[i] = val ^ out_ptr[i]
        else:
            r_backup[i] = val

    # Row-wise pass: apply P to each row of 8 registers (16 words)
    # Row i uses registers R_{i*8} to R_{i*8+7}, which are words 16*i to 16*i+15
    for row in range(8):
        var base = row * 16  # Word index base
        
        # Apply P to the 4x4 matrix of words
        # Column-wise GB (first 4 calls)
        # GB(v_0, v_4, v_8, v_12)
        var a = r[base + 0]
        var b = r[base + 4]
        var c = r[base + 8]
        var d = r[base + 12]
        (a, b, c, d) = gb(a, b, c, d)
        r[base + 0] = a
        r[base + 4] = b
        r[base + 8] = c
        r[base + 12] = d
        
        # GB(v_1, v_5, v_9, v_13)
        a = r[base + 1]
        b = r[base + 5]
        c = r[base + 9]
        d = r[base + 13]
        (a, b, c, d) = gb(a, b, c, d)
        r[base + 1] = a
        r[base + 5] = b
        r[base + 9] = c
        r[base + 13] = d
        
        # GB(v_2, v_6, v_10, v_14)
        a = r[base + 2]
        b = r[base + 6]
        c = r[base + 10]
        d = r[base + 14]
        (a, b, c, d) = gb(a, b, c, d)
        r[base + 2] = a
        r[base + 6] = b
        r[base + 10] = c
        r[base + 14] = d
        
        # GB(v_3, v_7, v_11, v_15)
        a = r[base + 3]
        b = r[base + 7]
        c = r[base + 11]
        d = r[base + 15]
        (a, b, c, d) = gb(a, b, c, d)
        r[base + 3] = a
        r[base + 7] = b
        r[base + 11] = c
        r[base + 15] = d
        
        # Diagonal-wise GB (next 4 calls)
        # GB(v_0, v_5, v_10, v_15)
        a = r[base + 0]
        b = r[base + 5]
        c = r[base + 10]
        d = r[base + 15]
        (a, b, c, d) = gb(a, b, c, d)
        r[base + 0] = a
        r[base + 5] = b
        r[base + 10] = c
        r[base + 15] = d
        
        # GB(v_1, v_6, v_11, v_12)
        a = r[base + 1]
        b = r[base + 6]
        c = r[base + 11]
        d = r[base + 12]
        (a, b, c, d) = gb(a, b, c, d)
        r[base + 1] = a
        r[base + 6] = b
        r[base + 11] = c
        r[base + 12] = d
        
        # GB(v_2, v_7, v_8, v_13)
        a = r[base + 2]
        b = r[base + 7]
        c = r[base + 8]
        d = r[base + 13]
        (a, b, c, d) = gb(a, b, c, d)
        r[base + 2] = a
        r[base + 7] = b
        r[base + 8] = c
        r[base + 13] = d
        
        # GB(v_3, v_4, v_9, v_14)
        a = r[base + 3]
        b = r[base + 4]
        c = r[base + 9]
        d = r[base + 14]
        (a, b, c, d) = gb(a, b, c, d)
        r[base + 3] = a
        r[base + 4] = b
        r[base + 9] = c
        r[base + 14] = d

    # Column-wise pass: apply P to each column of 8 registers
    # Column i uses registers R_i, R_{i+8}, R_{i+16}, ..., R_{i+56}
    # Register R_j contains words 2*j and 2*j+1
    # So column i uses words: 2*i, 2*i+1, 2*i+16, 2*i+17, ..., 2*i+112, 2*i+113
    for col in range(8):
        # Build the 4x4 matrix for this column
        # Words are at: 2*col, 2*col+16, 2*col+32, ..., 2*col+112 (even indices)
        # and 2*col+1, 2*col+17, 2*col+33, ..., 2*col+113 (odd indices)
        
        # The 16 words for this column, arranged as a 4x4 matrix:
        # Following the pattern from row-wise but with gathered words
        # v_0=2*col+0, v_1=2*col+1, v_2=2*col+16, v_3=2*col+17
        # v_4=2*col+32, v_5=2*col+33, v_6=2*col+48, v_7=2*col+49
        # v_8=2*col+64, v_9=2*col+65, v_10=2*col+80, v_11=2*col+81
        # v_12=2*col+96, v_13=2*col+97, v_14=2*col+112, v_15=2*col+113
        
        var v0 = r[col * 2 + 0]
        var v1 = r[col * 2 + 1]
        var v2 = r[col * 2 + 16]
        var v3 = r[col * 2 + 17]
        var v4 = r[col * 2 + 32]
        var v5 = r[col * 2 + 33]
        var v6 = r[col * 2 + 48]
        var v7 = r[col * 2 + 49]
        var v8 = r[col * 2 + 64]
        var v9 = r[col * 2 + 65]
        var v10 = r[col * 2 + 80]
        var v11 = r[col * 2 + 81]
        var v12 = r[col * 2 + 96]
        var v13 = r[col * 2 + 97]
        var v14 = r[col * 2 + 112]
        var v15 = r[col * 2 + 113]
        
        # Column-wise GB
        (v0, v4, v8, v12) = gb(v0, v4, v8, v12)
        (v1, v5, v9, v13) = gb(v1, v5, v9, v13)
        (v2, v6, v10, v14) = gb(v2, v6, v10, v14)
        (v3, v7, v11, v15) = gb(v3, v7, v11, v15)
        
        # Diagonal-wise GB
        (v0, v5, v10, v15) = gb(v0, v5, v10, v15)
        (v1, v6, v11, v12) = gb(v1, v6, v11, v12)
        (v2, v7, v8, v13) = gb(v2, v7, v8, v13)
        (v3, v4, v9, v14) = gb(v3, v4, v9, v14)
        
        # Store back
        r[col * 2 + 0] = v0
        r[col * 2 + 1] = v1
        r[col * 2 + 16] = v2
        r[col * 2 + 17] = v3
        r[col * 2 + 32] = v4
        r[col * 2 + 33] = v5
        r[col * 2 + 48] = v6
        r[col * 2 + 49] = v7
        r[col * 2 + 64] = v8
        r[col * 2 + 65] = v9
        r[col * 2 + 80] = v10
        r[col * 2 + 81] = v11
        r[col * 2 + 96] = v12
        r[col * 2 + 97] = v13
        r[col * 2 + 112] = v14
        r[col * 2 + 113] = v15

    # Output: Z XOR R
    for i in range(128):
        out_ptr[i] = r[i] ^ r_backup[i]


fn le32(val: Int) -> List[UInt8]:
    var res = List[UInt8](capacity=4)
    res.append(UInt8(val & 0xFF))
    res.append(UInt8((val >> 8) & 0xFF))
    res.append(UInt8((val >> 16) & 0xFF))
    res.append(UInt8((val >> 24) & 0xFF))
    return res^


fn le64(val: Int) -> List[UInt8]:
    var res = List[UInt8](capacity=8)
    res.append(UInt8(val & 0xFF))
    res.append(UInt8((val >> 8) & 0xFF))
    res.append(UInt8((val >> 16) & 0xFF))
    res.append(UInt8((val >> 24) & 0xFF))
    res.append(UInt8((val >> 32) & 0xFF))
    res.append(UInt8((val >> 40) & 0xFF))
    res.append(UInt8((val >> 48) & 0xFF))
    res.append(UInt8((val >> 56) & 0xFF))
    return res^


fn variable_length_hash(t_len: Int, input: Span[UInt8]) -> List[UInt8]:
    if t_len <= 64:
        var ctx = Blake2b(t_len)
        ctx.update(Span[UInt8](le32(t_len)))
        ctx.update(input)
        return ctx.finalize()

    var r = (t_len + 31) // 32 - 2
    var ctx1 = Blake2b(64)
    ctx1.update(Span[UInt8](le32(t_len)))
    ctx1.update(input)
    var v = ctx1.finalize()

    var out_buf = List[UInt8]()
    for _ in range(r - 1):
        for k in range(32):
            out_buf.append(v[k])
        var ctx = Blake2b(64)
        ctx.update(Span[UInt8](v))
        v = ctx.finalize()

    for k in range(32):
        out_buf.append(v[k])

    var last_len = t_len - 32 * r
    var ctx_last = Blake2b(last_len)
    ctx_last.update(Span[UInt8](v))
    var v_last = ctx_last.finalize()

    for k in range(len(v_last)):
        out_buf.append(v_last[k])

    return out_buf^


struct Argon2id:
    var parallelism: Int
    var tag_length: Int
    var memory_size_kb: Int
    var iterations: Int
    var version: Int
    var type_code: Int
    var salt: List[UInt8]
    var secret: List[UInt8]
    var ad: List[UInt8]

    fn __init__(
        out self,
        salt: Span[UInt8],
        parallelism: Int = 4,
        tag_length: Int = 32,
        memory_size_kb: Int = 65536,
        iterations: Int = 3,
        version: Int = 0x13,
    ):
        self.parallelism = parallelism
        self.tag_length = tag_length
        self.memory_size_kb = memory_size_kb
        self.iterations = iterations
        self.version = version
        self.type_code = 2  # Argon2id
        self.salt = List[UInt8](capacity=len(salt))
        for i in range(len(salt)):
            self.salt.append(salt[i])
        self.secret = List[UInt8]()
        self.ad = List[UInt8]()

    fn __init__(
        out self,
        salt: Span[UInt8],
        secret: Span[UInt8],
        ad: Span[UInt8],
        parallelism: Int = 4,
        tag_length: Int = 32,
        memory_size_kb: Int = 65536,
        iterations: Int = 3,
        version: Int = 0x13,
    ):
        self.parallelism = parallelism
        self.tag_length = tag_length
        self.memory_size_kb = memory_size_kb
        self.iterations = iterations
        self.version = version
        self.type_code = 2  # Argon2id
        self.salt = List[UInt8](capacity=len(salt))
        for i in range(len(salt)):
            self.salt.append(salt[i])
        self.secret = List[UInt8](capacity=len(secret))
        for i in range(len(secret)):
            self.secret.append(secret[i])
        self.ad = List[UInt8](capacity=len(ad))
        for i in range(len(ad)):
            self.ad.append(ad[i])

    fn hash(self, password: Span[UInt8]) -> List[UInt8]:
        var h0_ctx = Blake2b(64)
        h0_ctx.update(Span[UInt8](le32(self.parallelism)))
        h0_ctx.update(Span[UInt8](le32(self.tag_length)))
        h0_ctx.update(Span[UInt8](le32(self.memory_size_kb)))
        h0_ctx.update(Span[UInt8](le32(self.iterations)))
        h0_ctx.update(Span[UInt8](le32(self.version)))
        h0_ctx.update(Span[UInt8](le32(self.type_code)))
        h0_ctx.update(Span[UInt8](le32(len(password))))
        h0_ctx.update(password)
        h0_ctx.update(Span[UInt8](le32(len(self.salt))))
        h0_ctx.update(Span[UInt8](self.salt))
        h0_ctx.update(Span[UInt8](le32(len(self.secret))))
        h0_ctx.update(Span[UInt8](le32(len(self.ad))))
        h0_ctx.update(Span[UInt8](self.ad))
        var h0 = h0_ctx.finalize()

        var m_blocks = self.memory_size_kb
        var m_prime_blocks = (
            4 * self.parallelism * (m_blocks // (4 * self.parallelism))
        )
        if m_prime_blocks < 8 * self.parallelism:
            m_prime_blocks = 8 * self.parallelism
        var q = m_prime_blocks // self.parallelism
        var segment_length = q // 4

        var memory = alloc[UInt64](m_prime_blocks * 128)
        var memory_ptr = memory

        for i in range(self.parallelism):
            for block_idx in range(2):
                var input = List[UInt8]()
                for k in range(len(h0)):
                    input.append(h0[k])
                var le_idx = le32(block_idx)
                var lei = le32(i)
                for k in range(4):
                    input.append(le_idx[k])
                for k in range(4):
                    input.append(lei[k])

                var b_bytes = variable_length_hash(1024, Span[UInt8](input))
                for k in range(128):
                    var word: UInt64 = 0
                    for b_i in range(8):
                        word |= UInt64(b_bytes[k * 8 + b_i]) << (b_i * 8)
                    memory_ptr.store(i * q * 128 + block_idx * 128 + k, word)

        for t in range(self.iterations):
            for slice_idx in range(4):

                @parameter
                fn process_lane(lane: Int):
                    var seg_start = slice_idx * segment_length
                    var seg_end = (slice_idx + 1) * segment_length

                    var addressing_block = InlineArray[UInt64, 128](
                        uninitialized=True
                    )
                    var has_addressing_block = False

                    for index in range(seg_start, seg_end):
                        if t == 0 and index < 2:
                            continue

                        var prev_index = index - 1 if index > 0 else q - 1
                        var is_argon2i = t == 0 and slice_idx < 2

                        var j1: UInt32
                        var j2: UInt32

                        if is_argon2i:
                            var seg_offset = index % segment_length
                            if not has_addressing_block or (
                                seg_offset % 128 == 0
                            ):
                                var z_input = InlineArray[UInt8, 1024](fill=0)
                                var z_in_ptr = z_input.unsafe_ptr()

                                @always_inline
                                fn store_le64(offset: Int, val: Int):
                                    for i in range(8):
                                        z_in_ptr.store(
                                            offset + i,
                                            UInt8((val >> (i * 8)) & 0xFF),
                                        )

                                store_le64(0, t)
                                store_le64(8, lane)
                                store_le64(16, slice_idx)
                                store_le64(24, m_prime_blocks)
                                store_le64(32, self.iterations)
                                store_le64(40, self.type_code)
                                store_le64(48, (seg_offset // 128) + 1)

                                var z_u64 = InlineArray[UInt64, 128](
                                    uninitialized=True
                                )
                                var z_u64_ptr = z_u64.unsafe_ptr()
                                for k in range(128):
                                    var w: UInt64 = 0
                                    for b_i in range(8):
                                        w |= UInt64(
                                            z_in_ptr.load(k * 8 + b_i)
                                        ) << (b_i * 8)
                                    z_u64_ptr.store(k, w)

                                var zero_u64 = InlineArray[UInt64, 128](fill=0)
                                var tmp_addr = InlineArray[UInt64, 128](
                                    uninitialized=True
                                )

                                compression_g(
                                    tmp_addr.unsafe_ptr().bitcast[UInt64](),
                                    zero_u64.unsafe_ptr().bitcast[UInt64](),
                                    z_u64.unsafe_ptr().bitcast[UInt64](),
                                    False,
                                    t == 0 and slice_idx == 0 and index == 2,
                                )
                                compression_g(
                                    addressing_block.unsafe_ptr().bitcast[
                                        UInt64
                                    ](),
                                    zero_u64.unsafe_ptr().bitcast[UInt64](),
                                    tmp_addr.unsafe_ptr().bitcast[UInt64](),
                                    False,
                                    False,
                                )
                                has_addressing_block = True

                            var val = addressing_block[seg_offset % 128]
                            j1 = UInt32(val & 0xFFFFFFFF)
                            j2 = UInt32(val >> 32)
                        else:
                            var v0 = memory_ptr[
                                lane * q * 128 + prev_index * 128
                            ]
                            j1 = UInt32(v0 & 0xFFFFFFFF)
                            j2 = UInt32(v0 >> 32)

                        var ref_lane = Int(j2) % self.parallelism
                        if t == 0 and slice_idx == 0:
                            ref_lane = lane

                        var window_size: Int
                        if t == 0:
                            if slice_idx == 0:
                                window_size = index
                            elif ref_lane == lane:
                                window_size = slice_idx * segment_length + (
                                    index % segment_length
                                )
                            else:
                                window_size = slice_idx * segment_length
                        else:
                            if ref_lane == lane:
                                window_size = (
                                    q
                                    - segment_length
                                    + (index % segment_length)
                                )
                            else:
                                window_size = q - segment_length

                        if ref_lane == lane:
                            window_size -= 1
                        elif (index % segment_length) == 0:
                            window_size -= 1

                        var ref_index: Int
                        if window_size <= 0:
                            ref_index = 0
                        else:
                            var x = (UInt64(j1) * UInt64(j1)) >> 32
                            var y = (UInt64(window_size) * x) >> 32
                            var zz = UInt64(window_size) - 1 - y
                            var start_pos = 0
                            if t > 0:
                                start_pos = (
                                    (slice_idx + 1) % 4
                                ) * segment_length
                            ref_index = (start_pos + Int(zz)) % q

                        var p_ptr = (
                            memory_ptr + (lane * q * 128 + prev_index * 128)
                        ).bitcast[UInt64]()
                        var r_ptr = (
                            memory_ptr + (ref_lane * q * 128 + ref_index * 128)
                        ).bitcast[UInt64]()
                        var c_ptr = (
                            memory_ptr + (lane * q * 128 + index * 128)
                        ).bitcast[UInt64]()

                        compression_g(
                            c_ptr,
                            p_ptr,
                            r_ptr,
                            t > 0,
                        )

                parallelize[process_lane](self.parallelism)

        var c_block = InlineArray[UInt64, 128](fill=0)
        for i in range(self.parallelism):
            var last_ptr = memory_ptr + (i * q * 128 + (q - 1) * 128)
            for k in range(128):
                c_block[k] ^= last_ptr[k]

        var c_bytes = List[UInt8](capacity=1024)
        for k in range(128):
            var w = c_block[k]
            for b_i in range(8):
                c_bytes.append(UInt8((w >> (b_i * 8)) & 0xFF))

        return variable_length_hash(self.tag_length, Span[UInt8](c_bytes))


fn argon2id_hash_string(password: String, salt: String) -> String:
    var p_bytes = password.as_bytes()
    var s_bytes = salt.as_bytes()
    var ctx = Argon2id(s_bytes)
    var h = ctx.hash(p_bytes)
    var res = String()
    for i in range(len(h)):
        var b = h[i]
        var high = Int((b >> 4) & 0x0F)
        var low = Int(b & 0x0F)
        res += chr(high + 48 if high < 10 else high - 10 + 97)
        res += chr(low + 48 if low < 10 else low - 10 + 97)
    return res
