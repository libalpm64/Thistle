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

from collections import List
from memory import alloc, UnsafePointer
from algorithm import parallelize
from bit import rotate_bits_left
from .blake2b import Blake2b


comptime MASK32 = 0xFFFFFFFF

@always_inline
fn zero_buffer(ptr: UnsafePointer[UInt8, MutAnyOrigin], len: Int):
    for i in range(len):
        ptr[i] = 0

@always_inline
fn zero_buffer_u64(ptr: UnsafePointer[UInt64, MutAnyOrigin], len: Int):
    for i in range(len):
        ptr[i] = 0

@always_inline
fn zero_and_free(ptr: UnsafePointer[UInt8, MutAnyOrigin], len: Int):
    zero_buffer(ptr, len)
    ptr.free()

@always_inline
fn zero_and_free_u64(ptr: UnsafePointer[UInt64, MutAnyOrigin], len: Int):
    zero_buffer_u64(ptr, len)
    ptr.free()


@always_inline
fn f_bla_mka(x: UInt64, y: UInt64) -> UInt64:
    return x + y + 2 * (x & MASK32) * (y & MASK32)

@always_inline
fn gb(a: UInt64, b: UInt64, c: UInt64, d: UInt64) -> Tuple[UInt64, UInt64, UInt64, UInt64]:
    var a_new = f_bla_mka(a, b)
    var d_new = rotate_bits_left[shift=32](d ^ a_new)
    var c_new = f_bla_mka(c, d_new)
    var b_new = rotate_bits_left[shift=40](b ^ c_new)
    a_new = f_bla_mka(a_new, b_new)
    d_new = rotate_bits_left[shift=48](d_new ^ a_new)
    c_new = f_bla_mka(c_new, d_new)
    b_new = rotate_bits_left[shift=1](b_new ^ c_new)
    return (a_new, b_new, c_new, d_new)

@always_inline
fn _p_column(base: Int, v: UnsafePointer[UInt64, MutAnyOrigin]):
    var v0, v4, v8, v12 = gb(v[base + 0], v[base + 4], v[base + 8], v[base + 12])
    var v1, v5, v9, v13 = gb(v[base + 1], v[base + 5], v[base + 9], v[base + 13])
    var v2, v6, v10, v14 = gb(v[base + 2], v[base + 6], v[base + 10], v[base + 14])
    var v3, v7, v11, v15 = gb(v[base + 3], v[base + 7], v[base + 11], v[base + 15])
    v[base + 0] = v0
    v[base + 4] = v4
    v[base + 8] = v8
    v[base + 12] = v12
    v[base + 1] = v1
    v[base + 5] = v5
    v[base + 9] = v9
    v[base + 13] = v13
    v[base + 2] = v2
    v[base + 6] = v6
    v[base + 10] = v10
    v[base + 14] = v14
    v[base + 3] = v3
    v[base + 7] = v7
    v[base + 11] = v11
    v[base + 15] = v15

@always_inline
fn _p_diagonal(base: Int, v: UnsafePointer[UInt64, MutAnyOrigin]):
    var v0, v5, v10, v15 = gb(v[base + 0], v[base + 5], v[base + 10], v[base + 15])
    var v1, v6, v11, v12 = gb(v[base + 1], v[base + 6], v[base + 11], v[base + 12])
    var v2, v7, v8, v13 = gb(v[base + 2], v[base + 7], v[base + 8], v[base + 13])
    var v3, v4, v9, v14 = gb(v[base + 3], v[base + 4], v[base + 9], v[base + 14])
    v[base + 0] = v0
    v[base + 5] = v5
    v[base + 10] = v10
    v[base + 15] = v15
    v[base + 1] = v1
    v[base + 6] = v6
    v[base + 11] = v11
    v[base + 12] = v12
    v[base + 2] = v2
    v[base + 7] = v7
    v[base + 8] = v8
    v[base + 13] = v13
    v[base + 3] = v3
    v[base + 4] = v4
    v[base + 9] = v9
    v[base + 14] = v14

@always_inline
fn compression_g(
    out_ptr: UnsafePointer[UInt64, MutAnyOrigin],
    x_ptr: UnsafePointer[UInt64, ImmutAnyOrigin],
    y_ptr: UnsafePointer[UInt64, ImmutAnyOrigin],
    with_xor: Bool,
):
    var block = alloc[UInt64](128)
    var block_xy = alloc[UInt64](128)
    
    for i in range(128):
        var val = x_ptr[i] ^ y_ptr[i]
        block[i] = val
        if with_xor:
            block_xy[i] = val ^ out_ptr[i]
        else:
            block_xy[i] = val
    
    for i in range(8):
        var base = i * 16
        _p_column(base, block)
        _p_diagonal(base, block)
    
    for col in range(8):
        var v0 = block[col * 2 + 0]
        var v1 = block[col * 2 + 1]
        var v2 = block[col * 2 + 16]
        var v3 = block[col * 2 + 17]
        var v4 = block[col * 2 + 32]
        var v5 = block[col * 2 + 33]
        var v6 = block[col * 2 + 48]
        var v7 = block[col * 2 + 49]
        var v8 = block[col * 2 + 64]
        var v9 = block[col * 2 + 65]
        var v10 = block[col * 2 + 80]
        var v11 = block[col * 2 + 81]
        var v12 = block[col * 2 + 96]
        var v13 = block[col * 2 + 97]
        var v14 = block[col * 2 + 112]
        var v15 = block[col * 2 + 113]
        
        v0, v4, v8, v12 = gb(v0, v4, v8, v12)
        v1, v5, v9, v13 = gb(v1, v5, v9, v13)
        v2, v6, v10, v14 = gb(v2, v6, v10, v14)
        v3, v7, v11, v15 = gb(v3, v7, v11, v15)
        
        v0, v5, v10, v15 = gb(v0, v5, v10, v15)
        v1, v6, v11, v12 = gb(v1, v6, v11, v12)
        v2, v7, v8, v13 = gb(v2, v7, v8, v13)
        v3, v4, v9, v14 = gb(v3, v4, v9, v14)
        
        block[col * 2 + 0] = v0
        block[col * 2 + 1] = v1
        block[col * 2 + 16] = v2
        block[col * 2 + 17] = v3
        block[col * 2 + 32] = v4
        block[col * 2 + 33] = v5
        block[col * 2 + 48] = v6
        block[col * 2 + 49] = v7
        block[col * 2 + 64] = v8
        block[col * 2 + 65] = v9
        block[col * 2 + 80] = v10
        block[col * 2 + 81] = v11
        block[col * 2 + 96] = v12
        block[col * 2 + 97] = v13
        block[col * 2 + 112] = v14
        block[col * 2 + 113] = v15
    
    for i in range(128):
        out_ptr[i] = block[i] ^ block_xy[i]
    
    zero_and_free_u64(block, 128)
    zero_and_free_u64(block_xy, 128)


@always_inline
fn store_le32(ptr: UnsafePointer[UInt8, MutAnyOrigin], offset: Int, val: Int):
    ptr[offset + 0] = UInt8(val & 0xFF)
    ptr[offset + 1] = UInt8((val >> 8) & 0xFF)
    ptr[offset + 2] = UInt8((val >> 16) & 0xFF)
    ptr[offset + 3] = UInt8((val >> 24) & 0xFF)


@always_inline
fn store_le64(ptr: UnsafePointer[UInt8, MutAnyOrigin], offset: Int, val: Int):
    ptr[offset + 0] = UInt8(val & 0xFF)
    ptr[offset + 1] = UInt8((val >> 8) & 0xFF)
    ptr[offset + 2] = UInt8((val >> 16) & 0xFF)
    ptr[offset + 3] = UInt8((val >> 24) & 0xFF)
    ptr[offset + 4] = UInt8((val >> 32) & 0xFF)
    ptr[offset + 5] = UInt8((val >> 40) & 0xFF)
    ptr[offset + 6] = UInt8((val >> 48) & 0xFF)
    ptr[offset + 7] = UInt8((val >> 56) & 0xFF)


fn blake2b_with_le32_prefix(digest_size: Int, prefix_val: Int, input: Span[UInt8]) -> List[UInt8]:
    var ctx = Blake2b(digest_size)
    var le_buf = alloc[UInt8](4)
    store_le32(le_buf, 0, prefix_val)
    ctx.update(Span[UInt8](ptr=le_buf, length=4))
    ctx.update(input)
    le_buf.free()
    return ctx.finalize()


fn variable_length_hash_to_ptr(t_len: Int, input: Span[UInt8], out_ptr: UnsafePointer[UInt8, MutAnyOrigin]):
    if t_len <= 64:
        var ctx = Blake2b(t_len)
        var le_buf = alloc[UInt8](4)
        store_le32(le_buf, 0, t_len)
        ctx.update(Span[UInt8](ptr=le_buf, length=4))
        ctx.update(input)
        le_buf.free()
        var result = ctx.finalize()
        for i in range(len(result)):
            out_ptr[i] = result[i]
        return

    var r = (t_len + 31) // 32 - 2
    var v_buf = alloc[UInt8](64)
    
    var ctx1 = Blake2b(64)
    var le_buf = alloc[UInt8](4)
    store_le32(le_buf, 0, t_len)
    ctx1.update(Span[UInt8](ptr=le_buf, length=4))
    ctx1.update(input)
    le_buf.free()
    var v = ctx1.finalize()
    for k in range(64):
        v_buf[k] = v[k]

    var out_offset = 0
    for _ in range(r - 1):
        for k in range(32):
            out_ptr[out_offset + k] = v_buf[k]
        out_offset += 32
        
        var ctx = Blake2b(64)
        ctx.update(Span[UInt8](ptr=v_buf, length=64))
        v = ctx.finalize()
        for k in range(64):
            v_buf[k] = v[k]

    for k in range(32):
        out_ptr[out_offset + k] = v_buf[k]
    out_offset += 32

    var last_len = t_len - 32 * r
    var ctx_last = Blake2b(last_len)
    ctx_last.update(Span[UInt8](ptr=v_buf, length=64))
    var v_last = ctx_last.finalize()
    for k in range(len(v_last)):
        out_ptr[out_offset + k] = v_last[k]

    zero_and_free(v_buf, 64)


fn variable_length_hash(t_len: Int, input: Span[UInt8]) -> List[UInt8]:
    var out_buf = alloc[UInt8](t_len)
    variable_length_hash_to_ptr(t_len, input, out_buf)
    var result = List[UInt8](capacity=t_len)
    for i in range(t_len):
        result.append(out_buf[i])
    zero_and_free(out_buf, t_len)
    return result^


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
        self.type_code = 2
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
        self.type_code = 2
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
        
        var le_buf = alloc[UInt8](4)
        store_le32(le_buf, 0, self.parallelism)
        h0_ctx.update(Span[UInt8](ptr=le_buf, length=4))
        store_le32(le_buf, 0, self.tag_length)
        h0_ctx.update(Span[UInt8](ptr=le_buf, length=4))
        store_le32(le_buf, 0, self.memory_size_kb)
        h0_ctx.update(Span[UInt8](ptr=le_buf, length=4))
        store_le32(le_buf, 0, self.iterations)
        h0_ctx.update(Span[UInt8](ptr=le_buf, length=4))
        store_le32(le_buf, 0, self.version)
        h0_ctx.update(Span[UInt8](ptr=le_buf, length=4))
        store_le32(le_buf, 0, self.type_code)
        h0_ctx.update(Span[UInt8](ptr=le_buf, length=4))
        store_le32(le_buf, 0, len(password))
        h0_ctx.update(Span[UInt8](ptr=le_buf, length=4))
        le_buf.free()
        
        h0_ctx.update(password)
        
        le_buf = alloc[UInt8](4)
        store_le32(le_buf, 0, len(self.salt))
        h0_ctx.update(Span[UInt8](ptr=le_buf, length=4))
        le_buf.free()
        h0_ctx.update(Span[UInt8](self.salt))
        
        le_buf = alloc[UInt8](4)
        store_le32(le_buf, 0, len(self.secret))
        h0_ctx.update(Span[UInt8](ptr=le_buf, length=4))
        le_buf.free()
        h0_ctx.update(Span[UInt8](self.secret))
        
        le_buf = alloc[UInt8](4)
        store_le32(le_buf, 0, len(self.ad))
        h0_ctx.update(Span[UInt8](ptr=le_buf, length=4))
        le_buf.free()
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

        var h0_input = alloc[UInt8](72)
        for k in range(64):
            h0_input[k] = h0[k]

        for i in range(self.parallelism):
            for block_idx in range(2):
                store_le32(h0_input, 64, block_idx)
                store_le32(h0_input, 68, i)
                
                var b_bytes = alloc[UInt8](1024)
                variable_length_hash_to_ptr(1024, Span[UInt8](ptr=h0_input, length=72), b_bytes)
                
                for k in range(128):
                    var word: UInt64 = 0
                    for b_i in range(8):
                        word |= UInt64(b_bytes[k * 8 + b_i]) << (b_i * 8)
                    memory[i * q * 128 + block_idx * 128 + k] = word
                zero_and_free(b_bytes, 1024)

        zero_and_free(h0_input, 72)

        for t in range(self.iterations):
            for slice_idx in range(4):

                @parameter
                fn process_lane(lane: Int):
                    var seg_start = slice_idx * segment_length
                    var seg_end = (slice_idx + 1) * segment_length

                    var addressing_block = alloc[UInt64](128)
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
                                var z_u64 = alloc[UInt64](128)
                                for k in range(128):
                                    z_u64[k] = 0
                                z_u64[0] = UInt64(t)
                                z_u64[1] = UInt64(lane)
                                z_u64[2] = UInt64(slice_idx)
                                z_u64[3] = UInt64(m_prime_blocks)
                                z_u64[4] = UInt64(self.iterations)
                                z_u64[5] = UInt64(self.type_code)
                                z_u64[6] = UInt64((seg_offset // 128) + 1)

                                var zero_u64 = alloc[UInt64](128)
                                for k in range(128):
                                    zero_u64[k] = 0
                                var tmp_addr = alloc[UInt64](128)

                                compression_g(tmp_addr, zero_u64, z_u64, False)
                                compression_g(addressing_block, zero_u64, tmp_addr, False)
                                has_addressing_block = True
                                
                                zero_and_free_u64(z_u64, 128)
                                zero_and_free_u64(zero_u64, 128)
                                zero_and_free_u64(tmp_addr, 128)

                            var val = addressing_block[seg_offset % 128]
                            j1 = UInt32(val & 0xFFFFFFFF)
                            j2 = UInt32(val >> 32)
                        else:
                            var v0 = memory[lane * q * 128 + prev_index * 128]
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

                        var p_ptr = memory + (lane * q * 128 + prev_index * 128)
                        var r_ptr = memory + (ref_lane * q * 128 + ref_index * 128)
                        var c_ptr = memory + (lane * q * 128 + index * 128)

                        compression_g(c_ptr, p_ptr, r_ptr, t > 0)

                    zero_and_free_u64(addressing_block, 128)

                parallelize[process_lane](self.parallelism)

        var c_block = alloc[UInt64](128)
        for k in range(128):
            c_block[k] = 0
        for i in range(self.parallelism):
            var last_ptr = memory + (i * q * 128 + (q - 1) * 128)
            for k in range(128):
                c_block[k] ^= last_ptr[k]

        var c_bytes = alloc[UInt8](1024)
        for k in range(128):
            var w = c_block[k]
            for b_i in range(8):
                c_bytes[k * 8 + b_i] = UInt8((w >> (b_i * 8)) & 0xFF)

        zero_and_free_u64(c_block, 128)
        zero_and_free_u64(memory, m_prime_blocks * 128)
        
        var result = variable_length_hash(self.tag_length, Span[UInt8](ptr=c_bytes, length=1024))
        zero_and_free(c_bytes, 1024)
        return result^


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
