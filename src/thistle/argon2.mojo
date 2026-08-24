"""
Argon2id/Argon2d Implementation in Mojo
RFC 9106
"""

from std.collections import List
from std.memory import Layout, Pointer, alloc, unsafe_memcpy, unsafe_memset_zero
from max.algorithm import parallelize
from std.bit import rotate_bits_left
from .blake2b import Blake2b

comptime MASK32 = 0xFFFFFFFF

@always_inline
def zero_buffer(ptr: Pointer[mut=True, UInt8, _, address_space=_], len: Int):
    var i = 0
    while i + 16 <= len:
        ptr.unsafe_store[width=16, volatile=True](
            i, SIMD[DType.uint8, 16](0)
        )
        i += 16
    while i < len:
        ptr.unsafe_store[volatile=True](i, UInt8(0))
        i += 1

@always_inline
def zero_buffer_u64(ptr: Pointer[mut=True, UInt64, _, address_space=_], len: Int):
    var i = 0
    while i + 8 <= len:
        ptr.unsafe_store[width=8, volatile=True](
            i, SIMD[DType.uint64, 8](0)
        )
        i += 8
    while i < len:
        ptr.unsafe_store[volatile=True](i, UInt64(0))
        i += 1

@always_inline
def zero_and_free(ptr: Pointer[mut=True, UInt8, _, address_space=_], len: Int):
    zero_buffer(ptr, len)
    ptr.unsafe_free()

@always_inline
def zero_and_free_u64(ptr: Pointer[mut=True, UInt64, _, address_space=_], len: Int):
    zero_buffer_u64(ptr, len)
    ptr.unsafe_free()

@always_inline
def f_bla_mka(x: UInt64, y: UInt64) -> UInt64:
    return x + y + (((x & MASK32) * (y & MASK32)) << UInt64(1))

@always_inline
def gb(a: UInt64, b: UInt64, c: UInt64, d: UInt64) -> Tuple[UInt64, UInt64, UInt64, UInt64]:
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
def _p_column(base: Int, v: Pointer[mut=True, UInt64, _, address_space=_]):
    var v0, v4, v8, v12 = gb(v[unsafe_offset=base + 0], v[unsafe_offset=base + 4], v[unsafe_offset=base + 8], v[unsafe_offset=base + 12])
    var v1, v5, v9, v13 = gb(v[unsafe_offset=base + 1], v[unsafe_offset=base + 5], v[unsafe_offset=base + 9], v[unsafe_offset=base + 13])
    var v2, v6, v10, v14 = gb(v[unsafe_offset=base + 2], v[unsafe_offset=base + 6], v[unsafe_offset=base + 10], v[unsafe_offset=base + 14])
    var v3, v7, v11, v15 = gb(v[unsafe_offset=base + 3], v[unsafe_offset=base + 7], v[unsafe_offset=base + 11], v[unsafe_offset=base + 15])
    v[unsafe_offset=base + 0] = v0
    v[unsafe_offset=base + 4] = v4
    v[unsafe_offset=base + 8] = v8
    v[unsafe_offset=base + 12] = v12
    v[unsafe_offset=base + 1] = v1
    v[unsafe_offset=base + 5] = v5
    v[unsafe_offset=base + 9] = v9
    v[unsafe_offset=base + 13] = v13
    v[unsafe_offset=base + 2] = v2
    v[unsafe_offset=base + 6] = v6
    v[unsafe_offset=base + 10] = v10
    v[unsafe_offset=base + 14] = v14
    v[unsafe_offset=base + 3] = v3
    v[unsafe_offset=base + 7] = v7
    v[unsafe_offset=base + 11] = v11
    v[unsafe_offset=base + 15] = v15

@always_inline
def _p_diagonal(base: Int, v: Pointer[mut=True, UInt64, _, address_space=_]):
    var v0, v5, v10, v15 = gb(v[unsafe_offset=base + 0], v[unsafe_offset=base + 5], v[unsafe_offset=base + 10], v[unsafe_offset=base + 15])
    var v1, v6, v11, v12 = gb(v[unsafe_offset=base + 1], v[unsafe_offset=base + 6], v[unsafe_offset=base + 11], v[unsafe_offset=base + 12])
    var v2, v7, v8, v13 = gb(v[unsafe_offset=base + 2], v[unsafe_offset=base + 7], v[unsafe_offset=base + 8], v[unsafe_offset=base + 13])
    var v3, v4, v9, v14 = gb(v[unsafe_offset=base + 3], v[unsafe_offset=base + 4], v[unsafe_offset=base + 9], v[unsafe_offset=base + 14])
    v[unsafe_offset=base + 0] = v0
    v[unsafe_offset=base + 5] = v5
    v[unsafe_offset=base + 10] = v10
    v[unsafe_offset=base + 15] = v15
    v[unsafe_offset=base + 1] = v1
    v[unsafe_offset=base + 6] = v6
    v[unsafe_offset=base + 11] = v11
    v[unsafe_offset=base + 12] = v12
    v[unsafe_offset=base + 2] = v2
    v[unsafe_offset=base + 7] = v7
    v[unsafe_offset=base + 8] = v8
    v[unsafe_offset=base + 13] = v13
    v[unsafe_offset=base + 3] = v3
    v[unsafe_offset=base + 4] = v4
    v[unsafe_offset=base + 9] = v9
    v[unsafe_offset=base + 14] = v14

struct MemoryPool:
    var block_buffer: Pointer[UInt64, MutUntrackedOrigin]
    var temp_buffer: Pointer[UInt64, MutUntrackedOrigin]
    var buffer_size: Int

    def __init__(out self, size: Int):
        self.buffer_size = size
        self.block_buffer = alloc(Layout[UInt64](count=size)).unsafe_leak()
        self.temp_buffer = alloc(Layout[UInt64](count=size)).unsafe_leak()

    def __deinit__(deinit self):
        zero_and_free_u64(self.block_buffer, self.buffer_size)
        zero_and_free_u64(self.temp_buffer, self.buffer_size)

    @always_inline
    def get_block(self) -> Pointer[UInt64, MutUntrackedOrigin]:
        return self.block_buffer

    @always_inline
    def get_temp(self) -> Pointer[UInt64, MutUntrackedOrigin]:
        return self.temp_buffer

@always_inline
def compression_g_with_pool(
    out_ptr: Pointer[mut=True, UInt64, _, address_space=_],
    x_ptr: Pointer[mut=False, UInt64, _, address_space=_],
    y_ptr: Pointer[mut=False, UInt64, _, address_space=_],
    with_xor: Bool,
    pool: MemoryPool,
):
    var block = pool.get_block()
    var block_xy = pool.get_temp()

    for i in range(128):
        var val = x_ptr[unsafe_offset=i] ^ y_ptr[unsafe_offset=i]
        block[unsafe_offset=i] = val
        if with_xor:
            block_xy[unsafe_offset=i] = val ^ out_ptr[unsafe_offset=i]
        else:
            block_xy[unsafe_offset=i] = val

    for i in range(8):
        var base = i * 16
        _p_column(base, block)
        _p_diagonal(base, block)

    for col in range(8):
        var v0 = block[unsafe_offset=col * 2 + 0]
        var v1 = block[unsafe_offset=col * 2 + 1]
        var v2 = block[unsafe_offset=col * 2 + 16]
        var v3 = block[unsafe_offset=col * 2 + 17]
        var v4 = block[unsafe_offset=col * 2 + 32]
        var v5 = block[unsafe_offset=col * 2 + 33]
        var v6 = block[unsafe_offset=col * 2 + 48]
        var v7 = block[unsafe_offset=col * 2 + 49]
        var v8 = block[unsafe_offset=col * 2 + 64]
        var v9 = block[unsafe_offset=col * 2 + 65]
        var v10 = block[unsafe_offset=col * 2 + 80]
        var v11 = block[unsafe_offset=col * 2 + 81]
        var v12 = block[unsafe_offset=col * 2 + 96]
        var v13 = block[unsafe_offset=col * 2 + 97]
        var v14 = block[unsafe_offset=col * 2 + 112]
        var v15 = block[unsafe_offset=col * 2 + 113]

        v0, v4, v8, v12 = gb(v0, v4, v8, v12)
        v1, v5, v9, v13 = gb(v1, v5, v9, v13)
        v2, v6, v10, v14 = gb(v2, v6, v10, v14)
        v3, v7, v11, v15 = gb(v3, v7, v11, v15)

        v0, v5, v10, v15 = gb(v0, v5, v10, v15)
        v1, v6, v11, v12 = gb(v1, v6, v11, v12)
        v2, v7, v8, v13 = gb(v2, v7, v8, v13)
        v3, v4, v9, v14 = gb(v3, v4, v9, v14)

        block[unsafe_offset=col * 2 + 0] = v0
        block[unsafe_offset=col * 2 + 1] = v1
        block[unsafe_offset=col * 2 + 16] = v2
        block[unsafe_offset=col * 2 + 17] = v3
        block[unsafe_offset=col * 2 + 32] = v4
        block[unsafe_offset=col * 2 + 33] = v5
        block[unsafe_offset=col * 2 + 48] = v6
        block[unsafe_offset=col * 2 + 49] = v7
        block[unsafe_offset=col * 2 + 64] = v8
        block[unsafe_offset=col * 2 + 65] = v9
        block[unsafe_offset=col * 2 + 80] = v10
        block[unsafe_offset=col * 2 + 81] = v11
        block[unsafe_offset=col * 2 + 96] = v12
        block[unsafe_offset=col * 2 + 97] = v13
        block[unsafe_offset=col * 2 + 112] = v14
        block[unsafe_offset=col * 2 + 113] = v15

    for i in range(128):
        out_ptr[unsafe_offset=i] = block[unsafe_offset=i] ^ block_xy[unsafe_offset=i]

@always_inline
def store_le32(ptr: Pointer[mut=True, UInt8, _, address_space=_], offset: Int, val: Int):
    ptr[unsafe_offset=offset + 0] = UInt8(val & 0xFF)
    ptr[unsafe_offset=offset + 1] = UInt8((val >> 8) & 0xFF)
    ptr[unsafe_offset=offset + 2] = UInt8((val >> 16) & 0xFF)
    ptr[unsafe_offset=offset + 3] = UInt8((val >> 24) & 0xFF)


def variable_length_hash_into(
    t_len: Int, input: Span[UInt8, ...], output: Span[mut=True, UInt8, ...]
) raises:
    if t_len < 1:
        raise Error("Argon2 variable-length hash output must not be empty")
    if t_len > len(output):
        raise Error("Argon2 variable-length hash output exceeds destination")
    if t_len > Int.MAX - 31:
        raise Error("Argon2 variable-length hash output is too large")

    var out_ptr = output.unsafe_ptr()

    if t_len <= 64:
        var le_buf = alloc(Layout[UInt8](count=4)).unsafe_leak()
        try:
            var ctx = Blake2b(t_len)
            store_le32(le_buf, 0, t_len)
            ctx.update(Span[UInt8, ...](unsafe_ptr=le_buf, length=4))
            ctx.update(input)
            ctx.finalize_into(output)
        finally:
            zero_and_free(le_buf, 4)
        return

    var le_buf = alloc(Layout[UInt8](count=4)).unsafe_leak()
    var r = (t_len + 31) // 32 - 2
    var v_buf = alloc(Layout[UInt8](count=64)).unsafe_leak()
    try:
        var ctx1 = Blake2b(64)
        store_le32(le_buf, 0, t_len)
        ctx1.update(Span[UInt8, ...](unsafe_ptr=le_buf, length=4))
        ctx1.update(input)
        ctx1.finalize_into(
            Span[mut=True, UInt8, ...](unsafe_ptr=v_buf, length=64)
        )

        var out_offset = 0
        for _ in range(r - 1):
            for j in range(32):
                out_ptr[unsafe_offset=out_offset + j] = v_buf[unsafe_offset=j]
            out_offset += 32

            var ctx = Blake2b(64)
            ctx.update(Span[UInt8, ...](unsafe_ptr=v_buf, length=64))
            ctx.finalize_into(
                Span[mut=True, UInt8, ...](unsafe_ptr=v_buf, length=64)
            )

        for j in range(32):
            out_ptr[unsafe_offset=out_offset + j] = v_buf[unsafe_offset=j]
        out_offset += 32

        var last_len = t_len - 32 * r
        var ctx_last = Blake2b(last_len)
        ctx_last.update(Span[UInt8, ...](unsafe_ptr=v_buf, length=64))
        ctx_last.finalize_into(
            Span[mut=True, UInt8, ...](
                unsafe_ptr=out_ptr.unsafe_offset(out_offset), length=last_len
            )
        )
    finally:
        zero_and_free(v_buf, 64)
        zero_and_free(le_buf, 4)

def variable_length_hash(t_len: Int, input: Span[UInt8, ...]) raises -> List[UInt8]:
    if t_len < 1:
        raise Error("Argon2 variable-length hash output must not be empty")
    var out_buf = alloc(Layout[UInt8](count=t_len)).unsafe_leak()
    try:
        variable_length_hash_into(
            t_len,
            input,
            Span[mut=True, UInt8, ...](unsafe_ptr=out_buf, length=t_len),
        )
        var result = List[UInt8](capacity=t_len)
        for i in range(t_len):
            result.append(out_buf[unsafe_offset=i])
        return result^
    finally:
        zero_and_free(out_buf, t_len)

@always_inline
def _argon2_process_lane(
    memory: Pointer[mut=True, UInt64, _, address_space=_],
    lane: Int,
    t: Int,
    slice_idx: Int,
    seg_start: Int,
    seg_end: Int,
    segment_length: Int,
    q: Int,
    m_prime_blocks: Int,
    iterations: Int,
    type_code: Int,
    parallelism: Int,
):
    var addressing_block = alloc(Layout[UInt64](count=128)).unsafe_leak()
    var z_u64 = alloc(Layout[UInt64](count=128)).unsafe_leak()
    var zero_u64 = alloc(Layout[UInt64](count=128)).unsafe_leak()
    var tmp_addr = alloc(Layout[UInt64](count=128)).unsafe_leak()
    var pool = MemoryPool(128)
    var has_addressing_block = False
    zero_buffer_u64(zero_u64, 128)

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
                zero_buffer_u64(z_u64, 128)
                z_u64[unsafe_offset=0] = UInt64(t)
                z_u64[unsafe_offset=1] = UInt64(lane)
                z_u64[unsafe_offset=2] = UInt64(slice_idx)
                z_u64[unsafe_offset=3] = UInt64(m_prime_blocks)
                z_u64[unsafe_offset=4] = UInt64(iterations)
                z_u64[unsafe_offset=5] = UInt64(type_code)
                z_u64[unsafe_offset=6] = UInt64((seg_offset // 128) + 1)

                compression_g_with_pool(tmp_addr, zero_u64, z_u64, False, pool)
                compression_g_with_pool(addressing_block, zero_u64, tmp_addr, False, pool)
                has_addressing_block = True

            var val = addressing_block[unsafe_offset=seg_offset % 128]
            j1 = UInt32(val & 0xFFFFFFFF)
            j2 = UInt32(val >> 32)
        else:
            var v0 = memory[unsafe_offset=lane * q * 128 + prev_index * 128]
            j1 = UInt32(v0 & 0xFFFFFFFF)
            j2 = UInt32(v0 >> 32)

        var ref_lane = Int(j2) % parallelism
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

        var p_ptr = memory.unsafe_offset((lane * q * 128 + prev_index * 128))
        var r_ptr = memory.unsafe_offset((ref_lane * q * 128 + ref_index * 128))
        var c_ptr = memory.unsafe_offset((lane * q * 128 + index * 128))

        compression_g_with_pool(
            c_ptr,
            p_ptr.unsafe_origin_cast[MutAnyOrigin](),
            r_ptr.unsafe_origin_cast[MutAnyOrigin](),
            t > 0,
            pool,
        )

    zero_and_free_u64(addressing_block, 128)
    zero_and_free_u64(z_u64, 128)
    zero_and_free_u64(zero_u64, 128)
    zero_and_free_u64(tmp_addr, 128)

def _validate_params(parallelism: Int, tag_length: Int, memory_size_kb: Int, iterations: Int, version: Int) raises:
    # RFC 9106 section 3 parameter bounds
    if parallelism < 1 or parallelism >= (1 << 24):
        raise Error("Argon2 parallelism must be in [1, 2^24)")
    if tag_length < 4 or tag_length >= (1 << 32):
        raise Error("Argon2 tag length must be in [4, 2^32)")
    if memory_size_kb < 8 * parallelism or memory_size_kb >= (1 << 32):
        raise Error("Argon2 memory must be in [8*parallelism, 2^32) KiB")
    if iterations < 1 or iterations >= (1 << 32):
        raise Error("Argon2 iterations must be in [1, 2^32)")
    if version != 0x13:
        raise Error("Argon2 version must be 0x13")


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

    def __deinit__(deinit self):
        var secret_ptr = self.secret.unsafe_ptr()
        for i in range(len(self.secret)):
            secret_ptr.unsafe_store[volatile=True](i, UInt8(0))

    def __init__(
        out self,
        salt: Span[UInt8, ...],
        parallelism: Int = 4,
        tag_length: Int = 32,
        memory_size_kb: Int = 65536,
        iterations: Int = 3,
        version: Int = 0x13,
    ) raises:
        _validate_params(parallelism, tag_length, memory_size_kb, iterations, version)
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

    def __init__(
        out self,
        salt: Span[UInt8, ...],
        secret: Span[UInt8, ...],
        ad: Span[UInt8, ...],
        parallelism: Int = 4,
        tag_length: Int = 32,
        memory_size_kb: Int = 65536,
        iterations: Int = 3,
        version: Int = 0x13,
    ) raises:
        _validate_params(parallelism, tag_length, memory_size_kb, iterations, version)
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

    def hash(self, password: Span[UInt8, ...]) raises -> List[UInt8]:
        var h0_ctx = Blake2b(64)
        var le_buf = alloc(Layout[UInt8](count=4)).unsafe_leak()
        store_le32(le_buf, 0, self.parallelism)
        h0_ctx.update(Span[UInt8, ...](unsafe_ptr=le_buf, length=4))
        store_le32(le_buf, 0, self.tag_length)
        h0_ctx.update(Span[UInt8, ...](unsafe_ptr=le_buf, length=4))
        store_le32(le_buf, 0, self.memory_size_kb)
        h0_ctx.update(Span[UInt8, ...](unsafe_ptr=le_buf, length=4))
        store_le32(le_buf, 0, self.iterations)
        h0_ctx.update(Span[UInt8, ...](unsafe_ptr=le_buf, length=4))
        store_le32(le_buf, 0, self.version)
        h0_ctx.update(Span[UInt8, ...](unsafe_ptr=le_buf, length=4))
        store_le32(le_buf, 0, self.type_code)
        h0_ctx.update(Span[UInt8, ...](unsafe_ptr=le_buf, length=4))
        store_le32(le_buf, 0, len(password))
        h0_ctx.update(Span[UInt8, ...](unsafe_ptr=le_buf, length=4))
        h0_ctx.update(password)
        store_le32(le_buf, 0, len(self.salt))
        h0_ctx.update(Span[UInt8, ...](unsafe_ptr=le_buf, length=4))
        h0_ctx.update(Span[UInt8, ...](self.salt))
        store_le32(le_buf, 0, len(self.secret))
        h0_ctx.update(Span[UInt8, ...](unsafe_ptr=le_buf, length=4))
        h0_ctx.update(Span[UInt8, ...](self.secret))
        store_le32(le_buf, 0, len(self.ad))
        h0_ctx.update(Span[UInt8, ...](unsafe_ptr=le_buf, length=4))
        h0_ctx.update(Span[UInt8, ...](self.ad))
        zero_and_free(le_buf, 4)

        var h0_buf = alloc(Layout[UInt8](count=64)).unsafe_leak()
        h0_ctx.finalize_into(
            Span[mut=True, UInt8, ...](unsafe_ptr=h0_buf, length=64)
        )

        var m_blocks = self.memory_size_kb
        var m_prime_blocks = (
            4 * self.parallelism * (m_blocks // (4 * self.parallelism))
        )
        if m_prime_blocks < 8 * self.parallelism:
            m_prime_blocks = 8 * self.parallelism
        var q = m_prime_blocks // self.parallelism
        var segment_length = q // 4

        var memory = alloc(Layout[UInt64](count=m_prime_blocks * 128)).unsafe_leak()

        var h0_input = alloc(Layout[UInt8](count=72)).unsafe_leak()
        unsafe_memcpy(dest=h0_input, src=h0_buf, count=64)
        zero_and_free(h0_buf, 64)

        for i in range(self.parallelism):
            for block_idx in range(2):
                store_le32(h0_input, 64, block_idx)
                store_le32(h0_input, 68, i)
                
                var b_bytes = alloc(Layout[UInt8](count=1024)).unsafe_leak()
                variable_length_hash_into(
                    1024,
                    Span[UInt8, ...](unsafe_ptr=h0_input, length=72),
                    Span[mut=True, UInt8, ...](
                        unsafe_ptr=b_bytes, length=1024
                    ),
                )
                
                for k in range(128):
                    var word = (b_bytes.unsafe_offset(k * 8)).unsafe_bitcast[UInt64]().unsafe_load[width=1, alignment=1]()
                    memory[unsafe_offset=i * q * 128 + block_idx * 128 + k] = word
                zero_and_free(b_bytes, 1024)

        zero_and_free(h0_input, 72)

        var iterations = self.iterations
        var type_code = self.type_code
        var parallelism = self.parallelism

        for t in range(iterations):
            for slice_idx in range(4):
                var seg_start = slice_idx * segment_length
                var seg_end = (slice_idx + 1) * segment_length

                @always_inline
                @__copy_capture(
                    memory, seg_start, seg_end, segment_length,
                    q, m_prime_blocks, t, slice_idx, iterations,
                    type_code, parallelism,
                )
                @parameter
                def process_lane(lane: Int):
                    _argon2_process_lane(
                        memory, lane, t, slice_idx, seg_start, seg_end,
                        segment_length, q, m_prime_blocks, iterations,
                        type_code, parallelism,
                    )

                parallelize[process_lane](parallelism)

        var c_block = alloc(Layout[UInt64](count=128)).unsafe_leak()
        zero_buffer_u64(c_block, 128)
        for i in range(self.parallelism):
            var last_ptr = memory.unsafe_offset((i * q * 128 + (q - 1) * 128))
            for k in range(128):
                c_block[unsafe_offset=k] ^= last_ptr[unsafe_offset=k]

        var c_bytes = alloc(Layout[UInt8](count=1024)).unsafe_leak()
        for k in range(128):
            (c_bytes.unsafe_offset(k * 8)).unsafe_bitcast[UInt64]().unsafe_store[alignment=1](c_block[unsafe_offset=k])

        zero_and_free_u64(c_block, 128)
        zero_and_free_u64(memory, m_prime_blocks * 128)
        
        var result = variable_length_hash(self.tag_length, Span[UInt8, ...](unsafe_ptr=c_bytes, length=1024))
        zero_and_free(c_bytes, 1024)
        return result^

def argon2id_hash_string(password: String, salt: String) raises -> String:
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
