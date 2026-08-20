"""
BLAKE3 cryptographic hash function
"""

from max.algorithm import parallelize
from std.collections import List
from std.memory import Pointer, bitcast
from std.bit import count_trailing_zeros
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

@always_inline
def bit_rotr[n: Int, w: Int](v: SIMD[DType.uint32, w]) -> SIMD[DType.uint32, w]:
    var shift = SIMD[DType.uint32, w](n)
    return (v >> shift) | (v << (SIMD[DType.uint32, w](32) - shift))


@always_inline
def g_v_half1[
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
def g_v_half2[
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
def g_v[
    w: Int
](
    mut a: SIMD[DType.uint32, w],
    mut b: SIMD[DType.uint32, w],
    mut c: SIMD[DType.uint32, w],
    mut d: SIMD[DType.uint32, w],
    x: SIMD[DType.uint32, w],
    y: SIMD[DType.uint32, w],
):
    g_v_half1[w](a, b, c, d, x)
    g_v_half2[w](a, b, c, d, y)


@always_inline
def g_idx[
    w: Int, ai: Int, bi: Int, ci: Int, di: Int
](
    mut v: StackInlineArray[SIMD[DType.uint32, w], 16],
    x: SIMD[DType.uint32, w],
    y: SIMD[DType.uint32, w],
):
    # copy in/out so we never hold two mut refs into the same array
    var a = v[ai]
    var b = v[bi]
    var c = v[ci]
    var d = v[di]
    g_v[w](a, b, c, d, x, y)
    v[ai] = a
    v[bi] = b
    v[ci] = c
    v[di] = d

@always_inline
def compress_internal[
    w: Int
](
    cv: SIMD[DType.uint32, 8],
    var m: StackInlineArray[SIMD[DType.uint32, w], 16],
    counter: UInt64,
    blen: UInt8,
    flags: UInt8,
    out_ptr: Pointer[mut=True, SIMD[DType.uint32, w], _, address_space=_],
):
    """BLAKE3 compression: 7 rounds of G with message permutation."""
    # fmt: off
    var v: StackInlineArray[SIMD[DType.uint32, w], 16] = [
        cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
        UInt32(0x6A09E667), UInt32(0xBB67AE85), UInt32(0x3C6EF372), UInt32(0xA54FF53A),
        UInt32(counter & 0xFFFFFFFF),
        UInt32(counter >> 32),
        UInt32(blen),
        UInt32(flags),
    ]
    # fmt: on

    @parameter
    @always_inline
    def round():
        g_idx[w, 0, 4, 8, 12](v, m[0], m[1])
        g_idx[w, 1, 5, 9, 13](v, m[2], m[3])
        g_idx[w, 2, 6, 10, 14](v, m[4], m[5])
        g_idx[w, 3, 7, 11, 15](v, m[6], m[7])
        g_idx[w, 0, 5, 10, 15](v, m[8], m[9])
        g_idx[w, 1, 6, 11, 12](v, m[10], m[11])
        g_idx[w, 2, 7, 8, 13](v, m[12], m[13])
        g_idx[w, 3, 4, 9, 14](v, m[14], m[15])
    
    @parameter
    @always_inline
    def transform():
        # fmt: off
        m = [
            m[2], m[6], m[3], m[10], m[7], m[0], m[4], m[13],
            m[1], m[11], m[12], m[5], m[9], m[14], m[15], m[8],        
        ]
        # fmt: on

    round()
    comptime for _ in range(6):
        transform()
        round()

    out_ptr.unsafe_bitcast[UInt32]().unsafe_store(
        v.unsafe_ptr().unsafe_bitcast[UInt32]().unsafe_load[width=w * 16]()
    )

@always_inline
def compress_core(
    cv: SIMD[DType.uint32, 8],
    block: SIMD[DType.uint32, 16],
    counter: UInt64,
    blen: UInt8,
    flags: UInt8,
) -> SIMD[DType.uint32, 16]:
    """Single-block compression returning 16-word output."""
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

    comptime for i in range(8):
        final[i] = res[i][0] ^ res[i + 8][0]
        final[i + 8] = res[i + 8][0] ^ cv[i]
    return final

@always_inline
def compress_internal_16way(
    c: StackInlineArray[SIMD[DType.uint32, 16], 8],
    var m: StackInlineArray[SIMD[DType.uint32, 16], 16],
    base_counter: UInt64,
    blen: UInt8,
    flags: UInt8,
    out_ptr: Pointer[mut=True, SIMD[DType.uint32, 16], _, address_space=_],
):
    """16-way SIMD compression with per-lane sequential counters."""
    var counters_low = SIMD[DType.uint32, 16](
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    )
    counters_low += UInt32(base_counter & 0xFFFFFFFF)
    # fmt: off
    var v: StackInlineArray[SIMD[DType.uint32, 16], 16] = [
        c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7],
        UInt32(0x6A09E667), UInt32(0xBB67AE85), UInt32(0x3C6EF372), UInt32(0xA54FF53A),
        counters_low,
        UInt32(base_counter >> 32),
        UInt32(blen),
        UInt32(flags),
    ]
    # fmt: on

    @parameter
    @always_inline
    def round():
        g_idx[16, 0, 4, 8, 12](v, m[0], m[1])
        g_idx[16, 1, 5, 9, 13](v, m[2], m[3])
        g_idx[16, 2, 6, 10, 14](v, m[4], m[5])
        g_idx[16, 3, 7, 11, 15](v, m[6], m[7])
        g_idx[16, 0, 5, 10, 15](v, m[8], m[9])
        g_idx[16, 1, 6, 11, 12](v, m[10], m[11])
        g_idx[16, 2, 7, 8, 13](v, m[12], m[13])
        g_idx[16, 3, 4, 9, 14](v, m[14], m[15])

    @parameter
    @always_inline
    def transform():
        # fmt: off
        m = [
            m[2], m[6], m[3], m[10], m[7], m[0], m[4], m[13],
            m[1], m[11], m[12], m[5], m[9], m[14], m[15], m[8],        
        ]
        # fmt: on

    round()
    comptime for _ in range(6):
        transform()
        round()

    out_ptr[unsafe_offset=0] = v[0] ^ v[8]
    out_ptr[unsafe_offset=1] = v[1] ^ v[9]
    out_ptr[unsafe_offset=2] = v[2] ^ v[10]
    out_ptr[unsafe_offset=3] = v[3] ^ v[11]
    out_ptr[unsafe_offset=4] = v[4] ^ v[12]
    out_ptr[unsafe_offset=5] = v[5] ^ v[13]
    out_ptr[unsafe_offset=6] = v[6] ^ v[14]
    out_ptr[unsafe_offset=7] = v[7] ^ v[15]

struct Hasher:
    var key: SIMD[DType.uint32, 8]
    var original_key: SIMD[DType.uint32, 8]
    var cv_stack: StackInlineArray[SIMD[DType.uint32, 8], 54]
    var stack_len: Int
    var buf: StackInlineArray[UInt8, 64]
    var buf_len: Int
    var chunk_counter: UInt64
    var blocks_compressed: Int

    def __init__(out self):
        self.key = IV
        self.original_key = IV
        self.cv_stack = {uninitialized=True}

        self.stack_len = 0

        self.buf = {uninitialized=True}

        self.buf_len = 0
        self.chunk_counter = 0
        self.blocks_compressed = 0

    def update(mut self, input: Span[UInt8, ...]):
        var d = input
        while len(d) > 0:
            if self.buf_len == 64:
                var blk = (
                    self.buf.unsafe_ptr().unsafe_bitcast[UInt32]().unsafe_load[width=16, alignment=1]()
                )

                if self.blocks_compressed == 15:
                    if len(d) > 0:
                        var res = compress_core(
                            self.key,
                            blk,
                            self.chunk_counter,
                            64,
                            (CHUNK_START if self.blocks_compressed == 0 else UInt8(0))
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
                        (CHUNK_START if self.blocks_compressed == 0 else UInt8(0)),
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
    def add_chunk_cv(
        mut self, cv_in: SIMD[DType.uint32, 8], total_chunks: UInt64
    ):
        var new_total = total_chunks + 1
        var new_cv = cv_in
        var num_merges = count_trailing_zeros(new_total)
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
    def add_subtree_cv(mut self, cv_in: SIMD[DType.uint32, 8], height: Int):
        var new_cv = cv_in
        self.chunk_counter += UInt64(1) << UInt64(height)
        var total_at_level = self.chunk_counter >> UInt64(height)

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
    def finalize(self, out_len: Int, out out_buf: List[UInt8]) raises:
        """Finalize the hash and return the output."""
        if out_len < 0:
            raise Error("BLAKE3 output length must be non-negative")
        out_buf = {unsafe_uninit_length=out_len}
        var temp_buf = StackInlineArray[UInt8, 64](uninitialized=True)

        for i in range(64):
            temp_buf.unsafe_set(i, 0)
        for i in range(self.buf_len):
            temp_buf.unsafe_set(i, self.buf[i])

        var blk = temp_buf.unsafe_ptr().unsafe_bitcast[UInt32]().unsafe_load[width=16, alignment=1]()

        var flags = (
            CHUNK_START if self.blocks_compressed == 0 else UInt8(0)
        ) | CHUNK_END

        var working_key: SIMD[DType.uint32, 8]
        var working_blk: SIMD[DType.uint32, 16]
        var working_blen: UInt8
        var working_flags: UInt8

        if self.stack_len == 0:
            working_key = self.key
            working_blk = blk
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

            if to_copy == 64:
                (out_buf.unsafe_ptr().unsafe_offset(bytes_written)).unsafe_store(b)
            else:
                for i in range(to_copy):
                    out_buf.unsafe_set(bytes_written + i, b[i])

            bytes_written += to_copy
            block_idx += 1


@always_inline
def blake3_parallel_hash(input: Span[UInt8, ...], out_len: Int = 32) raises -> List[UInt8]:
    var d = input
    var total_chunks = (len(d) + CHUNK_LEN - 1) // CHUNK_LEN

    if len(d) <= 65536:
        var h = Hasher()
        h.update(d)
        return h.finalize(out_len)

    comptime BSIZE = 64
    var chunks_to_parallelize = total_chunks - 1
    var num_full_batches = chunks_to_parallelize // BSIZE

    var batch_roots = List[SIMD[DType.uint32, 8]](capacity=num_full_batches)
    for _ in range(num_full_batches):
        batch_roots.append(SIMD[DType.uint32, 8](0))
    var batch_roots_ptr = batch_roots.unsafe_ptr()

    @parameter
    def process_batch(tid: Int):
        var task_base = tid * BSIZE
        var base_ptr = d.unsafe_ptr().unsafe_bitcast[UInt32]()
        var local_cvs = StackInlineArray[SIMD[DType.uint32, 8], 64](
            uninitialized=True
        )
        for i in range(0, BSIZE, 16):
            var base = task_base + i
            # fmt: off
            var c: StackInlineArray[SIMD[DType.uint32, 16], 8] = [
                UInt32(0x6A09E667), UInt32(0xBB67AE85), UInt32(0x3C6EF372), UInt32(0xA54FF53A),
                UInt32(0x510E527F), UInt32(0x9B05688C), UInt32(0x1F83D9AB), UInt32(0x5BE0CD19),
            ]
            # fmt: on

            for b in range(16):
                var flags = (CHUNK_START if b == 0 else UInt8(0)) | (
                    CHUNK_END if b == 15 else UInt8(0)
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
                    def _load_idx(v: Int) -> SIMD[DType.uint32, 4]:
                        return base_ptr.unsafe_load[width=4, alignment=1](
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
                c[0] = res[0]
                c[1] = res[1]
                c[2] = res[2]
                c[3] = res[3]
                c[4] = res[4]
                c[5] = res[5]
                c[6] = res[6]
                c[7] = res[7]

            comptime
            for k in range(16):
                # fmt: off
                local_cvs.unsafe_set(i + k, {
                    c[0][k], c[1][k], c[2][k], c[3][k],
                    c[4][k], c[5][k], c[6][k], c[7][k]
                })
                # fmt: on

        for j in [32, 16, 8, 4, 2, 1]:
            for i in range(j):
                var left = local_cvs.unsafe_get(i * 2)
                var right = local_cvs.unsafe_get(i * 2 + 1)
                var combined = compress_core(
                    IV, left.join(right), 0, 64, PARENT
                )
                local_cvs.unsafe_set(i, combined.slice[8]())
        batch_roots_ptr[unsafe_offset=tid] = local_cvs[0]

    parallelize[process_batch](num_full_batches)

    var h = Hasher()
    for i in range(num_full_batches):
        h.add_subtree_cv(batch_roots[i], height=6)

    h.update(d[num_full_batches * 64 * 1024 :])
    return h.finalize(out_len)

def blake3_hash(input: Span[UInt8, ...], out_len: Int = 32) raises -> List[UInt8]:
    return blake3_parallel_hash(input, out_len)
