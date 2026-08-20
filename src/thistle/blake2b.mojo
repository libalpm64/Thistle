"""
BLAKE2b Implementation in Mojo
RFC 7693
"""

from std.collections import List
from std.memory import Pointer, unsafe_memcpy, unsafe_memset_zero
from .utils import bytes_to_hex, string_to_bytes

comptime BLAKE2B_IV = SIMD[DType.uint64, 8](
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
)

comptime SIGMA = (
    SIMD[DType.uint8, 16](0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    SIMD[DType.uint8, 16](14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
    SIMD[DType.uint8, 16](11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
    SIMD[DType.uint8, 16](7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
    SIMD[DType.uint8, 16](9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
    SIMD[DType.uint8, 16](2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
    SIMD[DType.uint8, 16](12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
    SIMD[DType.uint8, 16](13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
    SIMD[DType.uint8, 16](6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
    SIMD[DType.uint8, 16](10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
    SIMD[DType.uint8, 16](0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    SIMD[DType.uint8, 16](14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
)


@always_inline
def rotr64[n: Int](x: UInt64) -> UInt64:
    return (x >> UInt64(n)) | (x << UInt64(64 - n))


@always_inline
def g(a: UInt64, b: UInt64, c: UInt64, d: UInt64, x: UInt64, y: UInt64) -> Tuple[UInt64, UInt64, UInt64, UInt64]:
    var va = a + b + x
    var vd = rotr64[32](d ^ va)
    var vc = c + vd
    var vb = rotr64[24](b ^ vc)
    va = va + vb + y
    vd = rotr64[16](vd ^ va)
    vc = vc + vd
    vb = rotr64[63](vb ^ vc)
    return (va, vb, vc, vd)


@always_inline
def _mload(m: Pointer[mut=False, UInt8, _, address_space=_], i: Int) -> UInt64:
    return (m.unsafe_offset(i * 8)).unsafe_bitcast[UInt64]().unsafe_load[width=1, alignment=1]()


@always_inline
def round_fn[r: Int](
    mut v0: UInt64, mut v1: UInt64, mut v2: UInt64, mut v3: UInt64,
    mut v4: UInt64, mut v5: UInt64, mut v6: UInt64, mut v7: UInt64,
    mut v8: UInt64, mut v9: UInt64, mut v10: UInt64, mut v11: UInt64,
    mut v12: UInt64, mut v13: UInt64, mut v14: UInt64, mut v15: UInt64,
    m: Pointer[mut=False, UInt8, _, address_space=_],
) -> Tuple[UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64]:
    comptime s = SIGMA[r]

    v0, v4, v8, v12 = g(v0, v4, v8, v12, _mload(m, Int(s[0])), _mload(m, Int(s[1])))
    v1, v5, v9, v13 = g(v1, v5, v9, v13, _mload(m, Int(s[2])), _mload(m, Int(s[3])))
    v2, v6, v10, v14 = g(v2, v6, v10, v14, _mload(m, Int(s[4])), _mload(m, Int(s[5])))
    v3, v7, v11, v15 = g(v3, v7, v11, v15, _mload(m, Int(s[6])), _mload(m, Int(s[7])))

    v0, v5, v10, v15 = g(v0, v5, v10, v15, _mload(m, Int(s[8])), _mload(m, Int(s[9])))
    v1, v6, v11, v12 = g(v1, v6, v11, v12, _mload(m, Int(s[10])), _mload(m, Int(s[11])))
    v2, v7, v8, v13 = g(v2, v7, v8, v13, _mload(m, Int(s[12])), _mload(m, Int(s[13])))
    v3, v4, v9, v14 = g(v3, v4, v9, v14, _mload(m, Int(s[14])), _mload(m, Int(s[15])))

    return (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15)


struct Blake2b(Movable):
    var h: SIMD[DType.uint64, 8]
    var t_low: UInt64
    var t_high: UInt64
    var buffer: InlineArray[UInt64, 16]
    var buffer_len: Int
    var out_len: Int
    var key_len: Int

    @always_inline
    def _buf_ptr(mut self) -> Pointer[UInt8, MutAnyOrigin]:
        return self.buffer.unsafe_ptr().unsafe_bitcast[UInt8]().unsafe_origin_cast[MutAnyOrigin]()

    def __init__(out self, out_len: Int = 64) raises:
        if out_len < 1 or out_len > 64:
            raise Error("BLAKE2b digest length must be 1..64")
        self.out_len = out_len
        self.key_len = 0
        self.h = BLAKE2B_IV
        self.t_low = 0
        self.t_high = 0
        self.buffer = InlineArray[UInt64, 16](fill=0)
        self.buffer_len = 0

        var p0: UInt64 = 0x01010000
        p0 |= UInt64(self.key_len) << 8
        p0 |= UInt64(self.out_len)

        self.h[0] ^= p0

    def __init__(out self, out_len: Int, key: Span[UInt8, ...]) raises:
        if out_len < 1 or out_len > 64:
            raise Error("BLAKE2b digest length must be 1..64")
        if len(key) > 64:
            raise Error("BLAKE2b key must be at most 64 bytes")
        self.out_len = out_len
        self.key_len = len(key)
        self.h = BLAKE2B_IV
        self.t_low = 0
        self.t_high = 0
        self.buffer = InlineArray[UInt64, 16](fill=0)
        self.buffer_len = 0

        var p0: UInt64 = 0x01010000
        p0 |= UInt64(self.key_len) << 8
        p0 |= UInt64(self.out_len)

        self.h[0] ^= p0

        if self.key_len > 0:
            self.update(key)
            var buf = self._buf_ptr()
            while self.buffer_len < 128:
                buf[unsafe_offset=self.buffer_len] = 0
                self.buffer_len += 1

    def __init__(out self, *, deinit move: Self):
        self.h = move.h
        self.t_low = move.t_low
        self.t_high = move.t_high
        self.buffer = move.buffer^
        self.buffer_len = move.buffer_len
        self.out_len = move.out_len
        self.key_len = move.key_len

    def __deinit__(deinit self):
        Pointer(to=self.h).unsafe_bitcast[UInt64]().unsafe_store[volatile=True](
            0, SIMD[DType.uint64, 8](0)
        )
        unsafe_memset_zero(self.buffer.unsafe_ptr(), 16)

    @always_inline
    def _inc_counter(mut self):
        self.t_low += 128
        if self.t_low < 128:
            self.t_high += 1

    def compress(mut self, m: Pointer[mut=False, UInt8, _, address_space=_], is_last: Bool):
        var v0 = self.h[0]
        var v1 = self.h[1]
        var v2 = self.h[2]
        var v3 = self.h[3]
        var v4 = self.h[4]
        var v5 = self.h[5]
        var v6 = self.h[6]
        var v7 = self.h[7]
        var v8 = BLAKE2B_IV[0]
        var v9 = BLAKE2B_IV[1]
        var v10 = BLAKE2B_IV[2]
        var v11 = BLAKE2B_IV[3]
        var v12 = BLAKE2B_IV[4]
        var v13 = BLAKE2B_IV[5]
        var v14 = BLAKE2B_IV[6]
        var v15 = BLAKE2B_IV[7]

        v12 ^= self.t_low
        v13 ^= self.t_high

        if is_last:
            v14 ^= 0xFFFFFFFFFFFFFFFF

        (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) = round_fn[0](v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, m)
        (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) = round_fn[1](v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, m)
        (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) = round_fn[2](v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, m)
        (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) = round_fn[3](v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, m)
        (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) = round_fn[4](v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, m)
        (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) = round_fn[5](v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, m)
        (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) = round_fn[6](v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, m)
        (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) = round_fn[7](v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, m)
        (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) = round_fn[8](v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, m)
        (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) = round_fn[9](v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, m)
        (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) = round_fn[10](v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, m)
        (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) = round_fn[11](v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, m)

        self.h[0] ^= v0 ^ v8
        self.h[1] ^= v1 ^ v9
        self.h[2] ^= v2 ^ v10
        self.h[3] ^= v3 ^ v11
        self.h[4] ^= v4 ^ v12
        self.h[5] ^= v5 ^ v13
        self.h[6] ^= v6 ^ v14
        self.h[7] ^= v7 ^ v15

    def update(mut self, data: Span[UInt8, ...]):
        var total = len(data)
        if total == 0:
            return
        var i = 0

        if self.buffer_len > 0:
            if self.buffer_len < 128:
                var to_copy = 128 - self.buffer_len
                if total < to_copy:
                    to_copy = total
                for j in range(to_copy):
                    self._buf_ptr()[unsafe_offset=self.buffer_len + j] = data[j]
                self.buffer_len += to_copy
                i += to_copy
            if i == total:
                return
            self._inc_counter()
            self.compress(self._buf_ptr(), False)
            self.buffer_len = 0

        while total - i > 128:
            self._inc_counter()
            self.compress(data.unsafe_ptr().unsafe_offset(i), False)
            i += 128

        for j in range(total - i):
            self._buf_ptr()[unsafe_offset=j] = data[i + j]
        self.buffer_len = total - i

    def finalize_into(mut self, output: Pointer[mut=True, UInt8, _, address_space=_]):
        var old_low = self.t_low
        self.t_low += UInt64(self.buffer_len)
        if self.t_low < old_low:
            self.t_high += 1

        if self.buffer_len < 128:
            unsafe_memset_zero(self._buf_ptr().unsafe_offset(self.buffer_len), 128 - self.buffer_len)
            self.buffer_len = 128

        self.compress(self._buf_ptr(), True)

        var h_copy = self.h
        var h_bytes = Pointer(to=h_copy).unsafe_bitcast[UInt8]()
        for i in range(self.out_len):
            output[unsafe_offset=i] = h_bytes[unsafe_offset=i]

    def finalize(mut self) -> List[UInt8]:
        var output = List[UInt8](capacity=self.out_len)
        for _ in range(self.out_len):
            output.append(0)
        self.finalize_into(output.unsafe_ptr())
        return output^


def blake2b_hash(data: Span[UInt8, ...], out_len: Int = 64) raises -> List[UInt8]:
    if out_len < 1 or out_len > 64:
        raise Error("BLAKE2b digest length must be 1..64")
    var ctx = Blake2b(out_len)
    ctx.update(data)
    return ctx.finalize()


def blake2b_hash_keyed(
    data: Span[UInt8, ...], key: Span[UInt8, ...], out_len: Int = 64
) raises -> List[UInt8]:
    if out_len < 1 or out_len > 64:
        raise Error("BLAKE2b digest length must be 1..64")
    if len(key) > 64:
        raise Error("BLAKE2b key must be at most 64 bytes")
    var ctx = Blake2b(out_len, key)
    ctx.update(data)
    return ctx.finalize()


def blake2b_hash_string(s: String, out_len: Int = 64) raises -> String:
    var data = string_to_bytes(s)
    var hash = blake2b_hash(Span[UInt8, ...](data), out_len)
    return bytes_to_hex(hash)
