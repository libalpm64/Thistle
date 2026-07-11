"""
SHA-2 (SHA-256/SHA-512) Implementation in Mojo
RFC 6234 / FIPS 180-4 / CAVP validated
"""

from std.collections import List
from std.memory import UnsafePointer, alloc, memcpy, memset_zero
from std.bit import rotate_bits_left, rotate_bits_right, byte_swap
from std.builtin.simd import SIMD
from std.builtin.dtype import DType

comptime SHA256_K = SIMD[DType.uint32, 64](
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B,
    0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01,
    0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7,
    0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152,
    0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
    0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC,
    0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819,
    0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116, 0x1E376C08,
    0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F,
    0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)

comptime SHA512_K = SIMD[DType.uint64, 80](
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC, 0x3956C25BF348B538,
    0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118, 0xD807AA98A3030242, 0x12835B0145706FBE,
    0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2, 0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235,
    0xC19BF174CF692694, 0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5, 0x983E5152EE66DFAB,
    0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4, 0xC6E00BF33DA88FC2, 0xD5A79147930AA725,
    0x06CA6351E003826F, 0x142929670A0E6E70, 0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED,
    0x53380D139D95B3DF, 0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
    0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30, 0xD192E819D6EF5218,
    0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8, 0x19A4C116B8D2D0C8, 0x1E376C085141AB53,
    0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8, 0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373,
    0x682E6FF3D6B2B8A3, 0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
    0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B, 0xCA273ECEEA26619C,
    0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178, 0x06F067AA72176FBA, 0x0A637DC5A2C898A6,
    0x113F9804BEF90DAE, 0x1B710B35131C471B, 0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC,
    0x431D67C49C100D4C, 0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
)

@always_inline
def ch32(x: UInt32, y: UInt32, z: UInt32) -> UInt32:
    return (x & y) ^ ((~x) & z)


@always_inline
def maj32(x: UInt32, y: UInt32, z: UInt32) -> UInt32:
    return (x & y) ^ (x & z) ^ (y & z)


@always_inline
def ch64(x: UInt64, y: UInt64, z: UInt64) -> UInt64:
    return (x & y) ^ ((~x) & z)


@always_inline
def maj64(x: UInt64, y: UInt64, z: UInt64) -> UInt64:
    return (x & y) ^ (x & z) ^ (y & z)


@always_inline
def sigma0_32(x: UInt32) -> UInt32:
    return rotate_bits_right[2](x) ^ rotate_bits_right[13](x) ^ rotate_bits_right[22](x)


@always_inline
def sigma1_32(x: UInt32) -> UInt32:
    return rotate_bits_right[6](x) ^ rotate_bits_right[11](x) ^ rotate_bits_right[25](x)


@always_inline
def small_sigma0_32(x: UInt32) -> UInt32:
    return rotate_bits_right[7](x) ^ rotate_bits_right[18](x) ^ (x >> 3)


@always_inline
def small_sigma1_32(x: UInt32) -> UInt32:
    return rotate_bits_right[17](x) ^ rotate_bits_right[19](x) ^ (x >> 10)


@always_inline
def sigma0_64(x: UInt64) -> UInt64:
    return rotate_bits_right[28](x) ^ rotate_bits_right[34](x) ^ rotate_bits_right[39](x)


@always_inline
def sigma1_64(x: UInt64) -> UInt64:
    return rotate_bits_right[14](x) ^ rotate_bits_right[18](x) ^ rotate_bits_right[41](x)


@always_inline
def small_sigma0_64(x: UInt64) -> UInt64:
    return rotate_bits_right[1](x) ^ rotate_bits_right[8](x) ^ (x >> 7)


@always_inline
def small_sigma1_64(x: UInt64) -> UInt64:
    return rotate_bits_right[19](x) ^ rotate_bits_right[61](x) ^ (x >> 6)


struct SHA2Config[
    WordType: DType,
    Rounds: Int,
    BlockSize: Int,
    DigestSize: Int,
    WordByteSize: Int,
    IV: SIMD[WordType, 8],
    K: SIMD[WordType, Rounds],
]:
    alias word_size = WordByteSize
    alias rounds = Rounds
    alias block_size = BlockSize
    alias digest_size = DigestSize


comptime SHA256Config = SHA2Config[
    DType.uint32, 64, 64, 32, 4, SHA256_IV, SHA256_K
]
comptime SHA512Config = SHA2Config[
    DType.uint64, 80, 128, 64, 8, SHA512_IV, SHA512_K
]
comptime SHA224Config = SHA2Config[
    DType.uint32, 64, 64, 32, 4, SHA224_IV, SHA256_K
]
comptime SHA384Config = SHA2Config[
    DType.uint64, 80, 128, 64, 8, SHA384_IV, SHA512_K
]


@always_inline
def ch_generic[WordType: DType](x: SIMD[WordType, 1], y: SIMD[WordType, 1], z: SIMD[WordType, 1]) -> SIMD[WordType, 1]:
    return (x & y) ^ ((~x) & z)


@always_inline
def maj_generic[WordType: DType](x: SIMD[WordType, 1], y: SIMD[WordType, 1], z: SIMD[WordType, 1]) -> SIMD[WordType, 1]:
    return (x & y) ^ (x & z) ^ (y & z)


@always_inline
def sigma0_generic[WordType: DType](x: SIMD[WordType, 1]) -> SIMD[WordType, 1]:
    comptime if WordType == DType.uint32:
        return SIMD[WordType, 1](rotate_bits_right[2](x[0]) ^ rotate_bits_right[13](x[0]) ^ rotate_bits_right[22](x[0]))
    else:
        return SIMD[WordType, 1](rotate_bits_right[28](x[0]) ^ rotate_bits_right[34](x[0]) ^ rotate_bits_right[39](x[0]))


@always_inline
def sigma1_generic[WordType: DType](x: SIMD[WordType, 1]) -> SIMD[WordType, 1]:
    comptime if WordType == DType.uint32:
        return SIMD[WordType, 1](rotate_bits_right[6](x[0]) ^ rotate_bits_right[11](x[0]) ^ rotate_bits_right[25](x[0]))
    else:
        return SIMD[WordType, 1](rotate_bits_right[14](x[0]) ^ rotate_bits_right[18](x[0]) ^ rotate_bits_right[41](x[0]))


@always_inline
def small_sigma0_generic[WordType: DType](x: SIMD[WordType, 1]) -> SIMD[WordType, 1]:
    comptime if WordType == DType.uint32:
        return SIMD[WordType, 1](rotate_bits_right[7](x[0]) ^ rotate_bits_right[18](x[0]) ^ (x[0] >> 3))
    else:
        return SIMD[WordType, 1](rotate_bits_right[1](x[0]) ^ rotate_bits_right[8](x[0]) ^ (x[0] >> 7))


@always_inline
def small_sigma1_generic[WordType: DType](x: SIMD[WordType, 1]) -> SIMD[WordType, 1]:
    comptime if WordType == DType.uint32:
        return SIMD[WordType, 1](rotate_bits_right[17](x[0]) ^ rotate_bits_right[19](x[0]) ^ (x[0] >> 10))
    else:
        return SIMD[WordType, 1](rotate_bits_right[19](x[0]) ^ rotate_bits_right[61](x[0]) ^ (x[0] >> 6))


@always_inline
def nibble_to_hex_char(nibble: UInt8) -> UInt8:
    """Convert a nibble (0-15) to its hex character ASCII value."""
    if nibble < 10:
        return nibble + 0x30
    else:
        return nibble - 10 + 0x61


def bytes_to_hex(data: List[UInt8]) -> String:
    """Convert a byte list to a hexadecimal string."""
    var result = String(capacity=len(data) * 2)
    for i in range(len(data)):
        var b = data[i]
        var high = (b >> 4) & 0x0F
        var low = b & 0x0F
        result += chr(Int(nibble_to_hex_char(high)))
        result += chr(Int(nibble_to_hex_char(low)))
    return result


def bytes_to_hex(data: SIMD[DType.uint8, 16]) -> String:
    """Convert a 16-byte SIMD vector to a hexadecimal string."""
    var result = String(capacity=32)
    for i in range(16):
        var b = data[i]
        var high = (b >> 4) & 0x0F
        var low = b & 0x0F
        result += chr(Int(nibble_to_hex_char(high)))
        result += chr(Int(nibble_to_hex_char(low)))
    return result


def bytes_to_hex(data: Span[UInt8, ...]) -> String:
    """Convert a byte span to a hexadecimal string."""
    var result = String(capacity=len(data) * 2)
    for i in range(len(data)):
        var b = data[i]
        var high = (b >> 4) & 0x0F
        var low = b & 0x0F
        result += chr(Int(nibble_to_hex_char(high)))
        result += chr(Int(nibble_to_hex_char(low)))
    return result


def string_to_bytes(s: String) -> List[UInt8]:
    """Convert a string to a list of bytes."""
    var bytes = s.as_bytes()
    var data = List[UInt8](capacity=len(bytes))
    for i in range(len(bytes)):
        data.append(bytes[i])
    return data^

comptime SHA256_IV = SIMD[DType.uint32, 8](
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)

comptime SHA224_IV = SIMD[DType.uint32, 8](
    0xC1059ED8,
    0x367CD507,
    0x3070DD17,
    0xF70E5939,
    0xFFC00B31,
    0x68581511,
    0x64F98FA7,
    0xBEFA4FA4,
)

comptime SHA512_IV = SIMD[DType.uint64, 8](
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
)

comptime SHA384_IV = SIMD[DType.uint64, 8](
    0xCBBB9D5DC1059ED8,
    0x629A292A367CD507,
    0x9159015A3070DD17,
    0x152FECD8F70E5939,
    0x67332667FFC00B31,
    0x8EB44A8768581511,
    0xDB0C2E0D64F98FA7,
    0x47B5481DBEFA4FA4,
)

@always_inline
def zero_buffer(ptr: UnsafePointer[UInt8, MutAnyOrigin], len: Int):
    memset_zero(ptr, len)


@always_inline
def load_32be(ptr: UnsafePointer[UInt8, ImmutAnyOrigin], offset: Int) -> UInt32:
    return byte_swap((ptr + offset).bitcast[UInt32]().load[width=1, alignment=1]())


@always_inline
def load_64be(ptr: UnsafePointer[UInt8, ImmutAnyOrigin], offset: Int) -> UInt64:
    return byte_swap((ptr + offset).bitcast[UInt64]().load[width=1, alignment=1]())

@always_inline
def zero_and_free(ptr: UnsafePointer[UInt8, MutAnyOrigin], len: Int):
    zero_buffer(ptr, len)
    ptr.free()

struct SHA256Context(Movable):
    var state: SIMD[DType.uint32, 8]
    var count: UInt64
    var buffer: InlineArray[UInt8, 64]
    var buffer_len: Int

    def __init__(out self):
        self.state = SHA256_IV
        self.count = 0
        self.buffer = InlineArray[UInt8, 64](fill=0)
        self.buffer_len = 0

    def __init__(out self, iv: SIMD[DType.uint32, 8]):
        self.state = iv
        self.count = 0
        self.buffer = InlineArray[UInt8, 64](fill=0)
        self.buffer_len = 0

    def __init__(out self, *, deinit take: Self):
        self.state = take.state
        self.count = take.count
        self.buffer = take.buffer^
        self.buffer_len = take.buffer_len

    def __del__(deinit self):
        memset_zero(self.buffer.unsafe_ptr(), 64)

    def reset(mut self):
        self.state = SHA256_IV
        self.count = 0
        memset_zero(self.buffer.unsafe_ptr(), 64)
        self.buffer_len = 0

    def reset(mut self, iv: SIMD[DType.uint32, 8]):
        self.state = iv
        self.count = 0
        memset_zero(self.buffer.unsafe_ptr(), 64)
        self.buffer_len = 0

@always_inline
def sha256_transform_blocks(
    mut state: SIMD[DType.uint32, 8],
    data: UnsafePointer[UInt8, ImmutAnyOrigin],
    nblocks: Int,
):
    var a0 = state[0]
    var b0 = state[1]
    var c0 = state[2]
    var d0 = state[3]
    var e0 = state[4]
    var f0 = state[5]
    var g0 = state[6]
    var h0 = state[7]

    for blk in range(nblocks):
        var block = data + blk * 64
        var w = InlineArray[UInt32, 16](uninitialized=True)

        var a = a0
        var b = b0
        var c = c0
        var d = d0
        var e = e0
        var f = f0
        var g = g0
        var h = h0

        comptime for i in range(16):
            var word = load_32be(block, i * 4)
            w[i] = word

            var t1 = h + sigma1_32(e) + ch32(e, f, g) + SHA256_K[i] + word
            var t2 = sigma0_32(a) + maj32(a, b, c)
            h = g
            g = f
            f = e
            e = d + t1
            d = c
            c = b
            b = a
            a = t1 + t2

        comptime for i in range(16, 64):
            var idx = i & 0xF
            var s0 = small_sigma0_32(w[(i - 15) & 0xF])
            var s1 = small_sigma1_32(w[(i - 2) & 0xF])
            var word = s1 + w[(i - 7) & 0xF] + s0 + w[(i - 16) & 0xF]
            w[idx] = word

            var t1 = h + sigma1_32(e) + ch32(e, f, g) + SHA256_K[i] + word
            var t2 = sigma0_32(a) + maj32(a, b, c)
            h = g
            g = f
            f = e
            e = d + t1
            d = c
            c = b
            b = a
            a = t1 + t2

        a0 += a
        b0 += b
        c0 += c
        d0 += d
        e0 += e
        f0 += f
        g0 += g
        h0 += h

    state = SIMD[DType.uint32, 8](a0, b0, c0, d0, e0, f0, g0, h0)


@always_inline
def sha256_transform(
    state: SIMD[DType.uint32, 8], block: Span[UInt8, ...]
) -> SIMD[DType.uint32, 8]:
    var s = state
    sha256_transform_blocks(s, block.unsafe_ptr(), 1)
    return s


def sha256_update(mut ctx: SHA256Context, data: Span[UInt8, ...]):
    var buf_ptr = ctx.buffer.unsafe_ptr()
    var i = 0
    var total_len = len(data)

    if ctx.buffer_len > 0:
        var available = 64 - ctx.buffer_len
        if total_len >= available:
            memcpy(
                dest=buf_ptr + ctx.buffer_len,
                src=data.unsafe_ptr(),
                count=available,
            )
            ctx.state = sha256_transform(
                ctx.state, Span[UInt8, ...](ptr=buf_ptr, length=64)
            )
            ctx.count += 512
            i += available
            ctx.buffer_len = 0
        else:
            memcpy(
                dest=buf_ptr + ctx.buffer_len,
                src=data.unsafe_ptr(),
                count=total_len,
            )
            ctx.buffer_len += total_len
            return

    var nblocks = (total_len - i) // 64
    if nblocks > 0:
        sha256_transform_blocks(ctx.state, data.unsafe_ptr() + i, nblocks)
        ctx.count += UInt64(nblocks) * 512
        i += nblocks * 64

    if i < total_len:
        var remaining = total_len - i
        memcpy(
            dest=buf_ptr + ctx.buffer_len,
            src=data.unsafe_ptr() + i,
            count=remaining,
        )
        ctx.buffer_len += remaining


def sha256_final(mut ctx: SHA256Context) -> List[UInt8]:
    var output = List[UInt8](capacity=32)
    for _ in range(32):
        output.append(0)
    sha256_final_to_buffer(ctx, output.unsafe_ptr())
    return output^

def sha256_hash(data: Span[UInt8, ...]) -> List[UInt8]:
    var ctx = SHA256Context()
    sha256_update(ctx, data)
    return sha256_final(ctx)


def sha256_final_to_buffer(mut ctx: SHA256Context, output: UnsafePointer[UInt8, MutAnyOrigin]):
    var buf_ptr = ctx.buffer.unsafe_ptr()
    var bit_count = ctx.count + UInt64(ctx.buffer_len) * 8

    ctx.buffer[ctx.buffer_len] = 0x80
    ctx.buffer_len += 1

    if ctx.buffer_len > 56:
        memset_zero(buf_ptr + ctx.buffer_len, 64 - ctx.buffer_len)
        ctx.state = sha256_transform(
            ctx.state, Span[UInt8, ...](ptr=buf_ptr, length=64)
        )
        ctx.buffer_len = 0

    memset_zero(buf_ptr + ctx.buffer_len, 56 - ctx.buffer_len)
    ctx.buffer_len = 56

    for i in range(8):
        ctx.buffer[56 + i] = UInt8(UInt64(bit_count >> UInt64(56 - i * 8)) & 0xFF)

    ctx.state = sha256_transform(
        ctx.state, Span[UInt8, ...](ptr=buf_ptr, length=64)
    )

    for i in range(8):
        (output + i * 4).bitcast[UInt32]().store[alignment=1](byte_swap(ctx.state[i]))

struct SHA512Context(Movable):
    var state: SIMD[DType.uint64, 8]
    var count_high: UInt64
    var count_low: UInt64
    var buffer: InlineArray[UInt8, 128]
    var buffer_len: Int

    def __init__(out self):
        var iv = SHA512_IV
        self.state = iv
        self.count_high = 0
        self.count_low = 0
        self.buffer = InlineArray[UInt8, 128](fill=0)
        self.buffer_len = 0

    def __init__(out self, iv: SIMD[DType.uint64, 8]):
        self.state = iv
        self.count_high = 0
        self.count_low = 0
        self.buffer = InlineArray[UInt8, 128](fill=0)
        self.buffer_len = 0

    def __init__(out self, *, deinit take: Self):
        self.state = take.state
        self.count_high = take.count_high
        self.count_low = take.count_low
        self.buffer = take.buffer^
        self.buffer_len = take.buffer_len

    def __del__(deinit self):
        memset_zero(self.buffer.unsafe_ptr(), 128)

    def wipe(mut self):
        UnsafePointer(to=self.state).bitcast[UInt64]().store[volatile=True](
            0, SIMD[DType.uint64, 8](0)
        )
        var buf_ptr = self.buffer.unsafe_ptr()
        for i in range(128):
            buf_ptr.store[volatile=True](i, UInt8(0))
        self.count_high = 0
        self.count_low = 0
        self.buffer_len = 0

    def reset(mut self):
        var iv = SHA512_IV
        self.state = iv
        self.count_high = 0
        self.count_low = 0
        memset_zero(self.buffer.unsafe_ptr(), 128)
        self.buffer_len = 0

    def reset(mut self, iv: SIMD[DType.uint64, 8]):
        self.state = iv
        self.count_high = 0
        self.count_low = 0
        memset_zero(self.buffer.unsafe_ptr(), 128)
        self.buffer_len = 0


@always_inline
def sha512_transform_blocks(
    mut state: SIMD[DType.uint64, 8],
    data: UnsafePointer[UInt8, ImmutAnyOrigin],
    nblocks: Int,
):
    var a0 = state[0]
    var b0 = state[1]
    var c0 = state[2]
    var d0 = state[3]
    var e0 = state[4]
    var f0 = state[5]
    var g0 = state[6]
    var h0 = state[7]

    for blk in range(nblocks):
        var block = data + blk * 128
        var w = InlineArray[UInt64, 16](uninitialized=True)

        var a = a0
        var b = b0
        var c = c0
        var d = d0
        var e = e0
        var f = f0
        var g = g0
        var h = h0

        comptime for i in range(16):
            var word = load_64be(block, i * 8)
            w[i] = word

            var t1 = h + sigma1_64(e) + ch64(e, f, g) + SHA512_K[i] + word
            var t2 = sigma0_64(a) + maj64(a, b, c)
            h = g
            g = f
            f = e
            e = d + t1
            d = c
            c = b
            b = a
            a = t1 + t2

        comptime for i in range(16, 80):
            var s0 = small_sigma0_64(w[(i - 15) & 0xF])
            var word = s1 + w[(i - 7) & 0xF] + s0 + w[(i - 16) & 0xF]
            w[i & 0xF] = word

            var t1 = h + sigma1_64(e) + ch64(e, f, g) + SHA512_K[i] + word
            var t2 = sigma0_64(a) + maj64(a, b, c)
            h = g
            g = f
            f = e
            e = d + t1
            d = c
            c = b
            b = a
            a = t1 + t2

        a0 += a
        b0 += b
        c0 += c
        d0 += d
        e0 += e
        f0 += f
        g0 += g
        h0 += h

    state = SIMD[DType.uint64, 8](a0, b0, c0, d0, e0, f0, g0, h0)


@always_inline
def sha512_transform(
    state: SIMD[DType.uint64, 8], block: Span[UInt8, ...]
) -> SIMD[DType.uint64, 8]:
    var s = state
    sha512_transform_blocks(s, block.unsafe_ptr(), 1)
    return s


@always_inline
def sha512_update(mut ctx: SHA512Context, data: Span[UInt8, ...]):
    var buf_ptr = ctx.buffer.unsafe_ptr()
    var i = 0
    var total_len = len(data)

    if ctx.buffer_len > 0:
        var available = 128 - ctx.buffer_len
        if total_len >= available:
            memcpy(
                dest=buf_ptr + ctx.buffer_len,
                src=data.unsafe_ptr(),
                count=available,
            )
            ctx.state = sha512_transform(
                ctx.state, Span[UInt8, ...](ptr=buf_ptr, length=128)
            )

            var old_low = ctx.count_low
            ctx.count_low += 1024
            if ctx.count_low < old_low:
                ctx.count_high += 1

            i += available
            ctx.buffer_len = 0
        else:
            memcpy(
                dest=buf_ptr + ctx.buffer_len,
                src=data.unsafe_ptr(),
                count=total_len,
            )
            ctx.buffer_len += total_len
            return

    var nblocks = (total_len - i) // 128
    if nblocks > 0:
        sha512_transform_blocks(ctx.state, data.unsafe_ptr() + i, nblocks)

        var old_low = ctx.count_low
        ctx.count_low += UInt64(nblocks) * 1024
        if ctx.count_low < old_low:
            ctx.count_high += 1

        i += nblocks * 128

    if i < total_len:
        var remaining = total_len - i
        memcpy(
            dest=buf_ptr + ctx.buffer_len,
            src=data.unsafe_ptr() + i,
            count=remaining,
        )
        ctx.buffer_len += remaining


def sha512_final(mut ctx: SHA512Context) -> List[UInt8]:
    var output = List[UInt8](capacity=64)
    for _ in range(64):
        output.append(0)
    sha512_final_to_buffer(ctx, output.unsafe_ptr())
    return output^

def sha512_hash(data: Span[UInt8, ...]) -> List[UInt8]:
    var ctx = SHA512Context(SHA512_IV)
    sha512_update(ctx, data)
    return sha512_final(ctx)


def sha512_final_to_buffer(mut ctx: SHA512Context, output: UnsafePointer[UInt8, MutAnyOrigin]):
    var buf_ptr = ctx.buffer.unsafe_ptr()
    var final_low = ctx.count_low + UInt64(ctx.buffer_len) * 8
    var final_high = ctx.count_high
    if final_low < ctx.count_low:
        final_high += 1

    ctx.buffer[ctx.buffer_len] = 0x80
    ctx.buffer_len += 1

    if ctx.buffer_len > 112:
        memset_zero(buf_ptr + ctx.buffer_len, 128 - ctx.buffer_len)
        ctx.state = sha512_transform(
            ctx.state, Span[UInt8, ...](ptr=buf_ptr, length=128)
        )
        ctx.buffer_len = 0

    memset_zero(buf_ptr + ctx.buffer_len, 112 - ctx.buffer_len)
    ctx.buffer_len = 112

    for i in range(8):
        ctx.buffer[112 + i] = UInt8(UInt64(final_high >> UInt64(56 - i * 8)) & 0xFF)
    for i in range(8):
        ctx.buffer[120 + i] = UInt8(UInt64(final_low >> UInt64(56 - i * 8)) & 0xFF)

    ctx.state = sha512_transform(
        ctx.state, Span[UInt8, ...](ptr=buf_ptr, length=128)
    )

    for i in range(8):
        (output + i * 8).bitcast[UInt64]().store[alignment=1](byte_swap(ctx.state[i]))

def sha256_final_with_len(mut ctx: SHA256Context, output_len: Int) -> List[UInt8]:
    var buf_ptr = ctx.buffer.unsafe_ptr()
    var bit_count = ctx.count + UInt64(ctx.buffer_len) * 8

    ctx.buffer[ctx.buffer_len] = 0x80
    ctx.buffer_len += 1

    if ctx.buffer_len > 56:
        memset_zero(buf_ptr + ctx.buffer_len, 64 - ctx.buffer_len)
        ctx.state = sha256_transform(
            ctx.state, Span[UInt8, ...](ptr=buf_ptr, length=64)
        )
        ctx.buffer_len = 0

    memset_zero(buf_ptr + ctx.buffer_len, 56 - ctx.buffer_len)
    ctx.buffer_len = 56

    for i in range(8):
        ctx.buffer[56 + i] = UInt8(UInt64(bit_count >> UInt64(56 - i * 8)) & 0xFF)

    ctx.state = sha256_transform(
        ctx.state, Span[UInt8, ...](ptr=buf_ptr, length=64)
    )

    var output = List[UInt8](capacity=output_len)
    var words_needed = (output_len + 3) // 4
    for i in range(words_needed):
        var word = ctx.state[i]
        var bytes_in_word = 4
        if i == words_needed - 1:
            bytes_in_word = output_len - i * 4
        for j in range(bytes_in_word):
            output.append(UInt8(UInt32(word >> UInt32(24 - j * 8)) & 0xFF))
    return output^


def sha224_hash(data: Span[UInt8, ...]) -> List[UInt8]:
    var ctx = SHA256Context(SHA224_IV)
    sha256_update(ctx, data)
    return sha256_final_with_len(ctx, 28)


@always_inline
def high_bits_mask(n: Int) -> UInt8:
    if n == 0:
        return 0x00
    return UInt8(0xFF) << UInt8(8 - n)


@always_inline
def padding_bit(n: Int) -> UInt8:
    return UInt8(0x80 >> n)


def sha256_final_partial(
    mut ctx: SHA256Context, final_octet: UInt8, final_bit_count: Int, output_len: Int
) -> List[UInt8]:
    var buf_ptr = ctx.buffer.unsafe_ptr()
    var bit_count = ctx.count + UInt64(ctx.buffer_len) * 8 + UInt64(final_bit_count)
    ctx.buffer[ctx.buffer_len] = (final_octet & high_bits_mask(final_bit_count)) | padding_bit(final_bit_count)
    ctx.buffer_len += 1

    if ctx.buffer_len > 56:
        memset_zero(buf_ptr + ctx.buffer_len, 64 - ctx.buffer_len)
        ctx.state = sha256_transform(
            ctx.state, Span[UInt8, ...](ptr=buf_ptr, length=64)
        )
        ctx.buffer_len = 0

    memset_zero(buf_ptr + ctx.buffer_len, 56 - ctx.buffer_len)
    ctx.buffer_len = 56

    for i in range(8):
        ctx.buffer[56 + i] = UInt8(UInt64(bit_count >> UInt64(56 - i * 8)) & 0xFF)

    ctx.state = sha256_transform(
        ctx.state, Span[UInt8, ...](ptr=buf_ptr, length=64)
    )

    var output = List[UInt8](capacity=output_len)
    var words_needed = (output_len + 3) // 4
    for i in range(words_needed):
        var word = ctx.state[i]
        var bytes_in_word = 4
        if i == words_needed - 1:
            bytes_in_word = output_len - i * 4
        for j in range(bytes_in_word):
            output.append(UInt8(UInt32(word >> UInt32(24 - j * 8)) & 0xFF))
    return output^


def sha224_hash_bits(data: Span[UInt8, ...], bit_len: Int) -> List[UInt8]:
    var ctx = SHA256Context(SHA224_IV)
    var full_bytes = bit_len // 8
    var rem_bits = bit_len % 8
    if full_bytes > 0:
        sha256_update(ctx, data[0:full_bytes])
    if rem_bits == 0:
        return sha256_final_with_len(ctx, 28)
    return sha256_final_partial(ctx, data[full_bytes], rem_bits, 28)


def sha256_hash_bits(data: Span[UInt8, ...], bit_len: Int) -> List[UInt8]:
    var ctx = SHA256Context()
    var full_bytes = bit_len // 8
    var rem_bits = bit_len % 8
    if full_bytes > 0:
        sha256_update(ctx, data[0:full_bytes])
    if rem_bits == 0:
        return sha256_final(ctx)
    return sha256_final_partial(ctx, data[full_bytes], rem_bits, 32)


def sha512_final_with_len(mut ctx: SHA512Context, output_len: Int) -> List[UInt8]:
    var buf_ptr = ctx.buffer.unsafe_ptr()
    var final_low = ctx.count_low + UInt64(ctx.buffer_len) * 8
    var final_high = ctx.count_high
    if final_low < ctx.count_low:
        final_high += 1

    ctx.buffer[ctx.buffer_len] = 0x80
    ctx.buffer_len += 1

    if ctx.buffer_len > 112:
        memset_zero(buf_ptr + ctx.buffer_len, 128 - ctx.buffer_len)
        ctx.state = sha512_transform(
            ctx.state, Span[UInt8, ...](ptr=buf_ptr, length=128)
        )
        ctx.buffer_len = 0

    memset_zero(buf_ptr + ctx.buffer_len, 112 - ctx.buffer_len)
    ctx.buffer_len = 112

    for i in range(8):
        ctx.buffer[112 + i] = UInt8(UInt64(final_high >> UInt64(56 - i * 8)) & 0xFF)
    for i in range(8):
        ctx.buffer[120 + i] = UInt8(UInt64(final_low >> UInt64(56 - i * 8)) & 0xFF)

    ctx.state = sha512_transform(
        ctx.state, Span[UInt8, ...](ptr=buf_ptr, length=128)
    )

    var output = List[UInt8](capacity=output_len)
    var words_needed = (output_len + 7) // 8
    for i in range(words_needed):
        var word = ctx.state[i]
        var bytes_in_word = 8
        if i == words_needed - 1:
            bytes_in_word = output_len - i * 8
        for j in range(bytes_in_word):
            output.append(UInt8(UInt64(word >> UInt64(56 - j * 8)) & 0xFF))
    return output^


def sha384_hash(data: Span[UInt8, ...]) -> List[UInt8]:
    var ctx = SHA512Context(SHA384_IV)
    sha512_update(ctx, data)
    return sha512_final_with_len(ctx, 48)


def sha512_final_partial(
    mut ctx: SHA512Context, final_octet: UInt8, final_bit_count: Int, output_len: Int
) -> List[UInt8]:
    var buf_ptr = ctx.buffer.unsafe_ptr()
    var final_low = ctx.count_low + UInt64(ctx.buffer_len) * 8 + UInt64(final_bit_count)
    var final_high = ctx.count_high
    if final_low < ctx.count_low:
        final_high += 1
    ctx.buffer[ctx.buffer_len] = (final_octet & high_bits_mask(final_bit_count)) | padding_bit(final_bit_count)
    ctx.buffer_len += 1

    if ctx.buffer_len > 112:
        memset_zero(buf_ptr + ctx.buffer_len, 128 - ctx.buffer_len)
        ctx.state = sha512_transform(
            ctx.state, Span[UInt8, ...](ptr=buf_ptr, length=128)
        )
        ctx.buffer_len = 0

    memset_zero(buf_ptr + ctx.buffer_len, 112 - ctx.buffer_len)
    ctx.buffer_len = 112

    for i in range(8):
        ctx.buffer[112 + i] = UInt8(UInt64(final_high >> UInt64(56 - i * 8)) & 0xFF)
    for i in range(8):
        ctx.buffer[120 + i] = UInt8(UInt64(final_low >> UInt64(56 - i * 8)) & 0xFF)

    ctx.state = sha512_transform(
        ctx.state, Span[UInt8, ...](ptr=buf_ptr, length=128)
    )

    var output = List[UInt8](capacity=output_len)
    var words_needed = (output_len + 7) // 8
    for i in range(words_needed):
        var word = ctx.state[i]
        var bytes_in_word = 8
        if i == words_needed - 1:
            bytes_in_word = output_len - i * 8
        for j in range(bytes_in_word):
            output.append(UInt8(UInt64(word >> UInt64(56 - j * 8)) & 0xFF))
    return output^


def sha384_hash_bits(data: Span[UInt8, ...], bit_len: Int) -> List[UInt8]:
    var ctx = SHA512Context(SHA384_IV)
    var full_bytes = bit_len // 8
    var rem_bits = bit_len % 8
    if full_bytes > 0:
        sha512_update(ctx, data[0:full_bytes])
    if rem_bits == 0:
        return sha512_final_with_len(ctx, 48)
    return sha512_final_partial(ctx, data[full_bytes], rem_bits, 48)


def sha512_hash_bits(data: Span[UInt8, ...], bit_len: Int) -> List[UInt8]:
    var ctx = SHA512Context(SHA512_IV)
    var full_bytes = bit_len // 8
    var rem_bits = bit_len % 8
    if full_bytes > 0:
        sha512_update(ctx, data[0:full_bytes])
    if rem_bits == 0:
        return sha512_final(ctx)
    return sha512_final_partial(ctx, data[full_bytes], rem_bits, 64)

def sha256_hash_string(s: String) -> String:
    var data = string_to_bytes(s)
    var hash = sha256_hash(Span[UInt8, ...](data))
    return bytes_to_hex(hash)


def sha512_hash_string(s: String) -> String:
    var data = string_to_bytes(s)
    var hash = sha512_hash(Span[UInt8, ...](data))
    return bytes_to_hex(hash)


def sha224_hash_string(s: String) -> String:
    var data = string_to_bytes(s)
    var hash = sha224_hash(Span[UInt8, ...](data))
    return bytes_to_hex(hash)


def sha384_hash_string(s: String) -> String:
    var data = string_to_bytes(s)
    var hash = sha384_hash(Span[UInt8, ...](data))
    return bytes_to_hex(hash)
