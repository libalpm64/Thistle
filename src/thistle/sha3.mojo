"""SHA-3 and SHAKE sponge functions (FIPS 202)."""

from std.bit import rotate_bits_left
from std.builtin.dtype import DType
from std.builtin.simd import SIMD
from std.collections import List
from std.memory import Pointer, stack_allocation, unsafe_memcpy, unsafe_memset_zero
from std.os import abort
from std.sys import llvm_intrinsic, CompilationTarget, simd_width_of
from std.utils import StaticTuple
from .utils import StackBuffer, bytes_to_hex, string_to_bytes

# Round constants for the 24 rounds of Keccak-f[1600] (FIPS 202, sec. 3.2.5).
comptime KECCAK_RC = StaticTuple[UInt64, 24](
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B,
    0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080,
    0x0000000080000001, 0x8000000080008008
)


@always_inline
def rotl64[n: Int](x: UInt64) -> UInt64:
    return rotate_bits_left[n](x)


comptime _U64x2 = SIMD[DType.uint64, 2]

comptime _has_sha3_ext = (
    CompilationTarget.has_neon()
    and not CompilationTarget.is_x86()
    and CompilationTarget._has_feature["sha3"]()
)


@always_inline
def _eor3(a: _U64x2, b: _U64x2, c: _U64x2) -> _U64x2:
    return llvm_intrinsic["llvm.aarch64.crypto.eor3u", _U64x2, has_side_effect=False](a, b, c)


@always_inline
def _rax1(a: _U64x2, b: _U64x2) -> _U64x2:
    return llvm_intrinsic["llvm.aarch64.crypto.rax1", _U64x2, has_side_effect=False](a, b)


@always_inline
def _xar[r: Int](a: _U64x2, b: _U64x2) -> _U64x2:
    return llvm_intrinsic["llvm.aarch64.crypto.xar", _U64x2, has_side_effect=False](a, b, Int64(64 - r))


@always_inline
def _bcax(a: _U64x2, b: _U64x2, c: _U64x2) -> _U64x2:
    return llvm_intrinsic["llvm.aarch64.crypto.bcaxu", _U64x2, has_side_effect=False](a, b, c)


def _keccak_f1600_hw(state: Pointer[mut=True, UInt64, _, address_space=_]):
    var a0 = _U64x2(state[unsafe_offset=0], 0)
    var a1 = _U64x2(state[unsafe_offset=1], 0)
    var a2 = _U64x2(state[unsafe_offset=2], 0)
    var a3 = _U64x2(state[unsafe_offset=3], 0)
    var a4 = _U64x2(state[unsafe_offset=4], 0)
    var a5 = _U64x2(state[unsafe_offset=5], 0)
    var a6 = _U64x2(state[unsafe_offset=6], 0)
    var a7 = _U64x2(state[unsafe_offset=7], 0)
    var a8 = _U64x2(state[unsafe_offset=8], 0)
    var a9 = _U64x2(state[unsafe_offset=9], 0)
    var a10 = _U64x2(state[unsafe_offset=10], 0)
    var a11 = _U64x2(state[unsafe_offset=11], 0)
    var a12 = _U64x2(state[unsafe_offset=12], 0)
    var a13 = _U64x2(state[unsafe_offset=13], 0)
    var a14 = _U64x2(state[unsafe_offset=14], 0)
    var a15 = _U64x2(state[unsafe_offset=15], 0)
    var a16 = _U64x2(state[unsafe_offset=16], 0)
    var a17 = _U64x2(state[unsafe_offset=17], 0)
    var a18 = _U64x2(state[unsafe_offset=18], 0)
    var a19 = _U64x2(state[unsafe_offset=19], 0)
    var a20 = _U64x2(state[unsafe_offset=20], 0)
    var a21 = _U64x2(state[unsafe_offset=21], 0)
    var a22 = _U64x2(state[unsafe_offset=22], 0)
    var a23 = _U64x2(state[unsafe_offset=23], 0)
    var a24 = _U64x2(state[unsafe_offset=24], 0)

    comptime for round in range(24):
        var c0 = _eor3(a0, a5, _eor3(a10, a15, a20))
        var c1 = _eor3(a1, a6, _eor3(a11, a16, a21))
        var c2 = _eor3(a2, a7, _eor3(a12, a17, a22))
        var c3 = _eor3(a3, a8, _eor3(a13, a18, a23))
        var c4 = _eor3(a4, a9, _eor3(a14, a19, a24))

        var d0 = _rax1(c4, c1)
        var d1 = _rax1(c0, c2)
        var d2 = _rax1(c1, c3)
        var d3 = _rax1(c2, c4)
        var d4 = _rax1(c3, c0)

        # Fuse theta XOR, rho rotation, and pi permutation into one XAR per lane.
        var b0 = a0 ^ d0
        var b1 = _xar[44](a6, d1)
        var b2 = _xar[43](a12, d2)
        var b3 = _xar[21](a18, d3)
        var b4 = _xar[14](a24, d4)
        var b5 = _xar[28](a3, d3)
        var b6 = _xar[20](a9, d4)
        var b7 = _xar[3](a10, d0)
        var b8 = _xar[45](a16, d1)
        var b9 = _xar[61](a22, d2)
        var b10 = _xar[1](a1, d1)
        var b11 = _xar[6](a7, d2)
        var b12 = _xar[25](a13, d3)
        var b13 = _xar[8](a19, d4)
        var b14 = _xar[18](a20, d0)
        var b15 = _xar[27](a4, d4)
        var b16 = _xar[36](a5, d0)
        var b17 = _xar[10](a11, d1)
        var b18 = _xar[15](a17, d2)
        var b19 = _xar[56](a23, d3)
        var b20 = _xar[62](a2, d2)
        var b21 = _xar[55](a8, d3)
        var b22 = _xar[39](a14, d4)
        var b23 = _xar[41](a15, d0)
        var b24 = _xar[2](a21, d1)

        a0 = _bcax(b0, b2, b1) ^ _U64x2(KECCAK_RC[round], 0)
        a1 = _bcax(b1, b3, b2)
        a2 = _bcax(b2, b4, b3)
        a3 = _bcax(b3, b0, b4)
        a4 = _bcax(b4, b1, b0)
        a5 = _bcax(b5, b7, b6)
        a6 = _bcax(b6, b8, b7)
        a7 = _bcax(b7, b9, b8)
        a8 = _bcax(b8, b5, b9)
        a9 = _bcax(b9, b6, b5)
        a10 = _bcax(b10, b12, b11)
        a11 = _bcax(b11, b13, b12)
        a12 = _bcax(b12, b14, b13)
        a13 = _bcax(b13, b10, b14)
        a14 = _bcax(b14, b11, b10)
        a15 = _bcax(b15, b17, b16)
        a16 = _bcax(b16, b18, b17)
        a17 = _bcax(b17, b19, b18)
        a18 = _bcax(b18, b15, b19)
        a19 = _bcax(b19, b16, b15)
        a20 = _bcax(b20, b22, b21)
        a21 = _bcax(b21, b23, b22)
        a22 = _bcax(b22, b24, b23)
        a23 = _bcax(b23, b20, b24)
        a24 = _bcax(b24, b21, b20)

    state[unsafe_offset=0] = a0[0]
    state[unsafe_offset=1] = a1[0]
    state[unsafe_offset=2] = a2[0]
    state[unsafe_offset=3] = a3[0]
    state[unsafe_offset=4] = a4[0]
    state[unsafe_offset=5] = a5[0]
    state[unsafe_offset=6] = a6[0]
    state[unsafe_offset=7] = a7[0]
    state[unsafe_offset=8] = a8[0]
    state[unsafe_offset=9] = a9[0]
    state[unsafe_offset=10] = a10[0]
    state[unsafe_offset=11] = a11[0]
    state[unsafe_offset=12] = a12[0]
    state[unsafe_offset=13] = a13[0]
    state[unsafe_offset=14] = a14[0]
    state[unsafe_offset=15] = a15[0]
    state[unsafe_offset=16] = a16[0]
    state[unsafe_offset=17] = a17[0]
    state[unsafe_offset=18] = a18[0]
    state[unsafe_offset=19] = a19[0]
    state[unsafe_offset=20] = a20[0]
    state[unsafe_offset=21] = a21[0]
    state[unsafe_offset=22] = a22[0]
    state[unsafe_offset=23] = a23[0]
    state[unsafe_offset=24] = a24[0]


def keccak_f1600(state: Pointer[mut=True, UInt64, _, address_space=_]):
    """Apply all 24 rounds of Keccak-f[1600] to the 25-lane state (FIPS 202, sec. 3.3)."""
    comptime if _has_sha3_ext:
        _keccak_f1600_hw(state)
        return
    _keccak_f1600_scalar(state)


@always_inline
def _keccak_round(
    src: Pointer[mut=True, UInt64, _, address_space=_],
    dst: Pointer[mut=True, UInt64, _, address_space=_],
    rc: UInt64,
):
    var c0 = (
        src[unsafe_offset=0] ^ src[unsafe_offset=5] ^ src[unsafe_offset=10]
        ^ src[unsafe_offset=15] ^ src[unsafe_offset=20]
    )
    var c1 = (
        src[unsafe_offset=1] ^ src[unsafe_offset=6] ^ src[unsafe_offset=11]
        ^ src[unsafe_offset=16] ^ src[unsafe_offset=21]
    )
    var c2 = (
        src[unsafe_offset=2] ^ src[unsafe_offset=7] ^ src[unsafe_offset=12]
        ^ src[unsafe_offset=17] ^ src[unsafe_offset=22]
    )
    var c3 = (
        src[unsafe_offset=3] ^ src[unsafe_offset=8] ^ src[unsafe_offset=13]
        ^ src[unsafe_offset=18] ^ src[unsafe_offset=23]
    )
    var c4 = (
        src[unsafe_offset=4] ^ src[unsafe_offset=9] ^ src[unsafe_offset=14]
        ^ src[unsafe_offset=19] ^ src[unsafe_offset=24]
    )
    var d0 = c4 ^ rotl64[1](c1)
    var d1 = c0 ^ rotl64[1](c2)
    var d2 = c1 ^ rotl64[1](c3)
    var d3 = c2 ^ rotl64[1](c4)
    var d4 = c3 ^ rotl64[1](c0)

    var b0 = src[unsafe_offset=0] ^ d0
    var b1 = rotl64[44](src[unsafe_offset=6] ^ d1)
    var b2 = rotl64[43](src[unsafe_offset=12] ^ d2)
    var b3 = rotl64[21](src[unsafe_offset=18] ^ d3)
    var b4 = rotl64[14](src[unsafe_offset=24] ^ d4)
    dst[unsafe_offset=0] = b0 ^ (~b1 & b2) ^ rc
    dst[unsafe_offset=1] = b1 ^ (~b2 & b3)
    dst[unsafe_offset=2] = b2 ^ (~b3 & b4)
    dst[unsafe_offset=3] = b3 ^ (~b4 & b0)
    dst[unsafe_offset=4] = b4 ^ (~b0 & b1)

    b0 = rotl64[28](src[unsafe_offset=3] ^ d3)
    b1 = rotl64[20](src[unsafe_offset=9] ^ d4)
    b2 = rotl64[3](src[unsafe_offset=10] ^ d0)
    b3 = rotl64[45](src[unsafe_offset=16] ^ d1)
    b4 = rotl64[61](src[unsafe_offset=22] ^ d2)
    dst[unsafe_offset=5] = b0 ^ (~b1 & b2)
    dst[unsafe_offset=6] = b1 ^ (~b2 & b3)
    dst[unsafe_offset=7] = b2 ^ (~b3 & b4)
    dst[unsafe_offset=8] = b3 ^ (~b4 & b0)
    dst[unsafe_offset=9] = b4 ^ (~b0 & b1)

    b0 = rotl64[1](src[unsafe_offset=1] ^ d1)
    b1 = rotl64[6](src[unsafe_offset=7] ^ d2)
    b2 = rotl64[25](src[unsafe_offset=13] ^ d3)
    b3 = rotl64[8](src[unsafe_offset=19] ^ d4)
    b4 = rotl64[18](src[unsafe_offset=20] ^ d0)
    dst[unsafe_offset=10] = b0 ^ (~b1 & b2)
    dst[unsafe_offset=11] = b1 ^ (~b2 & b3)
    dst[unsafe_offset=12] = b2 ^ (~b3 & b4)
    dst[unsafe_offset=13] = b3 ^ (~b4 & b0)
    dst[unsafe_offset=14] = b4 ^ (~b0 & b1)

    b0 = rotl64[27](src[unsafe_offset=4] ^ d4)
    b1 = rotl64[36](src[unsafe_offset=5] ^ d0)
    b2 = rotl64[10](src[unsafe_offset=11] ^ d1)
    b3 = rotl64[15](src[unsafe_offset=17] ^ d2)
    b4 = rotl64[56](src[unsafe_offset=23] ^ d3)
    dst[unsafe_offset=15] = b0 ^ (~b1 & b2)
    dst[unsafe_offset=16] = b1 ^ (~b2 & b3)
    dst[unsafe_offset=17] = b2 ^ (~b3 & b4)
    dst[unsafe_offset=18] = b3 ^ (~b4 & b0)
    dst[unsafe_offset=19] = b4 ^ (~b0 & b1)

    b0 = rotl64[62](src[unsafe_offset=2] ^ d2)
    b1 = rotl64[55](src[unsafe_offset=8] ^ d3)
    b2 = rotl64[39](src[unsafe_offset=14] ^ d4)
    b3 = rotl64[41](src[unsafe_offset=15] ^ d0)
    b4 = rotl64[2](src[unsafe_offset=21] ^ d1)
    dst[unsafe_offset=20] = b0 ^ (~b1 & b2)
    dst[unsafe_offset=21] = b1 ^ (~b2 & b3)
    dst[unsafe_offset=22] = b2 ^ (~b3 & b4)
    dst[unsafe_offset=23] = b3 ^ (~b4 & b0)
    dst[unsafe_offset=24] = b4 ^ (~b0 & b1)


def _keccak_f1600_scalar(state: Pointer[mut=True, UInt64, _, address_space=_]):
    var scratch = stack_allocation[25, UInt64]()
    for pair in range(12):
        _keccak_round(state, scratch, KECCAK_RC[pair * 2])
        _keccak_round(scratch, state, KECCAK_RC[pair * 2 + 1])


struct SHA3Context:
    """Keccak sponge state; the constructor accepts rate bits and stores the rate in bytes."""
    var state: StackBuffer[UInt64, 25]
    var rate_bytes: Int
    var buffer: StackBuffer[UInt8, 168]
    var buffer_len: Int

    def __init__(out self, rate_bits: Int):
        if not (0 < rate_bits <= 1344 and rate_bits % 64 == 0):
            abort(
                "SHA-3 rate must be a positive multiple of 64 no larger than 1344 bits"
            )
        self.state = StackBuffer[UInt64, 25](fill=0)
        self.rate_bytes = rate_bits // 8
        self.buffer = StackBuffer[UInt8, 168](fill=0)
        self.buffer_len = 0

    def __init__(out self, *, deinit move: Self):
        self.state = move.state^
        self.rate_bytes = move.rate_bytes
        self.buffer = move.buffer^
        self.buffer_len = move.buffer_len

    def __deinit__(deinit self):
        comptime W64 = simd_width_of[DType.uint64]()
        comptime W8 = simd_width_of[DType.uint8]()
        var state_ptr = self.state.ptr()
        var i = 0
        while i + W64 <= 25:
            state_ptr.unsafe_store[width=W64, volatile=True](
                i, SIMD[DType.uint64, W64](0)
            )
            i += W64
        while i < 25:
            state_ptr.unsafe_store[volatile=True](i, UInt64(0))
            i += 1
        var buffer_ptr = self.buffer.ptr()
        i = 0
        while i + W8 <= 168:
            buffer_ptr.unsafe_store[width=W8, volatile=True](
                i, SIMD[DType.uint8, W8](0)
            )
            i += W8
        while i < 168:
            buffer_ptr.unsafe_store[volatile=True](i, UInt8(0))
            i += 1


@always_inline
def sha3_absorb_block(state: Pointer[mut=True, UInt64, _, address_space=_], block: Pointer[mut=False, UInt8, _, address_space=_], rate_bytes: Int
):
    var full_lanes = rate_bytes // 8
    for i in range(full_lanes):
        state[unsafe_offset=i] ^= (
            block.unsafe_offset(i * 8).unsafe_bitcast[UInt64]().unsafe_load[width=1, alignment=1]()
        )
    keccak_f1600(state)


def sha3_update(mut ctx: SHA3Context, data: Span[UInt8, ...]):
    var i = 0
    var total_len = len(data)

    if ctx.buffer_len > 0:
        var available = ctx.rate_bytes - ctx.buffer_len
        if total_len >= available:
            for j in range(available):
                ctx.buffer[ctx.buffer_len + j] = data[j]
            sha3_absorb_block(ctx.state.ptr(), ctx.buffer.ptr(), ctx.rate_bytes)
            ctx.buffer_len = 0
            i += available
        else:
            for j in range(total_len):
                ctx.buffer[ctx.buffer_len + j] = data[j]
            ctx.buffer_len += total_len
            return

    while i + ctx.rate_bytes <= total_len:
        sha3_absorb_block(ctx.state.ptr(), data.unsafe_ptr().unsafe_offset(i), ctx.rate_bytes)
        i += ctx.rate_bytes

    if i < total_len:
        var remaining = total_len - i
        for j in range(remaining):
            ctx.buffer[j] = data[i + j]
        ctx.buffer_len = remaining


def sha3_final(mut ctx: SHA3Context, output_len_bytes: Int) -> List[UInt8]:
    if output_len_bytes < 0:
        abort("SHA-3 output length cannot be negative")
    ctx.buffer[ctx.buffer_len] = 0x06
    ctx.buffer_len += 1

    var pad_len = ctx.rate_bytes - ctx.buffer_len
    if pad_len > 0:
        unsafe_memset_zero(ctx.buffer.ptr().unsafe_offset(ctx.buffer_len), pad_len)
        ctx.buffer_len = ctx.rate_bytes

    ctx.buffer[ctx.rate_bytes - 1] |= 0x80
    sha3_absorb_block(ctx.state.ptr(), ctx.buffer.ptr(), ctx.rate_bytes)

    var output = List[UInt8](capacity=output_len_bytes)
    for _ in range(output_len_bytes):
        output.append(0)

    var offset = 0
    while offset < output_len_bytes:
        var limit = ctx.rate_bytes
        if output_len_bytes - offset < limit:
            limit = output_len_bytes - offset

        unsafe_memcpy(
            dest=output.unsafe_ptr().unsafe_offset(offset),
            src=ctx.state.ptr().unsafe_bitcast[UInt8](),
            count=limit
        )

        offset += limit
        if offset < output_len_bytes:
            keccak_f1600(ctx.state.ptr())

    return output^


@always_inline
def sha3_final_into(mut ctx: SHA3Context, mut output: StackBuffer[UInt8, ...], output_len_bytes: Int
):
    if output_len_bytes < 0 or output_len_bytes > output.capacity():
        abort("SHA-3 output length exceeds destination capacity")
    output.clear()
    ctx.buffer[ctx.buffer_len] = 0x06
    ctx.buffer_len += 1

    var pad_len = ctx.rate_bytes - ctx.buffer_len
    if pad_len > 0:
        unsafe_memset_zero(ctx.buffer.ptr().unsafe_offset(ctx.buffer_len), pad_len)
        ctx.buffer_len = ctx.rate_bytes

    ctx.buffer[ctx.rate_bytes - 1] |= 0x80
    sha3_absorb_block(ctx.state.ptr(), ctx.buffer.ptr(), ctx.rate_bytes)

    output.set_len(output_len_bytes)

    var offset = 0
    while offset < output_len_bytes:
        var limit = ctx.rate_bytes
        if output_len_bytes - offset < limit:
            limit = output_len_bytes - offset

        unsafe_memcpy(
            dest=output.ptr().unsafe_offset(offset),
            src=ctx.state.ptr().unsafe_bitcast[UInt8](),
            count=limit
        )

        offset += limit
        if offset < output_len_bytes:
            keccak_f1600(ctx.state.ptr())


@always_inline
def sha3_hash(rate_bits: Int, data: Span[UInt8, ...], output_len: Int) -> List[UInt8]:
    """Hash with rate r in bits, SHA-3 domain suffix 0x06, and the requested output length (FIPS
    202, sec. 6.1 and Appendix B.2).
    """
    var ctx = SHA3Context(rate_bits)
    sha3_update(ctx, data)
    return sha3_final(ctx, output_len)


@always_inline
def sha3_hash_into(mut output: StackBuffer[UInt8, ...], rate_bits: Int, data: Span[UInt8, ...], output_len: Int
):
    var ctx = SHA3Context(rate_bits)
    sha3_update(ctx, data)
    sha3_final_into(ctx, output, output_len)


def sha3_224(data: Span[UInt8, ...]) -> List[UInt8]:
    """Return a 28-byte SHA3-224 digest (FIPS 202, sec. 6.1)."""
    return sha3_hash(1152, data, 28)


def sha3_256(data: Span[UInt8, ...]) -> List[UInt8]:
    """Return a 32-byte SHA3-256 digest (FIPS 202, sec. 6.1)."""
    return sha3_hash(1088, data, 32)


def sha3_384(data: Span[UInt8, ...]) -> List[UInt8]:
    """Return a 48-byte SHA3-384 digest (FIPS 202, sec. 6.1)."""
    return sha3_hash(832, data, 48)


def sha3_512(data: Span[UInt8, ...]) -> List[UInt8]:
    """Return a 64-byte SHA3-512 digest (FIPS 202, sec. 6.1)."""
    return sha3_hash(576, data, 64)


@always_inline
def sha3_256_into(mut output: StackBuffer[UInt8, ...], data: Span[UInt8, ...]):
    sha3_hash_into(output, 1088, data, 32)


@always_inline
def sha3_512_into(mut output: StackBuffer[UInt8, ...], data: Span[UInt8, ...]):
    sha3_hash_into(output, 576, data, 64)


def sha3_224_hash_string(s: String) -> String:
    var data = string_to_bytes(s)
    var hash = sha3_224(Span[UInt8, ...](data))
    return bytes_to_hex(hash)


def sha3_256_hash_string(s: String) -> String:
    var data = string_to_bytes(s)
    var hash = sha3_256(Span[UInt8, ...](data))
    return bytes_to_hex(hash)


def sha3_384_hash_string(s: String) -> String:
    var data = string_to_bytes(s)
    var hash = sha3_384(Span[UInt8, ...](data))
    return bytes_to_hex(hash)


def sha3_512_hash_string(s: String) -> String:
    var data = string_to_bytes(s)
    var hash = sha3_512(Span[UInt8, ...](data))
    return bytes_to_hex(hash)


@always_inline
def shake_finalize(mut ctx: SHA3Context):
    ctx.buffer[ctx.buffer_len] = 0x1F
    ctx.buffer_len += 1

    var pad_len = ctx.rate_bytes - ctx.buffer_len
    if pad_len > 0:
        unsafe_memset_zero(ctx.buffer.ptr().unsafe_offset(ctx.buffer_len), pad_len)
        ctx.buffer_len = ctx.rate_bytes

    ctx.buffer[ctx.rate_bytes - 1] |= 0x80
    sha3_absorb_block(ctx.state.ptr(), ctx.buffer.ptr(), ctx.rate_bytes)
    ctx.buffer_len = 0


@always_inline
def shake_squeeze_prefix_into(mut ctx: SHA3Context, mut output: StackBuffer[UInt8, ...], output_len: Int):
    if output_len < 0 or output_len > output.capacity():
        abort("SHAKE output length exceeds destination capacity")
    output.clear()
    output.set_len(output_len)

    var offset = 0
    while offset < output_len:
        var limit = ctx.rate_bytes
        if output_len - offset < limit:
            limit = output_len - offset

        unsafe_memcpy(
            dest=output.ptr().unsafe_offset(offset),
            src=ctx.state.ptr().unsafe_bitcast[UInt8](),
            count=limit
        )

        offset += limit
        if offset < output_len:
            keccak_f1600(ctx.state.ptr())


@always_inline
def shake_advance(mut ctx: SHA3Context):
    keccak_f1600(ctx.state.ptr())


@always_inline
def shake_final(mut ctx: SHA3Context, output_len: Int) -> List[UInt8]:
    if output_len < 0:
        abort("SHAKE output length cannot be negative")
    shake_finalize(ctx)

    var output = List[UInt8](capacity=output_len)
    for _ in range(output_len):
        output.append(0)

    var offset = 0
    while offset < output_len:
        var limit = ctx.rate_bytes
        if output_len - offset < limit:
            limit = output_len - offset

        unsafe_memcpy(
            dest=output.unsafe_ptr().unsafe_offset(offset),
            src=ctx.state.ptr().unsafe_bitcast[UInt8](),
            count=limit
        )

        offset += limit
        if offset < output_len:
            keccak_f1600(ctx.state.ptr())

    return output^


@always_inline
def shake_final_into(mut ctx: SHA3Context, mut output: StackBuffer[UInt8, ...], output_len: Int):
    if output_len < 0 or output_len > output.capacity():
        abort("SHAKE output length exceeds destination capacity")
    output.clear()
    shake_finalize(ctx)

    output.set_len(output_len)

    var offset = 0
    while offset < output_len:
        var limit = ctx.rate_bytes
        if output_len - offset < limit:
            limit = output_len - offset

        unsafe_memcpy(
            dest=output.ptr().unsafe_offset(offset),
            src=ctx.state.ptr().unsafe_bitcast[UInt8](),
            count=limit
        )

        offset += limit
        if offset < output_len:
            keccak_f1600(ctx.state.ptr())


@always_inline
def shake_hash(rate_bits: Int, data: Span[UInt8, ...], output_len: Int) -> List[UInt8]:
    """Squeeze the requested output length with rate r in bits and SHAKE domain suffix 0x1F (FIPS
    202, sec. 6.2 and Appendix B.2).
    """
    var ctx = SHA3Context(rate_bits)
    sha3_update(ctx, data)
    return shake_final(ctx, output_len)


@always_inline
def shake_hash_into(mut output: StackBuffer[UInt8, ...], rate_bits: Int, data: Span[UInt8, ...], output_len: Int
):
    var ctx = SHA3Context(rate_bits)
    sha3_update(ctx, data)
    shake_final_into(ctx, output, output_len)


def shake128(data: Span[UInt8, ...], output_len_bytes: Int) -> List[UInt8]:
    """Return the requested number of SHAKE128 output bytes (FIPS 202, sec. 6.2)."""
    return shake_hash(1344, data, output_len_bytes)


def shake256(data: Span[UInt8, ...], output_len_bytes: Int) -> List[UInt8]:
    """Return the requested number of SHAKE256 output bytes (FIPS 202, sec. 6.2)."""
    return shake_hash(1088, data, output_len_bytes)


@always_inline
def shake128_into(mut output: StackBuffer[UInt8, ...], data: Span[UInt8, ...], output_len_bytes: Int
):
    shake_hash_into(output, 1344, data, output_len_bytes)


@always_inline
def shake256_into(mut output: StackBuffer[UInt8, ...], data: Span[UInt8, ...], output_len_bytes: Int
):
    shake_hash_into(output, 1088, data, output_len_bytes)
