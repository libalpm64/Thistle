"""
SHA-NI implementation In Mojo.
"""

from std.sys import llvm_intrinsic, CompilationTarget, prefetch, PrefetchOptions
from std.memory import UnsafePointer, bitcast
from .utils import StackBuffer
from std.builtin.simd import SIMD
from std.builtin.dtype import DType
from .sha2 import SHA256_IV, sha256_transform

comptime SIMD128 = SIMD[DType.uint32, 4]
comptime PAL_0 = 1
comptime PAL_1 = 2
comptime PAL_2 = 3
comptime PAL_3 = 4

comptime RND_0 = 2
comptime RND_1 = 3
comptime RND_2 = 0
comptime RND_3 = 1

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


@always_inline
def has_x86_sha_ni() -> Bool:
    return CompilationTarget.is_x86() and CompilationTarget._has_feature["sse"]() and CompilationTarget._has_feature["sha"]()


@always_inline
def has_arm_sha2() -> Bool:
    return CompilationTarget.has_neon() and CompilationTarget._has_feature["sha2"]() and not CompilationTarget.is_x86()


@always_inline("nodebug")
def _rnds2(cdgh: SIMD128, abef: SIMD128, wk: SIMD128) -> SIMD128:
    comptime if CompilationTarget._has_feature["sse"]() and CompilationTarget._has_feature["sha"]():
        return llvm_intrinsic["llvm.x86.sha256rnds2", SIMD128, has_side_effect=False](cdgh, abef, wk)
    else:
        return SIMD128(0)


@always_inline("nodebug")
def _msg1(a: SIMD128, b: SIMD128) -> SIMD128:
    comptime if CompilationTarget._has_feature["sse"]() and CompilationTarget._has_feature["sha"]():
        return llvm_intrinsic["llvm.x86.sha256msg1", SIMD128, has_side_effect=False](a, b)
    else:
        return SIMD128(0)


@always_inline("nodebug")
def _msg2(a: SIMD128, b: SIMD128) -> SIMD128:
    comptime if CompilationTarget._has_feature["sse"]() and CompilationTarget._has_feature["sha"]():
        return llvm_intrinsic["llvm.x86.sha256msg2", SIMD128, has_side_effect=False](a, b)
    else:
        return SIMD128(0)


@always_inline("nodebug")
def _arm_sha256h(abcd: SIMD128, efgh: SIMD128, wk: SIMD128) -> SIMD128:
    comptime if CompilationTarget.has_neon() and CompilationTarget._has_feature["sha2"]() and not CompilationTarget.is_x86():
        return llvm_intrinsic["llvm.aarch64.crypto.sha256h", SIMD128, has_side_effect=False](abcd, efgh, wk)
    else:
        return SIMD128(0)


@always_inline("nodebug")
def _arm_sha256h2(efgh: SIMD128, abcd: SIMD128, wk: SIMD128) -> SIMD128:
    comptime if CompilationTarget.has_neon() and CompilationTarget._has_feature["sha2"]() and not CompilationTarget.is_x86():
        return llvm_intrinsic["llvm.aarch64.crypto.sha256h2", SIMD128, has_side_effect=False](efgh, abcd, wk)
    else:
        return SIMD128(0)


@always_inline("nodebug")
def _arm_sha256su0(w0_3: SIMD128, w4_7: SIMD128) -> SIMD128:
    comptime if CompilationTarget.has_neon() and CompilationTarget._has_feature["sha2"]() and not CompilationTarget.is_x86():
        return llvm_intrinsic["llvm.aarch64.crypto.sha256su0", SIMD128, has_side_effect=False](w0_3, w4_7)
    else:
        return SIMD128(0)


@always_inline("nodebug")
def _arm_sha256su1(tw0_3: SIMD128, w8_11: SIMD128, w12_15: SIMD128) -> SIMD128:
    comptime if CompilationTarget.has_neon() and CompilationTarget._has_feature["sha2"]() and not CompilationTarget.is_x86():
        return llvm_intrinsic["llvm.aarch64.crypto.sha256su1", SIMD128, has_side_effect=False](tw0_3, w8_11, w12_15)
    else:
        return SIMD128(0)


@always_inline("nodebug")
def byte_swap32(v: SIMD128) -> SIMD128:
    var bytes = bitcast[DType.uint8, 16](v)
    var swapped = bytes.shuffle[3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12]()
    return bitcast[DType.uint32, 4](swapped)


@always_inline("nodebug")
def Load(ptr: UnsafePointer[UInt8, ImmutAnyOrigin]) -> SIMD128:
    return byte_swap32(ptr.bitcast[UInt32]().load[width=4, alignment=1]())


@always_inline("nodebug")
def Load_aligned(ptr: UnsafePointer[UInt8, ImmutAnyOrigin]) -> SIMD128:
    return byte_swap32(ptr.bitcast[UInt32]().load[width=4, alignment=16]())


@always_inline("nodebug")
def prefetch_next_block(ptr: UnsafePointer[UInt8, ImmutAnyOrigin]):
    prefetch[PrefetchOptions().for_read().high_locality().to_data_cache()](ptr + 64)


def sha256ni_transform(state: SIMD[DType.uint32, 8], block: Span[UInt8, ...]) -> SIMD[DType.uint32, 8]:
    # fall back to the scalar transform so unsupported CPUs never get zeros
    comptime if CompilationTarget.is_x86() and CompilationTarget._has_feature["sse"]() and CompilationTarget._has_feature["sha"]():
        return _sha256ni_transform_x86(state, block)
    elif CompilationTarget.has_neon() and CompilationTarget._has_feature["sha2"]() and not CompilationTarget.is_x86():
        return _sha256ni_transform_arm(state, block)
    else:
        return sha256_transform(state, block)


def _sha256ni_transform_arm(state: SIMD[DType.uint32, 8], block: Span[UInt8, ...]) -> SIMD[DType.uint32, 8]:
    var ptr = block.unsafe_ptr()

    # st0 = [A, B, C, D], st1 = [E, F, G, H].
    var st0 = SIMD128(state[0], state[1], state[2], state[3])
    var st1 = SIMD128(state[4], state[5], state[6], state[7])
    var old_st0 = st0
    var old_st1 = st1

    var w = InlineArray[SIMD128, 4](uninitialized=True)
    w[0] = Load(ptr)
    w[1] = Load(ptr + 16)
    w[2] = Load(ptr + 32)
    w[3] = Load(ptr + 48)

    comptime for i in range(16):
        var wk = w[i & 3] + SIMD128(SHA256_K[4 * i], SHA256_K[4 * i + 1], SHA256_K[4 * i + 2], SHA256_K[4 * i + 3])
        comptime if i < 12:
            w[i & 3] = _arm_sha256su1(
                _arm_sha256su0(w[i & 3], w[(i + 1) & 3]),
                w[(i + 2) & 3],
                w[(i + 3) & 3],
            )
        var tmp = st0
        st0 = _arm_sha256h(st0, st1, wk)
        st1 = _arm_sha256h2(st1, tmp, wk)

    st0 += old_st0
    st1 += old_st1

    return SIMD[DType.uint32, 8](
        st0[0], st0[1], st0[2], st0[3], st1[0], st1[1], st1[2], st1[3]
    )


def _sha256ni_transform_x86(state: SIMD[DType.uint32, 8], block: Span[UInt8, ...]) -> SIMD[DType.uint32, 8]:
    var ptr = block.unsafe_ptr()

    # s1 = [H, G, D, C], s0 = [F, E, B, A]
    var s1 = SIMD128(state[7], state[6], state[3], state[2])
    var s0 = SIMD128(state[5], state[4], state[1], state[0])
    
    var old_s0 = s0
    var old_s1 = s1
    
    # expand all 64 words to 16 simd registers
    var w0 = Load(ptr)
    var w1 = Load(ptr + 16)
    var w2 = Load(ptr + 32)
    var w3 = Load(ptr + 48)
    
    var w = InlineArray[SIMD128, 16](uninitialized=True)
    w[0] = w0
    w[1] = w1
    w[2] = w2
    w[3] = w3
    
    comptime for i in range(4, 16):
        var p = w[i-2].shuffle[PAL_0, PAL_1, PAL_2, PAL_3](w[i-1])
        w[i] = _msg2(_msg1(w[i-4], w[i-3]) + p, w[i-1])

    comptime for i in range(16):
        var wk = w[i] + SIMD128(SHA256_K[4*i], SHA256_K[4*i+1], SHA256_K[4*i+2], SHA256_K[4*i+3])
        s1 = _rnds2(s1, s0, wk)
        s0 = _rnds2(s0, s1, wk.shuffle[RND_0, RND_1, RND_2, RND_3]())
        
    # s0 is ABEF_64, s1 is CDGH_64
    s0 += old_s0
    s1 += old_s1
    
    # s0 = [F, E, B, A], s1 = [H, G, D, C]
    return SIMD[DType.uint32, 8](
        s0[3], s0[2], s1[3], s1[2], s0[1], s0[0], s1[1], s1[0]
    )


struct SHA256NIContext(Movable):
    var state: SIMD[DType.uint32, 8]
    var count: UInt64
    var buffer: StackBuffer[UInt8, 64]
    var buffer_len: Int

    def __init__(out self):
        self.state = SHA256_IV
        self.count = 0
        self.buffer = StackBuffer[UInt8, 64](fill=0)
        self.buffer_len = 0


def sha256ni_hash(data: Span[UInt8, ...]) -> List[UInt8]:
    var ctx = SHA256NIContext()

    var i = 0
    var total_len = len(data)

    while i + 64 <= total_len:
        if i + 64 < total_len:
            prefetch_next_block(data.unsafe_ptr() + i)
        ctx.state = sha256ni_transform(ctx.state, data[i:i+64])
        ctx.count += 512
        i += 64

    if i < total_len:
        var remaining = total_len - i
        for j in range(remaining):
            ctx.buffer[j] = data[i + j]
        ctx.buffer_len = remaining

    var bit_count = ctx.count + UInt64(ctx.buffer_len) * 8

    ctx.buffer[ctx.buffer_len] = 0x80
    ctx.buffer_len += 1

    if ctx.buffer_len > 56:
        ctx.state = sha256ni_transform(ctx.state, Span[UInt8, ...](ptr=ctx.buffer.ptr(), length=64))
        ctx.buffer_len = 0

    while ctx.buffer_len < 56:
        ctx.buffer[ctx.buffer_len] = 0
        ctx.buffer_len += 1

    for k in range(8):
        ctx.buffer[56 + k] = UInt8(UInt64(bit_count >> UInt64(56 - k * 8)) & 0xFF)

    ctx.state = sha256ni_transform(ctx.state, Span[UInt8, ...](ptr=ctx.buffer.ptr(), length=64))

    var output = List[UInt8](capacity=32)
    for k in range(8):
        output.append(UInt8(UInt32(ctx.state[k] >> 24) & 0xFF))
        output.append(UInt8(UInt32(ctx.state[k] >> 16) & 0xFF))
        output.append(UInt8(UInt32(ctx.state[k] >> 8) & 0xFF))
        output.append(UInt8(UInt32(ctx.state[k]) & 0xFF))

    return output^

def has_sha_ni() -> Bool:
    return has_x86_sha_ni() or has_arm_sha2()


def sha256ni_transform_blocks(
    mut state: SIMD[DType.uint32, 8],
    data: UnsafePointer[UInt8, ImmutAnyOrigin],
    nblocks: Int,
):
    comptime if CompilationTarget.has_neon() and CompilationTarget._has_feature["sha2"]() and not CompilationTarget.is_x86():
        var st0 = SIMD128(state[0], state[1], state[2], state[3])
        var st1 = SIMD128(state[4], state[5], state[6], state[7])

        for blk in range(nblocks):
            var ptr = data + blk * 64
            if blk + 1 < nblocks:
                prefetch_next_block(ptr)
            var old_st0 = st0
            var old_st1 = st1

            var w = InlineArray[SIMD128, 4](uninitialized=True)
            w[0] = Load(ptr)
            w[1] = Load(ptr + 16)
            w[2] = Load(ptr + 32)
            w[3] = Load(ptr + 48)

            comptime for i in range(16):
                var wk = w[i & 3] + SIMD128(SHA256_K[4 * i], SHA256_K[4 * i + 1], SHA256_K[4 * i + 2], SHA256_K[4 * i + 3])
                comptime if i < 12:
                    w[i & 3] = _arm_sha256su1(
                        _arm_sha256su0(w[i & 3], w[(i + 1) & 3]),
                        w[(i + 2) & 3],
                        w[(i + 3) & 3],
                    )
                var tmp = st0
                st0 = _arm_sha256h(st0, st1, wk)
                st1 = _arm_sha256h2(st1, tmp, wk)

            st0 += old_st0
            st1 += old_st1

        state = SIMD[DType.uint32, 8](
            st0[0], st0[1], st0[2], st0[3], st1[0], st1[1], st1[2], st1[3]
        )
        return

    for blk in range(nblocks):
        var span = Span[UInt8, ...](ptr=data + blk * 64, length=64)
        state = sha256ni_transform(state, span)


comptime SIMD64x2 = SIMD[DType.uint64, 2]

comptime SHA512NI_K = SIMD[DType.uint64, 80](
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
def has_arm_sha512() -> Bool:
    return CompilationTarget.has_neon() and CompilationTarget._has_feature["sha3"]() and not CompilationTarget.is_x86()


@always_inline("nodebug")
def _sha512h(a: SIMD64x2, b: SIMD64x2, c: SIMD64x2) -> SIMD64x2:
    comptime if CompilationTarget.has_neon() and CompilationTarget._has_feature["sha3"]() and not CompilationTarget.is_x86():
        return llvm_intrinsic["llvm.aarch64.crypto.sha512h", SIMD64x2, has_side_effect=False](a, b, c)
    else:
        return SIMD64x2(0)


@always_inline("nodebug")
def _sha512h2(a: SIMD64x2, b: SIMD64x2, c: SIMD64x2) -> SIMD64x2:
    comptime if CompilationTarget.has_neon() and CompilationTarget._has_feature["sha3"]() and not CompilationTarget.is_x86():
        return llvm_intrinsic["llvm.aarch64.crypto.sha512h2", SIMD64x2, has_side_effect=False](a, b, c)
    else:
        return SIMD64x2(0)


@always_inline("nodebug")
def _sha512su0(a: SIMD64x2, b: SIMD64x2) -> SIMD64x2:
    comptime if CompilationTarget.has_neon() and CompilationTarget._has_feature["sha3"]() and not CompilationTarget.is_x86():
        return llvm_intrinsic["llvm.aarch64.crypto.sha512su0", SIMD64x2, has_side_effect=False](a, b)
    else:
        return SIMD64x2(0)


@always_inline("nodebug")
def _sha512su1(a: SIMD64x2, b: SIMD64x2, c: SIMD64x2) -> SIMD64x2:
    comptime if CompilationTarget.has_neon() and CompilationTarget._has_feature["sha3"]() and not CompilationTarget.is_x86():
        return llvm_intrinsic["llvm.aarch64.crypto.sha512su1", SIMD64x2, has_side_effect=False](a, b, c)
    else:
        return SIMD64x2(0)


@always_inline("nodebug")
def byte_swap64(v: SIMD64x2) -> SIMD64x2:
    var bytes = bitcast[DType.uint8, 16](v)
    var swapped = bytes.shuffle[7,6,5,4,3,2,1,0, 15,14,13,12,11,10,9,8]()
    return bitcast[DType.uint64, 2](swapped)


@always_inline("nodebug")
def Load512(ptr: UnsafePointer[UInt8, ImmutAnyOrigin]) -> SIMD64x2:
    return byte_swap64(ptr.bitcast[UInt64]().load[width=2, alignment=1]())


@always_inline("nodebug")
def _ext1(a: SIMD64x2, b: SIMD64x2) -> SIMD64x2:
    return a.shuffle[1, 2](b)


@always_inline("nodebug")
def prefetch_next_block512(ptr: UnsafePointer[UInt8, ImmutAnyOrigin]):
    prefetch[PrefetchOptions().for_read().high_locality().to_data_cache()](ptr + 128)


def sha512ni_transform_blocks(
    mut state: SIMD[DType.uint64, 8],
    data: UnsafePointer[UInt8, ImmutAnyOrigin],
    nblocks: Int,
):
    var ab = SIMD64x2(state[0], state[1])
    var cd = SIMD64x2(state[2], state[3])
    var ef = SIMD64x2(state[4], state[5])
    var gh = SIMD64x2(state[6], state[7])

    for blk in range(nblocks):
        var block = data + blk * 128
        if blk + 1 < nblocks:
            prefetch_next_block512(block)

        var w = InlineArray[SIMD64x2, 8](uninitialized=True)
        comptime for i in range(8):
            w[i] = Load512(block + i * 16)

        var v = InlineArray[SIMD64x2, 4](uninitialized=True)
        v[0] = ab
        v[1] = cd
        v[2] = ef
        v[3] = gh

        comptime for t in range(40):
            comptime d = (3 - t) & 3
            var initial_sum = w[t & 7] + SIMD64x2(SHA512NI_K[2 * t], SHA512NI_K[2 * t + 1])
            var sum = initial_sum.shuffle[1, 0]() + v[d]
            var intermed = _sha512h(sum, _ext1(v[(d + 3) & 3], v[d]), _ext1(v[(d + 2) & 3], v[(d + 3) & 3]))
            comptime if t < 32:
                w[t & 7] = _sha512su1(
                    _sha512su0(w[t & 7], w[(t + 1) & 7]),
                    w[(t + 7) & 7],
                    _ext1(w[(t + 4) & 7], w[(t + 5) & 7]),
                )
            v[d] = _sha512h2(intermed, v[(d + 2) & 3], v[(d + 1) & 3])
            v[(d + 2) & 3] += intermed

        ab += v[0]
        cd += v[1]
        ef += v[2]
        gh += v[3]

    state = SIMD[DType.uint64, 8](
        ab[0], ab[1], cd[0], cd[1], ef[0], ef[1], gh[0], gh[1]
    )
