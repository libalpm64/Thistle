"""
AES-NI implementation
"""

from std.collections import List, InlineArray
from std.sys import llvm_intrinsic, CompilationTarget
from std.memory import alloc, bitcast, memset_zero, memcpy, UnsafePointer, Span
from std.utils import StaticTuple
from .aes import cpu_aes_encrypt, cpu_aes_ct_encrypt, cpu_aes_ct_encrypt16, cpu_aes_ct_skey, expand_key_128, expand_key_192, expand_key_256
from .utils import StackBuffer

comptime SIMD16 = SIMD[DType.uint8, 16]
comptime SIMD128 = SIMD[DType.uint64, 2]

@always_inline
def has_arm_crypto() -> Bool:
    return CompilationTarget.has_neon() and not CompilationTarget.is_x86() and (
        CompilationTarget._has_feature["crypto"]() or CompilationTarget._has_feature["aes"]()
    )

@always_inline
def has_x86_aes_ni() -> Bool:
    return CompilationTarget.is_x86() and CompilationTarget._has_feature["sse"]() and CompilationTarget._has_feature["aes"]()

@always_inline
def _aese(lhs: SIMD16, rhs: SIMD16) -> SIMD16:
    comptime if has_arm_crypto():
        return llvm_intrinsic["llvm.aarch64.crypto.aese", SIMD16, has_side_effect=False](
            lhs, rhs
        )
    else:
        return SIMD16(0)

@always_inline
def _aesmc(state: SIMD16) -> SIMD16:
    comptime if has_arm_crypto():
        return llvm_intrinsic["llvm.aarch64.crypto.aesmc", SIMD16, has_side_effect=False](
            state
        )
    else:
        return SIMD16(0)

@always_inline
def _mm_aesenc_si128(lhs: SIMD128, rhs: SIMD128) -> SIMD128:
    comptime if has_x86_aes_ni():
        return llvm_intrinsic["llvm.x86.aesni.aesenc", SIMD128, has_side_effect=False](
            lhs, rhs
        )
    else:
        return SIMD128(0)

@always_inline
def _mm_aesenclast_si128(lhs: SIMD128, rhs: SIMD128) -> SIMD128:
    comptime if has_x86_aes_ni():
        return llvm_intrinsic["llvm.x86.aesni.aesenclast", SIMD128, has_side_effect=False](
            lhs, rhs
        )
    else:
        return SIMD128(0)

@always_inline
def _mm_aeskeygenassist_si128(v: SIMD128, imm8: Int) -> SIMD128:
    comptime if has_x86_aes_ni():
        return llvm_intrinsic[
            "llvm.x86.aesni.aeskeygenassist",
            SIMD128,
            has_side_effect=False,
        ](v, imm8)
    else:
        return SIMD128(0)


@always_inline
def _mm_loadu_si128(ptr: UnsafePointer[UInt8, MutAnyOrigin]) -> SIMD128:
    return ptr.bitcast[UInt64]().load[width=2, alignment=1]()

@always_inline
def _mm_storeu_si128(ptr: UnsafePointer[UInt8, MutAnyOrigin], data: SIMD128) -> None:
    var bytes: SIMD[DType.uint8, 16] = bitcast[DType.uint8, 16](data)
    ptr.store[width=16, alignment=1](0, bytes)

@always_inline
def _write_gcm_counter(
    counter_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    j0_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    block_index: Int,
) -> None:
    for j in range(12):
        counter_ptr.store(j, j0_ptr.load(j))

    var base = (
        (UInt32(j0_ptr.load(12)) << 24) | (UInt32(j0_ptr.load(13)) << 16)
        | (UInt32(j0_ptr.load(14)) << 8) | UInt32(j0_ptr.load(15))
    )
    var ctr = base + UInt32(1) + UInt32(block_index & 0xFFFFFFFF)
    counter_ptr.store(12, UInt8((ctr >> 24) & 0xFF))
    counter_ptr.store(13, UInt8((ctr >> 16) & 0xFF))
    counter_ptr.store(14, UInt8((ctr >> 8) & 0xFF))
    counter_ptr.store(15, UInt8(ctr & 0xFF))

@always_inline
def _load_round_key(idx: Int, round_keys: UnsafePointer[UInt32, MutAnyOrigin]) -> SIMD128:
    var w0 = round_keys.load(idx * 4)
    var w1 = round_keys.load(idx * 4 + 1)
    var w2 = round_keys.load(idx * 4 + 2)
    var w3 = round_keys.load(idx * 4 + 3)
    var bytes = SIMD[DType.uint8, 16](
        UInt8(w0 >> 24), UInt8(w0 >> 16), UInt8(w0 >> 8), UInt8(w0),
        UInt8(w1 >> 24), UInt8(w1 >> 16), UInt8(w1 >> 8), UInt8(w1),
        UInt8(w2 >> 24), UInt8(w2 >> 16), UInt8(w2 >> 8), UInt8(w2),
        UInt8(w3 >> 24), UInt8(w3 >> 16), UInt8(w3 >> 8), UInt8(w3)
    )
    return bitcast[DType.uint64, 2](bytes.to_bits())


def x86_aes_encrypt_128(
    pt: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin]
) -> None:
    var state = _mm_loadu_si128(pt)
    x86_aes_encrypt_128_direct(state, round_keys)
    _mm_storeu_si128(pt, state)


def x86_aes_encrypt_192(
    pt: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin]
) -> None:
    var state = _mm_loadu_si128(pt)
    x86_aes_encrypt_192_direct(state, round_keys)
    _mm_storeu_si128(pt, state)


def x86_aes_encrypt_256(
    pt: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin]
) -> None:
    var state = _mm_loadu_si128(pt)
    x86_aes_encrypt_256_direct(state, round_keys)
    _mm_storeu_si128(pt, state)

@always_inline
def x86_aes_encrypt_128_direct(
    mut state: SIMD128,
    round_keys: UnsafePointer[UInt32, MutAnyOrigin]
) -> None:
    var keys = StaticTuple[SIMD128, 11]()
    comptime for i in range(11):
        keys[i] = _load_round_key(i, round_keys)

    state = state ^ keys[0]
    comptime for i in range(1, 10):
        state = _mm_aesenc_si128(state, keys[i])
    state = _mm_aesenclast_si128(state, keys[10])

@always_inline
def x86_aes_encrypt_192_direct(
    mut state: SIMD128,
    round_keys: UnsafePointer[UInt32, MutAnyOrigin]
) -> None:
    var keys = StaticTuple[SIMD128, 13]()
    comptime for i in range(13):
        keys[i] = _load_round_key(i, round_keys)

    state = state ^ keys[0]
    comptime for i in range(1, 12):
        state = _mm_aesenc_si128(state, keys[i])
    state = _mm_aesenclast_si128(state, keys[12])

@always_inline
def x86_aes_encrypt_256_direct(
    mut state: SIMD128,
    round_keys: UnsafePointer[UInt32, MutAnyOrigin]
) -> None:
    var keys = StaticTuple[SIMD128, 15]()
    comptime for i in range(15):
        keys[i] = _load_round_key(i, round_keys)

    state = state ^ keys[0]
    comptime for i in range(1, 14):
        state = _mm_aesenc_si128(state, keys[i])
    state = _mm_aesenclast_si128(state, keys[14])


@always_inline
def _arm_load_keys[N: Int](
    round_keys: UnsafePointer[UInt32, MutAnyOrigin]
) -> InlineArray[SIMD16, N]:
    var keys = InlineArray[SIMD16, N](uninitialized=True)
    comptime for i in range(N):
        var raw = (round_keys + i * 4).bitcast[UInt8]().load[
            width=16, alignment=1
        ]()
        keys[i] = raw.shuffle[
            3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12
        ]()
    return keys


@always_inline
def _arm_enc_block[NR: Int](
    x0: SIMD16, keys: InlineArray[SIMD16, NR + 1]
) -> SIMD16:
    var x = x0
    comptime for r in range(NR - 1):
        x = _aesmc(_aese(x, keys[r]))
    x = _aese(x, keys[NR - 1])
    return x ^ keys[NR]


def arm_aes_encrypt_128(
    pt: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin]
) -> None:
    var keys = _arm_load_keys[11](round_keys)
    var x = pt.load[width=16, alignment=1](0)
    pt.store[alignment=1](0, _arm_enc_block[10](x, keys))


def arm_aes_encrypt_192(
    pt: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin]
) -> None:
    var keys = _arm_load_keys[13](round_keys)
    var x = pt.load[width=16, alignment=1](0)
    pt.store[alignment=1](0, _arm_enc_block[12](x, keys))


def arm_aes_encrypt_256(
    pt: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin]
) -> None:
    var keys = _arm_load_keys[15](round_keys)
    var x = pt.load[width=16, alignment=1](0)
    pt.store[alignment=1](0, _arm_enc_block[14](x, keys))

@always_inline
def _arm_ecb_loop[NR: Int](
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
    num_blocks: Int,
) -> None:
    var keys = _arm_load_keys[NR + 1](round_keys)
    var i = 0
    while i + 4 <= num_blocks:
        var p = input_ptr + i * 16
        var b0 = p.load[width=16, alignment=1](0)
        var b1 = p.load[width=16, alignment=1](16)
        var b2 = p.load[width=16, alignment=1](32)
        var b3 = p.load[width=16, alignment=1](48)
        comptime for r in range(NR - 1):
            b0 = _aesmc(_aese(b0, keys[r]))
            b1 = _aesmc(_aese(b1, keys[r]))
            b2 = _aesmc(_aese(b2, keys[r]))
            b3 = _aesmc(_aese(b3, keys[r]))
        b0 = _aese(b0, keys[NR - 1]) ^ keys[NR]
        b1 = _aese(b1, keys[NR - 1]) ^ keys[NR]
        b2 = _aese(b2, keys[NR - 1]) ^ keys[NR]
        b3 = _aese(b3, keys[NR - 1]) ^ keys[NR]
        var q = output_ptr + i * 16
        q.store[alignment=1](0, b0)
        q.store[alignment=1](16, b1)
        q.store[alignment=1](32, b2)
        q.store[alignment=1](48, b3)
        i += 4
    while i < num_blocks:
        var x = (input_ptr + i * 16).load[width=16, alignment=1](0)
        (output_ptr + i * 16).store[alignment=1](0, _arm_enc_block[NR](x, keys))
        i += 1


@always_inline
def arm_aes_ecb_kernel(
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
    num_blocks: Int,
    rounds: Int
) -> None:
    if rounds == 10:
        _arm_ecb_loop[10](input_ptr, output_ptr, round_keys, num_blocks)
    elif rounds == 12:
        _arm_ecb_loop[12](input_ptr, output_ptr, round_keys, num_blocks)
    else:
        _arm_ecb_loop[14](input_ptr, output_ptr, round_keys, num_blocks)


@always_inline
def _arm_cbc_loop[NR: Int](
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
    num_blocks: Int,
    iv_ptr: UnsafePointer[UInt8, MutAnyOrigin],
) -> None:
    var keys = _arm_load_keys[NR + 1](round_keys)
    var prev = iv_ptr.load[width=16, alignment=1](0)
    var src = input_ptr
    var dst = output_ptr
    var i = 0
    while i < num_blocks:
        var x = src.load[width=16, alignment=1](0) ^ prev
        prev = _arm_enc_block[NR](x, keys)
        dst.store[alignment=1](0, prev)
        src += 16
        dst += 16
        i += 1


@always_inline
def arm_aes_cbc_kernel(
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
    num_blocks: Int,
    iv_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    rounds: Int
) -> None:
    if rounds == 10:
        _arm_cbc_loop[10](input_ptr, output_ptr, round_keys, num_blocks, iv_ptr)
    elif rounds == 12:
        _arm_cbc_loop[12](input_ptr, output_ptr, round_keys, num_blocks, iv_ptr)
    else:
        _arm_cbc_loop[14](input_ptr, output_ptr, round_keys, num_blocks, iv_ptr)

@always_inline
def arm_aes_xts_kernel(
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys1: UnsafePointer[UInt32, MutAnyOrigin],
    round_keys2: UnsafePointer[UInt32, MutAnyOrigin],
    num_blocks: Int,
    tweak_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    rounds: Int
) -> None:
    var tweak = tweak_ptr.load[width=16, alignment=1](0)
    if rounds == 10:
        tweak = _arm_enc_block[10](tweak, _arm_load_keys[11](round_keys2))
    else:
        tweak = _arm_enc_block[14](tweak, _arm_load_keys[15](round_keys2))
    if rounds == 10:
        var keys = _arm_load_keys[11](round_keys1)
        var i = 0
        while i < num_blocks:
            var x = (input_ptr + i * 16).load[width=16, alignment=1](0) ^ tweak
            x = _arm_enc_block[10](x, keys) ^ tweak
            (output_ptr + i * 16).store[alignment=1](0, x)
            tweak = bitcast[DType.uint8, 16](
                _gf_mul2_xts_simd(bitcast[DType.uint64, 2](tweak))
            )
            i += 1
    else:
        var keys = _arm_load_keys[15](round_keys1)
        var i = 0
        while i < num_blocks:
            var x = (input_ptr + i * 16).load[width=16, alignment=1](0) ^ tweak
            x = _arm_enc_block[14](x, keys) ^ tweak
            (output_ptr + i * 16).store[alignment=1](0, x)
            tweak = bitcast[DType.uint8, 16](
                _gf_mul2_xts_simd(bitcast[DType.uint64, 2](tweak))
            )
            i += 1

@always_inline
def x86_aes_ecb_kernel(
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
    num_blocks: Int,
    rounds: Int
) -> None:
    var i = 0
    while i < num_blocks:
        var block = _mm_loadu_si128(input_ptr + i * 16)
        
        if rounds == 10:
            x86_aes_encrypt_128_direct(block, round_keys)
        elif rounds == 12:
            x86_aes_encrypt_192_direct(block, round_keys)
        else:
            x86_aes_encrypt_256_direct(block, round_keys)
        
        _mm_storeu_si128(output_ptr + i * 16, block)
        i += 1

@always_inline
def x86_aes_cbc_kernel(
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
    num_blocks: Int,
    iv_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    rounds: Int
) -> None:
    var prev_block = _mm_loadu_si128(iv_ptr)
    
    var i = 0
    while i < num_blocks:
        var block = _mm_loadu_si128(input_ptr + i * 16)
        block = block ^ prev_block
        
        if rounds == 10:
            x86_aes_encrypt_128_direct(block, round_keys)
        elif rounds == 12:
            x86_aes_encrypt_192_direct(block, round_keys)
        else:
            x86_aes_encrypt_256_direct(block, round_keys)
        
        _mm_storeu_si128(output_ptr + i * 16, block)
        prev_block = block
        i += 1

@always_inline
def _gf_mul2_xts_simd(val: SIMD128) -> SIMD128:
    var carry_lo_to_hi = val[0] >> 63
    var msb = val[1] >> 63
    var shifted_lo = val[0] << 1
    var shifted_hi = (val[1] << 1) | carry_lo_to_hi
    return SIMD128(shifted_lo ^ (msb * UInt64(0x87)), shifted_hi)

@always_inline
def x86_aes_xts_kernel(
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys1: UnsafePointer[UInt32, MutAnyOrigin],
    round_keys2: UnsafePointer[UInt32, MutAnyOrigin],
    num_blocks: Int,
    tweak_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    rounds: Int
) -> None:
    var tweak = _mm_loadu_si128(tweak_ptr)
    
    if rounds == 10:
        x86_aes_encrypt_128_direct(tweak, round_keys2)
    else:
        x86_aes_encrypt_256_direct(tweak, round_keys2)
    
    var i = 0
    while i < num_blocks:
        var in_block = _mm_loadu_si128(input_ptr + i * 16)
        var xored = in_block ^ tweak
        
        if rounds == 10:
            x86_aes_encrypt_128_direct(xored, round_keys1)
        else:
            x86_aes_encrypt_256_direct(xored, round_keys1)
        
        var result = xored ^ tweak
        _mm_storeu_si128(output_ptr + i * 16, result)
        
        tweak = _gf_mul2_xts_simd(tweak)
        i += 1

@always_inline
def aes_encrypt(
    pt: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
    rounds: Int = 10
) -> None:
    """Unified AES encryption function.

    Uses X86 AES-NI or ARM Crypto Extensions on supported hardware, falls back to
    software implementation otherwise.
    """
    comptime if CompilationTarget._has_feature["sse"]() and CompilationTarget._has_feature["aes"]():
        if rounds == 10:
            x86_aes_encrypt_128(pt, round_keys)
        elif rounds == 12:
            x86_aes_encrypt_192(pt, round_keys)
        else:
            x86_aes_encrypt_256(pt, round_keys)
    else:
        comptime if CompilationTarget._has_feature["crypto"]() or CompilationTarget._has_feature["aes"]():
            if rounds == 10:
                arm_aes_encrypt_128(pt, round_keys)
            elif rounds == 12:
                arm_aes_encrypt_192(pt, round_keys)
            else:
                arm_aes_encrypt_256(pt, round_keys)
        else:
            cpu_aes_encrypt(pt, round_keys, rounds)

@always_inline
def aes_gcm_ctr_kernel(
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
    num_blocks: Int,
    j0_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    rounds: Int
) -> None:
    comptime if CompilationTarget._has_feature["sse"]() and CompilationTarget._has_feature["aes"]():
        _hw_gcm_ctr_kernel(input_ptr, output_ptr, round_keys, num_blocks, j0_ptr, rounds)
    else:
        comptime if CompilationTarget._has_feature["crypto"]() or CompilationTarget._has_feature["aes"]():
            _hw_gcm_ctr_kernel(input_ptr, output_ptr, round_keys, num_blocks, j0_ptr, rounds)
        else:
            _soft_gcm_ctr_kernel(input_ptr, output_ptr, round_keys, num_blocks, j0_ptr, rounds)


@always_inline
def _hw_gcm_ctr_kernel(
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
    num_blocks: Int,
    j0_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    rounds: Int
) -> None:
    comptime if has_arm_crypto():
        if rounds == 10:
            _arm_gcm_ctr_loop[10](
                input_ptr, output_ptr, round_keys, num_blocks, j0_ptr
            )
        elif rounds == 12:
            _arm_gcm_ctr_loop[12](
                input_ptr, output_ptr, round_keys, num_blocks, j0_ptr
            )
        else:
            _arm_gcm_ctr_loop[14](
                input_ptr, output_ptr, round_keys, num_blocks, j0_ptr
            )
        return

    var counter_block = StackBuffer[UInt8, 16]()
    var cp = counter_block.ptr()

    var i = 0
    while i < num_blocks:
        _write_gcm_counter(cp, j0_ptr, i)
        aes_encrypt(cp, round_keys, rounds)

        var in_block = input_ptr + i * 16
        var out_block = output_ptr + i * 16
        for j in range(16):
            out_block.store(j, in_block.load(j) ^ cp.load(j))

        i += 1


@always_inline
def _arm_gcm_ctr_loop[NR: Int](
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
    num_blocks: Int,
    j0_ptr: UnsafePointer[UInt8, MutAnyOrigin],
) -> None:
    var keys = _arm_load_keys[NR + 1](round_keys)
    var ctr = StackBuffer[UInt8, 64]()
    var cp = ctr.ptr()
    var i = 0
    while i + 4 <= num_blocks:
        _write_gcm_counter(cp, j0_ptr, i)
        _write_gcm_counter(cp + 16, j0_ptr, i + 1)
        _write_gcm_counter(cp + 32, j0_ptr, i + 2)
        _write_gcm_counter(cp + 48, j0_ptr, i + 3)
        var b0 = cp.load[width=16, alignment=1](0)
        var b1 = cp.load[width=16, alignment=1](16)
        var b2 = cp.load[width=16, alignment=1](32)
        var b3 = cp.load[width=16, alignment=1](48)
        comptime for r in range(NR - 1):
            b0 = _aesmc(_aese(b0, keys[r]))
            b1 = _aesmc(_aese(b1, keys[r]))
            b2 = _aesmc(_aese(b2, keys[r]))
            b3 = _aesmc(_aese(b3, keys[r]))
        b0 = _aese(b0, keys[NR - 1]) ^ keys[NR]
        b1 = _aese(b1, keys[NR - 1]) ^ keys[NR]
        b2 = _aese(b2, keys[NR - 1]) ^ keys[NR]
        b3 = _aese(b3, keys[NR - 1]) ^ keys[NR]
        var p = input_ptr + i * 16
        var q = output_ptr + i * 16
        q.store[alignment=1](0, p.load[width=16, alignment=1](0) ^ b0)
        q.store[alignment=1](16, p.load[width=16, alignment=1](16) ^ b1)
        q.store[alignment=1](32, p.load[width=16, alignment=1](32) ^ b2)
        q.store[alignment=1](48, p.load[width=16, alignment=1](48) ^ b3)
        i += 4
    while i < num_blocks:
        _write_gcm_counter(cp, j0_ptr, i)
        var ks = _arm_enc_block[NR](cp.load[width=16, alignment=1](0), keys)
        (output_ptr + i * 16).store[alignment=1](
            0, (input_ptr + i * 16).load[width=16, alignment=1](0) ^ ks
        )
        i += 1


@always_inline
def _soft_gcm_ctr_kernel(
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
    num_blocks: Int,
    j0_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    rounds: Int
) -> None:
    var skey = cpu_aes_ct_skey(round_keys, rounds)
    var ks = InlineArray[UInt8, 256](fill=0)
    var kp = ks.unsafe_ptr()
    var i = 0
    while i < num_blocks:
        var n = num_blocks - i
        if n > 16:
            n = 16
        for k in range(16):
            _write_gcm_counter(kp + k * 16, j0_ptr, i + (k if k < n else 0))
        cpu_aes_ct_encrypt16(kp, skey, rounds)
        for k in range(n):
            var in_block = input_ptr + (i + k) * 16
            var out_block = output_ptr + (i + k) * 16
            for j in range(16):
                out_block.store(j, in_block.load(j) ^ kp.load(k * 16 + j))
        i += n

@always_inline
def has_aes_ni() -> Bool:
    return has_x86_aes_ni() or has_arm_crypto()


# AES-GCM authenticated encryption (NIST SP 800-38D)

@always_inline
def _be_load64(p: UnsafePointer[UInt8, MutAnyOrigin], off: Int) -> UInt64:
    var v: UInt64 = 0
    for i in range(8):
        v = (v << UInt64(8)) | UInt64(p[off + i])
    return v


@always_inline
def _be_store64(p: UnsafePointer[UInt8, MutAnyOrigin], off: Int, v: UInt64):
    for i in range(8):
        p[off + i] = UInt8((v >> UInt64(56 - 8 * i)) & 0xFF)


struct _GHash:
    var h_hi: UInt64
    var h_lo: UInt64
    var y_hi: UInt64
    var y_lo: UInt64

    def __init__(out self, h_hi: UInt64, h_lo: UInt64):
        self.h_hi = h_hi
        self.h_lo = h_lo
        self.y_hi = 0
        self.y_lo = 0

    @always_inline
    def _mul_y_by_h(mut self):
        var z_hi: UInt64 = 0
        var z_lo: UInt64 = 0
        var v_hi = self.y_hi
        var v_lo = self.y_lo
        comptime R_HI: UInt64 = 0xE100000000000000

        for i in range(128):
            var x_bit: UInt64
            if i < 64:
                x_bit = (self.h_hi >> UInt64(63 - i)) & 1
            else:
                x_bit = (self.h_lo >> UInt64(127 - i)) & 1
            var mask = UInt64(0) - x_bit
            z_hi ^= v_hi & mask
            z_lo ^= v_lo & mask

            var lsb = v_lo & 1
            v_lo = (v_lo >> UInt64(1)) | (v_hi << UInt64(63))
            v_hi = v_hi >> UInt64(1)
            v_hi ^= R_HI & (UInt64(0) - lsb)

        self.y_hi = z_hi
        self.y_lo = z_lo

    @always_inline
    def update(mut self, data: UnsafePointer[UInt8, MutAnyOrigin], length: Int):
        var off = 0
        while off < length:
            var block = InlineArray[UInt8, 16](fill=0)
            var n = length - off
            if n > 16:
                n = 16
            memcpy(dest=block.unsafe_ptr(), src=data + off, count=n)
            self.y_hi ^= _be_load64(block.unsafe_ptr(), 0)
            self.y_lo ^= _be_load64(block.unsafe_ptr(), 8)
            self._mul_y_by_h()
            off += 16

    @always_inline
    def update_lengths(mut self, aad_bits: UInt64, text_bits: UInt64):
        self.y_hi ^= aad_bits
        self.y_lo ^= text_bits
        self._mul_y_by_h()


def _gcm_expand(key: Span[UInt8, ...], mut key_buf: InlineArray[UInt8, 32]) raises -> UnsafePointer[UInt32, MutAnyOrigin]:
    for i in range(len(key)):
        key_buf[i] = key[i]
    var kp = key_buf.unsafe_ptr()
    if len(key) == 16:
        return expand_key_128(kp)
    if len(key) == 24:
        return expand_key_192(kp)
    return expand_key_256(kp)


@always_inline
def _encrypt_block(
    rk: UnsafePointer[UInt32, MutAnyOrigin], rounds: Int,
    src: UnsafePointer[UInt8, MutAnyOrigin], dst: UnsafePointer[UInt8, MutAnyOrigin]
):
    for i in range(16):
        dst[i] = src[i]
    comptime if CompilationTarget._has_feature["sse"]() and CompilationTarget._has_feature["aes"]():
        aes_encrypt(dst, rk, rounds)
    else:
        comptime if CompilationTarget._has_feature["crypto"]() or CompilationTarget._has_feature["aes"]():
            aes_encrypt(dst, rk, rounds)
        else:
            cpu_aes_ct_encrypt(dst, rk, rounds)


def _derive_j0(
    h_hi: UInt64, h_lo: UInt64,
    iv: Span[UInt8, ...], mut j0: InlineArray[UInt8, 16]
):
    if len(iv) == 12:
        for i in range(12):
            j0[i] = iv[i]
        j0[12] = 0
        j0[13] = 0
        j0[14] = 0
        j0[15] = 1
        return
    var gh = _GHash(h_hi, h_lo)
    var iv_buf = List[UInt8](capacity=len(iv))
    iv_buf.extend(iv)
    gh.update(iv_buf.unsafe_ptr(), len(iv))
    gh.update_lengths(UInt64(0), UInt64(len(iv)) * 8)
    _be_store64(j0.unsafe_ptr(), 0, gh.y_hi)
    _be_store64(j0.unsafe_ptr(), 8, gh.y_lo)


def _gctr_and_ghash(
    rk: UnsafePointer[UInt32, MutAnyOrigin], rounds: Int,
    j0: InlineArray[UInt8, 16],
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    length: Int,
    mut gh: _GHash,
    ghash_ciphertext: Bool,
):
    var j0_buf = InlineArray[UInt8, 16](fill=0)
    for i in range(16):
        j0_buf[i] = j0[i]
    var full_blocks = length // 16
    aes_gcm_ctr_kernel(
        input_ptr, output_ptr, rk, full_blocks, j0_buf.unsafe_ptr(), rounds
    )

    var rem = length - full_blocks * 16
    if rem > 0:
        var ctr = InlineArray[UInt8, 16](fill=0)
        var ks = InlineArray[UInt8, 16](fill=0)
        _write_gcm_counter(ctr.unsafe_ptr(), j0_buf.unsafe_ptr(), full_blocks)
        _encrypt_block(rk, rounds, ctr.unsafe_ptr(), ks.unsafe_ptr())
        var off = full_blocks * 16
        for i in range(rem):
            output_ptr[off + i] = input_ptr[off + i] ^ ks[i]

    if ghash_ciphertext:
        gh.update(output_ptr, length)
    else:
        gh.update(input_ptr, length)


def _gcm_core(
    key: Span[UInt8, ...], iv: Span[UInt8, ...], aad: Span[UInt8, ...],
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    length: Int,
    mut tag: InlineArray[UInt8, 16],
    ghash_ciphertext: Bool,
) raises:
    var rounds = 10 if len(key) == 16 else (12 if len(key) == 24 else 14)
    var key_buf = InlineArray[UInt8, 32](fill=0)
    var rk = _gcm_expand(key, key_buf)

    var zero_block = InlineArray[UInt8, 16](fill=0)
    var h_block = InlineArray[UInt8, 16](fill=0)
    _encrypt_block(rk, rounds, zero_block.unsafe_ptr(), h_block.unsafe_ptr())
    var h_hi = _be_load64(h_block.unsafe_ptr(), 0)
    var h_lo = _be_load64(h_block.unsafe_ptr(), 8)

    var j0 = InlineArray[UInt8, 16](fill=0)
    _derive_j0(h_hi, h_lo, iv, j0)

    var gh = _GHash(h_hi, h_lo)
    if len(aad) > 0:
        var aad_buf = List[UInt8](capacity=len(aad))
        aad_buf.extend(aad)
        gh.update(aad_buf.unsafe_ptr(), len(aad))

    _gctr_and_ghash(rk, rounds, j0, input_ptr, output_ptr, length, gh, ghash_ciphertext)
    gh.update_lengths(UInt64(len(aad)) * 8, UInt64(length) * 8)

    var ek_j0 = InlineArray[UInt8, 16](fill=0)
    _encrypt_block(rk, rounds, j0.unsafe_ptr(), ek_j0.unsafe_ptr())
    var t_hi = gh.y_hi ^ _be_load64(ek_j0.unsafe_ptr(), 0)
    var t_lo = gh.y_lo ^ _be_load64(ek_j0.unsafe_ptr(), 8)
    _be_store64(tag.unsafe_ptr(), 0, t_hi)
    _be_store64(tag.unsafe_ptr(), 8, t_lo)

    memset_zero(key_buf.unsafe_ptr(), 32)
    memset_zero(rk, 4 * (rounds + 1))
    rk.free()


def _valid_gcm_key(key: Span[UInt8, ...]) -> Bool:
    return len(key) == 16 or len(key) == 24 or len(key) == 32


def aes_gcm_encrypt(
    key: Span[UInt8, ...], iv: Span[UInt8, ...],
    plaintext: Span[UInt8, ...], aad: Span[UInt8, ...],
) raises -> Tuple[List[UInt8], List[UInt8]]:
    if not _valid_gcm_key(key):
        raise Error("invalid key size")
    if len(iv) == 0:
        raise Error("invalid iv size")

    var n = len(plaintext)
    var ciphertext = List[UInt8](unsafe_uninit_length=n)
    var pt_buf = List[UInt8](capacity=n)
    pt_buf.extend(plaintext)
    var tag = InlineArray[UInt8, 16](fill=0)

    _gcm_core(
        key, iv, aad, pt_buf.unsafe_ptr(), ciphertext.unsafe_ptr(), n, tag,
        ghash_ciphertext=True,
    )

    var tag_out = List[UInt8](capacity=16)
    for i in range(16):
        tag_out.append(tag[i])
    return (ciphertext^, tag_out^)


def aes_gcm_decrypt(
    key: Span[UInt8, ...], iv: Span[UInt8, ...],
    ciphertext: Span[UInt8, ...], aad: Span[UInt8, ...], tag: Span[UInt8, ...],
) raises -> Tuple[List[UInt8], Bool]:
    if not _valid_gcm_key(key):
        raise Error("invalid key size")
    if len(iv) == 0:
        raise Error("invalid iv size")
    if len(tag) != 16:
        raise Error("invalid tag size")

    var n = len(ciphertext)
    var plaintext = List[UInt8](unsafe_uninit_length=n)
    var ct_buf = List[UInt8](capacity=n)
    ct_buf.extend(ciphertext)
    var computed_tag = InlineArray[UInt8, 16](fill=0)

    _gcm_core(
        key, iv, aad, ct_buf.unsafe_ptr(), plaintext.unsafe_ptr(), n, computed_tag,
        ghash_ciphertext=False,
    )

    var diff = UInt8(0)
    for i in range(16):
        diff |= computed_tag[i] ^ tag[i]

    if diff != 0:
        var pt_ptr = plaintext.unsafe_ptr()
        for i in range(n):
            pt_ptr.store[volatile=True](i, UInt8(0))
        return (List[UInt8](), False)

    return (plaintext^, True)
