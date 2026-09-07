"""Hardware AES (FIPS 197) and AES-GCM (NIST SP 800-38D) with reusable key schedules."""

from std.collections import List, InlineArray
from std.bit import byte_swap
from std.sys import llvm_intrinsic, CompilationTarget
from std.memory import bitcast, unsafe_memset_zero, unsafe_memcpy, Pointer
from std.os import abort
from std.utils import StaticTuple
from .aes import (
    cpu_aes_encrypt, cpu_aes_ct_encrypt, cpu_aes_ct_encrypt16, cpu_aes_ct_skey, expand_key_128_into, expand_key_192_into, expand_key_256_into,
    _validate_aes_rounds,
    _validate_aes_block_count
)
from .utils import StackBuffer, load_64be, store_64be, volatile_wipe

comptime SIMD16 = SIMD[DType.uint8, 16]
comptime SIMD128 = SIMD[DType.uint64, 2]


@always_inline
def has_arm_crypto() -> Bool:
    return (
        CompilationTarget.has_neon() and not CompilationTarget.is_x86() and (
        CompilationTarget._has_feature["crypto"]() or CompilationTarget._has_feature["aes"]())
    )


@always_inline
def has_x86_aes_ni() -> Bool:
    return (
        CompilationTarget.is_x86() and CompilationTarget._has_feature["sse"]() and CompilationTarget._has_feature["aes"]()
    )


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
def _mm_loadu_si128(ptr: Pointer[mut=True, UInt8, _, address_space=_]) -> SIMD128:
    return ptr.unsafe_bitcast[UInt64]().unsafe_load[width=2, alignment=1]()


@always_inline
def _mm_storeu_si128(ptr: Pointer[mut=True, UInt8, _, address_space=_], data: SIMD128) -> None:
    var bytes: SIMD[DType.uint8, 16] = bitcast[DType.uint8, 16](data)
    ptr.unsafe_store[width=16, alignment=1](0, bytes)


@always_inline
def _write_gcm_counter(
    counter_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    j0_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    block_index: Int
) -> None:
    """Write J0 with its low 32 bits incremented by block_index + 1 for GCM (NIST SP 800-38D,
    secs. 6.2 and 7.1).
    """
    if block_index < 0:
        abort("GCM counter block_index cannot be negative")
    var block_u64 = UInt64(block_index)
    if block_u64 > 0xFFFFFFFD:
        abort("GCM counter block_index exceeds 2^32-2 limit")
    for j in range(12):
        counter_ptr.unsafe_store(j, j0_ptr.unsafe_load(j))

    var base = (
        (UInt32(j0_ptr.unsafe_load(12)) << 24) | (UInt32(j0_ptr.unsafe_load(13)) << 16)
        | (UInt32(j0_ptr.unsafe_load(14)) << 8) | UInt32(j0_ptr.unsafe_load(15))
    )
    var ctr = base + UInt32(1) + UInt32(block_u64)
    counter_ptr.unsafe_store(12, UInt8((ctr >> 24) & 0xFF))
    counter_ptr.unsafe_store(13, UInt8((ctr >> 16) & 0xFF))
    counter_ptr.unsafe_store(14, UInt8((ctr >> 8) & 0xFF))
    counter_ptr.unsafe_store(15, UInt8(ctr & 0xFF))


@always_inline
def _load_round_key(idx: Int, round_keys: Pointer[mut=True, UInt32, _, address_space=_]) -> SIMD128:
    var raw = (
        round_keys.unsafe_offset(idx * 4).unsafe_bitcast[UInt8]().unsafe_load[
            width=16, alignment=1
        ]()
    )
    var bytes = raw.shuffle[
        3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12
    ]()
    return bitcast[DType.uint64, 2](bytes)


def x86_aes_encrypt_128(
    pt: Pointer[mut=True, UInt8, _, address_space=_],
    round_keys: Pointer[mut=True, UInt32, _, address_space=_]
) -> None:
    """Encrypt one AES-128 block in place using AES-NI (FIPS 197, sec. 5.1)."""
    var state = _mm_loadu_si128(pt)
    x86_aes_encrypt_128_direct(state, round_keys)
    _mm_storeu_si128(pt, state)


def x86_aes_encrypt_192(
    pt: Pointer[mut=True, UInt8, _, address_space=_],
    round_keys: Pointer[mut=True, UInt32, _, address_space=_]
) -> None:
    """Encrypt one AES-192 block in place using AES-NI (FIPS 197, sec. 5.1)."""
    var state = _mm_loadu_si128(pt)
    x86_aes_encrypt_192_direct(state, round_keys)
    _mm_storeu_si128(pt, state)


def x86_aes_encrypt_256(
    pt: Pointer[mut=True, UInt8, _, address_space=_],
    round_keys: Pointer[mut=True, UInt32, _, address_space=_]
) -> None:
    """Encrypt one AES-256 block in place using AES-NI (FIPS 197, sec. 5.1)."""
    var state = _mm_loadu_si128(pt)
    x86_aes_encrypt_256_direct(state, round_keys)
    _mm_storeu_si128(pt, state)


@always_inline
def x86_aes_encrypt_128_direct(
    mut state: SIMD128,
    round_keys: Pointer[mut=True, UInt32, _, address_space=_]
) -> None:
    """Encrypt an AES-128 state held in a vector register."""
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
    round_keys: Pointer[mut=True, UInt32, _, address_space=_]
) -> None:
    """Encrypt an AES-192 state held in a vector register."""
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
    round_keys: Pointer[mut=True, UInt32, _, address_space=_]
) -> None:
    """Encrypt an AES-256 state held in a vector register."""
    var keys = StaticTuple[SIMD128, 15]()
    comptime for i in range(15):
        keys[i] = _load_round_key(i, round_keys)

    state = state ^ keys[0]
    comptime for i in range(1, 14):
        state = _mm_aesenc_si128(state, keys[i])
    state = _mm_aesenclast_si128(state, keys[14])


@always_inline
def _arm_load_keys[N: Int](
    round_keys: Pointer[mut=True, UInt32, _, address_space=_]
) -> InlineArray[SIMD16, N]:
    var keys = InlineArray[SIMD16, N](fill=SIMD16(0))
    comptime for i in range(N):
        var raw = (
            (round_keys.unsafe_offset(i * 4)).unsafe_bitcast[UInt8]().unsafe_load[
            width=16, alignment=1
        ]()
        )
        keys[i] = raw.shuffle[
            3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12
        ]()
    return keys^


@always_inline
def _arm_enc_block[NR: Int](
    x0: SIMD16, keys: InlineArray[SIMD16, NR + 1]
) -> SIMD16:
    """Apply ARM AES rounds; omit AESMC in the final round."""
    var x = x0
    comptime for r in range(NR - 1):
        x = _aesmc(_aese(x, keys[r]))
    x = _aese(x, keys[NR - 1])
    return x ^ keys[NR]


def arm_aes_encrypt_128(
    pt: Pointer[mut=True, UInt8, _, address_space=_],
    round_keys: Pointer[mut=True, UInt32, _, address_space=_]
) -> None:
    """Encrypt one AES-128 block in place using ARM crypto instructions."""
    var keys = _arm_load_keys[11](round_keys)
    var x = pt.unsafe_load[width=16, alignment=1](0)
    pt.unsafe_store[alignment=1](0, _arm_enc_block[10](x, keys))


def arm_aes_encrypt_192(
    pt: Pointer[mut=True, UInt8, _, address_space=_],
    round_keys: Pointer[mut=True, UInt32, _, address_space=_]
) -> None:
    """Encrypt one AES-192 block in place using ARM crypto instructions."""
    var keys = _arm_load_keys[13](round_keys)
    var x = pt.unsafe_load[width=16, alignment=1](0)
    pt.unsafe_store[alignment=1](0, _arm_enc_block[12](x, keys))


def arm_aes_encrypt_256(
    pt: Pointer[mut=True, UInt8, _, address_space=_],
    round_keys: Pointer[mut=True, UInt32, _, address_space=_]
) -> None:
    """Encrypt one AES-256 block in place using ARM crypto instructions."""
    var keys = _arm_load_keys[15](round_keys)
    var x = pt.unsafe_load[width=16, alignment=1](0)
    pt.unsafe_store[alignment=1](0, _arm_enc_block[14](x, keys))


@always_inline
def _arm_ecb_loop[NR: Int](
    input_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    output_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    round_keys: Pointer[mut=True, UInt32, _, address_space=_],
    num_blocks: Int
) -> None:
    """Interleave four independent ARM AES states to hide round latency."""
    var keys = _arm_load_keys[NR + 1](round_keys)
    var i = 0
    while i + 4 <= num_blocks:
        var p = input_ptr.unsafe_offset(i * 16)
        var b0 = p.unsafe_load[width=16, alignment=1](0)
        var b1 = p.unsafe_load[width=16, alignment=1](16)
        var b2 = p.unsafe_load[width=16, alignment=1](32)
        var b3 = p.unsafe_load[width=16, alignment=1](48)
        comptime for r in range(NR - 1):
            b0 = _aesmc(_aese(b0, keys[r]))
            b1 = _aesmc(_aese(b1, keys[r]))
            b2 = _aesmc(_aese(b2, keys[r]))
            b3 = _aesmc(_aese(b3, keys[r]))
        b0 = _aese(b0, keys[NR - 1]) ^ keys[NR]
        b1 = _aese(b1, keys[NR - 1]) ^ keys[NR]
        b2 = _aese(b2, keys[NR - 1]) ^ keys[NR]
        b3 = _aese(b3, keys[NR - 1]) ^ keys[NR]
        var q = output_ptr.unsafe_offset(i * 16)
        q.unsafe_store[alignment=1](0, b0)
        q.unsafe_store[alignment=1](16, b1)
        q.unsafe_store[alignment=1](32, b2)
        q.unsafe_store[alignment=1](48, b3)
        i += 4
    while i < num_blocks:
        var x = input_ptr.unsafe_offset(i * 16).unsafe_load[width=16, alignment=1](0)
        output_ptr.unsafe_offset(i * 16).unsafe_store[alignment=1](0, _arm_enc_block[NR](x, keys))
        i += 1


@always_inline
def arm_aes_ecb_kernel(
    input_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    output_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    round_keys: Pointer[mut=True, UInt32, _, address_space=_],
    num_blocks: Int,
    rounds: Int
) -> None:
    """Encrypt full ECB blocks with ARM AES; no padding is added."""
    _validate_aes_rounds(rounds)
    _validate_aes_block_count(num_blocks)
    if rounds == 10:
        _arm_ecb_loop[10](input_ptr, output_ptr, round_keys, num_blocks)
    elif rounds == 12:
        _arm_ecb_loop[12](input_ptr, output_ptr, round_keys, num_blocks)
    else:
        _arm_ecb_loop[14](input_ptr, output_ptr, round_keys, num_blocks)


@always_inline
def _arm_cbc_loop[NR: Int](
    input_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    output_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    round_keys: Pointer[mut=True, UInt32, _, address_space=_],
    num_blocks: Int,
    iv_ptr: Pointer[mut=True, UInt8, _, address_space=_]
) -> None:
    """Encrypt CBC blocks in order, retaining each ciphertext as the next chaining value."""
    var keys = _arm_load_keys[NR + 1](round_keys)
    var prev = iv_ptr.unsafe_load[width=16, alignment=1](0)
    var src = input_ptr
    var dst = output_ptr
    var i = 0
    while i < num_blocks:
        var x = src.unsafe_load[width=16, alignment=1](0) ^ prev
        prev = _arm_enc_block[NR](x, keys)
        dst.unsafe_store[alignment=1](0, prev)
        src = src.unsafe_offset(16)
        dst = dst.unsafe_offset(16)
        i += 1


@always_inline
def arm_aes_cbc_kernel(
    input_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    output_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    round_keys: Pointer[mut=True, UInt32, _, address_space=_],
    num_blocks: Int,
    iv_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    rounds: Int
) -> None:
    """Dispatch ARM CBC encryption for 10, 12, or 14 rounds."""
    _validate_aes_rounds(rounds)
    _validate_aes_block_count(num_blocks)
    if rounds == 10:
        _arm_cbc_loop[10](input_ptr, output_ptr, round_keys, num_blocks, iv_ptr)
    elif rounds == 12:
        _arm_cbc_loop[12](input_ptr, output_ptr, round_keys, num_blocks, iv_ptr)
    else:
        _arm_cbc_loop[14](input_ptr, output_ptr, round_keys, num_blocks, iv_ptr)


@always_inline
def arm_aes_xts_kernel(
    input_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    output_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    round_keys1: Pointer[mut=True, UInt32, _, address_space=_],
    round_keys2: Pointer[mut=True, UInt32, _, address_space=_],
    num_blocks: Int,
    tweak_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    rounds: Int
) -> None:
    """Encrypt full XTS blocks with ARM AES and advance the tweak."""
    _validate_aes_rounds(rounds)
    _validate_aes_block_count(num_blocks)
    var tweak = tweak_ptr.unsafe_load[width=16, alignment=1](0)
    if rounds == 10:
        tweak = _arm_enc_block[10](tweak, _arm_load_keys[11](round_keys2))
    elif rounds == 12:
        tweak = _arm_enc_block[12](tweak, _arm_load_keys[13](round_keys2))
    else:
        tweak = _arm_enc_block[14](tweak, _arm_load_keys[15](round_keys2))
    if rounds == 10:
        var keys = _arm_load_keys[11](round_keys1)
        var i = 0
        while i < num_blocks:
            var x = (input_ptr + i * 16).unsafe_load[width=16, alignment=1](0) ^ tweak
            x = _arm_enc_block[10](x, keys) ^ tweak
            (output_ptr + i * 16).unsafe_store[alignment=1](0, x)
            tweak = bitcast[DType.uint8, 16](
                _gf_mul2_xts_simd(bitcast[DType.uint64, 2](tweak))
            )
            i += 1
    elif rounds == 12:
        var keys = _arm_load_keys[13](round_keys1)
        var i = 0
        while i < num_blocks:
            var x = (input_ptr + i * 16).unsafe_load[width=16, alignment=1](0) ^ tweak
            x = _arm_enc_block[12](x, keys) ^ tweak
            (output_ptr + i * 16).unsafe_store[alignment=1](0, x)
            tweak = bitcast[DType.uint8, 16](
                _gf_mul2_xts_simd(bitcast[DType.uint64, 2](tweak))
            )
            i += 1
    else:
        var keys = _arm_load_keys[15](round_keys1)
        var i = 0
        while i < num_blocks:
            var x = (input_ptr + i * 16).unsafe_load[width=16, alignment=1](0) ^ tweak
            x = _arm_enc_block[14](x, keys) ^ tweak
            (output_ptr + i * 16).unsafe_store[alignment=1](0, x)
            tweak = bitcast[DType.uint8, 16](
                _gf_mul2_xts_simd(bitcast[DType.uint64, 2](tweak))
            )
            i += 1


@always_inline
def _x86_aes_ecb_loop[NR: Int](
    input_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    output_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    round_keys: Pointer[mut=True, UInt32, _, address_space=_],
    num_blocks: Int
) -> None:
    """Interleave eight independent AES blocks to hide AESENC latency."""
    var keys = StaticTuple[SIMD128, NR + 1]()
    comptime for r in range(NR + 1):
        keys[r] = _load_round_key(r, round_keys)

    var i = 0
    while i + 8 <= num_blocks:
        var b0 = _mm_loadu_si128(input_ptr.unsafe_offset((i + 0) * 16)) ^ keys[0]
        var b1 = _mm_loadu_si128(input_ptr.unsafe_offset((i + 1) * 16)) ^ keys[0]
        var b2 = _mm_loadu_si128(input_ptr.unsafe_offset((i + 2) * 16)) ^ keys[0]
        var b3 = _mm_loadu_si128(input_ptr.unsafe_offset((i + 3) * 16)) ^ keys[0]
        var b4 = _mm_loadu_si128(input_ptr.unsafe_offset((i + 4) * 16)) ^ keys[0]
        var b5 = _mm_loadu_si128(input_ptr.unsafe_offset((i + 5) * 16)) ^ keys[0]
        var b6 = _mm_loadu_si128(input_ptr.unsafe_offset((i + 6) * 16)) ^ keys[0]
        var b7 = _mm_loadu_si128(input_ptr.unsafe_offset((i + 7) * 16)) ^ keys[0]
        comptime for r in range(1, NR):
            b0 = _mm_aesenc_si128(b0, keys[r])
            b1 = _mm_aesenc_si128(b1, keys[r])
            b2 = _mm_aesenc_si128(b2, keys[r])
            b3 = _mm_aesenc_si128(b3, keys[r])
            b4 = _mm_aesenc_si128(b4, keys[r])
            b5 = _mm_aesenc_si128(b5, keys[r])
            b6 = _mm_aesenc_si128(b6, keys[r])
            b7 = _mm_aesenc_si128(b7, keys[r])
        b0 = _mm_aesenclast_si128(b0, keys[NR])
        b1 = _mm_aesenclast_si128(b1, keys[NR])
        b2 = _mm_aesenclast_si128(b2, keys[NR])
        b3 = _mm_aesenclast_si128(b3, keys[NR])
        b4 = _mm_aesenclast_si128(b4, keys[NR])
        b5 = _mm_aesenclast_si128(b5, keys[NR])
        b6 = _mm_aesenclast_si128(b6, keys[NR])
        b7 = _mm_aesenclast_si128(b7, keys[NR])
        _mm_storeu_si128(output_ptr.unsafe_offset((i + 0) * 16), b0)
        _mm_storeu_si128(output_ptr.unsafe_offset((i + 1) * 16), b1)
        _mm_storeu_si128(output_ptr.unsafe_offset((i + 2) * 16), b2)
        _mm_storeu_si128(output_ptr.unsafe_offset((i + 3) * 16), b3)
        _mm_storeu_si128(output_ptr.unsafe_offset((i + 4) * 16), b4)
        _mm_storeu_si128(output_ptr.unsafe_offset((i + 5) * 16), b5)
        _mm_storeu_si128(output_ptr.unsafe_offset((i + 6) * 16), b6)
        _mm_storeu_si128(output_ptr.unsafe_offset((i + 7) * 16), b7)
        i += 8

    while i < num_blocks:
        var block = _mm_loadu_si128(input_ptr.unsafe_offset(i * 16)) ^ keys[0]
        comptime for r in range(1, NR):
            block = _mm_aesenc_si128(block, keys[r])
        block = _mm_aesenclast_si128(block, keys[NR])
        _mm_storeu_si128(output_ptr.unsafe_offset(i * 16), block)
        i += 1


@always_inline
def x86_aes_ecb_kernel(
    input_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    output_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    round_keys: Pointer[mut=True, UInt32, _, address_space=_],
    num_blocks: Int,
    rounds: Int
) -> None:
    _validate_aes_rounds(rounds)
    _validate_aes_block_count(num_blocks)
    if rounds == 10:
        _x86_aes_ecb_loop[10](input_ptr, output_ptr, round_keys, num_blocks)
    elif rounds == 12:
        _x86_aes_ecb_loop[12](input_ptr, output_ptr, round_keys, num_blocks)
    else:
        _x86_aes_ecb_loop[14](input_ptr, output_ptr, round_keys, num_blocks)


@always_inline
def x86_aes_cbc_kernel(
    input_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    output_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    round_keys: Pointer[mut=True, UInt32, _, address_space=_],
    num_blocks: Int,
    iv_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    rounds: Int
) -> None:
    _validate_aes_rounds(rounds)
    _validate_aes_block_count(num_blocks)
    var prev_block = _mm_loadu_si128(iv_ptr)
    
    var i = 0
    while i < num_blocks:
        var block = _mm_loadu_si128(input_ptr.unsafe_offset(i * 16))
        block = block ^ prev_block
        
        if rounds == 10:
            x86_aes_encrypt_128_direct(block, round_keys)
        elif rounds == 12:
            x86_aes_encrypt_192_direct(block, round_keys)
        else:
            x86_aes_encrypt_256_direct(block, round_keys)
        
        _mm_storeu_si128(output_ptr.unsafe_offset(i * 16), block)
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
    input_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    output_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    round_keys1: Pointer[mut=True, UInt32, _, address_space=_],
    round_keys2: Pointer[mut=True, UInt32, _, address_space=_],
    num_blocks: Int,
    tweak_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    rounds: Int
) -> None:
    _validate_aes_rounds(rounds)
    _validate_aes_block_count(num_blocks)
    var tweak = _mm_loadu_si128(tweak_ptr)
    
    if rounds == 10:
        x86_aes_encrypt_128_direct(tweak, round_keys2)
    elif rounds == 12:
        x86_aes_encrypt_192_direct(tweak, round_keys2)
    else:
        x86_aes_encrypt_256_direct(tweak, round_keys2)
    
    var i = 0
    while i < num_blocks:
        var in_block = _mm_loadu_si128(input_ptr.unsafe_offset(i * 16))
        var xored = in_block ^ tweak
        
        if rounds == 10:
            x86_aes_encrypt_128_direct(xored, round_keys1)
        elif rounds == 12:
            x86_aes_encrypt_192_direct(xored, round_keys1)
        else:
            x86_aes_encrypt_256_direct(xored, round_keys1)
        
        var result = xored ^ tweak
        _mm_storeu_si128(output_ptr.unsafe_offset(i * 16), result)
        
        tweak = _gf_mul2_xts_simd(tweak)
        i += 1


@always_inline
def aes_encrypt(
    pt: Pointer[mut=True, UInt8, _, address_space=_],
    round_keys: Pointer[mut=True, UInt32, _, address_space=_],
    rounds: Int = 10
) -> None:
    """Select hardware AES from compile-time target features, with a bitsliced fallback."""
    if rounds != 10 and rounds != 12 and rounds != 14:
        abort("AES round count must be 10, 12, or 14")
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
    input_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    output_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    round_keys: Pointer[mut=True, UInt32, _, address_space=_],
    num_blocks: Int,
    j0_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    rounds: Int
) -> None:
    """Apply GCTR from inc32(J0) (NIST SP 800-38D, secs. 6.5 and 7.1); authentication is handled
    separately.
    """
    if rounds != 10 and rounds != 12 and rounds != 14:
        abort("AES round count must be 10, 12, or 14")
    if num_blocks < 0:
        abort("AES-GCM block count cannot be negative")
    if num_blocks > 0xFFFFFFFE:
        abort("AES-GCM block count exceeds 2^32-2 limit")
    comptime if CompilationTarget._has_feature["sse"]() and CompilationTarget._has_feature["aes"]():
        _hw_gcm_ctr_kernel(input_ptr, output_ptr, round_keys, num_blocks, j0_ptr, rounds)
    else:
        comptime if CompilationTarget._has_feature["crypto"]() or CompilationTarget._has_feature["aes"]():
            _hw_gcm_ctr_kernel(input_ptr, output_ptr, round_keys, num_blocks, j0_ptr, rounds)
        else:
            _soft_gcm_ctr_kernel(input_ptr, output_ptr, round_keys, num_blocks, j0_ptr, rounds)


@always_inline
def _hw_gcm_ctr_kernel(
    input_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    output_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    round_keys: Pointer[mut=True, UInt32, _, address_space=_],
    num_blocks: Int,
    j0_ptr: Pointer[mut=True, UInt8, _, address_space=_],
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

    comptime if has_x86_aes_ni():
        if rounds == 10:
            _x86_gcm_ctr_loop[10](input_ptr, output_ptr, round_keys, num_blocks, j0_ptr)
        elif rounds == 12:
            _x86_gcm_ctr_loop[12](input_ptr, output_ptr, round_keys, num_blocks, j0_ptr)
        else:
            _x86_gcm_ctr_loop[14](input_ptr, output_ptr, round_keys, num_blocks, j0_ptr)
        return

    var counter_block = StackBuffer[UInt8, 16]()
    var cp = counter_block.ptr()

    var i = 0
    while i < num_blocks:
        _write_gcm_counter(cp, j0_ptr, i)
        aes_encrypt(cp, round_keys, rounds)

        var in_block = input_ptr.unsafe_offset(i * 16)
        var out_block = output_ptr.unsafe_offset(i * 16)
        for j in range(16):
            out_block.unsafe_store(j, in_block.unsafe_load(j) ^ cp.unsafe_load(j))

        i += 1


@always_inline
def _x86_gcm_ctr_loop[NR: Int](
    input_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    output_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    round_keys: Pointer[mut=True, UInt32, _, address_space=_],
    num_blocks: Int,
    j0_ptr: Pointer[mut=True, UInt8, _, address_space=_]
):
    # Interleave independent counters so each round key serves the whole batch.
    var keys = StaticTuple[SIMD128, NR + 1]()
    comptime for r in range(NR + 1):
        keys[r] = _load_round_key(r, round_keys)
    var j0 = _mm_loadu_si128(j0_ptr)
    var prefix = j0[1] & UInt64(0xFFFFFFFF)
    var counter = byte_swap(UInt32(j0[1] >> 32)) + UInt32(1)
    var i = 0
    while i + 8 <= num_blocks:
        var blocks = StaticTuple[SIMD128, 8]()
        comptime for b in range(8):
            blocks[b] = SIMD128(j0[0], prefix | (UInt64(byte_swap(counter + UInt32(b))) << 32)) ^ keys[0]
        comptime for r in range(1, NR):
            comptime for b in range(8):
                blocks[b] = _mm_aesenc_si128(blocks[b], keys[r])
        comptime for b in range(8):
            blocks[b] = _mm_aesenclast_si128(blocks[b], keys[NR])
            var offset = (i + b) * 16
            _mm_storeu_si128(output_ptr.unsafe_offset(offset), _mm_loadu_si128(input_ptr.unsafe_offset(offset)) ^ blocks[b])
        comptime for b in range(8):
            Pointer(to=blocks).unsafe_bitcast[UInt64]().unsafe_store[volatile=True](2 * b, SIMD128(0))
        counter += 8
        i += 8
    while i < num_blocks:
        var block = SIMD128(j0[0], prefix | (UInt64(byte_swap(counter)) << 32)) ^ keys[0]
        comptime for r in range(1, NR):
            block = _mm_aesenc_si128(block, keys[r])
        block = _mm_aesenclast_si128(block, keys[NR])
        _mm_storeu_si128(output_ptr.unsafe_offset(i * 16), _mm_loadu_si128(input_ptr.unsafe_offset(i * 16)) ^ block)
        Pointer(to=block).unsafe_bitcast[UInt64]().unsafe_store[volatile=True](0, SIMD128(0))
        counter += 1
        i += 1
    volatile_wipe(Pointer(to=keys).unsafe_bitcast[UInt64](), 2 * (NR + 1))


@always_inline
def _arm_gcm_ctr_loop[NR: Int](
    input_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    output_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    round_keys: Pointer[mut=True, UInt32, _, address_space=_],
    num_blocks: Int,
    j0_ptr: Pointer[mut=True, UInt8, _, address_space=_]
) -> None:
    var keys = _arm_load_keys[NR + 1](round_keys)
    var ctr = StackBuffer[UInt8, 64]()
    var cp = ctr.ptr()
    var i = 0
    while i + 4 <= num_blocks:
        _write_gcm_counter(cp, j0_ptr, i)
        _write_gcm_counter(cp.unsafe_offset(16), j0_ptr, i + 1)
        _write_gcm_counter(cp.unsafe_offset(32), j0_ptr, i + 2)
        _write_gcm_counter(cp.unsafe_offset(48), j0_ptr, i + 3)
        var b0 = cp.unsafe_load[width=16, alignment=1](0)
        var b1 = cp.unsafe_load[width=16, alignment=1](16)
        var b2 = cp.unsafe_load[width=16, alignment=1](32)
        var b3 = cp.unsafe_load[width=16, alignment=1](48)
        comptime for r in range(NR - 1):
            b0 = _aesmc(_aese(b0, keys[r]))
            b1 = _aesmc(_aese(b1, keys[r]))
            b2 = _aesmc(_aese(b2, keys[r]))
            b3 = _aesmc(_aese(b3, keys[r]))
        b0 = _aese(b0, keys[NR - 1]) ^ keys[NR]
        b1 = _aese(b1, keys[NR - 1]) ^ keys[NR]
        b2 = _aese(b2, keys[NR - 1]) ^ keys[NR]
        b3 = _aese(b3, keys[NR - 1]) ^ keys[NR]
        var p = input_ptr.unsafe_offset(i * 16)
        var q = output_ptr.unsafe_offset(i * 16)
        q.unsafe_store[alignment=1](0, p.unsafe_load[width=16, alignment=1](0) ^ b0)
        q.unsafe_store[alignment=1](16, p.unsafe_load[width=16, alignment=1](16) ^ b1)
        q.unsafe_store[alignment=1](32, p.unsafe_load[width=16, alignment=1](32) ^ b2)
        q.unsafe_store[alignment=1](48, p.unsafe_load[width=16, alignment=1](48) ^ b3)
        i += 4
    while i < num_blocks:
        _write_gcm_counter(cp, j0_ptr, i)
        var ks = _arm_enc_block[NR](cp.unsafe_load[width=16, alignment=1](0), keys)
        (output_ptr.unsafe_offset(i * 16)).unsafe_store[alignment=1](
            0, (input_ptr.unsafe_offset(i * 16)).unsafe_load[width=16, alignment=1](0) ^ ks
        )
        i += 1


@always_inline
def _arm_gcm_fused_loop[NR: Int](
    input_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    output_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    round_keys: Pointer[mut=True, UInt32, _, address_space=_],
    num_blocks: Int,
    j0_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    mut gh: _GHash,
    ghash_ciphertext: Bool
) -> None:
    var keys = _arm_load_keys[NR + 1](round_keys)
    var y = SIMD128(_bitrev64(gh.y_hi), _bitrev64(gh.y_lo))

    var j0u32 = bitcast[DType.uint32, 4](j0_ptr.unsafe_load[width=16, alignment=1](0))
    var ctr_base = llvm_intrinsic["llvm.bswap.i32", UInt32, has_side_effect=False](j0u32[3]) + 1

    var i = 0
    while i + 8 <= num_blocks:
        var b = InlineArray[SIMD16, 8](fill=SIMD16(0))
        comptime for k in range(8):
            var cv = j0u32
            cv[3] = llvm_intrinsic["llvm.bswap.i32", UInt32, has_side_effect=False](
                ctr_base + UInt32(i + k)
            )
            b[k] = bitcast[DType.uint8, 16](cv)
        comptime for r in range(NR - 1):
            comptime for k in range(8):
                b[k] = _aesmc(_aese(b[k], keys[r]))
        comptime for k in range(8):
            b[k] = _aese(b[k], keys[NR - 1]) ^ keys[NR]

        var p = input_ptr.unsafe_offset(i * 16)
        var q = output_ptr.unsafe_offset(i * 16)
        var g = InlineArray[SIMD16, 8](fill=SIMD16(0))
        comptime for k in range(8):
            var pt = p.unsafe_load[width=16, alignment=1](k * 16)
            var ct = pt ^ b[k]
            q.unsafe_store[alignment=1](k * 16, ct)
            g[k] = ct if ghash_ciphertext else pt

        var lo = SIMD128(0)
        var hi = SIMD128(0)
        _clmul_acc(_rev128(g[0]) ^ y, gh.hn8, lo, hi)
        _clmul_acc(_rev128(g[1]), gh.hn7, lo, hi)
        _clmul_acc(_rev128(g[2]), gh.hn6, lo, hi)
        _clmul_acc(_rev128(g[3]), gh.hn5, lo, hi)
        _clmul_acc(_rev128(g[4]), gh.hn4, lo, hi)
        _clmul_acc(_rev128(g[5]), gh.hn3, lo, hi)
        _clmul_acc(_rev128(g[6]), gh.hn2, lo, hi)
        _clmul_acc(_rev128(g[7]), gh.hn, lo, hi)
        y = _reduce_vec(lo, hi)
        i += 8

    if i + 4 <= num_blocks:
        var b = InlineArray[SIMD16, 4](fill=SIMD16(0))
        comptime for k in range(4):
            var cv = j0u32
            cv[3] = llvm_intrinsic["llvm.bswap.i32", UInt32, has_side_effect=False](
                ctr_base + UInt32(i + k)
            )
            b[k] = bitcast[DType.uint8, 16](cv)
        comptime for r in range(NR - 1):
            comptime for k in range(4):
                b[k] = _aesmc(_aese(b[k], keys[r]))
        comptime for k in range(4):
            b[k] = _aese(b[k], keys[NR - 1]) ^ keys[NR]

        var p = input_ptr.unsafe_offset(i * 16)
        var q = output_ptr.unsafe_offset(i * 16)
        var g = InlineArray[SIMD16, 4](fill=SIMD16(0))
        comptime for k in range(4):
            var pt = p.unsafe_load[width=16, alignment=1](k * 16)
            var ct = pt ^ b[k]
            q.unsafe_store[alignment=1](k * 16, ct)
            g[k] = ct if ghash_ciphertext else pt

        var lo = SIMD128(0)
        var hi = SIMD128(0)
        _clmul_acc(_rev128(g[0]) ^ y, gh.hn4, lo, hi)
        _clmul_acc(_rev128(g[1]), gh.hn3, lo, hi)
        _clmul_acc(_rev128(g[2]), gh.hn2, lo, hi)
        _clmul_acc(_rev128(g[3]), gh.hn, lo, hi)
        y = _reduce_vec(lo, hi)
        i += 4

    while i < num_blocks:
        var cv = j0u32
        cv[3] = llvm_intrinsic["llvm.bswap.i32", UInt32, has_side_effect=False](
            ctr_base + UInt32(i)
        )
        var ks = _arm_enc_block[NR](bitcast[DType.uint8, 16](cv), keys)
        var p0 = (input_ptr.unsafe_offset(i * 16)).unsafe_load[width=16, alignment=1](0)
        var c0 = p0 ^ ks
        (output_ptr.unsafe_offset(i * 16)).unsafe_store[alignment=1](0, c0)
        var g0 = c0 if ghash_ciphertext else p0
        y = _gf_mul_nat(_rev128(g0) ^ y, gh.hn)
        i += 1

    gh.y_hi = _bitrev64(y[0])
    gh.y_lo = _bitrev64(y[1])


@always_inline
def _soft_gcm_ctr_kernel(
    input_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    output_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    round_keys: Pointer[mut=True, UInt32, _, address_space=_],
    num_blocks: Int,
    j0_ptr: Pointer[mut=True, UInt8, _, address_space=_],
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
            _write_gcm_counter(kp.unsafe_offset(k * 16), j0_ptr, i + (k if k < n else 0))
        cpu_aes_ct_encrypt16(kp, skey, rounds)
        for k in range(n):
            var in_block = input_ptr.unsafe_offset((i + k) * 16)
            var out_block = output_ptr.unsafe_offset((i + k) * 16)
            for j in range(16):
                out_block.unsafe_store(j, in_block.unsafe_load(j) ^ kp.unsafe_load(k * 16 + j))
        i += n
    volatile_wipe(skey.unsafe_ptr(), len(skey))
    volatile_wipe(kp, 256)


@always_inline
def has_aes_ni() -> Bool:
    """Return whether the compilation target enables hardware AES."""
    return has_x86_aes_ni() or has_arm_crypto()


# AES-GCM authenticated encryption (NIST SP 800-38D, sec. 7).

comptime _GCM_MAX_INPUT_BYTES = 68719476704


@always_inline("nodebug")
def _bitrev64(v: UInt64) -> UInt64:
    return llvm_intrinsic["llvm.bitreverse.i64", UInt64, has_side_effect=False](v)


@always_inline
def has_x86_pclmul() -> Bool:
    return CompilationTarget.is_x86() and CompilationTarget._has_feature["pclmul"]()


@always_inline
def _has_clmul() -> Bool:
    return has_x86_pclmul() or (
        CompilationTarget.has_neon() and CompilationTarget._has_feature["aes"]()
        and not CompilationTarget.is_x86()
    )


@always_inline("nodebug")
def _clmul64(a: UInt64, b: UInt64) -> SIMD128:
    comptime if has_x86_pclmul():
        return llvm_intrinsic[
            "llvm.x86.pclmulqdq", SIMD128, has_side_effect=False
        ](SIMD128(a, 0), SIMD128(b, 0), UInt8(0))
    elif CompilationTarget.has_neon() and CompilationTarget._has_feature["aes"]() and not CompilationTarget.is_x86():
        return bitcast[DType.uint64, 2](
            llvm_intrinsic["llvm.aarch64.neon.pmull64", SIMD16, has_side_effect=False](a, b)
        )
    else:
        return SIMD128(0)


@always_inline("nodebug")
def _rev128(v: SIMD16) -> SIMD128:
    return bitcast[DType.uint64, 2](
        llvm_intrinsic["llvm.bitreverse.v16i8", SIMD16, has_side_effect=False](v)
    )


@always_inline("nodebug")
def _load_nat128(p: Pointer[mut=True, UInt8, _, address_space=_]) -> SIMD128:
    return _rev128(p.unsafe_load[width=16, alignment=1](0))


comptime _ZERO128 = SIMD128(0)


@always_inline("nodebug")
def _shl64(v: SIMD128) -> SIMD128:
    return _ZERO128.shuffle[1, 2](v)


@always_inline("nodebug")
def _shr64(v: SIMD128) -> SIMD128:
    return v.shuffle[1, 2](_ZERO128)


@always_inline("nodebug")
def _clmul_acc(a: SIMD128, b: SIMD128, mut lo: SIMD128, mut hi: SIMD128):
    """XOR an unreduced Karatsuba carryless product into the lo/hi accumulators."""
    var p00 = _clmul64(a[0], b[0])
    var p11 = _clmul64(a[1], b[1])
    var axs = a ^ a.shuffle[1, 0]()
    var bxs = b ^ b.shuffle[1, 0]()
    var pm = _clmul64(axs[0], bxs[0]) ^ p00 ^ p11
    lo ^= p00 ^ _shl64(pm)
    hi ^= p11 ^ _shr64(pm)


@always_inline("nodebug")
def _reduce_vec(lo: SIMD128, hi: SIMD128) -> SIMD128:
    """Reduce a 256-bit carryless product modulo the GHASH polynomial (NIST SP 800-38D, sec.
    6.3).
    """
    # 0x87 encodes the low terms of x^128 + x^7 + x^2 + x + 1.
    var f = _clmul64(hi[1], 0x87)
    var hi2 = hi ^ _shr64(f)
    var lo2 = lo ^ _shl64(f)
    return lo2 ^ _clmul64(hi2[0], 0x87)


@always_inline("nodebug")
def _gf_mul_nat(a: SIMD128, b: SIMD128) -> SIMD128:
    """Multiply and reduce two elements in the GHASH field (NIST SP 800-38D, sec. 6.3)."""
    var lo = SIMD128(0)
    var hi = SIMD128(0)
    _clmul_acc(a, b, lo, hi)
    return _reduce_vec(lo, hi)


struct _GHash(Copyable, Movable):
    var h_hi: UInt64
    var h_lo: UInt64
    var y_hi: UInt64
    var y_lo: UInt64
    var hn: SIMD128
    var hn2: SIMD128
    var hn3: SIMD128
    var hn4: SIMD128
    var hn5: SIMD128
    var hn6: SIMD128
    var hn7: SIMD128
    var hn8: SIMD128

    def __init__(out self, h_hi: UInt64, h_lo: UInt64):
        self.h_hi = h_hi
        self.h_lo = h_lo
        self.y_hi = 0
        self.y_lo = 0
        self.hn = SIMD128(_bitrev64(h_hi), _bitrev64(h_lo))
        self.hn2 = _gf_mul_nat(self.hn, self.hn)
        self.hn3 = _gf_mul_nat(self.hn2, self.hn)
        self.hn4 = _gf_mul_nat(self.hn2, self.hn2)
        self.hn5 = _gf_mul_nat(self.hn4, self.hn)
        self.hn6 = _gf_mul_nat(self.hn4, self.hn2)
        self.hn7 = _gf_mul_nat(self.hn4, self.hn3)
        self.hn8 = _gf_mul_nat(self.hn4, self.hn4)

    @always_inline
    def _mul_y_by_h(mut self):
        comptime if _has_clmul():
            var y = _gf_mul_nat(SIMD128(_bitrev64(self.y_hi), _bitrev64(self.y_lo)), self.hn)
            self.y_hi = _bitrev64(y[0])
            self.y_lo = _bitrev64(y[1])
            return

        self._mul_y_by_h_soft()

    @always_inline
    def _mul_y_by_h_soft(mut self):
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
    def update(mut self, data: Pointer[mut=True, UInt8, _, address_space=_], length: Int
    ):
        comptime if _has_clmul():
            self._update_clmul(data, length)
            return

        self._update_soft(data, length)

    @always_inline
    def _update_clmul(mut self, data: Pointer[mut=True, UInt8, _, address_space=_], length: Int
    ):
        var y = SIMD128(_bitrev64(self.y_hi), _bitrev64(self.y_lo))
        var off = 0

        while off + 64 <= length:
            var lo = SIMD128(0)
            var hi = SIMD128(0)
            _clmul_acc(_load_nat128(data.unsafe_offset(off)) ^ y, self.hn4, lo, hi)
            _clmul_acc(_load_nat128(data.unsafe_offset(off).unsafe_offset(16)), self.hn3, lo, hi)
            _clmul_acc(_load_nat128(data.unsafe_offset(off).unsafe_offset(32)), self.hn2, lo, hi)
            _clmul_acc(_load_nat128(data.unsafe_offset(off).unsafe_offset(48)), self.hn, lo, hi)
            y = _reduce_vec(lo, hi)
            off += 64

        while off + 16 <= length:
            y = _gf_mul_nat(_load_nat128(data.unsafe_offset(off)) ^ y, self.hn)
            off += 16

        if off < length:
            var block = InlineArray[UInt8, 16](fill=0)
            for i in range(length - off):
                block[i] = data[unsafe_offset=off + i]
            y = _gf_mul_nat(_load_nat128(block.unsafe_ptr()) ^ y, self.hn)

        self.y_hi = _bitrev64(y[0])
        self.y_lo = _bitrev64(y[1])

    @always_inline
    def _update_soft(mut self, data: Pointer[mut=True, UInt8, _, address_space=_], length: Int
    ):
        var off = 0
        while off < length:
            var block = InlineArray[UInt8, 16](fill=0)
            var n = length - off
            if n > 16:
                n = 16
            for i in range(n):
                block[i] = data[unsafe_offset=off + i]
            self.y_hi ^= load_64be(block.unsafe_ptr(), 0)
            self.y_lo ^= load_64be(block.unsafe_ptr(), 8)
            self._mul_y_by_h_soft()
            off += 16

    @always_inline
    def update_lengths(mut self, aad_bits: UInt64, text_bits: UInt64):
        self.y_hi ^= aad_bits
        self.y_lo ^= text_bits
        self._mul_y_by_h()


@always_inline
def _encrypt_block(
    rk: Pointer[mut=True, UInt32, _, address_space=_], rounds: Int,
    src: Pointer[mut=True, UInt8, _, address_space=_], dst: Pointer[mut=True, UInt8, _, address_space=_]
):
    for i in range(16):
        dst[unsafe_offset=i] = src[unsafe_offset=i]
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
    for i in range(len(iv)):
        iv_buf.append(iv[i])
    gh.update(iv_buf.unsafe_ptr(), len(iv))
    gh.update_lengths(UInt64(0), UInt64(len(iv)) * 8)
    store_64be(j0.unsafe_ptr(), 0, gh.y_hi)
    store_64be(j0.unsafe_ptr(), 8, gh.y_lo)


def _gctr_and_ghash(
    rk: Pointer[mut=True, UInt32, _, address_space=_], rounds: Int,
    j0: InlineArray[UInt8, 16],
    input_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    output_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    length: Int,
    mut gh: _GHash,
    ghash_ciphertext: Bool
):
    var j0_buf = InlineArray[UInt8, 16](fill=0)
    for i in range(16):
        j0_buf[i] = j0[i]
    var full_blocks = length // 16

    var fused = False
    comptime if has_arm_crypto():
        if rounds == 10:
            _arm_gcm_fused_loop[10](
                input_ptr, output_ptr, rk, full_blocks, j0_buf.unsafe_ptr(), gh, ghash_ciphertext
            )
        elif rounds == 12:
            _arm_gcm_fused_loop[12](
                input_ptr, output_ptr, rk, full_blocks, j0_buf.unsafe_ptr(), gh, ghash_ciphertext
            )
        else:
            _arm_gcm_fused_loop[14](
                input_ptr, output_ptr, rk, full_blocks, j0_buf.unsafe_ptr(), gh, ghash_ciphertext
            )
        fused = True

    if not fused:
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
            output_ptr[unsafe_offset=off + i] = input_ptr[unsafe_offset=off + i] ^ ks[i]

    if fused:
        if rem > 0:
            var off = full_blocks * 16
            if ghash_ciphertext:
                gh.update(output_ptr.unsafe_offset(off), rem)
            else:
                gh.update(input_ptr.unsafe_offset(off), rem)
    elif ghash_ciphertext:
        gh.update(output_ptr, length)
    else:
        gh.update(input_ptr, length)


def _gcm_core_keyed(
    rk: Pointer[mut=True, UInt32, _, address_space=_], rounds: Int,
    mut gh: _GHash,
    iv: Span[UInt8, ...], aad: Span[UInt8, ...],
    input_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    output_ptr: Pointer[mut=True, UInt8, _, address_space=_],
    length: Int,
    mut tag: InlineArray[UInt8, 16],
    ghash_ciphertext: Bool
) raises:
    var j0 = InlineArray[UInt8, 16](fill=0)
    _derive_j0(gh.h_hi, gh.h_lo, iv, j0)

    if len(aad) > 0:
        var aad_ptr = aad.unsafe_ptr().unsafe_mut_cast[True]().unsafe_origin_cast[MutAnyOrigin]()
        gh.update(aad_ptr, len(aad))

    _gctr_and_ghash(rk, rounds, j0, input_ptr, output_ptr, length, gh, ghash_ciphertext)
    gh.update_lengths(UInt64(len(aad)) * 8, UInt64(length) * 8)

    var ek_j0 = InlineArray[UInt8, 16](fill=0)
    _encrypt_block(rk, rounds, j0.unsafe_ptr(), ek_j0.unsafe_ptr())
    var t_hi = gh.y_hi ^ load_64be(ek_j0.unsafe_ptr(), 0)
    var t_lo = gh.y_lo ^ load_64be(ek_j0.unsafe_ptr(), 8)
    store_64be(tag.unsafe_ptr(), 0, t_hi)
    store_64be(tag.unsafe_ptr(), 8, t_lo)


struct AESGCMContext(Copyable, Movable):
    """Cache the AES schedule and GHASH powers for repeated operations with one key."""
    var _rk: InlineArray[UInt32, 60]
    var _rounds: Int
    var _gh0: _GHash

    def __init__(out self, key: Span[UInt8, ...]) raises:
        if not _valid_gcm_key(key):
            raise Error("invalid key size")
        self._rounds = 10 if len(key) == 16 else (12 if len(key) == 24 else 14)
        self._rk = InlineArray[UInt32, 60](fill=0)

        var key_buf = InlineArray[UInt8, 32](fill=0)
        for i in range(len(key)):
            key_buf[i] = key[i]
        if len(key) == 16:
            expand_key_128_into(key_buf.unsafe_ptr(), self._rk.unsafe_ptr())
        elif len(key) == 24:
            expand_key_192_into(key_buf.unsafe_ptr(), self._rk.unsafe_ptr())
        else:
            expand_key_256_into(key_buf.unsafe_ptr(), self._rk.unsafe_ptr())
        volatile_wipe(key_buf.unsafe_ptr(), 32)

        var zero_block = InlineArray[UInt8, 16](fill=0)
        var h_block = InlineArray[UInt8, 16](fill=0)
        _encrypt_block(self._rk.unsafe_ptr(), self._rounds, zero_block.unsafe_ptr(), h_block.unsafe_ptr())
        self._gh0 = _GHash(
            load_64be(h_block.unsafe_ptr(), 0), load_64be(h_block.unsafe_ptr(), 8)
        )
        volatile_wipe(h_block.unsafe_ptr(), 16)

    def __deinit__(deinit self):
        volatile_wipe(self._rk.unsafe_ptr(), 60)
        volatile_wipe(Pointer(to=self._gh0).unsafe_bitcast[UInt64](), 20)

    def encrypt(
        self, iv: Span[UInt8, ...], plaintext: Span[UInt8, ...], aad: Span[UInt8, ...]
    ) raises -> Tuple[List[UInt8], List[UInt8]]:
        if len(iv) == 0:
            raise Error("invalid iv size")
        var n = len(plaintext)
        if n > _GCM_MAX_INPUT_BYTES:
            raise Error("plaintext too long for AES-GCM")
        var ciphertext = List[UInt8](unsafe_uninit_length=n)
        var pt_ptr = (
            plaintext.unsafe_ptr().unsafe_mut_cast[True]().unsafe_origin_cast[MutAnyOrigin]()
        )
        var tag = InlineArray[UInt8, 16](fill=0)
        var rk = self._rk.copy()
        var gh = self._gh0.copy()

        try:
            _gcm_core_keyed(
                rk.unsafe_ptr(),
                self._rounds,
                gh,
                iv,
                aad,
                pt_ptr,
                ciphertext.unsafe_ptr(),
                n,
                tag,
                ghash_ciphertext=True,
            )

            var tag_out = List[UInt8](capacity=16)
            for i in range(16):
                tag_out.append(tag[i])
            return (ciphertext^, tag_out^)
        finally:
            volatile_wipe(rk.unsafe_ptr(), 60)
            volatile_wipe(Pointer(to=gh).unsafe_bitcast[UInt64](), 20)
            volatile_wipe(tag.unsafe_ptr(), 16)

    def decrypt(
        self, iv: Span[UInt8, ...], ciphertext: Span[UInt8, ...],
        aad: Span[UInt8, ...], tag: Span[UInt8, ...]
    ) raises -> Tuple[List[UInt8], Bool]:
        if len(iv) == 0:
            raise Error("invalid iv size")
        if len(tag) != 16:
            raise Error("invalid tag size")
        var n = len(ciphertext)
        if n > _GCM_MAX_INPUT_BYTES:
            raise Error("ciphertext too long for AES-GCM")
        var plaintext = List[UInt8](unsafe_uninit_length=n)
        var ct_ptr = (
            ciphertext.unsafe_ptr().unsafe_mut_cast[True]().unsafe_origin_cast[MutAnyOrigin]()
        )
        var computed_tag = InlineArray[UInt8, 16](fill=0)
        var rk = self._rk.copy()
        var gh = self._gh0.copy()

        try:
            _gcm_core_keyed(
                rk.unsafe_ptr(),
                self._rounds,
                gh,
                iv,
                aad,
                ct_ptr,
                plaintext.unsafe_ptr(),
                n,
                computed_tag,
                ghash_ciphertext=False,
            )

            var diff = UInt8(0)
            for i in range(16):
                diff |= computed_tag[i] ^ tag[i]

            if diff != 0:
                var pt_ptr = plaintext.unsafe_ptr()
                for i in range(n):
                    pt_ptr.unsafe_store[volatile=True](i, UInt8(0))
                return (List[UInt8](), False)
            return (plaintext^, True)
        finally:
            volatile_wipe(rk.unsafe_ptr(), 60)
            volatile_wipe(Pointer(to=gh).unsafe_bitcast[UInt64](), 20)
            volatile_wipe(computed_tag.unsafe_ptr(), 16)


def _valid_gcm_key(key: Span[UInt8, ...]) -> Bool:
    return len(key) == 16 or len(key) == 24 or len(key) == 32


def aes_gcm_encrypt(
    key: Span[UInt8, ...], iv: Span[UInt8, ...],
    plaintext: Span[UInt8, ...], aad: Span[UInt8, ...]
) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Encrypt and authenticate, returning (ciphertext, tag) (NIST SP 800-38D, sec. 7.1)."""
    var ctx = AESGCMContext(key)
    return ctx.encrypt(iv, plaintext, aad)


def aes_gcm_decrypt(
    key: Span[UInt8, ...], iv: Span[UInt8, ...],
    ciphertext: Span[UInt8, ...], aad: Span[UInt8, ...], tag: Span[UInt8, ...]
) raises -> Tuple[List[UInt8], Bool]:
    """Authenticate and decrypt, returning (plaintext, valid); failure returns empty plaintext
    (NIST SP 800-38D, sec. 7.2).
    """
    var ctx = AESGCMContext(key)
    return ctx.decrypt(iv, ciphertext, aad, tag)
