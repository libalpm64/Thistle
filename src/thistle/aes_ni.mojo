"""
AES-NI implementation
"""

from std.collections import List
from std.sys import llvm_intrinsic, CompilationTarget
from std.memory import alloc, bitcast, memset_zero, memcpy, UnsafePointer
from std.utils import StaticTuple
from .aes import cpu_aes_encrypt, expand_key_128, expand_key_192, expand_key_256, SBOX
from .utils import StackBuffer

comptime SIMD16 = SIMD[DType.uint8, 16]
comptime SIMD128 = SIMD[DType.uint64, 2]

@always_inline
def _aese(lhs: SIMD16, rhs: SIMD16) -> SIMD16:
    comptime if CompilationTarget._has_feature["crypto"]() or CompilationTarget._has_feature["aes"]():
        return llvm_intrinsic["llvm.aarch64.crypto.aese", SIMD16, has_side_effect=False](
            lhs, rhs
        )
    else:
        return SIMD16(0)

@always_inline
def _aesmc(state: SIMD16) -> SIMD16:
    comptime if CompilationTarget._has_feature["crypto"]() or CompilationTarget._has_feature["aes"]():
        return llvm_intrinsic["llvm.aarch64.crypto.aesmc", SIMD16, has_side_effect=False](
            state
        )
    else:
        return SIMD16(0)

@always_inline
def has_arm_crypto() -> Bool:
    return CompilationTarget._has_feature["crypto"]() or CompilationTarget._has_feature["aes"]()

@always_inline
def _mm_aesenc_si128(lhs: SIMD128, rhs: SIMD128) -> SIMD128:
    comptime if CompilationTarget._has_feature["sse"]() and CompilationTarget._has_feature["aes"]():
        return llvm_intrinsic["llvm.x86.aesni.aesenc", SIMD128, has_side_effect=False](
            lhs, rhs
        )
    else:
        return SIMD128(0)

@always_inline
def _mm_aesenclast_si128(lhs: SIMD128, rhs: SIMD128) -> SIMD128:
    comptime if CompilationTarget._has_feature["sse"]() and CompilationTarget._has_feature["aes"]():
        return llvm_intrinsic["llvm.x86.aesni.aesenclast", SIMD128, has_side_effect=False](
            lhs, rhs
        )
    else:
        return SIMD128(0)

@always_inline
def _mm_aeskeygenassist_si128(v: SIMD128, imm8: Int) -> SIMD128:
    comptime if CompilationTarget._has_feature["sse"]() and CompilationTarget._has_feature["aes"]():
        return llvm_intrinsic[
            "llvm.x86.aesni.aeskeygenassist",
            SIMD128,
            has_side_effect=False,
        ](v, imm8)
    else:
        return SIMD128(0)

@always_inline
def has_x86_aes_ni() -> Bool:
    return CompilationTarget._has_feature["sse"]() and CompilationTarget._has_feature["aes"]()


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


def arm_aes_encrypt_128(
    pt: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin]
) -> None:
    var state = SIMD16(
        pt.load(0), pt.load(1), pt.load(2), pt.load(3),
        pt.load(4), pt.load(5), pt.load(6), pt.load(7),
        pt.load(8), pt.load(9), pt.load(10), pt.load(11),
        pt.load(12), pt.load(13), pt.load(14), pt.load(15)
    )
    
    var keys = StaticTuple[SIMD16, 11](
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    )
    
    comptime for i in range(11):
        var w0 = round_keys.load(i * 4)
        var w1 = round_keys.load(i * 4 + 1)
        var w2 = round_keys.load(i * 4 + 2)
        var w3 = round_keys.load(i * 4 + 3)
        
        var key = SIMD16(
            UInt8((w0 >> 24) & 0xff), UInt8((w0 >> 16) & 0xff),
            UInt8((w0 >> 8) & 0xff), UInt8(w0 & 0xff),
            UInt8((w1 >> 24) & 0xff), UInt8((w1 >> 16) & 0xff),
            UInt8((w1 >> 8) & 0xff), UInt8(w1 & 0xff),
            UInt8((w2 >> 24) & 0xff), UInt8((w2 >> 16) & 0xff),
            UInt8((w2 >> 8) & 0xff), UInt8(w2 & 0xff),
            UInt8((w3 >> 24) & 0xff), UInt8((w3 >> 16) & 0xff),
            UInt8((w3 >> 8) & 0xff), UInt8(w3 & 0xff)
        )
        keys[i] = key
    
    var result = state
    result = _aese(result, keys[0])
    result = _aesmc(result)
    
    result = _aese(result, keys[1])
    result = _aesmc(result)
    result = _aese(result, keys[2])
    result = _aesmc(result)
    result = _aese(result, keys[3])
    result = _aesmc(result)
    result = _aese(result, keys[4])
    result = _aesmc(result)
    result = _aese(result, keys[5])
    result = _aesmc(result)
    result = _aese(result, keys[6])
    result = _aesmc(result)
    result = _aese(result, keys[7])
    result = _aesmc(result)
    result = _aese(result, keys[8])
    result = _aesmc(result)
    result = _aese(result, keys[9])
    result = result ^ keys[10]
    
    pt.store(0, result[0])
    pt.store(1, result[1])
    pt.store(2, result[2])
    pt.store(3, result[3])
    pt.store(4, result[4])
    pt.store(5, result[5])
    pt.store(6, result[6])
    pt.store(7, result[7])
    pt.store(8, result[8])
    pt.store(9, result[9])
    pt.store(10, result[10])
    pt.store(11, result[11])
    pt.store(12, result[12])
    pt.store(13, result[13])
    pt.store(14, result[14])
    pt.store(15, result[15])


def arm_aes_encrypt_192(
    pt: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin]
) -> None:
    var state = SIMD16(
        pt.load(0), pt.load(1), pt.load(2), pt.load(3),
        pt.load(4), pt.load(5), pt.load(6), pt.load(7),
        pt.load(8), pt.load(9), pt.load(10), pt.load(11),
        pt.load(12), pt.load(13), pt.load(14), pt.load(15)
    )
    
    var keys = StaticTuple[SIMD16, 13](
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    )
    
    comptime for i in range(13):
        var w0 = round_keys.load(i * 4)
        var w1 = round_keys.load(i * 4 + 1)
        var w2 = round_keys.load(i * 4 + 2)
        var w3 = round_keys.load(i * 4 + 3)
        
        var key = SIMD16(
            UInt8((w0 >> 24) & 0xff), UInt8((w0 >> 16) & 0xff),
            UInt8((w0 >> 8) & 0xff), UInt8(w0 & 0xff),
            UInt8((w1 >> 24) & 0xff), UInt8((w1 >> 16) & 0xff),
            UInt8((w1 >> 8) & 0xff), UInt8(w1 & 0xff),
            UInt8((w2 >> 24) & 0xff), UInt8((w2 >> 16) & 0xff),
            UInt8((w2 >> 8) & 0xff), UInt8(w2 & 0xff),
            UInt8((w3 >> 24) & 0xff), UInt8((w3 >> 16) & 0xff),
            UInt8((w3 >> 8) & 0xff), UInt8(w3 & 0xff)
        )
        keys[i] = key
    
    var result = state
    result = _aese(result, keys[0])
    result = _aesmc(result)
    
    result = _aese(result, keys[1])
    result = _aesmc(result)
    result = _aese(result, keys[2])
    result = _aesmc(result)
    result = _aese(result, keys[3])
    result = _aesmc(result)
    result = _aese(result, keys[4])
    result = _aesmc(result)
    result = _aese(result, keys[5])
    result = _aesmc(result)
    result = _aese(result, keys[6])
    result = _aesmc(result)
    result = _aese(result, keys[7])
    result = _aesmc(result)
    result = _aese(result, keys[8])
    result = _aesmc(result)
    result = _aese(result, keys[9])
    result = _aesmc(result)
    result = _aese(result, keys[10])
    result = _aesmc(result)
    result = _aese(result, keys[11])
    result = result ^ keys[12]
    
    pt.store(0, result[0])
    pt.store(1, result[1])
    pt.store(2, result[2])
    pt.store(3, result[3])
    pt.store(4, result[4])
    pt.store(5, result[5])
    pt.store(6, result[6])
    pt.store(7, result[7])
    pt.store(8, result[8])
    pt.store(9, result[9])
    pt.store(10, result[10])
    pt.store(11, result[11])
    pt.store(12, result[12])
    pt.store(13, result[13])
    pt.store(14, result[14])
    pt.store(15, result[15])

def arm_aes_encrypt_256(
    pt: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin]
) -> None:
    var state = SIMD16(
        pt.load(0), pt.load(1), pt.load(2), pt.load(3),
        pt.load(4), pt.load(5), pt.load(6), pt.load(7),
        pt.load(8), pt.load(9), pt.load(10), pt.load(11),
        pt.load(12), pt.load(13), pt.load(14), pt.load(15)
    )
    
    var keys = StaticTuple[SIMD16, 15](
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        SIMD16(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    )
    
    comptime for i in range(15):
        var w0 = round_keys.load(i * 4)
        var w1 = round_keys.load(i * 4 + 1)
        var w2 = round_keys.load(i * 4 + 2)
        var w3 = round_keys.load(i * 4 + 3)
        
        var key = SIMD16(
            UInt8((w0 >> 24) & 0xff), UInt8((w0 >> 16) & 0xff),
            UInt8((w0 >> 8) & 0xff), UInt8(w0 & 0xff),
            UInt8((w1 >> 24) & 0xff), UInt8((w1 >> 16) & 0xff),
            UInt8((w1 >> 8) & 0xff), UInt8(w1 & 0xff),
            UInt8((w2 >> 24) & 0xff), UInt8((w2 >> 16) & 0xff),
            UInt8((w2 >> 8) & 0xff), UInt8(w2 & 0xff),
            UInt8((w3 >> 24) & 0xff), UInt8((w3 >> 16) & 0xff),
            UInt8((w3 >> 8) & 0xff), UInt8(w3 & 0xff)
        )
        keys[i] = key
    
    var result = state
    result = _aese(result, keys[0])
    result = _aesmc(result)
    
    result = _aese(result, keys[1])
    result = _aesmc(result)
    result = _aese(result, keys[2])
    result = _aesmc(result)
    result = _aese(result, keys[3])
    result = _aesmc(result)
    result = _aese(result, keys[4])
    result = _aesmc(result)
    result = _aese(result, keys[5])
    result = _aesmc(result)
    result = _aese(result, keys[6])
    result = _aesmc(result)
    result = _aese(result, keys[7])
    result = _aesmc(result)
    result = _aese(result, keys[8])
    result = _aesmc(result)
    result = _aese(result, keys[9])
    result = _aesmc(result)
    result = _aese(result, keys[10])
    result = _aesmc(result)
    result = _aese(result, keys[11])
    result = _aesmc(result)
    result = _aese(result, keys[12])
    result = _aesmc(result)
    result = _aese(result, keys[13])
    result = result ^ keys[14]
    
    pt.store(0, result[0])
    pt.store(1, result[1])
    pt.store(2, result[2])
    pt.store(3, result[3])
    pt.store(4, result[4])
    pt.store(5, result[5])
    pt.store(6, result[6])
    pt.store(7, result[7])
    pt.store(8, result[8])
    pt.store(9, result[9])
    pt.store(10, result[10])
    pt.store(11, result[11])
    pt.store(12, result[12])
    pt.store(13, result[13])
    pt.store(14, result[14])
    pt.store(15, result[15])

@always_inline
def arm_aes_ecb_kernel(
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
    num_blocks: Int,
    rounds: Int
) -> None:
    var temp_block = StackBuffer[UInt8, 16]()
    var tp = temp_block.ptr()

    var i = 0
    while i < num_blocks:
        var block_ptr = input_ptr + i * 16
        var out_ptr = output_ptr + i * 16

        for j in range(16):
            tp.store(j, block_ptr.load(j))

        if rounds == 10:
            arm_aes_encrypt_128(tp, round_keys)
        elif rounds == 12:
            arm_aes_encrypt_192(tp, round_keys)
        else:
            arm_aes_encrypt_256(tp, round_keys)

        for j in range(16):
            out_ptr.store(j, tp.load(j))

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
    var prev_block = StaticTuple[UInt8, 16](
        iv_ptr[0], iv_ptr[1], iv_ptr[2], iv_ptr[3],
        iv_ptr[4], iv_ptr[5], iv_ptr[6], iv_ptr[7],
        iv_ptr[8], iv_ptr[9], iv_ptr[10], iv_ptr[11],
        iv_ptr[12], iv_ptr[13], iv_ptr[14], iv_ptr[15]
    )
    var temp_block = StackBuffer[UInt8, 16]()
    var tp = temp_block.ptr()

    var i = 0
    while i < num_blocks:
        var block_ptr = input_ptr + i * 16
        var out_ptr = output_ptr + i * 16

        for j in range(16):
            tp.store(j, block_ptr.load(j) ^ prev_block[j])

        if rounds == 10:
            arm_aes_encrypt_128(tp, round_keys)
        elif rounds == 12:
            arm_aes_encrypt_192(tp, round_keys)
        else:
            arm_aes_encrypt_256(tp, round_keys)

        for j in range(16):
            var c = tp.load(j)
            out_ptr.store(j, c)
            prev_block[j] = c

        i += 1

def gf_mul2_xts(val: UInt8) -> UInt8:
    var result = val << 1
    if (val & 0x80) != 0:
        result = result ^ 0x87
    return result

def compute_xts_tweak(tweak_bytes: List[UInt8]) -> List[UInt8]:
    var result = List[UInt8](capacity=16)
    for i in range(16):
        result.append(tweak_bytes[i])
    
    var carry = False
    for i in range(16):
        var new_carry = (result[i] & 0x80) != 0
        result[i] = gf_mul2_xts(result[i])
        if carry:
            result[i] = result[i] ^ 1
        carry = new_carry
    
    return result^

def compute_xts_tweak_list(tweak_ptr: UnsafePointer[UInt8, MutAnyOrigin]) -> StackBuffer[UInt8, 16]:
    var result = StackBuffer[UInt8, 16]()
    var carry = UInt8(0)

    for i in range(16):
        var b = tweak_ptr.load(i)
        var next_carry = b >> 7
        result[i] = (b << 1) | carry
        carry = next_carry

    if carry != 0:
        result[0] = result[0] ^ 0x87

    return result

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
    var tweak = StackBuffer[UInt8, 16]()
    var tp = tweak.ptr()
    for j in range(16):
        tp.store(j, tweak_ptr[j])
    
    if rounds == 10:
        arm_aes_encrypt_128(tp, round_keys2)
    else:
        arm_aes_encrypt_256(tp, round_keys2)
    
    var i = 0
    while i < num_blocks:
        var in_block = input_ptr + i * 16
        var out_block = output_ptr + i * 16
        
        var xored = StackBuffer[UInt8, 16]()
        var xp = xored.ptr()
        for j in range(16):
            xp.store(j, in_block.load(j) ^ tp.load(j))
        
        if rounds == 10:
            arm_aes_encrypt_128(xp, round_keys1)
        else:
            arm_aes_encrypt_256(xp, round_keys1)
        
        for j in range(16):
            out_block.store(j, xp.load(j) ^ tp.load(j))
        
        var next_tweak = compute_xts_tweak_list(tp)
        for j in range(16):
            tp.store(j, next_tweak[j])
        
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
    aes_encrypt(dst, rk, rounds)


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
