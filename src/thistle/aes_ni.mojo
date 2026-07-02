"""
AES-NI implementation
"""

from std.sys import llvm_intrinsic, CompilationTarget
from std.memory import alloc, bitcast
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
def _write_counter_be32(
    counter_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    nonce_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    block_index: Int,
) -> None:
    for j in range(16):
        counter_ptr.store(j, nonce_ptr.load(j))

    var carry = block_index
    var pos = 15
    while pos >= 12:
        var sum = Int(counter_ptr.load(pos)) + (carry & 0xFF)
        counter_ptr.store(pos, UInt8(sum & 0xFF))
        carry = (carry >> 8) + (sum >> 8)
        pos -= 1

@always_inline
def _write_gcm_counter(
    counter_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    nonce_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    block_index: Int,
) -> None:
    for j in range(12):
        counter_ptr.store(j, nonce_ptr.load(j))
    counter_ptr.store(12, 0)
    counter_ptr.store(13, 0)
    counter_ptr.store(14, 0)
    counter_ptr.store(15, 0)

    var carry = block_index + 2
    var pos = 15
    while pos >= 12:
        counter_ptr.store(pos, UInt8(carry & 0xFF))
        carry = carry >> 8
        pos -= 1

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

@always_inline
def arm_aes_ctr_kernel(
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
    num_blocks: Int,
    nonce_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    rounds: Int
) -> None:
    var counter_block = StackBuffer[UInt8, 16]()
    var tp = counter_block.ptr()

    var i = 0
    while i < num_blocks:
        _write_counter_be32(tp, nonce_ptr, i)

        if rounds == 10:
            arm_aes_encrypt_128(tp, round_keys)
        elif rounds == 12:
            arm_aes_encrypt_192(tp, round_keys)
        else:
            arm_aes_encrypt_256(tp, round_keys)

        var in_block = input_ptr + i * 16
        var out_block = output_ptr + i * 16
        for j in range(16):
            out_block.store(j, in_block.load(j) ^ tp.load(j))

        i += 1

def gf_mul2(x: UInt8) -> UInt8:
    var result = x << 1
    var hi_bit = (x >> 7) & 1
    if hi_bit == 1:
        result = result ^ 0x1b
    return result

@always_inline
def arm_aes_gcm_kernel(
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
    num_blocks: Int,
    nonce_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    rounds: Int
) -> None:
    var counter_block = StackBuffer[UInt8, 16]()
    var cp = counter_block.ptr()

    var i = 0
    while i < num_blocks:
        _write_gcm_counter(cp, nonce_ptr, i)

        if rounds == 10:
            arm_aes_encrypt_128(cp, round_keys)
        elif rounds == 12:
            arm_aes_encrypt_192(cp, round_keys)
        else:
            arm_aes_encrypt_256(cp, round_keys)

        var in_block = input_ptr + i * 16
        var out_block = output_ptr + i * 16
        for j in range(16):
            out_block.store(j, in_block.load(j) ^ cp.load(j))

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
def x86_aes_ctr_kernel(
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
    num_blocks: Int,
    nonce_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    rounds: Int
) -> None:
    var counter_block = StackBuffer[UInt8, 16]()
    var cp = counter_block.ptr()

    var i = 0
    while i < num_blocks:
        _write_counter_be32(cp, nonce_ptr, i)
        var counter = _mm_loadu_si128(cp)

        if rounds == 10:
            x86_aes_encrypt_128_direct(counter, round_keys)
        elif rounds == 12:
            x86_aes_encrypt_192_direct(counter, round_keys)
        else:
            x86_aes_encrypt_256_direct(counter, round_keys)

        var in_block = _mm_loadu_si128(input_ptr + i * 16)
        var result = in_block ^ counter
        _mm_storeu_si128(output_ptr + i * 16, result)

        i += 1

@always_inline
def x86_aes_gcm_kernel(
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
    num_blocks: Int,
    nonce_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    rounds: Int
) -> None:
    var counter_block = StackBuffer[UInt8, 16]()
    var cp = counter_block.ptr()

    var i = 0
    while i < num_blocks:
        _write_gcm_counter(cp, nonce_ptr, i)
        var counter = _mm_loadu_si128(cp)

        if rounds == 10:
            x86_aes_encrypt_128_direct(counter, round_keys)
        elif rounds == 12:
            x86_aes_encrypt_192_direct(counter, round_keys)
        else:
            x86_aes_encrypt_256_direct(counter, round_keys)

        var in_block = _mm_loadu_si128(input_ptr + i * 16)
        var result = in_block ^ counter
        _mm_storeu_si128(output_ptr + i * 16, result)

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
def has_aes_ni() -> Bool:
    return has_x86_aes_ni() or has_arm_crypto()
