# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Libalpm64, Lostlab Technologies.

"""
AES-NI implementation
By Libalpm64 no attribution required.
Work in progress
"""

from std.sys import llvm_intrinsic, CompilationTarget
from std.memory import alloc
from std.utils import StaticTuple
from .aes import cpu_aes_encrypt, expand_key_128, expand_key_192, expand_key_256, SBOX

comptime SIMD16 = SIMD[DType.uint8, 16]


@always_inline
fn _aese(lhs: SIMD16, rhs: SIMD16) -> SIMD16:
    return llvm_intrinsic["llvm.aarch64.crypto.aese", SIMD16, has_side_effect=False](
        lhs, rhs
    )


@always_inline
fn _aesmc(state: SIMD16) -> SIMD16:
    return llvm_intrinsic["llvm.aarch64.crypto.aesmc", SIMD16, has_side_effect=False](
        state
    )


@always_inline
fn has_arm_crypto() -> Bool:
    return CompilationTarget.has_neon()


fn arm_aes_encrypt_128(
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
    
    for i in range(11):
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


fn arm_aes_encrypt_192(
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
    
    for i in range(13):
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


fn arm_aes_encrypt_256(
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
    
    for i in range(15):
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
fn arm_aes_ecb_kernel(
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
    num_blocks: Int,
    rounds: Int
) -> None:
    var i = 0
    while i < num_blocks:
        var block_ptr = input_ptr + i * 16
        var out_ptr = output_ptr + i * 16
        
        if rounds == 10:
            arm_aes_encrypt_128(block_ptr, round_keys)
        elif rounds == 12:
            arm_aes_encrypt_192(block_ptr, round_keys)
        else:
            arm_aes_encrypt_256(block_ptr, round_keys)
        
        for j in range(16):
            out_ptr.store(j, block_ptr.load(j))
        
        i += 1


@always_inline
fn arm_aes_cbc_kernel(
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
    
    var i = 0
    while i < num_blocks:
        var block_ptr = input_ptr + i * 16
        var out_ptr = output_ptr + i * 16
        
        var xored = StaticTuple[UInt8, 16](
            block_ptr[0] ^ prev_block[0], block_ptr[1] ^ prev_block[1],
            block_ptr[2] ^ prev_block[2], block_ptr[3] ^ prev_block[3],
            block_ptr[4] ^ prev_block[4], block_ptr[5] ^ prev_block[5],
            block_ptr[6] ^ prev_block[6], block_ptr[7] ^ prev_block[7],
            block_ptr[8] ^ prev_block[8], block_ptr[9] ^ prev_block[9],
            block_ptr[10] ^ prev_block[10], block_ptr[11] ^ prev_block[11],
            block_ptr[12] ^ prev_block[12], block_ptr[13] ^ prev_block[13],
            block_ptr[14] ^ prev_block[14], block_ptr[15] ^ prev_block[15]
        )
        
        for j in range(16):
            block_ptr.store(j, xored[j])
        
        if rounds == 10:
            arm_aes_encrypt_128(block_ptr, round_keys)
        elif rounds == 12:
            arm_aes_encrypt_192(block_ptr, round_keys)
        else:
            arm_aes_encrypt_256(block_ptr, round_keys)
        
        for j in range(16):
            out_ptr.store(j, block_ptr.load(j))
            prev_block[j] = block_ptr.load(j)
        
        i += 1


@always_inline
fn arm_aes_ctr_kernel(
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
    num_blocks: Int,
    nonce_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    rounds: Int
) -> None:
    var i = 0
    while i < num_blocks:
        var counter = StaticTuple[UInt8, 16](
            nonce_ptr[0], nonce_ptr[1], nonce_ptr[2], nonce_ptr[3],
            nonce_ptr[4], nonce_ptr[5], nonce_ptr[6], nonce_ptr[7],
            nonce_ptr[8], nonce_ptr[9], nonce_ptr[10], nonce_ptr[11],
            nonce_ptr[12], nonce_ptr[13], nonce_ptr[14], nonce_ptr[15]
        )
        
        counter[12] = counter[12] ^ UInt8((i >> 24) & 0xff)
        counter[13] = counter[13] ^ UInt8((i >> 16) & 0xff)
        counter[14] = counter[14] ^ UInt8((i >> 8) & 0xff)
        counter[15] = counter[15] ^ UInt8(i & 0xff)
        
        var temp_block = alloc[UInt8](16)
        for j in range(16):
            temp_block.store(j, counter[j])
        
        if rounds == 10:
            arm_aes_encrypt_128(temp_block, round_keys)
        elif rounds == 12:
            arm_aes_encrypt_192(temp_block, round_keys)
        else:
            arm_aes_encrypt_256(temp_block, round_keys)
        
        var in_block = input_ptr + i * 16
        var out_block = output_ptr + i * 16
        for j in range(16):
            out_block.store(j, in_block.load(j) ^ temp_block.load(j))
        
        temp_block.free()
        i += 1


fn gf_mul2(x: UInt8) -> UInt8:
    var result = x << 1
    var hi_bit = (x >> 7) & 1
    if hi_bit == 1:
        result = result ^ 0x1b
    return result


@always_inline
fn arm_aes_gcm_kernel(
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
    num_blocks: Int,
    nonce_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    rounds: Int
) -> None:
    var counter = StaticTuple[UInt8, 16](
        nonce_ptr[0], nonce_ptr[1], nonce_ptr[2], nonce_ptr[3],
        nonce_ptr[4], nonce_ptr[5], nonce_ptr[6], nonce_ptr[7],
        nonce_ptr[8], nonce_ptr[9], nonce_ptr[10], nonce_ptr[11],
        0, 0, 0, 2
    )
    
    var i = 0
    while i < num_blocks:
        counter[15] = UInt8((2 + i) & 0xff)
        counter[14] = UInt8(((2 + i) >> 8) & 0xff)
        
        var counter_block = alloc[UInt8](16)
        for j in range(16):
            counter_block.store(j, counter[j])
        
        if rounds == 10:
            arm_aes_encrypt_128(counter_block, round_keys)
        elif rounds == 12:
            arm_aes_encrypt_192(counter_block, round_keys)
        else:
            arm_aes_encrypt_256(counter_block, round_keys)
        
        var in_block = input_ptr + i * 16
        var out_block = output_ptr + i * 16
        for j in range(16):
            out_block.store(j, in_block.load(j) ^ counter_block.load(j))
        
        counter_block.free()
        i += 1


fn gf_mul2_xts(val: UInt8) -> UInt8:
    var result = val << 1
    if (val & 0x80) != 0:
        result = result ^ 0x87
    return result


fn compute_xts_tweak(tweak_bytes: List[UInt8]) -> List[UInt8]:
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


fn compute_xts_tweak_list(tweak_ptr: UnsafePointer[UInt8, MutAnyOrigin]) -> List[UInt8]:
    var result = List[UInt8](capacity=16)
    for i in range(16):
        result.append(tweak_ptr.load(i))
    
    var carry = False
    for i in range(16):
        var new_carry = (result[i] & 0x80) != 0
        result[i] = gf_mul2_xts(result[i])
        if carry:
            result[i] = result[i] ^ 1
        carry = new_carry
    
    return result^


@always_inline
fn arm_aes_xts_kernel(
    input_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys1: UnsafePointer[UInt32, MutAnyOrigin],
    round_keys2: UnsafePointer[UInt32, MutAnyOrigin],
    num_blocks: Int,
    tweak_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    rounds: Int
) -> None:
    var tweak = alloc[UInt8](16)
    for j in range(16):
        tweak.store(j, tweak_ptr[j])
    
    if rounds == 10:
        arm_aes_encrypt_128(tweak, round_keys2)
    else:
        arm_aes_encrypt_256(tweak, round_keys2)
    
    var i = 0
    while i < num_blocks:
        var in_block = input_ptr + i * 16
        var out_block = output_ptr + i * 16
        
        var xored = alloc[UInt8](16)
        for j in range(16):
            xored.store(j, in_block.load(j) ^ tweak.load(j))
        
        if rounds == 10:
            arm_aes_encrypt_128(xored, round_keys1)
        else:
            arm_aes_encrypt_256(xored, round_keys1)
        
        for j in range(16):
            out_block.store(j, xored.load(j) ^ tweak.load(j))
        
        xored.free()
        
        var next_tweak = compute_xts_tweak_list(tweak)
        for j in range(16):
            tweak.store(j, next_tweak[j])
        
        i += 1
    
    tweak.free()


@always_inline
fn aes_encrypt(
    pt: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys: UnsafePointer[UInt32, MutAnyOrigin],
    rounds: Int = 10
) -> None:
    """Unified AES encryption function.
    
    Uses ARM Crypto Extensions on supported hardware, falls back to
    software implementation otherwise.
    """
    if has_arm_crypto():
        if rounds == 10:
            arm_aes_encrypt_128(pt, round_keys)
        elif rounds == 12:
            arm_aes_encrypt_192(pt, round_keys)
        else:
            arm_aes_encrypt_256(pt, round_keys)
    else:
        cpu_aes_encrypt(pt, round_keys, rounds)


@always_inline
fn has_aes_ni() -> Bool:
    return has_arm_crypto()
