"""
AES-GPU implementation
"""

from std.gpu import global_idx
from std.memory import stack_allocation
from std.memory.unsafe_pointer import UnsafePointer
from .aes import _ct_encrypt_blocks

@always_inline
def add_counter_offset(counter: UnsafePointer[UInt8, MutAnyOrigin], offset: Int) -> None:
    var carry = offset
    for i in range(15, -1, -1):
        if carry == 0:
            break
        var old = counter[i]
        var addend = UInt8(carry & 0xff)
        var new_val = old + addend
        counter[i] = new_val
        carry = carry >> 8
        if new_val < old:
            carry += 1

@always_inline
def _gcm_counter_from_j0(
    j0: UnsafePointer[UInt8, MutAnyOrigin],
    block_index: Int,
    counter: UnsafePointer[UInt8, MutAnyOrigin],
) -> None:
    for i in range(12):
        counter[i] = j0[i]
    var base = (
        (UInt32(j0[12]) << 24) | (UInt32(j0[13]) << 16)
        | (UInt32(j0[14]) << 8) | UInt32(j0[15])
    )
    var ctr = base + UInt32(1) + UInt32(block_index & 0xFFFFFFFF)
    counter[12] = UInt8((ctr >> 24) & 0xFF)
    counter[13] = UInt8((ctr >> 16) & 0xFF)
    counter[14] = UInt8((ctr >> 8) & 0xFF)
    counter[15] = UInt8(ctr & 0xFF)

@always_inline
def aes_gpu_kernel_ecb(
    input_data: UnsafePointer[UInt8, MutAnyOrigin],
    output_data: UnsafePointer[UInt8, MutAnyOrigin],
    skey: UnsafePointer[UInt64, MutAnyOrigin],
    n: Int,
    rounds: Int,
) -> None:
    var tid = global_idx.x
    var base_block = Int(tid) * 4
    if base_block >= n:
        return
    var buf = stack_allocation[64, UInt8]()
    for k in range(4):
        var b = base_block + k
        if b >= n:
            b = base_block
        for j in range(16):
            buf[k * 16 + j] = input_data[b * 16 + j]
    _ct_encrypt_blocks[1](buf, skey, rounds)
    for k in range(4):
        var blk = base_block + k
        if blk < n:
            for j in range(16):
                output_data[blk * 16 + j] = buf[k * 16 + j]

@always_inline
def aes_gpu_kernel_ctr(
    input_data: UnsafePointer[UInt8, MutAnyOrigin],
    output_data: UnsafePointer[UInt8, MutAnyOrigin],
    skey: UnsafePointer[UInt64, MutAnyOrigin],
    n: Int,
    nonce: UnsafePointer[UInt8, MutAnyOrigin],
    rounds: Int,
) -> None:
    var tid = global_idx.x
    var base_block = Int(tid) * 4
    if base_block >= n:
        return
    var buf = stack_allocation[64, UInt8]()
    for k in range(4):
        var b = base_block + k
        if b >= n:
            b = base_block
        var dst = buf + k * 16
        for j in range(16):
            dst[j] = nonce[j]
        add_counter_offset(dst, b)
    _ct_encrypt_blocks[1](buf, skey, rounds)
    for k in range(4):
        var blk = base_block + k
        if blk < n:
            var bp = input_data + blk * 16
            var op = output_data + blk * 16
            for j in range(16):
                op[j] = bp[j] ^ buf[k * 16 + j]

@always_inline
def aes_gpu_kernel_gcm_ctr(
    input_data: UnsafePointer[UInt8, MutAnyOrigin],
    output_data: UnsafePointer[UInt8, MutAnyOrigin],
    skey: UnsafePointer[UInt64, MutAnyOrigin],
    n: Int,
    j0: UnsafePointer[UInt8, MutAnyOrigin],
    rounds: Int,
) -> None:
    var tid = global_idx.x
    var base_block = Int(tid) * 4
    if base_block >= n:
        return
    var buf = stack_allocation[64, UInt8]()
    for k in range(4):
        var b = base_block + k
        if b >= n:
            b = base_block
        _gcm_counter_from_j0(j0, b, buf + k * 16)
    _ct_encrypt_blocks[1](buf, skey, rounds)
    for k in range(4):
        var blk = base_block + k
        if blk < n:
            var bp = input_data + blk * 16
            var op = output_data + blk * 16
            for j in range(16):
                op[j] = bp[j] ^ buf[k * 16 + j]
