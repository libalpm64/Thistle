"""GPU AES kernels (FIPS 197), with ECB/CTR (NIST SP 800-38A) and the GCM counter stage (NIST SP
800-38D).
"""

from std.gpu import global_idx
from std.memory import stack_allocation
from std.memory.unsafe_pointer import Pointer
from .aes import _ct_encrypt_blocks
from .aes_ni import _write_gcm_counter


@always_inline
def add_counter_offset(counter: Pointer[mut=True, UInt8, _, address_space=_], offset: Int) -> None:
    var carry = offset
    for i in range(15, -1, -1):
        if carry == 0:
            break
        var old = counter[unsafe_offset=i]
        var addend = UInt8(carry & 0xff)
        var new_val = old + addend
        counter[unsafe_offset=i] = new_val
        carry = carry >> 8
        if new_val < old:
            carry += 1


@always_inline
def _gcm_counter_from_j0(
    j0: Pointer[mut=True, UInt8, _, address_space=_],
    block_index: Int,
    counter: Pointer[mut=True, UInt8, _, address_space=_]
) -> None:
    _write_gcm_counter(counter, j0, block_index)


@always_inline
def aes_gpu_kernel_ecb(
    input_data: Pointer[mut=True, UInt8, MutUntrackedOrigin],
    output_data: Pointer[mut=True, UInt8, MutUntrackedOrigin],
    skey: Pointer[mut=True, UInt64, MutUntrackedOrigin],
    n: Int32,
    rounds: Int32
) -> None:
    """Encrypt ECB blocks into output_data, with four bitsliced blocks per GPU thread (NIST SP
    800-38A, sec. 6.1).
    """
    if n <= 0 or (rounds != 10 and rounds != 12 and rounds != 14):
        return
    var tid = global_idx.x
    var base_block = Int(tid) * 4
    var num_blocks = Int(n)
    if base_block >= num_blocks:
        return
    var buf = stack_allocation[64, UInt8]()
    for k in range(4):
        var b = base_block + k
        if b >= num_blocks:
            b = base_block
        for j in range(16):
            buf[unsafe_offset=k * 16 + j] = input_data[unsafe_offset=b * 16 + j]
    _ct_encrypt_blocks[1](buf, skey, Int(rounds))
    for k in range(4):
        var blk = base_block + k
        if blk < num_blocks:
            for j in range(16):
                output_data[unsafe_offset=blk * 16 + j] = buf[unsafe_offset=k * 16 + j]


@always_inline
def aes_gpu_kernel_ctr(
    input_data: Pointer[mut=True, UInt8, MutUntrackedOrigin],
    output_data: Pointer[mut=True, UInt8, MutUntrackedOrigin],
    skey: Pointer[mut=True, UInt64, MutUntrackedOrigin],
    n: Int32,
    nonce: Pointer[mut=True, UInt8, MutUntrackedOrigin],
    rounds: Int32
) -> None:
    """XOR input with CTR keystream into output_data, with four blocks per GPU thread (NIST SP
    800-38A, sec. 6.5).
    """
    if n <= 0 or (rounds != 10 and rounds != 12 and rounds != 14):
        return
    var tid = global_idx.x
    var base_block = Int(tid) * 4
    var num_blocks = Int(n)
    if base_block >= num_blocks:
        return
    var buf = stack_allocation[64, UInt8]()
    for k in range(4):
        var b = base_block + k
        if b >= num_blocks:
            b = base_block
        var dst = buf.unsafe_offset(k * 16)
        for j in range(16):
            dst[unsafe_offset=j] = nonce[unsafe_offset=j]
        add_counter_offset(dst, b)
    _ct_encrypt_blocks[1](buf, skey, Int(rounds))
    for k in range(4):
        var blk = base_block + k
        if blk < num_blocks:
            var bp = input_data.unsafe_offset(blk * 16)
            var op = output_data.unsafe_offset(blk * 16)
            for j in range(16):
                op[unsafe_offset=j] = bp[unsafe_offset=j] ^ buf[unsafe_offset=k * 16 + j]


@always_inline
def aes_gpu_kernel_gcm_ctr(
    input_data: Pointer[mut=True, UInt8, MutUntrackedOrigin],
    output_data: Pointer[mut=True, UInt8, MutUntrackedOrigin],
    skey: Pointer[mut=True, UInt64, MutUntrackedOrigin],
    n: Int32,
    j0: Pointer[mut=True, UInt8, MutUntrackedOrigin],
    rounds: Int32
) -> None:
    """Apply GCTR from inc32(J0) (NIST SP 800-38D, secs. 6.5 and 7.1); this kernel does not
    authenticate data.
    """
    if n <= 0 or (rounds != 10 and rounds != 12 and rounds != 14):
        return
    var tid = global_idx.x
    var base_block = Int(tid) * 4
    var num_blocks = Int(n)
    if base_block >= num_blocks:
        return
    var buf = stack_allocation[64, UInt8]()
    for k in range(4):
        var b = base_block + k
        if b >= num_blocks:
            b = base_block
        _gcm_counter_from_j0(j0, b, buf.unsafe_offset(k * 16))
    _ct_encrypt_blocks[1](buf, skey, Int(rounds))
    for k in range(4):
        var blk = base_block + k
        if blk < num_blocks:
            var bp = input_data.unsafe_offset(blk * 16)
            var op = output_data.unsafe_offset(blk * 16)
            for j in range(16):
                op[unsafe_offset=j] = bp[unsafe_offset=j] ^ buf[unsafe_offset=k * 16 + j]
