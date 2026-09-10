"""GPU AES kernels (FIPS 197), with ECB/CTR (NIST SP 800-38A) and the GCM counter stage (NIST SP
800-38D).
"""

from std.bit import byte_swap
from std.collections import InlineArray
from std.gpu import global_idx
from std.memory.unsafe_pointer import Pointer
from .aes import (
    _ct_encrypt_state,
    _ct_interleave_in,
    _ct_interleave_out,
    _ct_le32,
    _ct_store_le32,
)

comptime _GPUWord = SIMD[DType.uint64, 1]
comptime _GPUState = InlineArray[_GPUWord, 8]


@always_inline
def _pack_block(
    w0: UInt64, w1: UInt64, w2: UInt64, w3: UInt64
) -> Tuple[_GPUWord, _GPUWord]:
    return _ct_interleave_in[1](
        _GPUWord(w0), _GPUWord(w1), _GPUWord(w2), _GPUWord(w3)
    )


@always_inline
def _load_block(
    data: Pointer[mut=True, UInt8, _, address_space=_], block: Int
) -> Tuple[_GPUWord, _GPUWord]:
    var base = block * 16
    return _pack_block(
        _ct_le32(data, base),
        _ct_le32(data, base + 4),
        _ct_le32(data, base + 8),
        _ct_le32(data, base + 12),
    )


@always_inline
def _store_block(
    data: Pointer[mut=True, UInt8, _, address_space=_],
    block: Int,
    a: _GPUWord,
    b: _GPUWord,
) -> None:
    var base = block * 16
    var w = _ct_interleave_out[1](a, b)
    _ct_store_le32(data, base, UInt64(w[0]))
    _ct_store_le32(data, base + 4, UInt64(w[1]))
    _ct_store_le32(data, base + 8, UInt64(w[2]))
    _ct_store_le32(data, base + 12, UInt64(w[3]))


@always_inline
def _xor_block(
    input_data: Pointer[mut=True, UInt8, _, address_space=_],
    output_data: Pointer[mut=True, UInt8, _, address_space=_],
    block: Int,
    a: _GPUWord,
    b: _GPUWord,
) -> None:
    var base = block * 16
    var w = _ct_interleave_out[1](a, b)
    _ct_store_le32(output_data, base, _ct_le32(input_data, base) ^ UInt64(w[0]))
    _ct_store_le32(
        output_data, base + 4, _ct_le32(input_data, base + 4) ^ UInt64(w[1])
    )
    _ct_store_le32(
        output_data, base + 8, _ct_le32(input_data, base + 8) ^ UInt64(w[2])
    )
    _ct_store_le32(
        output_data, base + 12, _ct_le32(input_data, base + 12) ^ UInt64(w[3])
    )


@always_inline
def aes_gpu_kernel_ecb(
    input_data: Pointer[mut=True, UInt8, MutUntrackedOrigin],
    output_data: Pointer[mut=True, UInt8, MutUntrackedOrigin],
    skey: Pointer[mut=True, UInt64, MutUntrackedOrigin],
    n: Int32,
    rounds: Int32,
) -> None:
    """Encrypt ECB blocks into output_data, with four bitsliced blocks per GPU thread."""
    if n <= 0 or (rounds != 10 and rounds != 12 and rounds != 14):
        return
    var num_blocks = Int(n)
    var groups = (num_blocks + 3) // 4
    var group = Int(global_idx.x)
    if group >= groups:
        return

    # Stride each thread's four blocks by the group count so adjacent GPU
    # threads access adjacent blocks at each lane.
    var q = _GPUState(fill=0)
    for k in range(4):
        var block = group + k * groups
        if block >= num_blocks:
            block = group
        var pair = _load_block(input_data, block)
        q[k] = pair[0]
        q[k + 4] = pair[1]
    _ct_encrypt_state[1](q, skey, Int(rounds))
    for k in range(4):
        var block = group + k * groups
        if block < num_blocks:
            _store_block(output_data, block, q[k], q[k + 4])


@always_inline
def aes_gpu_kernel_ctr(
    input_data: Pointer[mut=True, UInt8, MutUntrackedOrigin],
    output_data: Pointer[mut=True, UInt8, MutUntrackedOrigin],
    skey: Pointer[mut=True, UInt64, MutUntrackedOrigin],
    n: Int32,
    nonce: Pointer[mut=True, UInt8, MutUntrackedOrigin],
    rounds: Int32,
) -> None:
    """XOR input with CTR keystream into output_data, with four blocks per GPU thread."""
    if n <= 0 or (rounds != 10 and rounds != 12 and rounds != 14):
        return
    var num_blocks = Int(n)
    var groups = (num_blocks + 3) // 4
    var group = Int(global_idx.x)
    if group >= groups:
        return

    # Represent the big-endian 128-bit counter as two words and add each public
    # block index directly in registers.
    var n0 = UInt32(_ct_le32(nonce, 0))
    var n1 = UInt32(_ct_le32(nonce, 4))
    var n2 = UInt32(_ct_le32(nonce, 8))
    var n3 = UInt32(_ct_le32(nonce, 12))
    var hi = (UInt64(byte_swap(n0)) << 32) | UInt64(byte_swap(n1))
    var lo = (UInt64(byte_swap(n2)) << 32) | UInt64(byte_swap(n3))
    var q = _GPUState(fill=0)
    for k in range(4):
        var block = group + k * groups
        if block >= num_blocks:
            block = group
        var counter_lo = lo + UInt64(block)
        var counter_hi = hi + UInt64(counter_lo < lo)
        var pair = _pack_block(
            UInt64(byte_swap(UInt32(counter_hi >> 32))),
            UInt64(byte_swap(UInt32(counter_hi))),
            UInt64(byte_swap(UInt32(counter_lo >> 32))),
            UInt64(byte_swap(UInt32(counter_lo))),
        )
        q[k] = pair[0]
        q[k + 4] = pair[1]
    _ct_encrypt_state[1](q, skey, Int(rounds))
    for k in range(4):
        var block = group + k * groups
        if block < num_blocks:
            _xor_block(input_data, output_data, block, q[k], q[k + 4])


@always_inline
def aes_gpu_kernel_gcm_ctr(
    input_data: Pointer[mut=True, UInt8, MutUntrackedOrigin],
    output_data: Pointer[mut=True, UInt8, MutUntrackedOrigin],
    skey: Pointer[mut=True, UInt64, MutUntrackedOrigin],
    n: Int32,
    j0: Pointer[mut=True, UInt8, MutUntrackedOrigin],
    rounds: Int32,
) -> None:
    """Apply GCTR from inc32(J0); authentication is handled separately."""
    if n <= 0 or (rounds != 10 and rounds != 12 and rounds != 14):
        return
    var num_blocks = Int(n)
    var groups = (num_blocks + 3) // 4
    var group = Int(global_idx.x)
    if group >= groups:
        return

    # GCM increments only the low 32 bits of J0. The common prefix stays in
    # registers while each counter is constructed in the bitslice state.
    var w0 = _ct_le32(j0, 0)
    var w1 = _ct_le32(j0, 4)
    var w2 = _ct_le32(j0, 8)
    var base_counter = byte_swap(UInt32(_ct_le32(j0, 12)))
    var q = _GPUState(fill=0)
    for k in range(4):
        var block = group + k * groups
        if block >= num_blocks:
            block = group
        var counter = base_counter + UInt32(block) + UInt32(1)
        var pair = _pack_block(w0, w1, w2, UInt64(byte_swap(counter)))
        q[k] = pair[0]
        q[k + 4] = pair[1]
    _ct_encrypt_state[1](q, skey, Int(rounds))
    for k in range(4):
        var block = group + k * groups
        if block < num_blocks:
            _xor_block(input_data, output_data, block, q[k], q[k + 4])
