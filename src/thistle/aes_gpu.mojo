"""
AES-GPU implementation
"""

from std.gpu import global_idx
from std.memory import stack_allocation
from std.memory import AddressSpace
from std.memory.unsafe_pointer import UnsafePointer
from std.utils import StaticTuple

@always_inline
def gpu_gf_mul2(a: UInt8) -> UInt8:
    return (a << UInt8(1)) ^ (UInt8(0x1b) & (UInt8(0) - (a >> UInt8(7))))

@always_inline
def add_counter_offset(mut counter: StaticTuple[UInt8, 16], offset: Int) -> None:
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
def aes_encrypt_block[rounds: Int](
    state0: UInt8, state1: UInt8, state2: UInt8, state3: UInt8,
    state4: UInt8, state5: UInt8, state6: UInt8, state7: UInt8,
    state8: UInt8, state9: UInt8, state10: UInt8, state11: UInt8,
    state12: UInt8, state13: UInt8, state14: UInt8, state15: UInt8,
    round_keys_ptr: UnsafePointer[UInt32, MutAnyOrigin],
    sbox_buffer: UnsafePointer[UInt8, MutAnyOrigin],
    output_ptr: UnsafePointer[UInt8, MutAnyOrigin],
) -> None:
    var s0 = state0;   var s1 = state1;   var s2 = state2;   var s3 = state3
    var s4 = state4;   var s5 = state5;   var s6 = state6;   var s7 = state7
    var s8 = state8;   var s9 = state9;   var s10 = state10; var s11 = state11
    var s12 = state12; var s13 = state13; var s14 = state14; var s15 = state15

    var w0 = round_keys_ptr[0]
    s0  ^= UInt8((w0 >> 24) & 0xff); s1  ^= UInt8((w0 >> 16) & 0xff)
    s2  ^= UInt8((w0 >> 8)  & 0xff); s3  ^= UInt8(w0 & 0xff)

    var w1 = round_keys_ptr[1]
    s4  ^= UInt8((w1 >> 24) & 0xff); s5  ^= UInt8((w1 >> 16) & 0xff)
    s6  ^= UInt8((w1 >> 8)  & 0xff); s7  ^= UInt8(w1 & 0xff)

    var w2 = round_keys_ptr[2]
    s8  ^= UInt8((w2 >> 24) & 0xff); s9  ^= UInt8((w2 >> 16) & 0xff)
    s10 ^= UInt8((w2 >> 8)  & 0xff); s11 ^= UInt8(w2 & 0xff)

    var w3 = round_keys_ptr[3]
    s12 ^= UInt8((w3 >> 24) & 0xff); s13 ^= UInt8((w3 >> 16) & 0xff)
    s14 ^= UInt8((w3 >> 8)  & 0xff); s15 ^= UInt8(w3 & 0xff)

    comptime for r in range(1, rounds):
        var rk_base = r * 4

        s0  = sbox_buffer[Int(s0)];  s1  = sbox_buffer[Int(s1)]
        s2  = sbox_buffer[Int(s2)];  s3  = sbox_buffer[Int(s3)]
        s4  = sbox_buffer[Int(s4)];  s5  = sbox_buffer[Int(s5)]
        s6  = sbox_buffer[Int(s6)];  s7  = sbox_buffer[Int(s7)]
        s8  = sbox_buffer[Int(s8)];  s9  = sbox_buffer[Int(s9)]
        s10 = sbox_buffer[Int(s10)]; s11 = sbox_buffer[Int(s11)]
        s12 = sbox_buffer[Int(s12)]; s13 = sbox_buffer[Int(s13)]
        s14 = sbox_buffer[Int(s14)]; s15 = sbox_buffer[Int(s15)]

        var t1 = s1;  s1 = s5;  s5 = s9;  s9  = s13; s13 = t1
        var t2 = s2;  s2 = s10; s10 = t2
        var t6 = s6;  s6 = s14; s14 = t6
        var t15 = s15; s15 = s11; s11 = s7; s7 = s3; s3 = t15

        var a00 = s0;  var a01 = s1;  var a02 = s2;  var a03 = s3
        var m200 = gpu_gf_mul2(a00)
        var m201 = gpu_gf_mul2(a01)
        var m202 = gpu_gf_mul2(a02)
        var m203 = gpu_gf_mul2(a03)
        s0 = m200 ^ (a01 ^ m201) ^ a02 ^ a03
        s1 = a00 ^ m201 ^ (a02 ^ m202) ^ a03
        s2 = a00 ^ a01 ^ m202 ^ (a03 ^ m203)
        s3 = (a00 ^ m200) ^ a01 ^ a02 ^ m203

        var a10 = s4;  var a11 = s5;  var a12 = s6;  var a13 = s7
        var m210 = gpu_gf_mul2(a10)
        var m211 = gpu_gf_mul2(a11)
        var m212 = gpu_gf_mul2(a12)
        var m213 = gpu_gf_mul2(a13)
        s4 = m210 ^ (a11 ^ m211) ^ a12 ^ a13
        s5 = a10 ^ m211 ^ (a12 ^ m212) ^ a13
        s6 = a10 ^ a11 ^ m212 ^ (a13 ^ m213)
        s7 = (a10 ^ m210) ^ a11 ^ a12 ^ m213

        var a20 = s8;  var a21 = s9;  var a22 = s10; var a23 = s11
        var m220 = gpu_gf_mul2(a20)
        var m221 = gpu_gf_mul2(a21)
        var m222 = gpu_gf_mul2(a22)
        var m223 = gpu_gf_mul2(a23)
        s8  = m220 ^ (a21 ^ m221) ^ a22 ^ a23
        s9  = a20 ^ m221 ^ (a22 ^ m222) ^ a23
        s10 = a20 ^ a21 ^ m222 ^ (a23 ^ m223)
        s11 = (a20 ^ m220) ^ a21 ^ a22 ^ m223

        var a30 = s12; var a31 = s13; var a32 = s14; var a33 = s15
        var m230 = gpu_gf_mul2(a30)
        var m231 = gpu_gf_mul2(a31)
        var m232 = gpu_gf_mul2(a32)
        var m233 = gpu_gf_mul2(a33)
        s12 = m230 ^ (a31 ^ m231) ^ a32 ^ a33
        s13 = a30 ^ m231 ^ (a32 ^ m232) ^ a33
        s14 = a30 ^ a31 ^ m232 ^ (a33 ^ m233)
        s15 = (a30 ^ m230) ^ a31 ^ a32 ^ m233

        var rk0 = round_keys_ptr[rk_base + 0]
        s0  ^= UInt8((rk0 >> 24) & 0xff); s1  ^= UInt8((rk0 >> 16) & 0xff)
        s2  ^= UInt8((rk0 >> 8)  & 0xff); s3  ^= UInt8(rk0 & 0xff)

        var rk1 = round_keys_ptr[rk_base + 1]
        s4  ^= UInt8((rk1 >> 24) & 0xff); s5  ^= UInt8((rk1 >> 16) & 0xff)
        s6  ^= UInt8((rk1 >> 8)  & 0xff); s7  ^= UInt8(rk1 & 0xff)

        var rk2 = round_keys_ptr[rk_base + 2]
        s8  ^= UInt8((rk2 >> 24) & 0xff); s9  ^= UInt8((rk2 >> 16) & 0xff)
        s10 ^= UInt8((rk2 >> 8)  & 0xff); s11 ^= UInt8(rk2 & 0xff)

        var rk3 = round_keys_ptr[rk_base + 3]
        s12 ^= UInt8((rk3 >> 24) & 0xff); s13 ^= UInt8((rk3 >> 16) & 0xff)
        s14 ^= UInt8((rk3 >> 8)  & 0xff); s15 ^= UInt8(rk3 & 0xff)

    var frk_base = rounds * 4

    s0  = sbox_buffer[Int(s0)];  s1  = sbox_buffer[Int(s1)]
    s2  = sbox_buffer[Int(s2)];  s3  = sbox_buffer[Int(s3)]
    s4  = sbox_buffer[Int(s4)];  s5  = sbox_buffer[Int(s5)]
    s6  = sbox_buffer[Int(s6)];  s7  = sbox_buffer[Int(s7)]
    s8  = sbox_buffer[Int(s8)];  s9  = sbox_buffer[Int(s9)]
    s10 = sbox_buffer[Int(s10)]; s11 = sbox_buffer[Int(s11)]
    s12 = sbox_buffer[Int(s12)]; s13 = sbox_buffer[Int(s13)]
    s14 = sbox_buffer[Int(s14)]; s15 = sbox_buffer[Int(s15)]

    var ft1 = s1;  s1 = s5;  s5 = s9;  s9  = s13; s13 = ft1
    var ft2 = s2;  s2 = s10; s10 = ft2
    var ft6 = s6;  s6 = s14; s14 = ft6
    var ft15 = s15; s15 = s11; s11 = s7; s7 = s3; s3 = ft15

    var fk0 = round_keys_ptr[frk_base + 0]
    s0  ^= UInt8((fk0 >> 24) & 0xff); s1  ^= UInt8((fk0 >> 16) & 0xff)
    s2  ^= UInt8((fk0 >> 8)  & 0xff); s3  ^= UInt8(fk0 & 0xff)

    var fk1 = round_keys_ptr[frk_base + 1]
    s4  ^= UInt8((fk1 >> 24) & 0xff); s5  ^= UInt8((fk1 >> 16) & 0xff)
    s6  ^= UInt8((fk1 >> 8)  & 0xff); s7  ^= UInt8(fk1 & 0xff)

    var fk2 = round_keys_ptr[frk_base + 2]
    s8  ^= UInt8((fk2 >> 24) & 0xff); s9  ^= UInt8((fk2 >> 16) & 0xff)
    s10 ^= UInt8((fk2 >> 8)  & 0xff); s11 ^= UInt8(fk2 & 0xff)

    var fk3 = round_keys_ptr[frk_base + 3]
    s12 ^= UInt8((fk3 >> 24) & 0xff); s13 ^= UInt8((fk3 >> 16) & 0xff)
    s14 ^= UInt8((fk3 >> 8)  & 0xff); s15 ^= UInt8(fk3 & 0xff)

    output_ptr[0]  = s0;  output_ptr[1]  = s1;  output_ptr[2]  = s2;  output_ptr[3]  = s3
    output_ptr[4]  = s4;  output_ptr[5]  = s5;  output_ptr[6]  = s6;  output_ptr[7]  = s7
    output_ptr[8]  = s8;  output_ptr[9]  = s9;  output_ptr[10] = s10; output_ptr[11] = s11
    output_ptr[12] = s12; output_ptr[13] = s13; output_ptr[14] = s14; output_ptr[15] = s15

@always_inline
def aes_encrypt_ecb[rounds: Int](
    input_data: UnsafePointer[UInt8, MutAnyOrigin],
    output_data: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys_data: UnsafePointer[UInt32, MutAnyOrigin],
    sbox_buffer: UnsafePointer[UInt8, MutAnyOrigin],
    num_blocks: Int,
) -> None:
    for i in range(num_blocks):
        var ip = input_data + i * 16
        var op = output_data + i * 16
        aes_encrypt_block[rounds](
            ip[0], ip[1], ip[2],  ip[3],  ip[4],  ip[5],  ip[6],  ip[7],
            ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15],
            round_keys_data, sbox_buffer, op,
        )

@always_inline
def aes_encrypt_ctr[rounds: Int](
    input_data: UnsafePointer[UInt8, MutAnyOrigin],
    output_data: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys_data: UnsafePointer[UInt32, MutAnyOrigin],
    sbox_buffer: UnsafePointer[UInt8, MutAnyOrigin],
    num_blocks: Int,
    nonce: StaticTuple[UInt8, 16],
    scratch: UnsafePointer[UInt8, MutAnyOrigin],
) -> None:
    var counter = nonce
    var pt = StaticTuple[UInt8, 16]()

    for i in range(num_blocks):
        var ip = input_data + i * 16
        var op = output_data + i * 16

        for j in range(16):
            pt[j] = ip[j]

        for j in range(16):
            scratch[j] = 0

        aes_encrypt_block[rounds](
            counter[0], counter[1], counter[2],  counter[3],
            counter[4], counter[5], counter[6],  counter[7],
            counter[8], counter[9], counter[10], counter[11],
            counter[12],counter[13],counter[14], counter[15],
            round_keys_data, sbox_buffer, scratch,
        )

        for j in range(16):
            op[j] = scratch[j] ^ pt[j]

        incr_counter(counter)


@always_inline
def aes_encrypt_gcm[rounds: Int](
    input_data: UnsafePointer[UInt8, MutAnyOrigin],
    output_data: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys_data: UnsafePointer[UInt32, MutAnyOrigin],
    sbox_buffer: UnsafePointer[UInt8, MutAnyOrigin],
    num_blocks: Int,
    nonce: UnsafePointer[UInt8, MutAnyOrigin],
    scratch: UnsafePointer[UInt8, MutAnyOrigin],
) -> None:
    var counter = StaticTuple[UInt8, 16]()
    for i in range(12):
        counter[i] = nonce[i]
    counter[12] = 0
    counter[13] = 0
    counter[14] = 0
    counter[15] = 2

    var pt = StaticTuple[UInt8, 16]()

    for i in range(num_blocks):
        var ip = input_data + i * 16
        var op = output_data + i * 16

        for j in range(16):
            pt[j] = ip[j]

        for j in range(16):
            scratch[j] = 0

        aes_encrypt_block[rounds](
            counter[0], counter[1], counter[2],  counter[3],
            counter[4], counter[5], counter[6],  counter[7],
            counter[8], counter[9], counter[10], counter[11],
            counter[12],counter[13],counter[14], counter[15],
            round_keys_data, sbox_buffer, scratch,
        )

        for j in range(16):
            op[j] = scratch[j] ^ pt[j]

        incr_counter(counter)


def incr_counter(mut counter: StaticTuple[UInt8, 16]) -> None:
    var carry: UInt8 = 1
    for i in range(15, -1, -1):
        var new_val = counter[i] + carry
        carry = UInt8(1) if new_val < counter[i] else UInt8(0)
        counter[i] = new_val
        if carry == 0:
            break

@always_inline
def aes_gpu_kernel_ecb(
    input_data: UnsafePointer[UInt8, MutAnyOrigin],
    output_data: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys_data: UnsafePointer[UInt32, MutAnyOrigin],
    sbox_buffer: UnsafePointer[UInt8, MutAnyOrigin],
    n: Int,
    rounds: Int,
) -> None:
    var tid = global_idx.x
    if tid >= n:
        return
    var bp = input_data + tid * 16
    var op = output_data + tid * 16
    if rounds == 10:
        aes_encrypt_ecb[10](bp, op, round_keys_data, sbox_buffer, 1)
    elif rounds == 12:
        aes_encrypt_ecb[12](bp, op, round_keys_data, sbox_buffer, 1)
    else:
        aes_encrypt_ecb[14](bp, op, round_keys_data, sbox_buffer, 1)

@always_inline
def aes_gpu_kernel_ctr(
    input_data: UnsafePointer[UInt8, MutAnyOrigin],
    output_data: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys_data: UnsafePointer[UInt32, MutAnyOrigin],
    sbox_buffer: UnsafePointer[UInt8, MutAnyOrigin],
    n: Int,
    nonce: UnsafePointer[UInt8, MutAnyOrigin],
    rounds: Int,
) -> None:
    var tid = global_idx.x
    if tid >= n:
        return
    var bp = input_data + tid * 16
    var op = output_data + tid * 16

    var counter = StaticTuple[UInt8, 16]()
    for i in range(16):
        counter[i] = nonce[i]
    add_counter_offset(counter, tid)

    var scratch = stack_allocation[16, UInt8, address_space=AddressSpace.LOCAL]()

    if rounds == 10:
        aes_encrypt_ctr[10](bp, op, round_keys_data, sbox_buffer, 1, counter, scratch.address_space_cast[AddressSpace.GENERIC]())
    elif rounds == 12:
        aes_encrypt_ctr[12](bp, op, round_keys_data, sbox_buffer, 1, counter, scratch.address_space_cast[AddressSpace.GENERIC]())
    else:
        aes_encrypt_ctr[14](bp, op, round_keys_data, sbox_buffer, 1, counter, scratch.address_space_cast[AddressSpace.GENERIC]())

@always_inline
def aes_gpu_kernel_gcm(
    input_data: UnsafePointer[UInt8, MutAnyOrigin],
    output_data: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys_data: UnsafePointer[UInt32, MutAnyOrigin],
    sbox_buffer: UnsafePointer[UInt8, MutAnyOrigin],
    n: Int,
    nonce: UnsafePointer[UInt8, MutAnyOrigin],
    rounds: Int,
) -> None:
    # CTR encryption part of GCM only. GHASH/tag generation is not done here.
    var tid = global_idx.x
    if tid >= n:
        return
    var bp = input_data + tid * 16
    var op = output_data + tid * 16

    var counter = StaticTuple[UInt8, 16]()
    for i in range(12):
        counter[i] = nonce[i]
    counter[12] = 0
    counter[13] = 0
    counter[14] = 0
    counter[15] = 2
    add_counter_offset(counter, tid)

    var scratch = stack_allocation[16, UInt8, address_space=AddressSpace.LOCAL]()

    if rounds == 10:
        aes_encrypt_ctr[10](bp, op, round_keys_data, sbox_buffer, 1, counter, scratch.address_space_cast[AddressSpace.GENERIC]())
    elif rounds == 12:
        aes_encrypt_ctr[12](bp, op, round_keys_data, sbox_buffer, 1, counter, scratch.address_space_cast[AddressSpace.GENERIC]())
    else:
        aes_encrypt_ctr[14](bp, op, round_keys_data, sbox_buffer, 1, counter, scratch.address_space_cast[AddressSpace.GENERIC]())


