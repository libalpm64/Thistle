# SPDX-License-Identifier: MIT
#
# Copyright (c) 2026 Libalpm64, Lostlab Technologies.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


"""
AES-GPU implementation
By Libalpm64 no attribution required.
"""

from gpu import global_idx
from memory import alloc, stack_allocation
from memory import AddressSpace
from memory.unsafe_pointer import UnsafePointer
from utils import StaticTuple


@always_inline
fn aes_encrypt_block[rounds: Int](
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

    for r in range(1, rounds):
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
        var m200 = (a00 << 1) & UInt8(0xff)
        if (a00 & 0x80) != 0:
            m200 ^= 0x1b
        var m201 = (a01 << 1) & UInt8(0xff)
        if (a01 & 0x80) != 0:
            m201 ^= 0x1b
        var m202 = (a02 << 1) & UInt8(0xff)
        if (a02 & 0x80) != 0:
            m202 ^= 0x1b
        var m203 = (a03 << 1) & UInt8(0xff)
        if (a03 & 0x80) != 0:
            m203 ^= 0x1b
        s0 = m200 ^ (a01 ^ m201) ^ a02 ^ a03
        s1 = a00 ^ m201 ^ (a02 ^ m202) ^ a03
        s2 = a00 ^ a01 ^ m202 ^ (a03 ^ m203)
        s3 = (a00 ^ m200) ^ a01 ^ a02 ^ m203

        var a10 = s4;  var a11 = s5;  var a12 = s6;  var a13 = s7
        var m210 = (a10 << 1) & UInt8(0xff)
        if (a10 & 0x80) != 0:
            m210 ^= 0x1b
        var m211 = (a11 << 1) & UInt8(0xff)
        if (a11 & 0x80) != 0:
            m211 ^= 0x1b
        var m212 = (a12 << 1) & UInt8(0xff)
        if (a12 & 0x80) != 0:
            m212 ^= 0x1b
        var m213 = (a13 << 1) & UInt8(0xff)
        if (a13 & 0x80) != 0:
            m213 ^= 0x1b
        s4 = m210 ^ (a11 ^ m211) ^ a12 ^ a13
        s5 = a10 ^ m211 ^ (a12 ^ m212) ^ a13
        s6 = a10 ^ a11 ^ m212 ^ (a13 ^ m213)
        s7 = (a10 ^ m210) ^ a11 ^ a12 ^ m213

        var a20 = s8;  var a21 = s9;  var a22 = s10; var a23 = s11
        var m220 = (a20 << 1) & UInt8(0xff)
        if (a20 & 0x80) != 0:
            m220 ^= 0x1b
        var m221 = (a21 << 1) & UInt8(0xff)
        if (a21 & 0x80) != 0:
            m221 ^= 0x1b
        var m222 = (a22 << 1) & UInt8(0xff)
        if (a22 & 0x80) != 0:
            m222 ^= 0x1b
        var m223 = (a23 << 1) & UInt8(0xff)
        if (a23 & 0x80) != 0:
            m223 ^= 0x1b
        s8  = m220 ^ (a21 ^ m221) ^ a22 ^ a23
        s9  = a20 ^ m221 ^ (a22 ^ m222) ^ a23
        s10 = a20 ^ a21 ^ m222 ^ (a23 ^ m223)
        s11 = (a20 ^ m220) ^ a21 ^ a22 ^ m223

        var a30 = s12; var a31 = s13; var a32 = s14; var a33 = s15
        var m230 = (a30 << 1) & UInt8(0xff)
        if (a30 & 0x80) != 0:
            m230 ^= 0x1b
        var m231 = (a31 << 1) & UInt8(0xff)
        if (a31 & 0x80) != 0:
            m231 ^= 0x1b
        var m232 = (a32 << 1) & UInt8(0xff)
        if (a32 & 0x80) != 0:
            m232 ^= 0x1b
        var m233 = (a33 << 1) & UInt8(0xff)
        if (a33 & 0x80) != 0:
            m233 ^= 0x1b
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
fn aes_encrypt_ecb[rounds: Int](
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
fn aes_encrypt_cbc[rounds: Int](
    input_data: UnsafePointer[UInt8, MutAnyOrigin],
    output_data: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys_data: UnsafePointer[UInt32, MutAnyOrigin],
    sbox_buffer: UnsafePointer[UInt8, MutAnyOrigin],
    num_blocks: Int,
    iv: UnsafePointer[UInt8, MutAnyOrigin],
) -> None:
    var prev = StaticTuple[UInt8, 16]()
    for i in range(16):
        prev[i] = iv[i]

    for i in range(num_blocks):
        var ip = input_data + i * 16
        var op = output_data + i * 16

        var xored = StaticTuple[UInt8, 16]()
        for j in range(16):
            xored[j] = ip[j] ^ prev[j]

        aes_encrypt_block[rounds](
            xored[0], xored[1], xored[2],  xored[3],
            xored[4], xored[5], xored[6],  xored[7],
            xored[8], xored[9], xored[10], xored[11],
            xored[12],xored[13],xored[14], xored[15],
            round_keys_data, sbox_buffer, op,
        )

        for j in range(16):
            prev[j] = op[j]


@always_inline
fn aes_encrypt_ctr[rounds: Int](
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
fn aes_encrypt_gcm[rounds: Int](
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


fn incr_counter(mut counter: StaticTuple[UInt8, 16]) -> None:
    var carry: UInt8 = 1
    for i in range(15, -1, -1):
        var new_val = counter[i] + carry
        carry = UInt8(1) if new_val < counter[i] else UInt8(0)
        counter[i] = new_val
        if carry == 0:
            break

fn xts_mul_alpha(tweak: UnsafePointer[UInt8, MutAnyOrigin]) -> None:
    var high_bit = (tweak[0] & 0x80) != 0
    for i in range(16):
        var new_val = tweak[i] << 1
        if i > 0 and (tweak[i - 1] & 0x80) != 0:
            new_val = new_val | 1
        tweak[i] = new_val
    if high_bit:
        tweak[15] = tweak[15] ^ 0x87


@always_inline
fn aes_gpu_kernel_ecb(
    input_data: UnsafePointer[UInt8, MutAnyOrigin],
    output_data: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys_data: UnsafePointer[UInt32, MutAnyOrigin],
    sbox_buffer: UnsafePointer[UInt8, MutAnyOrigin],
    n: Int,
    rounds: Int,
) -> None:
    var tid = global_idx.x
    if tid >= UInt(n):
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
fn aes_gpu_kernel_cbc(
    input_data: UnsafePointer[UInt8, MutAnyOrigin],
    output_data: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys_data: UnsafePointer[UInt32, MutAnyOrigin],
    sbox_buffer: UnsafePointer[UInt8, MutAnyOrigin],
    n: Int,
    iv: UnsafePointer[UInt8, MutAnyOrigin],
    rounds: Int,
) -> None:
    var tid = global_idx.x
    if tid >= UInt(n):
        return
    var bp = input_data + tid * 16
    var op = output_data + tid * 16
    if rounds == 10:
        aes_encrypt_cbc[10](bp, op, round_keys_data, sbox_buffer, 1, iv)
    elif rounds == 12:
        aes_encrypt_cbc[12](bp, op, round_keys_data, sbox_buffer, 1, iv)
    else:
        aes_encrypt_cbc[14](bp, op, round_keys_data, sbox_buffer, 1, iv)


@always_inline
fn aes_gpu_kernel_ctr(
    input_data: UnsafePointer[UInt8, MutAnyOrigin],
    output_data: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys_data: UnsafePointer[UInt32, MutAnyOrigin],
    sbox_buffer: UnsafePointer[UInt8, MutAnyOrigin],
    n: Int,
    nonce: UnsafePointer[UInt8, MutAnyOrigin],
    rounds: Int,
) -> None:
    var tid = global_idx.x
    if tid >= UInt(n):
        return
    var bp = input_data + tid * 16
    var op = output_data + tid * 16

    var counter = StaticTuple[UInt8, 16]()
    for i in range(16):
        counter[i] = nonce[i]
    var carry = tid
    for i in range(15, -1, -1):
        var new_val = counter[i] + UInt8(carry & 0xFF)
        counter[i] = new_val
        carry = carry >> 8
        if carry == 0:
            break

    var scratch = stack_allocation[16, UInt8, address_space=AddressSpace.LOCAL]()

    if rounds == 10:
        aes_encrypt_ctr[10](bp, op, round_keys_data, sbox_buffer, 1, counter, scratch.address_space_cast[AddressSpace.GENERIC]())
    elif rounds == 12:
        aes_encrypt_ctr[12](bp, op, round_keys_data, sbox_buffer, 1, counter, scratch.address_space_cast[AddressSpace.GENERIC]())
    else:
        aes_encrypt_ctr[14](bp, op, round_keys_data, sbox_buffer, 1, counter, scratch.address_space_cast[AddressSpace.GENERIC]())


@always_inline
fn aes_gpu_kernel_gcm(
    input_data: UnsafePointer[UInt8, MutAnyOrigin],
    output_data: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys_data: UnsafePointer[UInt32, MutAnyOrigin],
    sbox_buffer: UnsafePointer[UInt8, MutAnyOrigin],
    n: Int,
    nonce: UnsafePointer[UInt8, MutAnyOrigin],
    rounds: Int,
) -> None:
    var tid = global_idx.x
    if tid >= UInt(n):
        return
    var bp = input_data + tid * 16
    var op = output_data + tid * 16

    var scratch = stack_allocation[16, UInt8, address_space=AddressSpace.LOCAL]()

    if rounds == 10:
        aes_encrypt_gcm[10](bp, op, round_keys_data, sbox_buffer, 1, nonce, scratch.address_space_cast[AddressSpace.GENERIC]())
    elif rounds == 12:
        aes_encrypt_gcm[12](bp, op, round_keys_data, sbox_buffer, 1, nonce, scratch.address_space_cast[AddressSpace.GENERIC]())
    else:
        aes_encrypt_gcm[14](bp, op, round_keys_data, sbox_buffer, 1, nonce, scratch.address_space_cast[AddressSpace.GENERIC]())


@always_inline
fn aes_gpu_kernel_xts(
    input_data: UnsafePointer[UInt8, MutAnyOrigin],
    output_data: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys_data1: UnsafePointer[UInt32, MutAnyOrigin],
    round_keys_data2: UnsafePointer[UInt32, MutAnyOrigin],
    sbox_buffer: UnsafePointer[UInt8, MutAnyOrigin],
    n: Int,
    tweak: UnsafePointer[UInt8, MutAnyOrigin],
    rounds: Int,
) -> None:
    var tid = global_idx.x
    if tid >= UInt(n):
        return
    var bp = input_data + tid * 16
    var op = output_data + tid * 16

    var enc_tweak = stack_allocation[16, UInt8, address_space=AddressSpace.LOCAL]()
    if rounds == 10:
        aes_encrypt_ecb[10](tweak, enc_tweak.address_space_cast[AddressSpace.GENERIC](), round_keys_data2, sbox_buffer, 1)
    elif rounds == 12:
        aes_encrypt_ecb[12](tweak, enc_tweak.address_space_cast[AddressSpace.GENERIC](), round_keys_data2, sbox_buffer, 1)
    else:
        aes_encrypt_ecb[14](tweak, enc_tweak.address_space_cast[AddressSpace.GENERIC](), round_keys_data2, sbox_buffer, 1)

    var tmp = stack_allocation[16, UInt8, address_space=AddressSpace.LOCAL]()
    for j in range(16):
        tmp[j] = bp[j] ^ enc_tweak[j]

    var enc_tmp = stack_allocation[16, UInt8, address_space=AddressSpace.LOCAL]()
    if rounds == 10:
        aes_encrypt_ecb[10](tmp.address_space_cast[AddressSpace.GENERIC](), enc_tmp.address_space_cast[AddressSpace.GENERIC](), round_keys_data1, sbox_buffer, 1)
    elif rounds == 12:
        aes_encrypt_ecb[12](tmp.address_space_cast[AddressSpace.GENERIC](), enc_tmp.address_space_cast[AddressSpace.GENERIC](), round_keys_data1, sbox_buffer, 1)
    else:
        aes_encrypt_ecb[14](tmp.address_space_cast[AddressSpace.GENERIC](), enc_tmp.address_space_cast[AddressSpace.GENERIC](), round_keys_data1, sbox_buffer, 1)

    for j in range(16):
        op[j] = enc_tmp[j] ^ enc_tweak[j]
