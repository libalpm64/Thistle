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
AES-128-GPU implementation
By Libalpm64 no attribution required.
Experimental - NOT meant for production.
"""

from gpu import global_idx


@always_inline
fn aes_kernel(
    input_data: UnsafePointer[UInt8, MutAnyOrigin],
    output_data: UnsafePointer[UInt8, MutAnyOrigin],
    round_keys_data: UnsafePointer[UInt32, MutAnyOrigin],
    sbox_buffer: UnsafePointer[UInt8, MutAnyOrigin],
    rounds: Int,
    n: Int,
) -> None:
    var tid = global_idx.x
    if tid >= UInt(n):
        return

    var input_ptr = input_data + Int(tid) * 16
    var output_ptr = output_data + Int(tid) * 16
    var round_keys_ptr = round_keys_data

    var state0 = input_ptr[0]
    var state1 = input_ptr[1]
    var state2 = input_ptr[2]
    var state3 = input_ptr[3]
    var state4 = input_ptr[4]
    var state5 = input_ptr[5]
    var state6 = input_ptr[6]
    var state7 = input_ptr[7]
    var state8 = input_ptr[8]
    var state9 = input_ptr[9]
    var state10 = input_ptr[10]
    var state11 = input_ptr[11]
    var state12 = input_ptr[12]
    var state13 = input_ptr[13]
    var state14 = input_ptr[14]
    var state15 = input_ptr[15]

    var w0 = round_keys_ptr[0]
    state0 = state0 ^ UInt8((w0 >> 24) & 0xff)
    state1 = state1 ^ UInt8((w0 >> 16) & 0xff)
    state2 = state2 ^ UInt8((w0 >> 8) & 0xff)
    state3 = state3 ^ UInt8(w0 & 0xff)
    
    var w1 = round_keys_ptr[1]
    state4 = state4 ^ UInt8((w1 >> 24) & 0xff)
    state5 = state5 ^ UInt8((w1 >> 16) & 0xff)
    state6 = state6 ^ UInt8((w1 >> 8) & 0xff)
    state7 = state7 ^ UInt8(w1 & 0xff)
    
    var w2 = round_keys_ptr[2]
    state8 = state8 ^ UInt8((w2 >> 24) & 0xff)
    state9 = state9 ^ UInt8((w2 >> 16) & 0xff)
    state10 = state10 ^ UInt8((w2 >> 8) & 0xff)
    state11 = state11 ^ UInt8(w2 & 0xff)
    
    var w3 = round_keys_ptr[3]
    state12 = state12 ^ UInt8((w3 >> 24) & 0xff)
    state13 = state13 ^ UInt8((w3 >> 16) & 0xff)
    state14 = state14 ^ UInt8((w3 >> 8) & 0xff)
    state15 = state15 ^ UInt8(w3 & 0xff)

    for r in range(1, rounds):
        var rk_base = r * 4

        state0 = sbox_buffer[Int(state0)]
        state1 = sbox_buffer[Int(state1)]
        state2 = sbox_buffer[Int(state2)]
        state3 = sbox_buffer[Int(state3)]
        state4 = sbox_buffer[Int(state4)]
        state5 = sbox_buffer[Int(state5)]
        state6 = sbox_buffer[Int(state6)]
        state7 = sbox_buffer[Int(state7)]
        state8 = sbox_buffer[Int(state8)]
        state9 = sbox_buffer[Int(state9)]
        state10 = sbox_buffer[Int(state10)]
        state11 = sbox_buffer[Int(state11)]
        state12 = sbox_buffer[Int(state12)]
        state13 = sbox_buffer[Int(state13)]
        state14 = sbox_buffer[Int(state14)]
        state15 = sbox_buffer[Int(state15)]

        var t1 = state1
        state1 = state5
        state5 = state9
        state9 = state13
        state13 = t1
        
        var t2 = state2
        state2 = state10
        state10 = t2
        
        var t6 = state6
        state6 = state14
        state14 = t6
        
        var t15 = state15
        state15 = state11
        state11 = state7
        state7 = state3
        state3 = t15

        var a0_0 = state0
        var a0_1 = state1
        var a0_2 = state2
        var a0_3 = state3
        
        var m2_0_0 = (a0_0 << 1) & UInt8(0xff)
        if (a0_0 & 0x80) != 0:
            m2_0_0 ^= 0x1b
        var m2_0_1 = (a0_1 << 1) & UInt8(0xff)
        if (a0_1 & 0x80) != 0:
            m2_0_1 ^= 0x1b
        var m2_0_2 = (a0_2 << 1) & UInt8(0xff)
        if (a0_2 & 0x80) != 0:
            m2_0_2 ^= 0x1b
        var m2_0_3 = (a0_3 << 1) & UInt8(0xff)
        if (a0_3 & 0x80) != 0:
            m2_0_3 ^= 0x1b
        
        state0 = m2_0_0 ^ (a0_1 ^ m2_0_1) ^ a0_2 ^ a0_3
        state1 = a0_0 ^ m2_0_1 ^ (a0_2 ^ m2_0_2) ^ a0_3
        state2 = a0_0 ^ a0_1 ^ m2_0_2 ^ (a0_3 ^ m2_0_3)
        state3 = (a0_0 ^ m2_0_0) ^ a0_1 ^ a0_2 ^ m2_0_3

        var a1_0 = state4
        var a1_1 = state5
        var a1_2 = state6
        var a1_3 = state7
        
        var m2_1_0 = (a1_0 << 1) & UInt8(0xff)
        if (a1_0 & 0x80) != 0:
            m2_1_0 ^= 0x1b
        var m2_1_1 = (a1_1 << 1) & UInt8(0xff)
        if (a1_1 & 0x80) != 0:
            m2_1_1 ^= 0x1b
        var m2_1_2 = (a1_2 << 1) & UInt8(0xff)
        if (a1_2 & 0x80) != 0:
            m2_1_2 ^= 0x1b
        var m2_1_3 = (a1_3 << 1) & UInt8(0xff)
        if (a1_3 & 0x80) != 0:
            m2_1_3 ^= 0x1b
        
        state4 = m2_1_0 ^ (a1_1 ^ m2_1_1) ^ a1_2 ^ a1_3
        state5 = a1_0 ^ m2_1_1 ^ (a1_2 ^ m2_1_2) ^ a1_3
        state6 = a1_0 ^ a1_1 ^ m2_1_2 ^ (a1_3 ^ m2_1_3)
        state7 = (a1_0 ^ m2_1_0) ^ a1_1 ^ a1_2 ^ m2_1_3

        var a2_0 = state8
        var a2_1 = state9
        var a2_2 = state10
        var a2_3 = state11
        
        var m2_2_0 = (a2_0 << 1) & UInt8(0xff)
        if (a2_0 & 0x80) != 0:
            m2_2_0 ^= 0x1b
        var m2_2_1 = (a2_1 << 1) & UInt8(0xff)
        if (a2_1 & 0x80) != 0:
            m2_2_1 ^= 0x1b
        var m2_2_2 = (a2_2 << 1) & UInt8(0xff)
        if (a2_2 & 0x80) != 0:
            m2_2_2 ^= 0x1b
        var m2_2_3 = (a2_3 << 1) & UInt8(0xff)
        if (a2_3 & 0x80) != 0:
            m2_2_3 ^= 0x1b
        
        state8 = m2_2_0 ^ (a2_1 ^ m2_2_1) ^ a2_2 ^ a2_3
        state9 = a2_0 ^ m2_2_1 ^ (a2_2 ^ m2_2_2) ^ a2_3
        state10 = a2_0 ^ a2_1 ^ m2_2_2 ^ (a2_3 ^ m2_2_3)
        state11 = (a2_0 ^ m2_2_0) ^ a2_1 ^ a2_2 ^ m2_2_3

        var a3_0 = state12
        var a3_1 = state13
        var a3_2 = state14
        var a3_3 = state15
        
        var m2_3_0 = (a3_0 << 1) & UInt8(0xff)
        if (a3_0 & 0x80) != 0:
            m2_3_0 ^= 0x1b
        var m2_3_1 = (a3_1 << 1) & UInt8(0xff)
        if (a3_1 & 0x80) != 0:
            m2_3_1 ^= 0x1b
        var m2_3_2 = (a3_2 << 1) & UInt8(0xff)
        if (a3_2 & 0x80) != 0:
            m2_3_2 ^= 0x1b
        var m2_3_3 = (a3_3 << 1) & UInt8(0xff)
        if (a3_3 & 0x80) != 0:
            m2_3_3 ^= 0x1b
        
        state12 = m2_3_0 ^ (a3_1 ^ m2_3_1) ^ a3_2 ^ a3_3
        state13 = a3_0 ^ m2_3_1 ^ (a3_2 ^ m2_3_2) ^ a3_3
        state14 = a3_0 ^ a3_1 ^ m2_3_2 ^ (a3_3 ^ m2_3_3)
        state15 = (a3_0 ^ m2_3_0) ^ a3_1 ^ a3_2 ^ m2_3_3

        var rkw0 = round_keys_ptr[rk_base + 0]
        state0 = state0 ^ UInt8((rkw0 >> 24) & 0xff)
        state1 = state1 ^ UInt8((rkw0 >> 16) & 0xff)
        state2 = state2 ^ UInt8((rkw0 >> 8) & 0xff)
        state3 = state3 ^ UInt8(rkw0 & 0xff)
        
        var rkw1 = round_keys_ptr[rk_base + 1]
        state4 = state4 ^ UInt8((rkw1 >> 24) & 0xff)
        state5 = state5 ^ UInt8((rkw1 >> 16) & 0xff)
        state6 = state6 ^ UInt8((rkw1 >> 8) & 0xff)
        state7 = state7 ^ UInt8(rkw1 & 0xff)
        
        var rkw2 = round_keys_ptr[rk_base + 2]
        state8 = state8 ^ UInt8((rkw2 >> 24) & 0xff)
        state9 = state9 ^ UInt8((rkw2 >> 16) & 0xff)
        state10 = state10 ^ UInt8((rkw2 >> 8) & 0xff)
        state11 = state11 ^ UInt8(rkw2 & 0xff)
        
        var rkw3 = round_keys_ptr[rk_base + 3]
        state12 = state12 ^ UInt8((rkw3 >> 24) & 0xff)
        state13 = state13 ^ UInt8((rkw3 >> 16) & 0xff)
        state14 = state14 ^ UInt8((rkw3 >> 8) & 0xff)
        state15 = state15 ^ UInt8(rkw3 & 0xff)

    var final_rk_base = rounds * 4

    state0 = sbox_buffer[Int(state0)]
    state1 = sbox_buffer[Int(state1)]
    state2 = sbox_buffer[Int(state2)]
    state3 = sbox_buffer[Int(state3)]
    state4 = sbox_buffer[Int(state4)]
    state5 = sbox_buffer[Int(state5)]
    state6 = sbox_buffer[Int(state6)]
    state7 = sbox_buffer[Int(state7)]
    state8 = sbox_buffer[Int(state8)]
    state9 = sbox_buffer[Int(state9)]
    state10 = sbox_buffer[Int(state10)]
    state11 = sbox_buffer[Int(state11)]
    state12 = sbox_buffer[Int(state12)]
    state13 = sbox_buffer[Int(state13)]
    state14 = sbox_buffer[Int(state14)]
    state15 = sbox_buffer[Int(state15)]

    var ft1 = state1
    state1 = state5
    state5 = state9
    state9 = state13
    state13 = ft1
    
    var ft2 = state2
    state2 = state10
    state10 = ft2
    
    var ft6 = state6
    state6 = state14
    state14 = ft6
    
    var ft15 = state15
    state15 = state11
    state11 = state7
    state7 = state3
    state3 = ft15

    var fkw0 = round_keys_ptr[final_rk_base + 0]
    state0 = state0 ^ UInt8((fkw0 >> 24) & 0xff)
    state1 = state1 ^ UInt8((fkw0 >> 16) & 0xff)
    state2 = state2 ^ UInt8((fkw0 >> 8) & 0xff)
    state3 = state3 ^ UInt8(fkw0 & 0xff)
    
    var fkw1 = round_keys_ptr[final_rk_base + 1]
    state4 = state4 ^ UInt8((fkw1 >> 24) & 0xff)
    state5 = state5 ^ UInt8((fkw1 >> 16) & 0xff)
    state6 = state6 ^ UInt8((fkw1 >> 8) & 0xff)
    state7 = state7 ^ UInt8(fkw1 & 0xff)
    
    var fkw2 = round_keys_ptr[final_rk_base + 2]
    state8 = state8 ^ UInt8((fkw2 >> 24) & 0xff)
    state9 = state9 ^ UInt8((fkw2 >> 16) & 0xff)
    state10 = state10 ^ UInt8((fkw2 >> 8) & 0xff)
    state11 = state11 ^ UInt8(fkw2 & 0xff)
    
    var fkw3 = round_keys_ptr[final_rk_base + 3]
    state12 = state12 ^ UInt8((fkw3 >> 24) & 0xff)
    state13 = state13 ^ UInt8((fkw3 >> 16) & 0xff)
    state14 = state14 ^ UInt8((fkw3 >> 8) & 0xff)
    state15 = state15 ^ UInt8(fkw3 & 0xff)

    output_ptr[0] = state0
    output_ptr[1] = state1
    output_ptr[2] = state2
    output_ptr[3] = state3
    output_ptr[4] = state4
    output_ptr[5] = state5
    output_ptr[6] = state6
    output_ptr[7] = state7
    output_ptr[8] = state8
    output_ptr[9] = state9
    output_ptr[10] = state10
    output_ptr[11] = state11
    output_ptr[12] = state12
    output_ptr[13] = state13
    output_ptr[14] = state14
    output_ptr[15] = state15
