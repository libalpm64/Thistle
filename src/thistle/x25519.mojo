# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Libalpm64, Lostlab Technologies.

"""
X25519 implementation
By Libalpm64
"""

from .curve25519 import FieldElement51
from .constants import APLUS2_OVER_FOUR
from .utils import StackInlineArray

@always_inline
def _cswap_fe(swap: Int, mut a: FieldElement51, mut b: FieldElement51):
    var mask = UInt64(0) - UInt64(swap)
    for i in range(5):
        var dummy = mask & (a.limbs[i] ^ b.limbs[i])
        a.limbs[i] = a.limbs[i] ^ dummy
        b.limbs[i] = b.limbs[i] ^ dummy

def x25519(scalar_in: Span[UInt8, ...], point: Span[UInt8, ...], output: UnsafePointer[UInt8, MutAnyOrigin]):
    var scalar = StackInlineArray[UInt8, 32](uninitialized=True)
    for i in range(32):
        scalar[i] = scalar_in[i]
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64

    var u = FieldElement51.from_bytes_span(point)

    var x_1 = u
    var x_2 = FieldElement51.ONE()
    var z_2 = FieldElement51.ZERO()
    var x_3 = u
    var z_3 = FieldElement51.ONE()
    
    var swap: Int = 0
    for i in range(254, -1, -1):
        var kt = (Int(scalar[i // 8]) >> (i % 8)) & 1
        swap ^= kt
        _cswap_fe(swap, x_2, x_3)
        _cswap_fe(swap, z_2, z_3)
        swap = kt
        
        var A = x_2 + z_2
        var AA = A.square()
        var B = x_2 - z_2
        var BB = B.square()
        var E = AA - BB
        var C = x_3 + z_3
        var D = x_3 - z_3
        var DA = D * A
        var CB = C * B
        
        x_3 = (DA + CB).square()
        z_3 = x_1 * (DA - CB).square()
        x_2 = AA * BB
        z_2 = E * (AA + APLUS2_OVER_FOUR * E)
        
    _cswap_fe(swap, x_2, x_3)
    _cswap_fe(swap, z_2, z_3)
        
    var res = x_2 * z_2.invert()
    res.to_bytes_into(output)