# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Libalpm64, Lostlab Technologies.

from .curve25519 import FieldElement51
from .constants import APLUS2_OVER_FOUR

def x25519(scalar_in: List[UInt8], point: List[UInt8]) -> List[UInt8]:
    var scalar = scalar_in.copy()
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    
    var u = FieldElement51.from_bytes(point)

    var x_1 = u
    var x_2 = FieldElement51.ONE()
    var z_2 = FieldElement51.ZERO()
    var x_3 = u
    var z_3 = FieldElement51.ONE()
    
    var swap: Int = 0
    for i in range(254, -1, -1):
        var kt = (Int(scalar[i // 8]) >> (i % 8)) & 1
        swap ^= kt
        # cswap(swap, x_2, x_3)
        if swap == 1:
            var tmp = x_2; x_2 = x_3; x_3 = tmp
            tmp = z_2; z_2 = z_3; z_3 = tmp
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
        
    if swap == 1:
        var tmp = x_2; x_2 = x_3; x_3 = tmp
        tmp = z_2; z_2 = z_3; z_3 = tmp
        
    var res = x_2 * z_2.invert()
    return res.to_bytes()
