"""
X25519 implementation
"""

from .curve25519 import FieldElement51
from .utils import StackInlineArray
from .random import random_bytes
from std.collections import List

@always_inline
def _cswap_fe(swap: UInt64, mut a: FieldElement51, mut b: FieldElement51):
    var mask = UInt64(0) - swap
    comptime for i in range(5):
        var dummy = mask & (a.limbs[i] ^ b.limbs[i])
        a.limbs[i] = a.limbs[i] ^ dummy
        b.limbs[i] = b.limbs[i] ^ dummy

@always_inline
def _cswap_pair(
    swap: UInt64,
    mut x_2: FieldElement51,
    mut x_3: FieldElement51,
    mut z_2: FieldElement51,
    mut z_3: FieldElement51,
):
    _cswap_fe(swap, x_2, x_3)
    _cswap_fe(swap, z_2, z_3)

@no_inline
def x25519(
    scalar_in: Span[UInt8, ...],
    point: Span[UInt8, ...],
    output: Span[mut=True, UInt8, ...],
) raises:
    if len(scalar_in) < 32:
        raise Error("X25519 scalar must be 32 bytes")
    if len(point) < 32:
        raise Error("X25519 point must be 32 bytes")
    if len(output) < 32:
        raise Error("X25519 output needs at least 32 writable bytes")
    var scalar = StackInlineArray[UInt8, 32](fill=0)
    for i in range(32):
        scalar[i] = scalar_in[i]
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64

    var u = FieldElement51.from_bytes_span(point)
    # RFC 7748 ignores the top input bit.
    u.limbs[4] &= (UInt64(1) << UInt64(51)) - UInt64(1)

    var x_1 = u
    var x_2 = FieldElement51.ONE()
    var z_2 = FieldElement51.ZERO()
    var x_3 = u
    var z_3 = FieldElement51.ONE()
    
    var swap: UInt64 = 0
    for i in range(254, -1, -1):
        var kt = UInt64((scalar[i // 8] >> UInt8(i % 8)) & UInt8(1))
        swap ^= kt
        _cswap_pair(swap, x_2, x_3, z_2, z_3)
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
        z_2 = E * (AA + E.mul_u32(121665))
        
    _cswap_pair(swap, x_2, x_3, z_2, z_3)
        
    var res = x_2 * z_2.invert()
    res.to_bytes_into(output.unsafe_ptr())
    var scalar_ptr = scalar.unsafe_ptr()
    for i in range(32):
        scalar_ptr.unsafe_store[volatile=True](i, UInt8(0))


def x25519_public_key(
    private_key: Span[UInt8, ...], output: Span[mut=True, UInt8, ...]
) raises:
    if len(private_key) != 32:
        raise Error("X25519 private key must be 32 bytes")
    var base = StackInlineArray[UInt8, 32](fill=0)
    base[0] = 9
    x25519(
        private_key,
        Span[UInt8, ...](unsafe_ptr=base.unsafe_ptr(), length=32),
        output,
    )


def x25519_keygen() raises -> Tuple[List[UInt8], List[UInt8]]:
    var private_key = random_bytes(32)
    var public_key = List[UInt8](unsafe_uninit_length=32)
    x25519_public_key(
        Span[UInt8, ...](private_key),
        Span[mut=True, UInt8, ...](public_key),
    )
    return (private_key^, public_key^)
