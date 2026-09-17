"""X25519 key agreement (RFC 7748, secs. 5 and 6.1), with raw and all-zero-checking interfaces."""

from .curve25519 import FieldElement51
from .random import random_bytes
from .ed25519 import _mul_base_ct
from std.collections import Array, List


@always_inline
def _cswap_fe(swap: UInt64, mut a: FieldElement51, mut b: FieldElement51):
    """Swap field elements by XOR-masking each limb."""
    var mask = UInt64(0) - swap
    comptime for i in range(5):
        var masked_diff = mask & (a.limbs[i] ^ b.limbs[i])
        a.limbs[i] = a.limbs[i] ^ masked_diff
        b.limbs[i] = b.limbs[i] ^ masked_diff


@always_inline
def _cswap_pair(
    swap: UInt64,
    mut x_2: FieldElement51,
    mut x_3: FieldElement51,
    mut z_2: FieldElement51,
    mut z_3: FieldElement51
):
    _cswap_fe(swap, x_2, x_3)
    _cswap_fe(swap, z_2, z_3)


@always_inline
def _ladder_sub(a: FieldElement51, b: FieldElement51) -> FieldElement51:
    # Inputs are reduced ladder outputs. Adding 2*p prevents underflow and
    # leaves limbs below 2^53; the following multiply/square propagates carries.
    return FieldElement51(
        a.limbs[0] + UInt64(0xFFFFFFFFFFFDA) - b.limbs[0],
        a.limbs[1] + UInt64(0xFFFFFFFFFFFFE) - b.limbs[1],
        a.limbs[2] + UInt64(0xFFFFFFFFFFFFE) - b.limbs[2],
        a.limbs[3] + UInt64(0xFFFFFFFFFFFFE) - b.limbs[3],
        a.limbs[4] + UInt64(0xFFFFFFFFFFFFE) - b.limbs[4]
    )


@no_inline
def _invert_ladder(x: FieldElement51) -> FieldElement51:
    # Both ladder specializations use the same unrolled inversion chain.
    return x.invert()


@no_inline
def _x25519[basepoint: Bool](
    scalar_in: Span[UInt8, ...],
    point: Span[UInt8, ...],
    output: Span[mut=True, UInt8, ...]
) raises:
    """Run the RFC 7748 ladder; basepoint=True requires the encoded point u=9."""
    if len(scalar_in) != 32:
        raise Error("X25519 scalar must be 32 bytes")
    if len(point) != 32:
        raise Error("X25519 point must be 32 bytes")
    if len(output) < 32:
        raise Error("X25519 output needs at least 32 writable bytes")
    var scalar = Array[UInt8, 32](fill=0)
    for i in range(32):
        scalar[i] = scalar_in[i]
    # Clamp scalar bits: clear 0, 1, 2, and 255; set 254 (RFC 7748, sec. 5).
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64

    var u = FieldElement51.from_bytes_span(point)
    # Ignore bit 255 of the encoded u coordinate (RFC 7748, sec. 5).
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

        # Every ladder product has input limbs below 2^53. Its carry reduction
        # returns 51-bit limbs, except limb 1 may exceed that by less than 2^16.
        # A and B feed the differential-addition products before AA and BB are reused
        # for the doubling update.
        var A = x_2 + z_2
        var B = _ladder_sub(x_2, z_2)
        var DA = _ladder_sub(x_3, z_3)._mul[True](A)
        var CB = (x_3 + z_3)._mul[True](B)

        x_3 = (DA + CB)._square[True]()
        var difference_squared = _ladder_sub(DA, CB)._square[True]()
        comptime if basepoint:
            z_3 = difference_squared.mul_u32(9)
        else:
            z_3 = x_1._mul[True](difference_squared)
        var AA = A._square[True]()
        var BB = B._square[True]()
        var E = _ladder_sub(AA, BB)
        x_2 = AA._mul[True](BB)
        # a24 = (A - 2) / 4 = 121665 for Curve25519, where A = 486662 (RFC 7748, sec. 5).
        z_2 = E._mul[True](AA + E.mul_u32(121665))

    _cswap_pair(swap, x_2, x_3, z_2, z_3)

    var result = x_2 * _invert_ladder(z_2)
    result.to_bytes_into(output.unsafe_ptr())
    var scalar_ptr = scalar.unsafe_ptr()
    for i in range(32):
        scalar_ptr.unsafe_store[volatile=True](i, UInt8(0))


@always_inline
def x25519(
    scalar_in: Span[UInt8, ...], point: Span[UInt8, ...], output: Span[mut=True, UInt8, ...]
) raises:
    """Compute X25519 with a clamped 32-byte scalar and 255-step Montgomery ladder (RFC 7748,
    sec. 5). This raw interface does not reject an all-zero result.
    """
    _x25519[False](scalar_in, point, output)


def x25519_checked(
    scalar_in: Span[UInt8, ...],
    point: Span[UInt8, ...],
    output: Span[mut=True, UInt8, ...]
) raises:
    """Compute X25519 and reject an all-zero shared secret (RFC 7748, sec. 6.1)."""
    x25519(scalar_in, point, output)
    var out_ptr = output.unsafe_ptr()
    var nonzero_acc: UInt8 = 0
    for i in range(32):
        nonzero_acc |= out_ptr[unsafe_offset=i]
    if nonzero_acc == 0:
        raise Error("X25519 shared secret is all-zero (low-order point)")


def x25519_public_key(
    private_key: Span[UInt8, ...], output: Span[mut=True, UInt8, ...]
) raises:
    if len(private_key) != 32:
        raise Error("X25519 private key must be 32 bytes")
    if len(output) < 32:
        raise Error("X25519 output needs at least 32 writable bytes")

    # The Montgomery base point u=9 maps to the standard Ed25519 base point.
    # Constant-time fixed-base Edwards multiplication produces projective y=Y/Z,
    # which maps back with u=(1+y)/(1-y)=(Z+Y)/(Z-Y).
    var scalar = Array[UInt8, 32](fill=0)
    for i in range(32):
        scalar[i] = private_key[i]
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    var edwards_point = _mul_base_ct(
        Span[UInt8, ...](unsafe_ptr=scalar.unsafe_ptr(), length=32)
    )
    var numerator = edwards_point.Z + edwards_point.Y
    var denominator = edwards_point.Z - edwards_point.Y
    var u_coordinate = numerator * denominator.invert()
    u_coordinate.to_bytes_into(output.unsafe_ptr())
    var scalar_ptr = scalar.unsafe_ptr()
    for i in range(32):
        scalar_ptr.unsafe_store[volatile=True](i, UInt8(0))


def x25519_keygen() raises -> Tuple[List[UInt8], List[UInt8]]:
    """Return (private_key, public_key), deriving the public key from base point u = 9 (RFC 7748,
    sec. 6.1).
    """
    var private_key = random_bytes(32)
    var public_key = List[UInt8](unsafe_uninit_length=32)
    x25519_public_key(
        Span[UInt8, ...](private_key),
        Span[mut=True, UInt8, ...](public_key)
    )
    return (private_key^, public_key^)
