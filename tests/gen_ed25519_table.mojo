# This file is to test table generation ignore this file it's not useful
# Mostly for auditing purposes.
from thistle.ed25519 import (
    EdwardsPoint,
    edwards_add,
    edwards_double,
    ed25519_base_point,
    ed25519_d2,
    fe_from_bytes,
)
from thistle.curve25519 import FieldElement51


def _canonical(fe: FieldElement51) -> FieldElement51:
    var bytes = InlineArray[UInt8, 32](uninitialized=True)
    fe.to_bytes_into(bytes.unsafe_ptr())
    return fe_from_bytes(Span[UInt8, ...](unsafe_ptr=bytes.unsafe_ptr(), length=32))


def _affine_niels_limbs(p: EdwardsPoint) -> InlineArray[UInt64, 15]:
    var z_inv = p.Z.invert()
    var x = p.X * z_inv
    var y = p.Y * z_inv
    var y_plus_x = _canonical(y + x)
    var y_minus_x = _canonical(y - x)
    var xy2d = _canonical(x * y * ed25519_d2())
    var out = InlineArray[UInt64, 15](uninitialized=True)
    for i in range(5):
        out[i] = y_plus_x.limbs[i]
        out[5 + i] = y_minus_x.limbs[i]
        out[10 + i] = xy2d.limbs[i]
    return out


def _print_chunk(name: String, points: InlineArray[EdwardsPoint, 8]):
    var s = String("comptime ") + name + " = SIMD[DType.uint64, 128](\n"
    for k in range(8):
        var limbs = _affine_niels_limbs(points[k])
        s += "    "
        for m in range(16):
            var v: UInt64 = 0
            if m < 15:
                v = limbs[m]
            s += String(v)
            if not (k == 7 and m == 15):
                s += ", "
        s += "\n"
    s += ")"
    print(s)


def main() raises:
    print("from std.builtin.dtype import DType")
    print("from std.builtin.simd import SIMD")
    print("from std.collections import InlineArray")
    print()

    var B = ed25519_base_point()

    var P = B
    for j in range(32):
        var row = InlineArray[EdwardsPoint, 8](uninitialized=True)
        row[0] = P
        for k in range(1, 8):
            row[k] = edwards_add(row[k - 1], P)
        _print_chunk(String("_ED25519_BT") + String(j), row)
        print()
        for _ in range(8):
            P = edwards_double(P)

    var B2 = edwards_double(B)
    var odd = InlineArray[EdwardsPoint, 8](uninitialized=True)
    odd[0] = B
    for k in range(1, 8):
        odd[k] = edwards_add(odd[k - 1], B2)
    _print_chunk(String("_ED25519_B_ODD"), odd)
    print()

    print("@no_inline")
    print("def ed25519_base_table() -> InlineArray[UInt64, 4096]:")
    print("    var t = InlineArray[UInt64, 4096](uninitialized=True)")
    print("    var p = t.unsafe_ptr()")
    for j in range(32):
        print("    p.store[alignment=8](" + String(j * 128) + ", _ED25519_BT" + String(j) + ")")
    print("    return t")
    print()
    print("@no_inline")
    print("def ed25519_b_odd_table() -> InlineArray[UInt64, 128]:")
    print("    var t = InlineArray[UInt64, 128](uninitialized=True)")
    print("    t.unsafe_ptr().store[alignment=8](0, _ED25519_B_ODD)")
    print("    return t")
