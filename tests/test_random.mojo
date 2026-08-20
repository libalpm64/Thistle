from std.collections import List
from thistle.random import random_bytes, random_fill

def _all_zero(buf: List[UInt8]) -> Bool:
    for i in range(len(buf)):
        if buf[i] != 0:
            return False
    return True

def _hex_char(n: UInt8) -> UInt8:
    if n < UInt8(10):
        return n + UInt8(48)
    return n - UInt8(10) + UInt8(97)

def _print_hex(label: String, buf: List[UInt8]):
    var s = String()
    for i in range(len(buf)):
        var b = buf[i]
        s += chr(Int(_hex_char((b >> UInt8(4)) & UInt8(0x0F))))
        s += chr(Int(_hex_char(b & UInt8(0x0F))))
    print(label, s)

def main() raises:
    var empty = random_bytes(0)
    if len(empty) != 0:
        raise Error("random_bytes(0) returned non-empty output")

    var small = random_bytes(32)
    if len(small) != 32:
        raise Error("random_bytes(32) returned wrong length")
    if _all_zero(small):
        raise Error("random_bytes(32) returned all-zero output")
    _print_hex("random_bytes(32):", small)

    var large = List[UInt8](capacity=257)
    for _ in range(257):
        large.append(0)
    random_fill(Span[mut=True, UInt8, ...](large))
    if _all_zero(large):
        raise Error("random_fill(257) returned all-zero output")

    if large[256] == 0:
        var second = List[UInt8](capacity=257)
        for _ in range(257):
            second.append(0)
        random_fill(Span[mut=True, UInt8, ...](second))
        if second[256] == 0:
            raise Error("random_fill(257) did not appear to write byte 256")

    var preview = List[UInt8](capacity=32)
    for i in range(32):
        preview.append(large[i])
    _print_hex("random_fill(257) first 32:", preview)

    print("random tests passed")
