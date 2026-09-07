"""ECDSA signature encoding as a DER SEQUENCE of INTEGER r and s (RFC 3279, sec. 2.2.3)."""

from std.collections import List


def ecdsa_der_encode(
    signature: Span[UInt8, ...], size: Int
) raises -> List[UInt8]:
    """Encode r and s in DER (RFC 3279, sec. 2.2.3); this codec limits the body to 127 bytes."""
    # This codec intentionally supports only DER's one-byte length form.  A
    # 60-byte scalar is the largest one whose two padded INTEGERs can fit.
    if size <= 0 or size > 60 or len(signature) != 2 * size:
        raise Error("invalid ECDSA signature size")
    var r_start = 0
    while r_start < size - 1 and signature[r_start] == 0:
        r_start += 1
    var s_start = 0
    while s_start < size - 1 and signature[size + s_start] == 0:
        s_start += 1
    var r_len = size - r_start
    var s_len = size - s_start
    # Prefix a positive INTEGER with 00 when its high bit is set.
    var r_pad = Int((signature[r_start] >> 7) & 1)
    var s_pad = Int((signature[size + s_start] >> 7) & 1)
    var body_len = 4 + r_pad + r_len + s_pad + s_len
    if body_len >= 128:
        raise Error("ECDSA DER signature is too large")

    var out = List[UInt8](capacity=body_len + 2)
    out.append(0x30)
    out.append(UInt8(body_len))
    out.append(0x02)
    out.append(UInt8(r_len + r_pad))
    if r_pad != 0:
        out.append(0)
    for i in range(r_start, size):
        out.append(signature[i])
    out.append(0x02)
    out.append(UInt8(s_len + s_pad))
    if s_pad != 0:
        out.append(0)
    for i in range(s_start, size):
        out.append(signature[size + i])
    return out^


def ecdsa_der_decode(signature: Span[UInt8, ...], size: Int) -> List[UInt8]:
    """Decode DER r and s (RFC 3279, sec. 2.2.3), returning an empty list on invalid input."""
    if size <= 0 or size > 60 or len(signature) < 6 or signature[0] != 0x30:
        return List[UInt8]()
    if signature[1] >= 0x80 or Int(signature[1]) != len(signature) - 2:
        return List[UInt8]()
    var out = List[UInt8](length=2 * size, fill=0)
    var pos = 2
    for scalar in range(2):
        if pos + 2 > len(signature) or signature[pos] != 0x02:
            return List[UInt8]()
        var value_len = Int(signature[pos + 1])
        pos += 2
        if value_len == 0 or pos + value_len > len(signature):
            return List[UInt8]()
        var skip = 0
        if signature[pos] == 0:
            if value_len > 1 and (signature[pos + 1] & 0x80) == 0:
                return List[UInt8]()
            skip = 1
        elif (signature[pos] & 0x80) != 0:
            return List[UInt8]()
        var integer_len = value_len - skip
        if integer_len > size:
            return List[UInt8]()
        for i in range(integer_len):
            out[scalar * size + size - integer_len + i] = signature[
                pos + skip + i
            ]
        pos += value_len
    if pos != len(signature):
        return List[UInt8]()
    return out^
