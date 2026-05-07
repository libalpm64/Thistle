from std.collections import List
from thistle.ed25519 import bytes_to_hex, Scalar, _scalar_mult_base, edwards_encode
from thistle.sha2 import sha512_hash

def hex_to_bytes(s: String) -> List[UInt8]:
    var r = List[UInt8]()
    var b = s.as_bytes()
    for i in range(0, len(s), 2):
        var hi = UInt8((b[i] - 48) - UInt8(39 if b[i] > 96 else (7 if b[i] > 64 else 0)))
        var lo = UInt8((b[i+1] - 48) - UInt8(39 if b[i+1] > 96 else (7 if b[i+1] > 64 else 0)))
        r.append((hi << 4) | lo)
    return r^

def main() raises:
    var priv = hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    var hash = sha512_hash(Span[UInt8, ...](priv))

    # Clamp s
    var s = List[UInt8](capacity=32)
    for i in range(32):
        s.append(hash[i])
    s[0] = s[0] & 0xF8; s[31] = s[31] & 0x7F; s[31] = s[31] | 0x40
    print("clamped s:", bytes_to_hex(s))

    # Extract prefix
    var prefix = List[UInt8](capacity=32)
    for i in range(32):
        prefix.append(hash[32 + i])
    print("prefix:", bytes_to_hex(prefix))

    # Hash prefix
    var r_in = List[UInt8](capacity=32)
    for i in range(32):
        r_in.append(prefix[i])
    var r_hash = sha512_hash(Span[UInt8, ...](r_in))
    print("r_hash:", bytes_to_hex(r_hash))

    # Reduce mod L
    var r_scalar = Scalar.from_bytes_wide(Span[UInt8, ...](r_hash))
    var r_bytes = r_scalar.to_bytes()
    print("r_scalar:", bytes_to_hex(r_bytes))

    # Scalar mult
    var R = _scalar_mult_base(Span[UInt8, ...](r_bytes))
    var R_enc = edwards_encode(R)
    print("R_enc:", bytes_to_hex(R_enc))
    print("R_exp: e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155")
