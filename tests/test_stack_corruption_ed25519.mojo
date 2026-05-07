from std.collections import List
from thistle.ed25519 import bytes_to_hex, Scalar, _scalar_mult_base, edwards_encode, ed25519_generate_public_key
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

    var priv_span = Span[UInt8, ...](priv)
    var hash = sha512_hash(priv_span)
    _ = priv_span

    var r_in = List[UInt8](capacity=32)
    for i in range(32):
        r_in.append(hash[32 + i])
    var r_in_span = Span[UInt8, ...](r_in)
    var r_hash = sha512_hash(r_in_span)
    _ = r_in

    var r_hash_span = Span[UInt8, ...](r_hash)
    var r_scalar = Scalar.from_bytes_wide(r_hash_span)
    _ = r_hash

    var s = List[UInt8](capacity=32)
    for i in range(32):
        s.append(hash[i])
    s[0] = s[0] & 0xF8; s[31] = s[31] & 0x7F; s[31] = s[31] | 0x40

    var s_span = Span[UInt8, ...](s)
    var s_scalar = Scalar.from_bytes(s_span)
    _ = s

    var priv_span2 = Span[UInt8, ...](priv)
    var A_enc = ed25519_generate_public_key(priv_span2)
    _ = priv_span2
    print("A_enc:", bytes_to_hex(A_enc))
    print("A_exp: d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")

    var r_bytes = r_scalar.to_bytes()
    print("r_bytes:", bytes_to_hex(r_bytes))
    print("r_exp:   f38907308c893deaf244787db4af53682249107418afc2edc58f75ac58a07404")

    var r_bytes_span = Span[UInt8, ...](r_bytes)
    var R = _scalar_mult_base(r_bytes_span)
    _ = r_bytes
    var R_enc = edwards_encode(R)
    print("R_enc:", bytes_to_hex(R_enc))
    print("R_exp: e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155")
