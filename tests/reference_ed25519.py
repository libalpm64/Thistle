"""
Ed25519 implementation to verify Mojo IVs.

THIS CODE IS NOT SECURE DO NOT USE THIS IS A TEST FILE WRITTEN IN PYTHON FOR COMPILER DEBUGGING purposes
DO NOT USE THIS CODE FOR ANYTHING BUT TESTING PURPOSES AS ITS VERY INSECURE. YOU HAVE BEEN WARNED.

By Libalpm64. This File has no Copyrgiht.
"""
import hashlib

# --- Constants ---
p = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
d = -121665 * pow(121666, p-2, p) % p

# --- CF/PA ---

def sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()

def int_to_le(x: int, length: int = 32) -> bytes:
    return (x % (2**256)).to_bytes(length, 'little')

def le_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'little')

def point_add(P, Q):
    x1, y1 = P
    x2, y2 = Q
    # Edwards curve point operations (affine transform for simplicity purposes)
    common = d * x1 * x2 * y1 * y2
    x3 = (x1*y2 + y1*x2) * pow(1 + common, p-2, p) % p
    y3 = (y1*y2 + x1*x2) * pow(1 - common, p-2, p) % p
    return (x3, y3)

def scalar_mult(k: int, P):
    # Netural values
    R = (0, 1)
    Q = P
    while k > 0:
        if k & 1:
            R = point_add(R, Q)
        Q = point_add(Q, Q)
        k >>= 1
    return R

# --- enccode / decoder ---

def encode_point(P) -> bytes:
    x, y = P
    b = bytearray(int_to_le(y))
    if x & 1:
        b[31] |= 0x80
    return bytes(b)

def clamp_scalar(h: bytes) -> bytes:
    s = bytearray(h[:32])
    s[0] &= 248
    s[31] &= 127
    s[31] |= 64
    return bytes(s)

# -- init ---

# Base ptr
By = 4 * pow(5, p-2, p) % p
Bx2 = (By*By - 1) * pow(d*By*By + 1, p-2, p) % p
Bx = pow(Bx2, (p+3)//8, p)
if (Bx*Bx - Bx2) % p != 0:
    Bx = (Bx * pow(2, (p-1)//4, p)) % p
if Bx & 1 != 0:
    Bx = p - Bx
B = (Bx, By)

def run_test_vector():
    priv = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    h = sha512(priv)

    s_bytes = clamp_scalar(h)
    s_int = le_to_int(s_bytes)
    
    A = scalar_mult(s_int, B)
    A_enc = encode_point(A)

    # use an empty message
    msg = b""
    prefix = h[32:]
    r_hash = sha512(prefix + msg)
    r_int = le_to_int(r_hash) % L
    R = scalar_mult(r_int, B)
    R_enc = encode_point(R)

    # CHLNG / Signature
    k_hash = sha512(R_enc + A_enc + msg)
    k_int = le_to_int(k_hash) % L
    S_int = (r_int + k_int * s_int) % L
    S_bytes = int_to_le(S_int)
    
    # Verify
    SB = scalar_mult(S_int, B)
    kA = scalar_mult(k_int, A)
    # SB = R + kA
    RkA = point_add(R, kA)

    return {
        "Bx_hex": int_to_le(Bx).hex(),
        "By_hex": int_to_le(By).hex(),
        "d_hex": int_to_le(d).hex(),
        "s_hex": s_bytes.hex(),
        "s_int": s_int,
        "A_enc": A_enc.hex(),
        "r_hex": int_to_le(r_int).hex(),
        "R_enc": R_enc.hex(),
        "k_hex": int_to_le(k_int).hex(),
        "S_hex": S_bytes.hex(),
        "sig": (R_enc + S_bytes).hex(),
        "SB_hex": encode_point(SB).hex(),
        "RkA_hex": encode_point(RkA).hex(),
        "match": SB == RkA
    }

res = run_test_vector()

print(f"Ref Ed25519")
print(f"Base point X: {res['Bx_hex']}")
print(f"Base point Y: {res['By_hex']}")
print(f"d constant:   {res['d_hex']}")
print("-" * 40)
print(f"Clamped scalar s: {res['s_hex']}")
print(f"s as integer:     {res['s_int']}")
print(f"Public key:       {res['A_enc']}")
print(f"Expected A:       d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
print("-" * 40)
print(f"r scalar:         {res['r_hex']}")
print(f"R encoded:        {res['R_enc']}")
print(f"k scalar:         {res['k_hex']}")
print(f"S bytes:          {res['S_hex']}")
print(f"Signature:        {res['sig']}")
print(f"Expected Sig:     e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
print("-" * 40)
print(f"Verification SB:   {res['SB_hex']}")
print(f"Verification RkA:  {res['RkA_hex']}")
print(f"Match:             {res['match']}")
