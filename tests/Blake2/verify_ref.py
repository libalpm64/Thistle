import hashlib
import struct

def test_blake2b_empty():
    h = hashlib.blake2b(digest_size=64)
    print(f"Blake2b Empty: {h.hexdigest()}")

def test_argon2_h0():
    # p=4, tag=32, m=16, i=3, v=0x13, type=2
    # pwd=32x01, salt=16x02, secret=8x03, ad=12x04
    p = 4
    tag = 32
    m = 16
    i = 3
    v = 0x13
    t = 2
    
    pwd = b"\x01" * 32
    salt = b"\x02" * 16
    secret = b"\x03" * 8
    ad = b"\x04" * 12
    
    data = (
        struct.pack("<I", p) +
        struct.pack("<I", tag) +
        struct.pack("<I", m) +
        struct.pack("<I", i) +
        struct.pack("<I", v) +
        struct.pack("<I", t) +
        struct.pack("<I", len(pwd)) + pwd +
        struct.pack("<I", len(salt)) + salt +
        struct.pack("<I", len(secret)) + secret +
        struct.pack("<I", len(ad)) + ad
    )
    
    h = hashlib.blake2b(data, digest_size=64)
    print(f"Argon2 H0: {h.hexdigest()}")

if __name__ == "__main__":
    test_blake2b_empty()
    test_argon2_h0()
