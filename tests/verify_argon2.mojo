from thistle.argon2 import Argon2id
from thistle.sha2 import bytes_to_hex
from thistle.blake2b import Blake2b
from testing import assert_equal


def test_blake2b():
    print("Testing Blake2b...")
    # RFC 7693 Appendix A, Blake2b-512 with empty input
    var ctx = Blake2b(64)
    var h = ctx.finalize()
    var hex = bytes_to_hex(h)
    var expected = "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"

    print("Actual:   " + hex)
    if hex == expected:
        print("Blake2b Test Passed!")
    else:
        print("Blake2b Test Failed!")


def main():
    test_blake2b()
    print("\nTesting Argon2id")

    var pwd = List[UInt8]()
    for _ in range(32):
        pwd.append(0x01)

    var salt = List[UInt8]()
    for _ in range(16):
        salt.append(0x02)

    var secret = List[UInt8]()
    for _ in range(8):
        secret.append(0x03)

    var ad = List[UInt8]()
    for _ in range(12):
        ad.append(0x04)

    var argon2 = Argon2id(
        Span[UInt8](salt),
        Span[UInt8](secret),
        Span[UInt8](ad),
        parallelism=4,
        tag_length=32,
        memory_size_kb=16,
        iterations=3,
        version=16,
    )

    var tag = argon2.hash(Span[UInt8](pwd))
    var tag_hex = bytes_to_hex(tag)

    var expected = (
        "8bc6df1fdc4b56a752f1a1f8fa787ee89c58eb5525c2bf34ca0d465caaa3c0aa"
    )
    print("Expected: " + expected)
    print("Actual:   " + tag_hex)

    if tag_hex == expected:
        print("Argon2id test pass!")
    else:
        print("Argon2id test failure.")
