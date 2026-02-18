from thistle.argon2 import Argon2id
from thistle.sha2 import bytes_to_hex
from thistle.blake2b import Blake2b
from testing import assert_equal


def test_blake2b():
    print("Testing Blake2b...")
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
    print("\nTesting Argon2id - Simple case (p=1, m=1024, t=2)")

    var pwd = String("password").as_bytes()
    var salt = String("somesalt").as_bytes()

    var argon2 = Argon2id(
        salt,
        parallelism=1,
        tag_length=32,
        memory_size_kb=1024,
        iterations=2,
        version=19,
    )

    var tag = argon2.hash(pwd)
    var tag_hex = bytes_to_hex(tag)

    var expected = "ec57ec9c0eaf51eeea2e92ffdcaa9cdee478f1927215b515b7b8d66657f41ed9"
    print("Expected: " + expected)
    print("Actual:   " + tag_hex)

    if tag_hex == expected:
        print("Argon2id test pass!")
    else:
        print("Argon2id test failure.")
