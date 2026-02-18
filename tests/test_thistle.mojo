from thistle import (
    sha256_hash,
    sha512_hash,
    blake3_hash,
    blake3_parallel_hash,
    Hasher,
    Argon2id,
    CamelliaCipher,
    pbkdf2_hmac_sha256,
    pbkdf2_hmac_sha512,
    blake2b_hash,
)
from thistle.sha2 import sha224_hash, sha384_hash, bytes_to_hex, string_to_bytes
from thistle.sha3 import sha3_224, sha3_256, sha3_384, sha3_512
from thistle.blake2b import blake2b_hash_string
from thistle.argon2 import argon2id_hash_string
from collections import List


fn sha256_hash_string(s: String) -> String:
    return bytes_to_hex(sha256_hash(Span[UInt8](string_to_bytes(s))))


fn sha512_hash_string(s: String) -> String:
    return bytes_to_hex(sha512_hash(Span[UInt8](string_to_bytes(s))))


fn sha224_hash_string(s: String) -> String:
    return bytes_to_hex(sha224_hash(Span[UInt8](string_to_bytes(s))))


fn sha384_hash_string(s: String) -> String:
    return bytes_to_hex(sha384_hash(Span[UInt8](string_to_bytes(s))))


fn sha3_224_hash_string(s: String) -> String:
    return bytes_to_hex(sha3_224(Span[UInt8](string_to_bytes(s))))


fn sha3_256_hash_string(s: String) -> String:
    return bytes_to_hex(sha3_256(Span[UInt8](string_to_bytes(s))))


fn sha3_384_hash_string(s: String) -> String:
    return bytes_to_hex(sha3_384(Span[UInt8](string_to_bytes(s))))


fn sha3_512_hash_string(s: String) -> String:
    return bytes_to_hex(sha3_512(Span[UInt8](string_to_bytes(s))))


fn hex_char_to_val(c: Int) -> UInt8:
    if c >= 48 and c <= 57:  # '0'-'9'
        return UInt8(c - 48)
    if c >= 97 and c <= 102:  # 'a'-'f'
        return UInt8(c - 97 + 10)
    if c >= 65 and c <= 70:  # 'A'-'F'
        return UInt8(c - 65 + 10)
    return 0

fn hex_str_to_bytes(s: String) -> List[UInt8]:
    var res = List[UInt8]()
    var char_list = s.as_bytes()
    var i = 0
    var clean_hex = List[UInt8]()
    while i < len(char_list):
        var c = Int(char_list[i])
        if (
            (c >= 48 and c <= 57)
            or (c >= 97 and c <= 102)
            or (c >= 65 and c <= 70)
        ):
            clean_hex.append(UInt8(c))
        i += 1

    i = 0
    while i < len(clean_hex):
        var high = hex_char_to_val(Int(clean_hex[i]))
        var low: UInt8 = 0
        if i + 1 < len(clean_hex):
            low = hex_char_to_val(Int(clean_hex[i + 1]))
        res.append((high << 4) | low)
        i += 2
    return res^

fn check_test(name: String, got: String, expected: String) -> Bool:
    if got == expected:
        print("  [passed] " + name)
        return True
    else:
        print("  [failure] " + name)
        print("    Expected: " + expected)
        print("    Got:      " + got)
        return False

fn main():
    print("Running Thistle Tests...")
    var all_passed = True

    print("\nSHA-2:")
    all_passed &= check_test(
        'SHA-256("")',
        sha256_hash_string(""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    all_passed &= check_test(
        'SHA-256("abc")',
        sha256_hash_string("abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    )
    all_passed &= check_test(
        'SHA-512("")',
        sha512_hash_string(""),
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    )

    print("\nSHA-3:")
    all_passed &= check_test(
        'SHA3-256("abc")',
        sha3_256_hash_string("abc"),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    )

    print("\nBlake3:")
    var h3 = Hasher()
    var out3 = List[UInt8]()
    for _ in range(32):
        out3.append(0)
    h3.finalize(out3.unsafe_ptr().as_any_origin(), 32)
    all_passed &= check_test(
        'Blake3("")',
        bytes_to_hex(out3),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    )

    print("\nArgon2id:")
    var pwd_bytes = List[UInt8]()
    for _ in range(32):
        pwd_bytes.append(1)
    var salt_bytes = List[UInt8]()
    for _ in range(16):
        salt_bytes.append(2)
    var argon2 = Argon2id(
        salt=Span[UInt8](salt_bytes), memory_size_kb=32, iterations=3
    )
    _ = argon2.hash(Span[UInt8](pwd_bytes))

    print("\nPBKDF2:")
    all_passed &= check_test(
        'PBKDF2-SHA256("password", "salt", 1, 32)',
        bytes_to_hex(pbkdf2_hmac_sha256("password".as_bytes(), "salt".as_bytes(), 1, 32)),
        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
    )
    all_passed &= check_test(
        'PBKDF2-SHA512("password", "salt", 1, 64)',
        bytes_to_hex(pbkdf2_hmac_sha512("password".as_bytes(), "salt".as_bytes(), 1, 64)),
        "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce",
    )

    print("\nCamellia Implementation")
    var cam_k128 = hex_str_to_bytes(
        "01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"
    )
    var cam_p128 = hex_str_to_bytes(
        "01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"
    )
    var cam128 = CamelliaCipher(Span[UInt8](cam_k128))
    all_passed &= check_test(
        "Camellia-128 Enc",
        bytes_to_hex(cam128.encrypt(Span[UInt8](cam_p128))),
        "67673138549669730857065648eabe43",
    )
    if all_passed:
        print("All tests pass!")
    else:
        print("Some tests fail.")
