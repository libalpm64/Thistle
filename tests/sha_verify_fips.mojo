from thistle.sha2 import (
    sha224_hash,
    sha256_hash,
    sha384_hash,
    sha512_hash,
    bytes_to_hex,
)
from thistle.sha3 import sha3_224, sha3_256, sha3_384, sha3_512
from collections import List


fn hex_to_byte(h: String) -> UInt8:
    var val: UInt8 = 0
    var bytes = h.as_bytes()

    var c0 = Int(bytes[0])
    if c0 >= ord("0") and c0 <= ord("9"):
        val = UInt8(c0 - ord("0"))
    elif c0 >= ord("a") and c0 <= ord("f"):
        val = UInt8(c0 - ord("a") + 10)
    elif c0 >= ord("A") and c0 <= ord("F"):
        val = UInt8(c0 - ord("A") + 10)

    val <<= 4

    var c1 = Int(bytes[1])
    if c1 >= ord("0") and c1 <= ord("9"):
        val |= UInt8(c1 - ord("0"))
    elif c1 >= ord("a") and c1 <= ord("f"):
        val |= UInt8(c1 - ord("a") + 10)
    elif c1 >= ord("A") and c1 <= ord("F"):
        val |= UInt8(c1 - ord("A") + 10)
    return val


fn hex_to_bytes(s: String) -> List[UInt8]:
    var res = List[UInt8]()
    if len(s) == 0 or s == "00":
        return res^
    for i in range(0, len(s), 2):
        if i + 1 < len(s):
            res.append(hex_to_byte(String(s[i : i + 2])))
    return res^


fn run_fips_file(file_path: String, algo: String) -> Bool:
    print("Testing " + algo + " with " + file_path + "...")
    try:
        var f = open(file_path, "r")
        var content = f.read()
        f.close()

        var lines = content.split("\n")
        var current_len = -1
        var current_msg = String("")
        var current_md = String("")
        var pass_count = 0
        var fail_count = 0

        for i in range(len(lines)):
            var line = lines[i].strip()
            if line.startswith("Len ="):
                var parts = line.split("=")
                current_len = Int(String(parts[1].strip()))
            elif line.startswith("Msg ="):
                var parts = line.split("=")
                current_msg = String(parts[1].strip())
            elif line.startswith("MD ="):
                var parts = line.split("=")
                current_md = String(parts[1].strip())

                # Run test
                if current_len >= 0:
                    var msg_bytes = hex_to_bytes(current_msg)
                    var got_hash = String("")

                    if algo == "SHA-224":
                        got_hash = bytes_to_hex(
                            sha224_hash(Span[UInt8](msg_bytes))
                        )
                    elif algo == "SHA-256":
                        got_hash = bytes_to_hex(
                            sha256_hash(Span[UInt8](msg_bytes))
                        )
                    elif algo == "SHA-384":
                        got_hash = bytes_to_hex(
                            sha384_hash(Span[UInt8](msg_bytes))
                        )
                    elif algo == "SHA-512":
                        got_hash = bytes_to_hex(
                            sha512_hash(Span[UInt8](msg_bytes))
                        )
                    elif algo == "SHA3-224":
                        got_hash = bytes_to_hex(
                            sha3_224(Span[UInt8](msg_bytes))
                        )
                    elif algo == "SHA3-256":
                        got_hash = bytes_to_hex(
                            sha3_256(Span[UInt8](msg_bytes))
                        )
                    elif algo == "SHA3-384":
                        got_hash = bytes_to_hex(
                            sha3_384(Span[UInt8](msg_bytes))
                        )
                    elif algo == "SHA3-512":
                        got_hash = bytes_to_hex(
                            sha3_512(Span[UInt8](msg_bytes))
                        )

                    if got_hash == current_md.lower():
                        pass_count += 1
                    else:
                        print("  [failure] Len=" + String(current_len))
                        print("    Exp: " + current_md.lower())
                        print("    Got: " + got_hash)
                        fail_count += 1
                        return False

                # Reset for next vector
                current_len = -1

        print("  [pass] " + String(pass_count) + " vectors passed")
        return True
    except e:
        print("  [error] " + String(e))
        return False


fn main():
    var base_sha2 = "tests/FIPS-180-4/shabytetestvectors/"
    var all_passed = True

    all_passed &= run_fips_file(base_sha2 + "SHA224ShortMsg.rsp", "SHA-224")
    all_passed &= run_fips_file(base_sha2 + "SHA256ShortMsg.rsp", "SHA-256")
    all_passed &= run_fips_file(base_sha2 + "SHA384ShortMsg.rsp", "SHA-384")
    all_passed &= run_fips_file(base_sha2 + "SHA512ShortMsg.rsp", "SHA-512")

    var base_sha3 = "tests/FIPS 202/sha-3bytetestvectors/"
    all_passed &= run_fips_file(base_sha3 + "SHA3_224ShortMsg.rsp", "SHA3-224")
    all_passed &= run_fips_file(base_sha3 + "SHA3_256ShortMsg.rsp", "SHA3-256")
    all_passed &= run_fips_file(base_sha3 + "SHA3_384ShortMsg.rsp", "SHA3-384")
    all_passed &= run_fips_file(base_sha3 + "SHA3_512ShortMsg.rsp", "SHA3-512")

    if all_passed:
        print("\nAll fips SM tests pass!")
    else:
        print("\nFips test failure!")
