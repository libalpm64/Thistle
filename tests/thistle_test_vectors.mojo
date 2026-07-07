from std.python import Python, PythonObject
from std.collections import List
from std.memory import alloc
from std.memory.unsafe_pointer import UnsafePointer
from std.builtin.type_aliases import MutExternalOrigin
from thistle.sha2 import (
    bytes_to_hex,
    string_to_bytes,
    sha224_hash_bits,
    sha256_hash_bits,
    sha384_hash_bits,
)
from thistle.argon2 import Argon2id
from thistle.blake2b import Blake2b
from thistle.blake3 import blake3_parallel_hash
from thistle.camellia import CamelliaCipher
from thistle.chacha20 import ChaCha20
from thistle.kcipher2 import KCipher2
from thistle.pbkdf2 import pbkdf2_hmac_sha256, pbkdf2_hmac_sha512
from thistle.aes import cpu_aes_encrypt, expand_key_128
from thistle.aes_ni import aes_encrypt, has_aes_ni, has_x86_aes_ni, aes_gcm_encrypt, aes_gcm_decrypt
from thistle.sha_ni import sha256ni_hash, has_sha_ni


def hex_char_to_val(c: Int) -> UInt8:
    if c <= 57:
        return UInt8(c - 48)
    if c <= 70:
        return UInt8(c - 55)
    return UInt8(c - 87)


def hex_to_bytes(hex_str: String) -> List[UInt8]:
    var res = List[UInt8]()
    var bytes_view = hex_str.as_bytes()
    var i = 0
    while i < hex_str.byte_length() - 1:
        res.append(
            (hex_char_to_val(Int(bytes_view[i])) << 4)
            | hex_char_to_val(Int(bytes_view[i + 1]))
        )
        i += 2
    return res^


def hex_to_u32_list(hex_str: String) -> SIMD[DType.uint32, 4]:
    var result = SIMD[DType.uint32, 4](0)
    var s = hex_str.as_bytes()
    for i in range(4):
        var val = 0
        for j in range(8):
            val = (val << 4) | Int(hex_char_to_val(Int(s[i * 8 + j])))
        result[i] = UInt32(val)
    return result


def u64_to_hex(z: UInt64) -> String:
    var bytes = List[UInt8]()
    for shift in range(56, -1, -8):
        bytes.append(UInt8((z >> UInt64(shift)) & 0xFF))
    return bytes_to_hex(bytes)


def byte_to_hex(b: UInt8) -> String:
    var hi = Int(b >> 4)
    var lo = Int(b & 0xF)
    return chr(48 + hi if hi < 10 else 87 + hi) + chr(
        48 + lo if lo < 10 else 87 + lo
    )


def ptr_to_hex(ptr: UnsafePointer[UInt8, MutAnyOrigin], count: Int) -> String:
    var s = String("")
    for j in range(count):
        s += byte_to_hex(ptr.load(j))
    return s


def generate_blake3_input(length: Int) -> List[UInt8]:
    var data = List[UInt8](capacity=length)
    for i in range(length):
        data.append(UInt8(i % 251))
    return data^


def list_to_simd32(lst: List[UInt8]) -> SIMD[DType.uint8, 32]:
    var result = SIMD[DType.uint8, 32](0)
    for i in range(min(len(lst), 32)):
        result[i] = lst[i]
    return result


def list_to_simd12(lst: List[UInt8]) -> SIMD[DType.uint8, 12]:
    var result = SIMD[DType.uint8, 12](0)
    for i in range(min(len(lst), 12)):
        result[i] = lst[i]
    return result


@fieldwise_init
struct TestResult(Copyable, Movable):
    var passed: Int
    var failed: Int
    var failures: List[String]


def load_json(path: String, py: PythonObject) raises -> PythonObject:
    var builtins = Python.import_module("builtins")
    var f = builtins.open(path, "r", encoding="utf-8")
    var data = py.loads(f.read())
    f.close()
    return data


def test_argon2(data: PythonObject, py: PythonObject) raises -> TestResult:
    var passed, failed = 0, 0
    var failures = List[String]()
    for i in range(Int(py=data.__len__())):
        var v = data[i]
        var name = String(v["name"])
        var pass_str = String(v["password"])
        var salt_str = String(v["salt"])
        var pass_bytes = string_to_bytes(pass_str)
        var salt_bytes = string_to_bytes(salt_str)
        var argon2 = Argon2id(
            salt_bytes,
            parallelism=Int(py=v["parallelism"]),
            tag_length=Int(py=v["tag_length"]),
            memory_size_kb=Int(py=v["memory_size_kb"]),
            iterations=Int(py=v["iterations"]),
            version=Int(py=v["version"]),
        )
        var got = bytes_to_hex(argon2.hash(Span[UInt8, ...](pass_bytes)))
        var expected = String(v["hash"])
        if got == expected:
            passed += 1
        else:
            failed += 1
            failures.append(
                "Argon2 " + name + ": expected " + expected + ", got " + got
            )
    return TestResult(passed, failed, failures^)


def test_blake2b(data: PythonObject, py: PythonObject) raises -> TestResult:
    var passed, failed = 0, 0
    var failures = List[String]()
    for i in range(Int(py=data.__len__())):
        var v = data[i]
        var name = String(v["name"])
        var expected = String(v["hash"])
        var ctx = Blake2b(Int(py=v["digest_size"]))
        ctx.update(Span[UInt8, ...](hex_to_bytes(String(v["input"]))))
        var got = bytes_to_hex(ctx.finalize())
        if got == expected:
            passed += 1
        else:
            failed += 1
            failures.append(
                "BLAKE2b " + name + ": expected " + expected + ", got " + got
            )
    return TestResult(passed, failed, failures^)


def test_blake3(data: PythonObject, py: PythonObject) raises -> TestResult:
    var passed, failed = 0, 0
    var failures = List[String]()
    var cases = data["cases"]
    for i in range(Int(py=cases.__len__())):
        var v = cases[i]
        var input_len = Int(py=v["input_len"])
        var expected = String(v["hash"])
        var got = bytes_to_hex(
            blake3_parallel_hash(
                Span[UInt8, ...](generate_blake3_input(input_len)),
                expected.byte_length() // 2,
            )
        )
        if got == expected:
            passed += 1
        else:
            failed += 1
            failures.append(
                "BLAKE3 "
                + String(input_len)
                + " bytes: expected "
                + expected
                + ", got "
                + got
            )
    return TestResult(passed, failed, failures^)


def test_camellia(data: PythonObject, py: PythonObject) raises -> TestResult:
    var passed, failed = 0, 0
    var failures = List[String]()
    for i in range(Int(py=data.__len__())):
        var v = data[i]
        var name = String(v["name"])
        var key = hex_to_bytes(String(v["key"]))
        var pt_hex = String(v["plaintext"])
        var ct_hex = String(v["ciphertext"])
        var cipher = CamelliaCipher(Span[UInt8, ...](key))
        var got_ct = bytes_to_hex(
            cipher.encrypt(Span[UInt8, ...](hex_to_bytes(pt_hex)))
        )
        if got_ct == ct_hex:
            passed += 1
        else:
            failed += 1
            failures.append(
                "Camellia "
                + name
                + " enc: expected "
                + ct_hex
                + ", got "
                + got_ct
            )
        var got_pt = bytes_to_hex(
            cipher.decrypt(Span[UInt8, ...](hex_to_bytes(ct_hex)))
        )
        if got_pt == pt_hex:
            passed += 1
        else:
            failed += 1
            failures.append(
                "Camellia "
                + name
                + " dec: expected "
                + pt_hex
                + ", got "
                + got_pt
            )
    return TestResult(passed, failed, failures^)


def test_chacha20(data: PythonObject, py: PythonObject) raises -> TestResult:
    var passed, failed = 0, 0
    var failures = List[String]()
    for i in range(Int(py=data.__len__())):
        var v = data[i]
        var name = String(v["name"])
        var cipher = ChaCha20(
            list_to_simd32(hex_to_bytes(String(v["key"]))),
            list_to_simd12(hex_to_bytes(String(v["nonce"]))),
            UInt32(Int(py=v["counter"])),
        )
        var pt_bytes = hex_to_bytes(String(v["plaintext"]))
        var expected_ct = hex_to_bytes(String(v["ciphertext"]))
        if len(pt_bytes) == 0:
            var null_ptr = UnsafePointer[
                UInt8, MutExternalOrigin
            ].unsafe_dangling()
            var out_span = Span[mut=True, UInt8, MutExternalOrigin](
                ptr=null_ptr, length=0
            )
            cipher.encrypt_into(Span[UInt8, ...](ptr=null_ptr, length=0), out_span)
            if len(expected_ct) == 0:
                passed += 1
            else:
                failed += 1
                failures.append(
                    "ChaCha20 " + name + ": empty plaintext test failed"
                )
        else:
            var ct_ptr = alloc[UInt8](len(pt_bytes))
            var ct_span = Span[mut=True, UInt8, MutExternalOrigin](
                ptr=ct_ptr, length=len(pt_bytes)
            )
            cipher.encrypt_into(Span[UInt8, ...](pt_bytes), ct_span)
            var ok = len(pt_bytes) == len(expected_ct)
            if ok:
                for j in range(len(pt_bytes)):
                    if ct_ptr[j] != expected_ct[j]:
                        ok = False
                        break
            if ok:
                passed += 1
            else:
                failed += 1
                failures.append(
                    "ChaCha20 "
                    + name
                    + ": expected "
                    + String(v["ciphertext"])
                    + ", got "
                    + ptr_to_hex(ct_ptr, min(len(pt_bytes), 16))
                    + "..."
                )
            ct_ptr.free()
    return TestResult(passed, failed, failures^)


def test_kcipher2(data: PythonObject, py: PythonObject) raises -> TestResult:
    var passed, failed = 0, 0
    var failures = List[String]()
    var vectors = data["test_vectors"]
    for i in range(Int(py=vectors.__len__())):
        var v = vectors[i]
        var kc2 = KCipher2(
            hex_to_u32_list(String(v["key"])), hex_to_u32_list(String(v["iv"]))
        )
        var key_streams = v["key_streams"]
        for j in range(Int(py=key_streams.__len__())):
            var expected = String(key_streams[j]).upper()
            var z = kc2.stream()
            kc2._next_normal()
            var got = u64_to_hex(z).upper()
            if got == expected:
                passed += 1
            else:
                failed += 1
                failures.append(
                    "KCipher2 vector "
                    + String(i)
                    + " stream "
                    + String(j)
                    + ": expected "
                    + expected
                    + ", got "
                    + got
                )
    return TestResult(passed, failed, failures^)


def _test_pbkdf2_sha256(
    data: PythonObject, py: PythonObject
) raises -> TestResult:
    var passed, failed = 0, 0
    var failures = List[String]()
    for i in range(Int(py=data.__len__())):
        var v = data[i]
        var password = hex_to_bytes(String(v["password"]))
        var salt = hex_to_bytes(String(v["salt"]))
        var got = bytes_to_hex(
            pbkdf2_hmac_sha256(
                password,
                Span[UInt8, ...](salt),
                Int(py=v["iterations"]),
                Int(py=v["dklen"]),
            )
        )
        var expected = String(v["derived_key"])
        if got == expected:
            passed += 1
        else:
            failed += 1
            failures.append(
                "PBKDF2-SHA256: expected " + expected + ", got " + got
            )
    return TestResult(passed, failed, failures^)


def _test_pbkdf2_sha512(
    data: PythonObject, py: PythonObject
) raises -> TestResult:
    var passed, failed = 0, 0
    var failures = List[String]()
    for i in range(Int(py=data.__len__())):
        var v = data[i]
        var password = hex_to_bytes(String(v["password"]))
        var salt = hex_to_bytes(String(v["salt"]))
        var got = bytes_to_hex(
            pbkdf2_hmac_sha512(
                password,
                Span[UInt8, ...](salt),
                Int(py=v["iterations"]),
                Int(py=v["dklen"]),
            )
        )
        var expected = String(v["derived_key"])
        if got == expected:
            passed += 1
        else:
            failed += 1
            failures.append(
                "PBKDF2-SHA512: expected " + expected + ", got " + got
            )
    return TestResult(passed, failed, failures^)


def test_pbkdf2(data: PythonObject, py: PythonObject) raises -> TestResult:
    var r = _test_pbkdf2_sha256(data["sha256"], py)
    var r2 = _test_pbkdf2_sha512(data["sha512"], py)
    r.passed += r2.passed
    r.failed += r2.failed
    for i in range(len(r2.failures)):
        r.failures.append(r2.failures[i])
    return r^


def _test_sha224(data: PythonObject, py: PythonObject) raises -> TestResult:
    var passed, failed = 0, 0
    var failures = List[String]()
    for i in range(Int(py=data.__len__())):
        var v = data[i]
        var bit_len = Int(py=v["len"])
        var msg = (
            hex_to_bytes(String(v["msg"])) if bit_len > 0 else List[UInt8]()
        )
        var got = bytes_to_hex(sha224_hash_bits(Span[UInt8, ...](msg), bit_len))
        var expected = String(v["md"])
        if got == expected:
            passed += 1
        else:
            failed += 1
            failures.append(
                "SHA224 len="
                + String(bit_len)
                + ": expected "
                + expected
                + ", got "
                + got
            )
    return TestResult(passed, failed, failures^)


def _test_sha256(data: PythonObject, py: PythonObject) raises -> TestResult:
    var passed, failed = 0, 0
    var failures = List[String]()
    for i in range(Int(py=data.__len__())):
        var v = data[i]
        var bit_len = Int(py=v["len"])
        var msg = (
            hex_to_bytes(String(v["msg"])) if bit_len > 0 else List[UInt8]()
        )
        var got = bytes_to_hex(sha256_hash_bits(Span[UInt8, ...](msg), bit_len))
        var expected = String(v["md"])
        if got == expected:
            passed += 1
        else:
            failed += 1
            failures.append(
                "SHA256 len="
                + String(bit_len)
                + ": expected "
                + expected
                + ", got "
                + got
            )
    return TestResult(passed, failed, failures^)


def _test_sha384(data: PythonObject, py: PythonObject) raises -> TestResult:
    var passed, failed = 0, 0
    var failures = List[String]()
    for i in range(Int(py=data.__len__())):
        var v = data[i]
        var bit_len = Int(py=v["len"])
        var msg = (
            hex_to_bytes(String(v["msg"])) if bit_len > 0 else List[UInt8]()
        )
        var got = bytes_to_hex(sha384_hash_bits(Span[UInt8, ...](msg), bit_len))
        var expected = String(v["md"])
        if got == expected:
            passed += 1
        else:
            failed += 1
            failures.append(
                "SHA384 len="
                + String(bit_len)
                + ": expected "
                + expected
                + ", got "
                + got
            )
    return TestResult(passed, failed, failures^)


def test_sha(data: PythonObject, py: PythonObject) raises -> TestResult:
    var r = _test_sha224(data["sha224"], py)
    var r256 = _test_sha256(data["sha256"], py)
    var r384 = _test_sha384(data["sha384"], py)
    r.passed += r256.passed + r384.passed
    r.failed += r256.failed + r384.failed
    for i in range(len(r256.failures)):
        r.failures.append(r256.failures[i])
    for i in range(len(r384.failures)):
        r.failures.append(r384.failures[i])
    return r^


def test_aes_cpu(data: PythonObject, py: PythonObject) raises -> TestResult:
    var passed, failed = 0, 0
    var failures = List[String]()
    for i in range(Int(py=data.__len__())):
        var v = data[i]
        var key_bytes = hex_to_bytes(String(v["key"]))
        var pt_bytes = hex_to_bytes(String(v["plaintext"]))
        var expected_ct = String(v["ciphertext"])
        var key_ptr = alloc[UInt8](16)
        var pt_ptr = alloc[UInt8](16)
        for j in range(16):
            key_ptr.store(j, key_bytes[j])
            pt_ptr.store(j, pt_bytes[j])
        var round_keys = expand_key_128(key_ptr)
        cpu_aes_encrypt(pt_ptr, round_keys)
        var got = ptr_to_hex(pt_ptr, 16)
        if got == expected_ct:
            passed += 1
        else:
            failed += 1
            failures.append(
                "AES-CPU "
                + String(v["name"])
                + ": expected "
                + expected_ct
                + ", got "
                + got
            )
        key_ptr.free()
        round_keys.free()
        pt_ptr.free()
    return TestResult(passed, failed, failures^)


def test_aes_ni(data: PythonObject, py: PythonObject) raises -> TestResult:
    var passed, failed = 0, 0
    var failures = List[String]()
    var has_ni = has_aes_ni()
    var has_x86 = has_x86_aes_ni()
    if not has_ni:
        print("  (AES-NI not available, skipping)")
        return TestResult(0, 0, failures^)
    print("  (using AES-NI: x86=" + String(has_x86) + ")")
    for i in range(Int(py=data.__len__())):
        var v = data[i]
        var key_bytes = hex_to_bytes(String(v["key"]))
        var pt_bytes = hex_to_bytes(String(v["plaintext"]))
        var expected_ct = String(v["ciphertext"])
        var key_ptr = alloc[UInt8](16)
        var pt_ptr = alloc[UInt8](16)
        for j in range(16):
            key_ptr.store(j, key_bytes[j])
            pt_ptr.store(j, pt_bytes[j])
        var round_keys = expand_key_128(key_ptr)
        aes_encrypt(pt_ptr, round_keys, 10)
        var got = ptr_to_hex(pt_ptr, 16)
        if got == expected_ct:
            passed += 1
        else:
            failed += 1
            failures.append(
                "AES-NI "
                + String(v["name"])
                + ": expected "
                + expected_ct
                + ", got "
                + got
            )
        key_ptr.free()
        round_keys.free()
        pt_ptr.free()
    return TestResult(passed, failed, failures^)


def test_sha_ni(data: PythonObject, py: PythonObject) raises -> TestResult:
    var passed, failed = 0, 0
    var failures = List[String]()
    var has_ni = has_sha_ni()
    if not has_ni:
        print("  (SHA-NI not available, skipping)")
        return TestResult(0, 0, failures^)
    print("  (using SHA-NI)")

    var sha256_data = data["sha256"]
    for i in range(Int(py=sha256_data.__len__())):
        var v = sha256_data[i]
        var bit_len = Int(py=v["len"])
        var msg = (
            hex_to_bytes(String(v["msg"])) if bit_len > 0 else List[UInt8]()
        )
        var got = bytes_to_hex(sha256ni_hash(Span[UInt8, ...](msg)))
        var expected = String(v["md"])
        if got == expected:
            passed += 1
        else:
            failed += 1
            failures.append(
                "SHA256-NI len="
                + String(bit_len)
                + ": expected "
                + expected
                + ", got "
                + got
            )
    return TestResult(passed, failed, failures^)


def test_aes_gcm(data: PythonObject, py: PythonObject) raises -> TestResult:
    var passed, failed = 0, 0
    var failures = List[String]()
    var groups = data["testGroups"]
    for g in groups:
        for t in g["tests"]:
            var tc_id = String(t["tcId"])
            var key = hex_to_bytes(String(t["key"]))
            var iv = hex_to_bytes(String(t["iv"]))
            var aad = hex_to_bytes(String(t["aad"]))
            var msg = hex_to_bytes(String(t["msg"]))
            var ct = hex_to_bytes(String(t["ct"]))
            var tag = hex_to_bytes(String(t["tag"]))
            var valid = String(t["result"]) == "valid"

            var ok: Bool
            if valid:
                ok = False
                try:
                    var enc = aes_gcm_encrypt(
                        Span[UInt8, ...](key), Span[UInt8, ...](iv),
                        Span[UInt8, ...](msg), Span[UInt8, ...](aad),
                    )
                    var dec = aes_gcm_decrypt(
                        Span[UInt8, ...](key), Span[UInt8, ...](iv),
                        Span[UInt8, ...](ct), Span[UInt8, ...](aad),
                        Span[UInt8, ...](tag),
                    )
                    ok = (
                        bytes_to_hex(enc[0]) == bytes_to_hex(ct)
                        and bytes_to_hex(enc[1]) == bytes_to_hex(tag)
                        and dec[1]
                        and bytes_to_hex(dec[0]) == bytes_to_hex(msg)
                    )
                except:
                    ok = False
            else:
                try:
                    var dec = aes_gcm_decrypt(
                        Span[UInt8, ...](key), Span[UInt8, ...](iv),
                        Span[UInt8, ...](ct), Span[UInt8, ...](aad),
                        Span[UInt8, ...](tag),
                    )
                    ok = (not dec[1]) and len(dec[0]) == 0
                except:
                    ok = True

            if ok:
                passed += 1
            else:
                failed += 1
                failures.append("AES-GCM tc" + tc_id)
    return TestResult(passed, failed, failures^)


def print_result(
    name: String, result: TestResult, mut tp: Int, mut tf: Int, mut af: Bool
):
    if result.failed == 0:
        print(
            "Testing "
            + name
            + " [pass] ("
            + String(result.passed)
            + " vectors)"
        )
    else:
        print(
            "Testing "
            + name
            + " [fail] ("
            + String(result.passed)
            + "/"
            + String(result.passed + result.failed)
            + " passed)"
        )
        for i in range(len(result.failures)):
            print("  - " + result.failures[i])
    tp += result.passed
    tf += result.failed
    if result.failed > 0:
        af = True


def main() raises:
    print("Thistle Crypto Test Vectors\n")
    var py = Python.import_module("json")
    var tp, tf = 0, 0
    var af = False

    try:
        print("Loading Argon2 vectors...")
        print_result(
            "Argon2",
            test_argon2(load_json("tests/vectors/argon2.json", py), py),
            tp,
            tf,
            af,
        )
    except e:
        print("Argon2 [error] " + String(e))
        af = True
    print()

    try:
        print("Loading BLAKE2b vectors...")
        print_result(
            "BLAKE2b",
            test_blake2b(load_json("tests/vectors/blake2b.json", py), py),
            tp,
            tf,
            af,
        )
    except e:
        print("BLAKE2b [error] " + String(e))
        af = True
    print()

    try:
        print("Loading BLAKE3 vectors...")
        print_result(
            "BLAKE3",
            test_blake3(load_json("tests/vectors/blake3.json", py), py),
            tp,
            tf,
            af,
        )
    except e:
        print("BLAKE3 [error] " + String(e))
        af = True
    print()

    try:
        print("Loading Camellia vectors...")
        print_result(
            "Camellia",
            test_camellia(load_json("tests/vectors/camellia.json", py), py),
            tp,
            tf,
            af,
        )
    except e:
        print("Camellia [error] " + String(e))
        af = True
    print()

    try:
        print("Loading ChaCha20 vectors...")
        print_result(
            "ChaCha20",
            test_chacha20(load_json("tests/vectors/chacha20.json", py), py),
            tp,
            tf,
            af,
        )
    except e:
        print("ChaCha20 [error] " + String(e))
        af = True
    print()

    try:
        print("Loading KCipher2 vectors...")
        print_result(
            "KCipher2",
            test_kcipher2(load_json("tests/vectors/kcipher2.json", py), py),
            tp,
            tf,
            af,
        )
    except e:
        print("KCipher2 [error] " + String(e))
        af = True
    print()

    try:
        print("Loading PBKDF2 vectors...")
        print_result(
            "PBKDF2",
            test_pbkdf2(load_json("tests/vectors/pbkdf2.json", py), py),
            tp,
            tf,
            af,
        )
    except e:
        print("PBKDF2 [error] " + String(e))
        af = True
    print()

    try:
        print("Loading SHA vectors...")
        print_result(
            "SHA",
            test_sha(load_json("tests/vectors/sha.json", py), py),
            tp,
            tf,
            af,
        )
    except e:
        print("SHA [error] " + String(e))
        af = True
    print()

    try:
        print("Loading AES vectors...")
        print_result(
            "AES-128-CPU",
            test_aes_cpu(load_json("tests/vectors/aes.json", py), py),
            tp,
            tf,
            af,
        )
    except e:
        print("AES-128-CPU [error] " + String(e))
        af = True
    print()

    try:
        print("Testing AES-NI...")
        print_result(
            "AES-128-NI",
            test_aes_ni(load_json("tests/vectors/aes.json", py), py),
            tp,
            tf,
            af,
        )
    except e:
        print("AES-128-NI [error] " + String(e))
        af = True
    print()

    try:
        print("Loading AES-GCM Wycheproof vectors...")
        print_result(
            "AES-GCM",
            test_aes_gcm(load_json("tests/Wycheproof/aes_gcm_test.json", py), py),
            tp,
            tf,
            af,
        )
    except e:
        print("AES-GCM [error] " + String(e))
        af = True
    print()

    try:
        print("Testing SHA-NI...")
        print_result(
            "SHA256-NI",
            test_sha_ni(load_json("tests/vectors/sha.json", py), py),
            tp,
            tf,
            af,
        )
    except e:
        print("SHA256-NI [error] " + String(e))
        af = True
    print()

    print("Total: " + String(tp) + " pass, " + String(tf) + " fail")
    print("Tests pass" if not af else "Tests fail")
