from std.python import Python, PythonObject
from std.collections import List
from std.memory import alloc
from std.memory.unsafe_pointer import UnsafePointer
from std.builtin.type_aliases import MutExternalOrigin
from thistle.sha2 import bytes_to_hex, sha224_hash, sha256_hash, sha384_hash, sha512_hash
from thistle.argon2 import Argon2id
from thistle.blake2b import Blake2b
from thistle.blake3 import blake3_parallel_hash
from thistle.camellia import CamelliaCipher
from thistle.chacha20 import ChaCha20
from thistle.kcipher2 import KCipher2
from thistle.pbkdf2 import pbkdf2_hmac_sha256, pbkdf2_hmac_sha512
from thistle.aes import cpu_aes_encrypt, expand_key_128


fn hex_char_to_val(c: Int) -> UInt8:
    if c <= 57:
        return UInt8(c - 48)
    if c <= 70:
        return UInt8(c - 55)
    return UInt8(c - 87)

fn hex_to_bytes(hex_str: String) -> List[UInt8]:
    var res = List[UInt8]()
    var bytes_view = hex_str.as_bytes()
    var i = 0
    while i < len(hex_str) - 1:
        res.append((hex_char_to_val(Int(bytes_view[i])) << 4) | hex_char_to_val(Int(bytes_view[i + 1])))
        i += 2
    return res^

fn hex_to_u32_list(hex_str: String) -> SIMD[DType.uint32, 4]:
    var result = SIMD[DType.uint32, 4](0)
    var s = hex_str.as_bytes()
    for i in range(4):
        var val = 0
        for j in range(8):
            val = (val << 4) | Int(hex_char_to_val(Int(s[i * 8 + j])))
        result[i] = UInt32(val)
    return result

fn u64_to_hex(z: UInt64) -> String:
    var bytes = List[UInt8]()
    for shift in range(56, -1, -8):
        bytes.append(UInt8((z >> UInt64(shift)) & 0xFF))
    return bytes_to_hex(bytes)

fn byte_to_hex(b: UInt8) -> String:
    var hi = Int(b >> 4)
    var lo = Int(b & 0xF)
    return chr(48 + hi if hi < 10 else 87 + hi) + chr(48 + lo if lo < 10 else 87 + lo)

fn ptr_to_hex(ptr: UnsafePointer[UInt8, MutAnyOrigin], count: Int) -> String:
    var s = String("")
    for j in range(count):
        s += byte_to_hex(ptr.load(j))
    return s

fn generate_blake3_input(length: Int) -> List[UInt8]:
    var data = List[UInt8](capacity=length)
    for i in range(length):
        data.append(UInt8(i % 251))
    return data^

fn list_to_simd32(lst: List[UInt8]) -> SIMD[DType.uint8, 32]:
    var result = SIMD[DType.uint8, 32](0)
    for i in range(min(len(lst), 32)):
        result[i] = lst[i]
    return result

fn list_to_simd12(lst: List[UInt8]) -> SIMD[DType.uint8, 12]:
    var result = SIMD[DType.uint8, 12](0)
    for i in range(min(len(lst), 12)):
        result[i] = lst[i]
    return result


@fieldwise_init
struct TestResult(Copyable, Movable):
    var passed: Int
    var failed: Int
    var failures: List[String]

fn load_json(path: String, py: PythonObject) raises -> PythonObject:
    var builtins = Python.import_module("builtins")
    var f = builtins.open(path, "r")
    var data = py.loads(f.read())
    f.close()
    return data

fn test_argon2(data: PythonObject, py: PythonObject) raises -> TestResult:
    var passed, failed = 0, 0
    var failures = List[String]()
    for i in range(Int(py=data.__len__())):
        var v = data[i]
        var name = String(v["name"])
        var password = String(v["password"]).as_bytes()
        var salt = String(v["salt"]).as_bytes()
        var argon2 = Argon2id(salt,
            parallelism=Int(py=v["parallelism"]), tag_length=Int(py=v["tag_length"]),
            memory_size_kb=Int(py=v["memory_size_kb"]), iterations=Int(py=v["iterations"]),
            version=Int(py=v["version"]),
        )
        var got = bytes_to_hex(argon2.hash(password))
        var expected = String(v["hash"])
        if got == expected:
            passed += 1
        else:
            failed += 1
            failures.append("Argon2 " + name + ": expected " + expected + ", got " + got)
    return TestResult(passed, failed, failures^)

fn test_blake2b(data: PythonObject, py: PythonObject) raises -> TestResult:
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
            failures.append("BLAKE2b " + name + ": expected " + expected + ", got " + got)
    return TestResult(passed, failed, failures^)

fn test_blake3(data: PythonObject, py: PythonObject) raises -> TestResult:
    var passed, failed = 0, 0
    var failures = List[String]()
    var cases = data["cases"]
    for i in range(Int(py=cases.__len__())):
        var v = cases[i]
        var input_len = Int(py=v["input_len"])
        var expected = String(v["hash"])
        var got = bytes_to_hex(blake3_parallel_hash(Span[UInt8, ...](generate_blake3_input(input_len)), len(expected) // 2))
        if got == expected:
            passed += 1
        else:
            failed += 1
            failures.append("BLAKE3 " + String(input_len) + " bytes: expected " + expected + ", got " + got)
    return TestResult(passed, failed, failures^)

fn test_camellia(data: PythonObject, py: PythonObject) raises -> TestResult:
    var passed, failed = 0, 0
    var failures = List[String]()
    for i in range(Int(py=data.__len__())):
        var v = data[i]
        var name = String(v["name"])
        var key = hex_to_bytes(String(v["key"]))
        var pt_hex = String(v["plaintext"])
        var ct_hex = String(v["ciphertext"])
        var cipher = CamelliaCipher(Span[UInt8, ...](key))
        var got_ct = bytes_to_hex(cipher.encrypt(Span[UInt8, ...](hex_to_bytes(pt_hex))))
        if got_ct == ct_hex:
            passed += 1
        else:
            failed += 1
            failures.append("Camellia " + name + " enc: expected " + ct_hex + ", got " + got_ct)
        var got_pt = bytes_to_hex(cipher.decrypt(Span[UInt8, ...](hex_to_bytes(ct_hex))))
        if got_pt == pt_hex:
            passed += 1
        else:
            failed += 1
            failures.append("Camellia " + name + " dec: expected " + pt_hex + ", got " + got_pt)
    return TestResult(passed, failed, failures^)

fn test_chacha20(data: PythonObject, py: PythonObject) raises -> TestResult:
    var passed, failed = 0, 0
    var failures = List[String]()
    for i in range(Int(py=data.__len__())):
        var v = data[i]
        var name = String(v["name"])
        var cipher = ChaCha20(list_to_simd32(hex_to_bytes(String(v["key"]))),
            list_to_simd12(hex_to_bytes(String(v["nonce"]))), UInt32(Int(py=v["counter"])))
        var pt_bytes = hex_to_bytes(String(v["plaintext"]))
        var expected_ct = hex_to_bytes(String(v["ciphertext"]))
        if len(pt_bytes) == 0:
            var null_ptr: UnsafePointer[UInt8, MutExternalOrigin] = {}
            var result_ptr = cipher.encrypt(Span[UInt8, ...](ptr=null_ptr, length=0))
            var null_check: UnsafePointer[UInt8, MutExternalOrigin] = {}
            if result_ptr == null_check and len(expected_ct) == 0:
                passed += 1
            else:
                failed += 1
                failures.append("ChaCha20 " + name + ": empty plaintext test failed")
        else:
            var ct_ptr = cipher.encrypt(Span(pt_bytes))
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
                failures.append("ChaCha20 " + name + ": expected " + String(v["ciphertext"]) + ", got " + ptr_to_hex(ct_ptr, min(len(pt_bytes), 16)) + "...")
            ct_ptr.free()
    return TestResult(passed, failed, failures^)

fn test_kcipher2(data: PythonObject, py: PythonObject) raises -> TestResult:
    var passed, failed = 0, 0
    var failures = List[String]()
    var vectors = data["test_vectors"]
    for i in range(Int(py=vectors.__len__())):
        var v = vectors[i]
        var kc2 = KCipher2(hex_to_u32_list(String(v["key"])), hex_to_u32_list(String(v["iv"])))
        var key_streams = v["key_streams"]
        for j in range(Int(py=key_streams.__len__())):
            var expected = String(key_streams[j]).upper()
            var z = kc2.stream()
            kc2._next(1)
            var got = u64_to_hex(z).upper()
            if got == expected:
                passed += 1
            else:
                failed += 1
                failures.append("KCipher2 vector " + String(i) + " stream " + String(j) + ": expected " + expected + ", got " + got)
    return TestResult(passed, failed, failures^)

fn _test_pbkdf2_algo[
    hash_fn: fn(Span[UInt8, ...], Span[UInt8, ...], Int, Int) -> List[UInt8]
](data: PythonObject, py: PythonObject, name: String) raises -> TestResult:
    var passed, failed = 0, 0
    var failures = List[String]()
    for i in range(Int(py=data.__len__())):
        var v = data[i]
        var password = String(v["password_ascii"]).as_bytes()
        var salt = hex_to_bytes(String(v["salt"]))
        var got = bytes_to_hex(hash_fn(password, Span[UInt8, ...](salt), Int(py=v["iterations"]), Int(py=v["dklen"])))
        var expected = String(v["derived_key"])
        if got == expected:
            passed += 1
        else:
            failed += 1
            failures.append("PBKDF2-" + name + ": expected " + expected + ", got " + got)
    return TestResult(passed, failed, failures^)

fn test_pbkdf2(data: PythonObject, py: PythonObject) raises -> TestResult:
    var r = _test_pbkdf2_algo[pbkdf2_hmac_sha256](data["sha256"], py, "SHA256")
    var r2 = _test_pbkdf2_algo[pbkdf2_hmac_sha512](data["sha512"], py, "SHA512")
    r.passed += r2.passed
    r.failed += r2.failed
    for i in range(len(r2.failures)):
        r.failures.append(r2.failures[i])
    return r^

fn _test_sha_algo[
    hash_fn: fn(Span[UInt8, ...]) -> List[UInt8]
](data: PythonObject, py: PythonObject, name: String) raises -> TestResult:
    var passed, failed = 0, 0
    var failures = List[String]()
    for i in range(Int(py=data.__len__())):
        var v = data[i]
        var bit_len = Int(py=v["len"])
        var msg = hex_to_bytes(String(v["msg"])) if bit_len > 0 else List[UInt8]()
        var got = bytes_to_hex(hash_fn(Span[UInt8, ...](msg)))
        var expected = String(v["md"])
        if got == expected:
            passed += 1
        else:
            failed += 1
            failures.append(name + " len=" + String(bit_len) + ": expected " + expected + ", got " + got)
    return TestResult(passed, failed, failures^)

fn test_sha(data: PythonObject, py: PythonObject) raises -> TestResult:
    var r = _test_sha_algo[sha224_hash](data["sha224"], py, "SHA224")
    var r256 = _test_sha_algo[sha256_hash](data["sha256"], py, "SHA256")
    var r384 = _test_sha_algo[sha384_hash](data["sha384"], py, "SHA384")
    r.passed += r256.passed + r384.passed
    r.failed += r256.failed + r384.failed
    for i in range(len(r256.failures)):
        r.failures.append(r256.failures[i])
    for i in range(len(r384.failures)):
        r.failures.append(r384.failures[i])
    return r^

fn test_aes_cpu(data: PythonObject, py: PythonObject) raises -> TestResult:
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
            failures.append("AES-CPU " + String(v["name"]) + ": expected " + expected_ct + ", got " + got)
        key_ptr.free()
        round_keys.free()
        pt_ptr.free()
    return TestResult(passed, failed, failures^)


fn print_result(name: String, result: TestResult, mut tp: Int, mut tf: Int, mut af: Bool):
    if result.failed == 0:
        print("Testing " + name + " [pass] (" + String(result.passed) + " vectors)")
    else:
        print("Testing " + name + " [fail] (" + String(result.passed) + "/" + String(result.passed + result.failed) + " passed)")
        for i in range(len(result.failures)):
            print("  - " + result.failures[i])
    tp += result.passed
    tf += result.failed
    if result.failed > 0: af = True

def main() raises:
    print("Thistle Crypto Test Vectors\n")
    var py = Python.import_module("json")
    var tp, tf = 0, 0
    var af = False

    try:
        print("Loading Argon2 vectors...")
        print_result("Argon2", test_argon2(load_json("tests/vectors/argon2.json", py), py), tp, tf, af)
    except e:
        print("Argon2 [error] " + String(e)); af = True
    print()

    try:
        print("Loading BLAKE2b vectors...")
        print_result("BLAKE2b", test_blake2b(load_json("tests/vectors/blake2b.json", py), py), tp, tf, af)
    except e:
        print("BLAKE2b [error] " + String(e)); af = True
    print()

    try:
        print("Loading BLAKE3 vectors...")
        print_result("BLAKE3", test_blake3(load_json("tests/vectors/blake3.json", py), py), tp, tf, af)
    except e:
        print("BLAKE3 [error] " + String(e)); af = True
    print()

    try:
        print("Loading Camellia vectors...")
        print_result("Camellia", test_camellia(load_json("tests/vectors/camellia.json", py), py), tp, tf, af)
    except e:
        print("Camellia [error] " + String(e)); af = True
    print()

    try:
        print("Loading ChaCha20 vectors...")
        print_result("ChaCha20", test_chacha20(load_json("tests/vectors/chacha20.json", py), py), tp, tf, af)
    except e:
        print("ChaCha20 [error] " + String(e)); af = True
    print()

    try:
        print("Loading KCipher2 vectors...")
        print_result("KCipher2", test_kcipher2(load_json("tests/vectors/kcipher2.json", py), py), tp, tf, af)
    except e:
        print("KCipher2 [error] " + String(e)); af = True
    print()

    try:
        print("Loading PBKDF2 vectors...")
        print_result("PBKDF2", test_pbkdf2(load_json("tests/vectors/pbkdf2.json", py), py), tp, tf, af)
    except e:
        print("PBKDF2 [error] " + String(e)); af = True
    print()

    try:
        print("Loading SHA vectors...")
        print_result("SHA", test_sha(load_json("tests/vectors/sha.json", py), py), tp, tf, af)
    except e:
        print("SHA [error] " + String(e)); af = True
    print()

    try:
        print("Loading AES vectors...")
        print_result("AES-128-CPU", test_aes_cpu(load_json("tests/vectors/aes.json", py), py), tp, tf, af)
    except e:
        print("AES-128-CPU [error] " + String(e)); af = True
    print()

    print("Total: " + String(tp) + " pass, " + String(tf) + " fail")
    print("Tests pass" if not af else "Tests fail")
