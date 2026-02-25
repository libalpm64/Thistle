from python import Python
from python import PythonObject
from collections import List
from thistle.sha2 import bytes_to_hex
from thistle.argon2 import Argon2id
from thistle.blake2b import Blake2b
from thistle.blake3 import blake3_parallel_hash
from thistle.camellia import CamelliaCipher
from thistle.chacha20 import ChaCha20
from thistle.kcipher2 import KCipher2
from thistle.pbkdf2 import pbkdf2_hmac_sha256, pbkdf2_hmac_sha512
from thistle.sha2 import sha224_hash, sha256_hash, sha384_hash, sha512_hash
from memory.unsafe_pointer import UnsafePointer
from builtin.type_aliases import MutExternalOrigin


fn hex_char_to_val(c: Int) -> UInt8:
    if c >= 48 and c <= 57:
        return UInt8(c - 48)
    if c >= 97 and c <= 102:
        return UInt8(c - 97 + 10)
    if c >= 65 and c <= 70:
        return UInt8(c - 65 + 10)
    return 0


fn hex_to_bytes(hex_str: String) -> List[UInt8]:
    var res = List[UInt8]()
    var s = hex_str
    var bytes_view = s.as_bytes()
    var i = 0
    while i < len(s) - 1:
        var high = hex_char_to_val(Int(bytes_view[i]))
        var low = hex_char_to_val(Int(bytes_view[i + 1]))
        res.append((high << 4) | low)
        i += 2
    return res^


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


fn generate_blake3_input(length: Int) -> List[UInt8]:
    var data = List[UInt8](capacity=length)
    for i in range(length):
        data.append(UInt8(i % 251))
    return data^


fn hex_to_u32_list(hex_str: String) -> SIMD[DType.uint32, 4]:
    var result = SIMD[DType.uint32, 4](0)
    var s_bytes = hex_str.as_bytes()
    for i in range(4):
        var val = 0
        for j in range(8):
            var c = s_bytes[i * 8 + j]
            val = val << 4
            if c >= 48 and c <= 57:
                val = val + (Int(c) - 48)
            elif c >= 97 and c <= 102:
                val = val + (Int(c) - 97 + 10)
            elif c >= 65 and c <= 70:
                val = val + (Int(c) - 65 + 10)
        result[i] = UInt32(val)
    return result


fn u64_to_hex(z: UInt64) -> String:
    var bytes = List[UInt8]()
    bytes.append(UInt8((z >> 56) & 0xFF))
    bytes.append(UInt8((z >> 48) & 0xFF))
    bytes.append(UInt8((z >> 40) & 0xFF))
    bytes.append(UInt8((z >> 32) & 0xFF))
    bytes.append(UInt8((z >> 24) & 0xFF))
    bytes.append(UInt8((z >> 16) & 0xFF))
    bytes.append(UInt8((z >> 8) & 0xFF))
    bytes.append(UInt8(z & 0xFF))
    return bytes_to_hex(bytes)


@fieldwise_init
struct TestResult(Copyable, Movable):
    var passed: Int
    var failed: Int
    var failures: List[String]


fn test_argon2(json_data: PythonObject, py: PythonObject) raises -> TestResult:
    var passed = 0
    var failed = 0
    var failures = List[String]()
    var count = Int(py=json_data.__len__())
    
    for i in range(count):
        var v = json_data[i]
        var name = String(v["name"])
        var password = String(v["password"]).as_bytes()
        var salt = String(v["salt"]).as_bytes()
        var parallelism = Int(py=v["parallelism"])
        var memory_size_kb = Int(py=v["memory_size_kb"])
        var iterations = Int(py=v["iterations"])
        var tag_length = Int(py=v["tag_length"])
        var version = Int(py=v["version"])
        var expected = String(v["hash"])
        
        var argon2 = Argon2id(
            salt,
            parallelism=parallelism,
            tag_length=tag_length,
            memory_size_kb=memory_size_kb,
            iterations=iterations,
            version=version,
        )
        var tag = argon2.hash(password)
        var got = bytes_to_hex(tag)
        
        if got == expected:
            passed += 1
        else:
            failed += 1
            failures.append("Argon2 " + name + ": expected " + expected + ", got " + got)
    
    return TestResult(passed, failed, failures^)


fn test_blake2b(json_data: PythonObject, py: PythonObject) raises -> TestResult:
    var passed = 0
    var failed = 0
    var failures = List[String]()
    var count = Int(py=json_data.__len__())
    
    for i in range(count):
        var v = json_data[i]
        var name = String(v["name"])
        var expected = String(v["hash"])
        var digest_size = Int(py=v["digest_size"])
        var input_hex = String(v["input"])
        
        var input_bytes = hex_to_bytes(input_hex)
        var ctx = Blake2b(digest_size)
        ctx.update(Span[UInt8](input_bytes))
        var hash = ctx.finalize()
        var got = bytes_to_hex(hash)
        
        if got == expected:
            passed += 1
        else:
            failed += 1
            failures.append("BLAKE2b " + name + ": expected " + expected + ", got " + got)
    
    return TestResult(passed, failed, failures^)


fn test_blake3(json_data: PythonObject, py: PythonObject) raises -> TestResult:
    var passed = 0
    var failed = 0
    var failures = List[String]()
    var cases = json_data["cases"]
    var count = Int(py=cases.__len__())
    
    for i in range(count):
        var v = cases[i]
        var input_len = Int(py=v["input_len"])
        var expected = String(v["hash"])
        
        var out_len = len(expected) // 2
        var data = generate_blake3_input(input_len)
        var hash_result = blake3_parallel_hash(Span[UInt8](data), out_len)
        var got = bytes_to_hex(hash_result)
        
        if got == expected:
            passed += 1
        else:
            failed += 1
            failures.append(String("BLAKE3 ", input_len, " bytes: expected ", expected, ", got ", got))
    
    return TestResult(passed, failed, failures^)


fn test_camellia(json_data: PythonObject, py: PythonObject) raises -> TestResult:
    var passed = 0
    var failed = 0
    var failures = List[String]()
    var count = Int(py=json_data.__len__())
    
    for i in range(count):
        var v = json_data[i]
        var name = String(v["name"])
        var key_hex = String(v["key"])
        var pt_hex = String(v["plaintext"])
        var ct_hex = String(v["ciphertext"])
        
        var key = hex_to_bytes(key_hex)
        var pt = hex_to_bytes(pt_hex)
        
        var cipher = CamelliaCipher(Span[UInt8](key))
        var got_ct = bytes_to_hex(cipher.encrypt(Span[UInt8](pt)))
        
        if got_ct == ct_hex:
            passed += 1
        else:
            failed += 1
            failures.append("Camellia " + name + " enc: expected " + ct_hex + ", got " + got_ct)
        
        var ct = hex_to_bytes(ct_hex)
        var got_pt = bytes_to_hex(cipher.decrypt(Span[UInt8](ct)))
        if got_pt == pt_hex:
            passed += 1
        else:
            failed += 1
            failures.append("Camellia " + name + " dec: expected " + pt_hex + ", got " + got_pt)
    
    return TestResult(passed, failed, failures^)


fn test_chacha20(json_data: PythonObject, py: PythonObject) raises -> TestResult:
    var passed = 0
    var failed = 0
    var failures = List[String]()
    var count = Int(py=json_data.__len__())
    
    for i in range(count):
        var v = json_data[i]
        var name = String(v["name"])
        var key_hex = String(v["key"])
        var nonce_hex = String(v["nonce"])
        var counter = UInt32(Int(py=v["counter"]))
        var pt_hex = String(v["plaintext"])
        var ct_hex = String(v["ciphertext"])
        
        var key_bytes = hex_to_bytes(key_hex)
        var nonce_bytes = hex_to_bytes(nonce_hex)
        var pt_bytes = hex_to_bytes(pt_hex)
        var expected_ct = hex_to_bytes(ct_hex)
        
        var key = list_to_simd32(key_bytes)
        var nonce = list_to_simd12(nonce_bytes)
        
        var cipher = ChaCha20(key, nonce, counter)
        
        if len(pt_bytes) == 0:
            var null_ptr: UnsafePointer[UInt8, MutExternalOrigin] = {}
            var result_ptr = cipher.encrypt(Span[UInt8](ptr=null_ptr, length=0))
            var null_check: UnsafePointer[UInt8, MutExternalOrigin] = {}
            if result_ptr == null_check and len(expected_ct) == 0:
                passed += 1
            else:
                failed += 1
                failures.append("ChaCha20 " + name + ": empty plaintext test failed")
        else:
            var ct_ptr = cipher.encrypt(Span(pt_bytes))
            var test_passed = True
            if len(pt_bytes) != len(expected_ct):
                test_passed = False
            else:
                for j in range(len(pt_bytes)):
                    if ct_ptr[j] != expected_ct[j]:
                        test_passed = False
                        break
            
            if test_passed:
                passed += 1
            else:
                var got_hex = String("")
                for j in range(min(len(pt_bytes), 16)):
                    got_hex += hex(Int(ct_ptr[j]))[2:].rjust(2, '0')
                failures.append("ChaCha20 " + name + ": expected " + ct_hex[:32] + "..., got " + got_hex + "...")
                failed += 1
            
            ct_ptr.free()
    
    return TestResult(passed, failed, failures^)


fn test_kcipher2(json_data: PythonObject, py: PythonObject) raises -> TestResult:
    var passed = 0
    var failed = 0
    var failures = List[String]()
    var vectors = json_data["test_vectors"]
    var count = Int(py=vectors.__len__())
    
    for i in range(count):
        var v = vectors[i]
        var key_hex = String(v["key"])
        var iv_hex = String(v["iv"])
        var key_streams = v["key_streams"]
        
        var key = hex_to_u32_list(key_hex)
        var iv = hex_to_u32_list(iv_hex)
        var kc2 = KCipher2(key, iv)
        
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


fn test_pbkdf2(json_data: PythonObject, py: PythonObject) raises -> TestResult:
    var passed = 0
    var failed = 0
    var failures = List[String]()
    
    var sha256_data = json_data["sha256"]
    var sha256_count = Int(py=sha256_data.__len__())
    for i in range(sha256_count):
        var v = sha256_data[i]
        var password = String(v["password_ascii"]).as_bytes()
        var salt_hex = String(v["salt"])
        var iterations = Int(py=v["iterations"])
        var dklen = Int(py=v["dklen"])
        var expected = String(v["derived_key"])
        
        var salt = hex_to_bytes(salt_hex)
        var got = bytes_to_hex(pbkdf2_hmac_sha256(password, Span[UInt8](salt), iterations, dklen))
        
        if got == expected:
            passed += 1
        else:
            failed += 1
            failures.append("PBKDF2-SHA256: expected " + expected + ", got " + got)
    
    var sha512_data = json_data["sha512"]
    var sha512_count = Int(py=sha512_data.__len__())
    for i in range(sha512_count):
        var v = sha512_data[i]
        var password = String(v["password_ascii"]).as_bytes()
        var salt_hex = String(v["salt"])
        var iterations = Int(py=v["iterations"])
        var dklen = Int(py=v["dklen"])
        var expected = String(v["derived_key"])
        
        var salt = hex_to_bytes(salt_hex)
        var got = bytes_to_hex(pbkdf2_hmac_sha512(password, Span[UInt8](salt), iterations, dklen))
        
        if got == expected:
            passed += 1
        else:
            failed += 1
            failures.append("PBKDF2-SHA512: expected " + expected + ", got " + got)
    
    return TestResult(passed, failed, failures^)


fn test_sha(json_data: PythonObject, py: PythonObject) raises -> TestResult:
    var passed = 0
    var failed = 0
    var failures = List[String]()
    
    var sha224_data = json_data["sha224"]
    var sha224_count = Int(py=sha224_data.__len__())
    for i in range(sha224_count):
        var v = sha224_data[i]
        var bit_len = Int(py=v["len"])
        var msg_hex = String(v["msg"])
        var expected = String(v["md"])
        
        var got_hash: List[UInt8]
        if bit_len == 0:
            var empty_msg = List[UInt8]()
            got_hash = sha224_hash(Span[UInt8](empty_msg))
        else:
            var msg = hex_to_bytes(msg_hex)
            got_hash = sha224_hash(Span[UInt8](msg))
        var got = bytes_to_hex(got_hash)
        
        if got == expected:
            passed += 1
        else:
            failed += 1
            failures.append("SHA224 len=" + String(bit_len) + ": expected " + expected + ", got " + got)
    
    var sha256_data = json_data["sha256"]
    var sha256_count = Int(py=sha256_data.__len__())
    for i in range(sha256_count):
        var v = sha256_data[i]
        var bit_len = Int(py=v["len"])
        var msg_hex = String(v["msg"])
        var expected = String(v["md"])
        
        var got_hash: List[UInt8]
        if bit_len == 0:
            var empty_msg = List[UInt8]()
            got_hash = sha256_hash(Span[UInt8](empty_msg))
        else:
            var msg = hex_to_bytes(msg_hex)
            got_hash = sha256_hash(Span[UInt8](msg))
        var got = bytes_to_hex(got_hash)
        
        if got == expected:
            passed += 1
        else:
            failed += 1
            failures.append("SHA256 len=" + String(bit_len) + ": expected " + expected + ", got " + got)
    
    var sha384_data = json_data["sha384"]
    var sha384_count = Int(py=sha384_data.__len__())
    for i in range(sha384_count):
        var v = sha384_data[i]
        var bit_len = Int(py=v["len"])
        var msg_hex = String(v["msg"])
        var expected = String(v["md"])
        
        var got_hash: List[UInt8]
        if bit_len == 0:
            var empty_msg = List[UInt8]()
            got_hash = sha384_hash(Span[UInt8](empty_msg))
        else:
            var msg = hex_to_bytes(msg_hex)
            got_hash = sha384_hash(Span[UInt8](msg))
        var got = bytes_to_hex(got_hash)
        
        if got == expected:
            passed += 1
        else:
            failed += 1
            failures.append("SHA384 len=" + String(Int(py=v["len"])) + ": expected " + expected + ", got " + got)
    
    return TestResult(passed, failed, failures^)


fn load_json(path: String, py: PythonObject) raises -> PythonObject:
    var builtins = Python.import_module("builtins")
    var f = builtins.open(path, "r")
    var data_str = f.read()
    f.close()
    return py.loads(data_str)


fn print_result(name: String, result: TestResult):
    if result.failed == 0:
        print("Testing " + name + " [pass] (" + String(result.passed) + " vectors)")
    else:
        print("Testing " + name + " [fail] (" + String(result.passed) + "/" + String(result.passed + result.failed) + " passed)")
        for i in range(len(result.failures)):
            print("  - " + result.failures[i])


def main():
    print("Thistle Crypto Test Vectors")
    print()
    
    var py = Python.import_module("json")
    
    var total_passed = 0
    var total_failed = 0
    var any_failures = False
    
    try:
        print("Loading Argon2 vectors...")
        var argon2_data = load_json("tests/vectors/argon2.json", py)
        var argon2_result = test_argon2(argon2_data, py)
        print_result("Argon2", argon2_result)
        total_passed += argon2_result.passed
        total_failed += argon2_result.failed
        if argon2_result.failed > 0:
            any_failures = True
    except e:
        print("Argon2 [error] " + String(e))
        any_failures = True
    
    print()
    
    try:
        print("Loading BLAKE2b vectors...")
        var blake2b_data = load_json("tests/vectors/blake2b.json", py)
        var blake2b_result = test_blake2b(blake2b_data, py)
        print_result("BLAKE2b", blake2b_result)
        total_passed += blake2b_result.passed
        total_failed += blake2b_result.failed
        if blake2b_result.failed > 0:
            any_failures = True
    except e:
        print("BLAKE2b [error] " + String(e))
        any_failures = True
    
    print()
    
    try:
        print("Loading BLAKE3 vectors...")
        var blake3_data = load_json("tests/vectors/blake3.json", py)
        var blake3_result = test_blake3(blake3_data, py)
        print_result("BLAKE3", blake3_result)
        total_passed += blake3_result.passed
        total_failed += blake3_result.failed
        if blake3_result.failed > 0:
            any_failures = True
    except e:
        print("BLAKE3 [error] " + String(e))
        any_failures = True
    
    print()
    
    try:
        print("Loading Camellia vectors...")
        var camellia_data = load_json("tests/vectors/camellia.json", py)
        var camellia_result = test_camellia(camellia_data, py)
        print_result("Camellia", camellia_result)
        total_passed += camellia_result.passed
        total_failed += camellia_result.failed
        if camellia_result.failed > 0:
            any_failures = True
    except e:
        print("Camellia [error] " + String(e))
        any_failures = True
    
    print()
    
    try:
        print("Loading ChaCha20 vectors...")
        var chacha20_data = load_json("tests/vectors/chacha20.json", py)
        var chacha20_result = test_chacha20(chacha20_data, py)
        print_result("ChaCha20", chacha20_result)
        total_passed += chacha20_result.passed
        total_failed += chacha20_result.failed
        if chacha20_result.failed > 0:
            any_failures = True
    except e:
        print("ChaCha20 [error] " + String(e))
        any_failures = True
    
    print()
    
    try:
        print("Loading KCipher2 vectors...")
        var kcipher2_data = load_json("tests/vectors/kcipher2.json", py)
        var kcipher2_result = test_kcipher2(kcipher2_data, py)
        print_result("KCipher2", kcipher2_result)
        total_passed += kcipher2_result.passed
        total_failed += kcipher2_result.failed
        if kcipher2_result.failed > 0:
            any_failures = True
    except e:
        print("KCipher2 [error] " + String(e))
        any_failures = True
    
    print()
    
    try:
        print("Loading PBKDF2 vectors...")
        var pbkdf2_data = load_json("tests/vectors/pbkdf2.json", py)
        var pbkdf2_result = test_pbkdf2(pbkdf2_data, py)
        print_result("PBKDF2", pbkdf2_result)
        total_passed += pbkdf2_result.passed
        total_failed += pbkdf2_result.failed
        if pbkdf2_result.failed > 0:
            any_failures = True
    except e:
        print("PBKDF2 [error] " + String(e))
        any_failures = True
    
    print()
    
    try:
        print("Loading SHA vectors...")
        var sha_data = load_json("tests/vectors/sha.json", py)
        var sha_result = test_sha(sha_data, py)
        print_result("SHA", sha_result)
        total_passed += sha_result.passed
        total_failed += sha_result.failed
        if sha_result.failed > 0:
            any_failures = True
    except e:
        print("SHA [error] " + String(e))
        any_failures = True
    
    print()
    print("Total: " + String(total_passed) + " pass, " + String(total_failed) + " fail")
    
    if any_failures:
        print("Tests fail")
    else:
        print("Tests pass")
