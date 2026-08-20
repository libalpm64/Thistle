from std.python import Python
from std.python import PythonObject
from std.collections import List
from std.sys import has_accelerator
from thistle.sha2 import bytes_to_hex
from thistle.aes import cpu_aes_ct_skey, AESExpandedKey
from thistle.aes_gpu import aes_gpu_kernel_ecb, aes_gpu_kernel_ctr, aes_gpu_kernel_gcm_ctr
from std.memory import alloc
from max.gpu.host import DeviceContext
from std.memory.unsafe_pointer import UnsafePointer


def byte_to_hex(b: UInt8) -> String:
    var hi = Int(b >> 4)
    var lo = Int(b & 0xF)
    return chr(48 + hi if hi < 10 else 87 + hi) + chr(48 + lo if lo < 10 else 87 + lo)

@fieldwise_init
struct TestResult(Copyable, Movable):
    var passed: Int
    var failed: Int
    var failures: List[String]


def hex_char_to_val(c: Int) -> UInt8:
    if c >= 48 and c <= 57:
        return UInt8(c - 48)
    if c >= 97 and c <= 102:
        return UInt8(c - 97 + 10)
    if c >= 65 and c <= 70:
        return UInt8(c - 65 + 10)
    return 0


def hex_to_bytes(hex_str: String) -> List[UInt8]:
    var result = List[UInt8]()
    var hex_bytes = hex_str.as_bytes()
    var i = 0
    while i < len(hex_bytes) - 1:
        var high = hex_bytes[i]
        var low = hex_bytes[i + 1]
        var high_val = hex_char_to_val(Int(high))
        var low_val = hex_char_to_val(Int(low))
        result.append((high_val << 4) | low_val)
        i += 2
    return result^


def load_json(path: String, py: PythonObject) raises -> PythonObject:
    var json = Python.import_module("json")
    var file = open(path, "r")
    var content = file.read()
    file.close()
    return json.loads(content)


def print_result(name: String, result: TestResult):
    if result.failed == 0:
        print("Testing " + name + " [pass] (" + String(result.passed) + " vectors)")
    else:
        print("Testing " + name + " [fail] (" + String(result.passed) + "/" + String(result.passed + result.failed) + " passed)")
        for i in range(len(result.failures)):
            print("  - " + result.failures[i])


def test_aes_gpu_basic(json_data: PythonObject, py: PythonObject) raises -> TestResult:
    var passed = 0
    var failed = 0
    var failures = List[String]()
    
    var count = Int(py=json_data.__len__())
    var num_test_vectors = min(count, 100)
    var stride = count // num_test_vectors
    if stride < 1:
        stride = 1

    with DeviceContext() as ctx:

        for test_idx in range(num_test_vectors):
            var v = json_data[test_idx * stride]
            var name = String(v["name"])
            var key_hex = String(v["key"])
            var pt_hex = String(v["plaintext"])
            var expected_ct_hex = String(v["ciphertext"])
            
            var key_bytes = hex_to_bytes(key_hex)
            var pt_bytes_data = hex_to_bytes(pt_hex)
            
            var key_len = len(key_bytes)
            var rounds = 10 if key_len == 16 else (12 if key_len == 24 else 14)
            
            var total_bytes = 64
            var input_host = alloc[Scalar[DType.uint8]](total_bytes)
            var output_host = alloc[Scalar[DType.uint8]](total_bytes)
            
            for block in range(4):
                for j in range(16):
                    input_host[block * 16 + j] = pt_bytes_data[j]
            
            var input_buffer = ctx.enqueue_create_buffer[DType.uint8](total_bytes)
            var output_buffer = ctx.enqueue_create_buffer[DType.uint8](total_bytes)

            var round_keys = AESExpandedKey(Span[UInt8, ...](key_bytes))
            var skey_host = cpu_aes_ct_skey(round_keys.ptr(), rounds)
            var skey_buffer = ctx.enqueue_create_buffer[DType.uint64]((rounds + 1) * 8)
            ctx.enqueue_copy(skey_buffer, skey_host.unsafe_ptr())
            ctx.enqueue_copy(input_buffer, input_host)
            ctx.synchronize()

            var block_dim = 1
            var grid_dim = 1

            ctx.enqueue_function[aes_gpu_kernel_ecb](
                input_buffer,
                output_buffer,
                skey_buffer,
                Int32(4),
                Int32(rounds),
                grid_dim=grid_dim,
                block_dim=block_dim,
            )
            ctx.synchronize()
            _ = skey_buffer
            
            ctx.enqueue_copy(output_host, output_buffer)
            ctx.synchronize()
            
            var correct = True
            var expected = String(v["ciphertext"])
            var all_passed = True
            for block in range(4):
                for j in range(16):
                    var expected_byte = hex_char_to_val(Int(expected.as_bytes()[j * 2])) << 4
                    expected_byte |= hex_char_to_val(Int(expected.as_bytes()[j * 2 + 1]))
                    var actual_byte = output_host[block * 16 + j]
                    if actual_byte != expected_byte:
                        all_passed = False
                        break
                if not all_passed:
                    break
            
            if all_passed:
                passed += 1
            else:
                failed += 1
                var got_hex = String("")
                for j in range(16):
                    got_hex += byte_to_hex(output_host[j])
                failures.append("AES-GPU " + name + ": expected " + expected + ", got " + got_hex)
            
            input_host.free()
            output_host.free()
    
    return TestResult(passed, failed, failures^)


def test_mode_gpu(json_data: PythonObject, mode: String) raises -> TestResult:
    var passed = 0
    var failed = 0
    var failures = List[String]()
    
    var ctx = DeviceContext()
    
    var count = Int(py=json_data.__len__())
    for i in range(min(count, 10)):
        var tv = json_data[i]
        var key_hex = String(tv["key"])
        var pt_hex = String(tv["plaintext"])
        var expected_ct = String(tv["ciphertext"])
        
        var key_bytes = hex_to_bytes(key_hex)
        var pt_bytes = hex_to_bytes(pt_hex)
        
        var key_len = len(key_bytes)
        var round_keys = AESExpandedKey(Span[UInt8, ...](key_bytes))
        
        var total_bytes = len(pt_bytes)
        var n_blocks = total_bytes // 16
        var pt_ptr = alloc[UInt8](total_bytes)
        for j in range(total_bytes):
            pt_ptr.store(j, pt_bytes[j])
        
        var ct_ptr = alloc[UInt8](total_bytes)
        
        var input_buffer = ctx.enqueue_create_buffer[DType.uint8](total_bytes)
        var output_buffer = ctx.enqueue_create_buffer[DType.uint8](total_bytes)

        ctx.enqueue_copy(input_buffer, pt_ptr)
        ctx.synchronize()
        
        var grid_dim = n_blocks
        var block_dim = 1
        
        var rounds: Int
        if key_len == 16:
            rounds = 10
        elif key_len == 24:
            rounds = 12
        else:
            rounds = 14

        var skey_host = cpu_aes_ct_skey(round_keys.ptr(), rounds)
        var skey_buffer = ctx.enqueue_create_buffer[DType.uint64]((rounds + 1) * 8)
        ctx.enqueue_copy(skey_buffer, skey_host.unsafe_ptr())
        
        var nonce_ptr = alloc[UInt8](16)
        var nonce_buffer = ctx.enqueue_create_buffer[DType.uint8](16)
        if "ECB" in mode:
            ctx.enqueue_function[aes_gpu_kernel_ecb](
                input_buffer,
                output_buffer,
                skey_buffer,
                Int32(n_blocks),
                Int32(rounds),
                grid_dim=grid_dim,
                block_dim=block_dim,
            )
        elif "CTR" in mode:
            var iv_hex = String(tv.get("iv", PythonObject()))
            if iv_hex.byte_length() == 0:
                for j in range(16):
                    nonce_ptr[j] = 0
            else:
                var iv_bytes = hex_to_bytes(iv_hex)
                for j in range(16):
                    nonce_ptr.store(j, iv_bytes[j])

            ctx.enqueue_copy(nonce_buffer, nonce_ptr)
            ctx.enqueue_function[aes_gpu_kernel_ctr](
                input_buffer,
                output_buffer,
                skey_buffer,
                Int32(n_blocks),
                nonce_buffer,
                Int32(rounds),
                grid_dim=grid_dim,
                block_dim=block_dim,
            )
        elif "GCM" in mode:
            var nonce_hex = String(tv.get("nonce", PythonObject()))
            if nonce_hex.byte_length() == 0:
                for j in range(12):
                    nonce_ptr[j] = 0
            else:
                var nonce_bytes = hex_to_bytes(nonce_hex)
                for j in range(12):
                    nonce_ptr.store(j, nonce_bytes[j])
            nonce_ptr[12] = 0
            nonce_ptr[13] = 0
            nonce_ptr[14] = 0
            nonce_ptr[15] = 1

            ctx.enqueue_copy(nonce_buffer, nonce_ptr)
            ctx.enqueue_function[aes_gpu_kernel_gcm_ctr](
                input_buffer,
                output_buffer,
                skey_buffer,
                Int32(n_blocks),
                nonce_buffer,
                Int32(rounds),
                grid_dim=grid_dim,
                block_dim=block_dim,
            )
        else:
            ctx.enqueue_function[aes_gpu_kernel_ecb](
                input_buffer,
                output_buffer,
                skey_buffer,
                Int32(n_blocks),
                Int32(rounds),
                grid_dim=grid_dim,
                block_dim=block_dim,
            )
        
        ctx.synchronize()
        ctx.enqueue_copy(ct_ptr, output_buffer)
        ctx.synchronize()
        _ = nonce_buffer
        _ = input_buffer
        _ = skey_buffer

        var correct = True
        var expected_len = expected_ct.byte_length() // 2
        if expected_len != total_bytes:
            correct = False
        else:
            for j in range(total_bytes):
                var expected_byte = hex_char_to_val(Int(expected_ct.as_bytes()[j * 2])) << 4
                expected_byte = expected_byte | hex_char_to_val(Int(expected_ct.as_bytes()[j * 2 + 1]))
                if ct_ptr.load(j) != expected_byte:
                    correct = False
                    break
        
        if correct:
            passed += 1
        else:
            failed += 1
            var got_hex = String("")
            for j in range(total_bytes):
                got_hex += byte_to_hex(ct_ptr.load(j))
            failures.append(mode + " " + String(i) + ": expected " + expected_ct + ", got " + got_hex)
        
        pt_ptr.free()
        ct_ptr.free()
        nonce_ptr.free()
    
    return TestResult(passed, failed, failures^)


def main() raises:
    comptime
    if not has_accelerator():
        print("GPU not available, skipping GPU tests")
        return
    
    print("Thistle GPU Test Vectors")
    print()
    
    var py = Python.import_module("json")
    
    var total_passed = 0
    var total_failed = 0
    var any_failures = False
    
    try:
        print("Loading AES single-block vectors...")
        var aes_data = load_json("tests/vectors/aes.json", py)
        var aes_gpu_result = test_aes_gpu_basic(aes_data, py)
        print_result("AES-GPU", aes_gpu_result)
        total_passed += aes_gpu_result.passed
        total_failed += aes_gpu_result.failed
        if aes_gpu_result.failed > 0:
            any_failures = True
    except e:
        print("AES-128-GPU [error] " + String(e))
        any_failures = True
    
    print()
    
    try:
        print("Loading AES mode vectors...")
        var json_data = load_json("tests/vectors/aes_test_vectors.json", py)
        var modes = ["AES-128-ECB", "AES-192-ECB", "AES-256-ECB", 
                     "AES-128-CTR", "AES-192-CTR", "AES-256-CTR",
                     "AES-128-GCM", "AES-192-GCM", "AES-256-GCM"]
        
        for mode in modes:
            print("Loading " + mode + " vectors...")
            var tv_data = json_data[mode]
            var result = test_mode_gpu(tv_data, mode)
            print_result(mode, result)
            total_passed += result.passed
            total_failed += result.failed
            if result.failed > 0:
                any_failures = True
            print()
    except e:
        print("AES modes [error] " + String(e))
        any_failures = True
    
    print("Total: " + String(total_passed) + " pass, " + String(total_failed) + " fail")
    
    if any_failures:
        print("Tests fail")
    else:
        print("Tests pass")
