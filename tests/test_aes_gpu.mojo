from python import Python
from python import PythonObject
from collections import List
from sys import has_accelerator
from thistle.sha2 import bytes_to_hex
from thistle.aes import SBOX, expand_key_128, expand_key_192, expand_key_256
from thistle.aes_gpu import aes_gpu_kernel_ecb, aes_gpu_kernel_ctr, aes_gpu_kernel_cbc, aes_gpu_kernel_gcm, aes_gpu_kernel_xts
from memory import alloc
from gpu.host import DeviceContext
from memory.unsafe_pointer import UnsafePointer

# This is a test file this is only for testing purposes.
# This file will be removed later on.

@fieldwise_init
struct TestResult(Copyable, Movable):
    var passed: Int
    var failed: Int
    var failures: List[String]


fn hex_char_to_val(c: Int) -> UInt8:
    if c >= 48 and c <= 57:
        return UInt8(c - 48)
    if c >= 97 and c <= 102:
        return UInt8(c - 97 + 10)
    if c >= 65 and c <= 70:
        return UInt8(c - 65 + 10)
    return 0


fn hex_to_bytes(hex_str: String) -> List[UInt8]:
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


fn load_json(path: String, py: PythonObject) raises -> PythonObject:
    var json = Python.import_module("json")
    var file = open(path, "r")
    var content = file.read()
    file.close()
    return json.loads(content)


fn print_result(name: String, result: TestResult):
    if result.failed == 0:
        print("Testing " + name + " [pass] (" + String(result.passed) + " vectors)")
    else:
        print("Testing " + name + " [fail] (" + String(result.passed) + "/" + String(result.passed + result.failed) + " passed)")
        for i in range(len(result.failures)):
            print("  - " + result.failures[i])


fn test_aes_gpu_basic(json_data: PythonObject, py: PythonObject) raises -> TestResult:
    var passed = 0
    var failed = 0
    var failures = List[String]()
    
    var count = Int(py=json_data.__len__())
    var num_test_vectors = min(count, 100)
    
    var sbox_host = alloc[Scalar[DType.uint8]](256)
    for i in range(256):
        sbox_host[i] = SBOX[i]
    
    with DeviceContext() as ctx:
        var sbox_buffer = ctx.enqueue_create_buffer[DType.uint8](256)
        ctx.enqueue_copy(sbox_buffer, sbox_host)
        ctx.synchronize()
        
        for test_idx in range(num_test_vectors):
            var v = json_data[test_idx]
            var name = String(v["name"])
            var key_hex = String(v["key"])
            var pt_hex = String(v["plaintext"])
            var expected_ct_hex = String(v["ciphertext"])
            
            var key_bytes = hex_to_bytes(key_hex)
            var pt_bytes_data = hex_to_bytes(pt_hex)
            
            var key_ptr = alloc[UInt8](16)
            for j in range(16):
                key_ptr.store(j, key_bytes[j])
            
            var total_bytes = 64
            var input_host = alloc[Scalar[DType.uint8]](total_bytes)
            var output_host = alloc[Scalar[DType.uint8]](total_bytes)
            
            for block in range(4):
                for j in range(16):
                    input_host[block * 16 + j] = pt_bytes_data[j]
            
            var input_buffer = ctx.enqueue_create_buffer[DType.uint8](total_bytes)
            var output_buffer = ctx.enqueue_create_buffer[DType.uint8](total_bytes)
            var round_keys_buffer = ctx.enqueue_create_buffer[DType.uint32](44)
            
            var round_keys = expand_key_128(key_ptr)
            ctx.enqueue_copy(input_buffer, input_host)
            ctx.enqueue_copy(round_keys_buffer, round_keys)
            ctx.synchronize()
            
            var block_dim = 1
            var grid_dim = 1
            
            ctx.enqueue_function[aes_gpu_kernel_ecb, aes_gpu_kernel_ecb](
                input_buffer.unsafe_ptr(),
                output_buffer.unsafe_ptr(),
                round_keys_buffer.unsafe_ptr(),
                sbox_buffer.unsafe_ptr(),
                1,
                10,
                grid_dim=grid_dim,
                block_dim=block_dim,
            )
            ctx.synchronize()
            
            ctx.enqueue_copy(output_host, output_buffer)
            ctx.synchronize()
            
            var correct = True
            var expected = String(v["ciphertext"])
            var all_passed = True
            for j in range(16):
                var expected_byte = hex_char_to_val(Int(expected.as_bytes()[j * 2])) << 4
                expected_byte |= hex_char_to_val(Int(expected.as_bytes()[j * 2 + 1]))
                var actual_byte = output_host[j]
                if actual_byte != expected_byte:
                    all_passed = False
                    break
            
            if all_passed:
                passed += 1
            else:
                failed += 1
                var got_hex = String("")
                for j in range(16):
                    got_hex += hex(Int(output_host[j]))[2:].rjust(2, '0')
                failures.append("AES-GPU " + name + ": expected " + expected + ", got " + got_hex)
            
            key_ptr.free()
            round_keys.free()
            input_host.free()
            output_host.free()
    
    sbox_host.free()
    return TestResult(passed, failed, failures^)


fn test_mode_gpu(json_data: PythonObject, mode: String) raises -> TestResult:
    var passed = 0
    var failed = 0
    var failures = List[String]()
    
    var ctx = DeviceContext()
    var sbox_buffer = ctx.enqueue_create_buffer[DType.uint8](256)
    
    var sbox_host = alloc[UInt8](256)
    for j in range(256):
        sbox_host[j] = SBOX[j]
    ctx.enqueue_copy(sbox_buffer, sbox_host)
    ctx.synchronize()
    
    var count = Int(py=json_data.__len__())
    for i in range(min(count, 10)):
        var tv = json_data[i]
        var key_hex = String(tv["key"])
        var pt_hex = String(tv["plaintext"])
        var expected_ct = String(tv["ciphertext"])
        
        var key_bytes = hex_to_bytes(key_hex)
        var pt_bytes = hex_to_bytes(pt_hex)
        
        var key_len = len(key_bytes)
        var key_ptr: UnsafePointer[UInt8, MutAnyOrigin]
        var round_keys_size: Int
        var round_keys: UnsafePointer[UInt32, MutAnyOrigin]
        
        if "XTS" in mode:
            key_ptr = alloc[UInt8](32)
            for j in range(min(key_len, 32)):
                key_ptr.store(j, key_bytes[j])
            round_keys_size = 44
            round_keys = expand_key_128(key_ptr)
        else:
            if key_len == 16:
                key_ptr = alloc[UInt8](16)
                for j in range(16):
                    key_ptr.store(j, key_bytes[j])
                round_keys_size = 44
                round_keys = expand_key_128(key_ptr)
            elif key_len == 24:
                key_ptr = alloc[UInt8](24)
                for j in range(24):
                    key_ptr.store(j, key_bytes[j])
                round_keys_size = 52
                round_keys = expand_key_192(key_ptr)
            else:
                key_ptr = alloc[UInt8](32)
                for j in range(32):
                    key_ptr.store(j, key_bytes[j])
                round_keys_size = 60
                round_keys = expand_key_256(key_ptr)
        
        var pt_ptr = alloc[UInt8](16)
        for j in range(16):
            pt_ptr.store(j, pt_bytes[j])
        
        var ct_ptr = alloc[UInt8](16)
        
        var input_buffer = ctx.enqueue_create_buffer[DType.uint8](16)
        var output_buffer = ctx.enqueue_create_buffer[DType.uint8](16)
        var round_keys_buffer = ctx.enqueue_create_buffer[DType.uint32](round_keys_size)
        
        ctx.enqueue_copy(input_buffer, pt_ptr)
        ctx.enqueue_copy(round_keys_buffer, round_keys)
        ctx.synchronize()
        
        var grid_dim = 1
        var block_dim = 1
        
        var rounds: Int
        if key_len == 16:
            rounds = 10
        elif key_len == 24:
            rounds = 12
        else:
            rounds = 14
        
        if "ECB" in mode:
            ctx.enqueue_function[aes_gpu_kernel_ecb, aes_gpu_kernel_ecb](
                input_buffer.unsafe_ptr(),
                output_buffer.unsafe_ptr(),
                round_keys_buffer.unsafe_ptr(),
                sbox_buffer.unsafe_ptr(),
                1,
                rounds,
                grid_dim=grid_dim,
                block_dim=block_dim,
            )
        elif "CBC" in mode:
            var iv_ptr = alloc[UInt8](16)
            var iv_hex = String(tv.get("iv", PythonObject()))
            if len(iv_hex) == 0:
                for j in range(16):
                    iv_ptr[j] = 0
            else:
                var iv_bytes = hex_to_bytes(iv_hex)
                for j in range(16):
                    iv_ptr.store(j, iv_bytes[j])
            
            var iv_buffer = ctx.enqueue_create_buffer[DType.uint8](16)
            ctx.enqueue_copy(iv_buffer, iv_ptr)
            ctx.enqueue_function[aes_gpu_kernel_cbc, aes_gpu_kernel_cbc](
                input_buffer.unsafe_ptr(),
                output_buffer.unsafe_ptr(),
                round_keys_buffer.unsafe_ptr(),
                sbox_buffer.unsafe_ptr(),
                1,
                iv_buffer.unsafe_ptr(),
                rounds,
                grid_dim=grid_dim,
                block_dim=block_dim,
            )
        elif "CTR" in mode:
            var iv_hex = String(tv.get("iv", PythonObject()))
            var nonce_ptr = alloc[UInt8](16)
            if len(iv_hex) == 0:
                for j in range(16):
                    nonce_ptr[j] = 0
            else:
                var iv_bytes = hex_to_bytes(iv_hex)
                for j in range(16):
                    nonce_ptr.store(j, iv_bytes[j])
            
            var nonce_buffer = ctx.enqueue_create_buffer[DType.uint8](16)
            ctx.enqueue_copy(nonce_buffer, nonce_ptr)
            ctx.enqueue_function[aes_gpu_kernel_ctr, aes_gpu_kernel_ctr](
                input_buffer.unsafe_ptr(),
                output_buffer.unsafe_ptr(),
                round_keys_buffer.unsafe_ptr(),
                sbox_buffer.unsafe_ptr(),
                1,
                nonce_buffer.unsafe_ptr(),
                rounds,
                grid_dim=grid_dim,
                block_dim=block_dim,
            )
        elif "GCM" in mode:
            var nonce_hex = String(tv.get("nonce", PythonObject()))
            var nonce_ptr = alloc[UInt8](12)
            if len(nonce_hex) == 0:
                for j in range(12):
                    nonce_ptr[j] = 0
            else:
                var nonce_bytes = hex_to_bytes(nonce_hex)
                for j in range(12):
                    nonce_ptr.store(j, nonce_bytes[j])
            
            var nonce_buffer = ctx.enqueue_create_buffer[DType.uint8](12)
            ctx.enqueue_copy(nonce_buffer, nonce_ptr)
            ctx.enqueue_function[aes_gpu_kernel_gcm, aes_gpu_kernel_gcm](
                input_buffer.unsafe_ptr(),
                output_buffer.unsafe_ptr(),
                round_keys_buffer.unsafe_ptr(),
                sbox_buffer.unsafe_ptr(),
                1,
                nonce_buffer.unsafe_ptr(),
                rounds,
                grid_dim=grid_dim,
                block_dim=block_dim,
            )
        elif "XTS" in mode:
            var tweak_hex = String(tv.get("tweak", PythonObject()))
            var tweak_ptr = alloc[UInt8](16)
            if len(tweak_hex) == 0:
                for j in range(16):
                    tweak_ptr[j] = 0
            else:
                var tweak_bytes = hex_to_bytes(tweak_hex)
                for j in range(16):
                    tweak_ptr.store(j, tweak_bytes[j])
            
            var key1_ptr: UnsafePointer[UInt8, MutAnyOrigin]
            var key2_ptr: UnsafePointer[UInt8, MutAnyOrigin]
            var xts_rounds: Int
            
            if key_len == 32:
                key1_ptr = alloc[UInt8](16)
                key2_ptr = alloc[UInt8](16)
                for j in range(16):
                    key1_ptr.store(j, key_bytes[j])
                    key2_ptr.store(j, key_bytes[j + 16])
                xts_rounds = 10
            else:
                key1_ptr = alloc[UInt8](32)
                key2_ptr = alloc[UInt8](32)
                for j in range(32):
                    key1_ptr.store(j, key_bytes[j])
                    key2_ptr.store(j, key_bytes[j + 32])
                xts_rounds = 14
            
            var round_keys1 = expand_key_128(key1_ptr) if xts_rounds == 10 else expand_key_256(key1_ptr)
            var round_keys2 = expand_key_128(key2_ptr) if xts_rounds == 10 else expand_key_256(key2_ptr)
            
            var round_keys1_size = 44 if xts_rounds == 10 else 60
            var round_keys2_size = 44 if xts_rounds == 10 else 60
            var round_keys1_buffer = ctx.enqueue_create_buffer[DType.uint32](round_keys1_size)
            var round_keys2_buffer = ctx.enqueue_create_buffer[DType.uint32](round_keys2_size)
            ctx.enqueue_copy(round_keys1_buffer, round_keys1)
            ctx.enqueue_copy(round_keys2_buffer, round_keys2)
            
            var tweak_buffer = ctx.enqueue_create_buffer[DType.uint8](16)
            ctx.enqueue_copy(tweak_buffer, tweak_ptr)
            ctx.synchronize()
            
            ctx.enqueue_function[aes_gpu_kernel_xts, aes_gpu_kernel_xts](
                input_buffer.unsafe_ptr(),
                output_buffer.unsafe_ptr(),
                round_keys1_buffer.unsafe_ptr(),
                round_keys2_buffer.unsafe_ptr(),
                sbox_buffer.unsafe_ptr(),
                1,
                tweak_buffer.unsafe_ptr(),
                xts_rounds,
                grid_dim=grid_dim,
                block_dim=block_dim,
            )
            round_keys1.free()
            round_keys2.free()
            key1_ptr.free()
            key2_ptr.free()
        else:
            ctx.enqueue_function[aes_gpu_kernel_ecb, aes_gpu_kernel_ecb](
                input_buffer.unsafe_ptr(),
                output_buffer.unsafe_ptr(),
                round_keys_buffer.unsafe_ptr(),
                sbox_buffer.unsafe_ptr(),
                1,
                rounds,
                grid_dim=grid_dim,
                block_dim=block_dim,
            )
        
        ctx.synchronize()
        ctx.enqueue_copy(ct_ptr, output_buffer)
        ctx.synchronize()
        
        var correct = True
        for j in range(16):
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
            for j in range(16):
                got_hex += hex(Int(ct_ptr.load(j)))[2:].rjust(2, '0')
            failures.append(mode + " " + String(i) + ": expected " + expected_ct + ", got " + got_hex)
        
        key_ptr.free()
        round_keys.free()
        pt_ptr.free()
        ct_ptr.free()
    
    return TestResult(passed, failed, failures^)


def main():
    @parameter
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
        print_result("AES-128-GPU", aes_gpu_result)
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
        var json_data = load_json("tests/aes_test_vectors.json", py)
        var modes = ["AES-128-ECB", "AES-192-ECB", "AES-256-ECB", 
                     "AES-128-CBC", "AES-192-CBC", "AES-256-CBC",
                     "AES-128-CTR", "AES-192-CTR", "AES-256-CTR",
                     "AES-128-GCM", "AES-192-GCM", "AES-256-GCM",
                     "AES-128-XTS", "AES-256-XTS"]
        
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
