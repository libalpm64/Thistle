from python import Python
from python import PythonObject
from collections import List
from sys import has_accelerator
from thistle.sha2 import bytes_to_hex
from thistle.aes import AESKey, SBOX, expand_key_128, ROUNDS_128
from memory import alloc
from gpu.host import DeviceContext
from thistle.aes_gpu import aes_kernel


@fieldwise_init
struct TestResult(Copyable, Movable):
    var passed: Int
    var failed: Int
    var failures: List[String]


fn hex_to_bytes(hex_str: String) -> List[UInt8]:
    var result = List[UInt8]()
    var hex_bytes = hex_str.as_bytes()
    var i = 0
    while i < len(hex_bytes):
        var high = hex_bytes[i]
        var low = hex_bytes[i + 1]
        var val: UInt8 = 0
        if high >= 48 and high <= 57:
            val = UInt8(high - 48) << 4
        elif high >= 97 and high <= 102:
            val = UInt8(high - 97 + 10) << 4
        elif high >= 65 and high <= 70:
            val = UInt8(high - 65 + 10) << 4
        
        if low >= 48 and low <= 57:
            val = val | UInt8(low - 48)
        elif low >= 97 and low <= 102:
            val = val | UInt8(low - 97 + 10)
        elif low >= 65 and low <= 70:
            val = val | UInt8(low - 65 + 10)
        
        result.append(val)
        i += 2
    return result^


fn hex_char_to_val(c: Int) -> UInt8:
    if c >= 48 and c <= 57:
        return UInt8(c - 48)
    if c >= 97 and c <= 102:
        return UInt8(c - 97 + 10)
    if c >= 65 and c <= 70:
        return UInt8(c - 65 + 10)
    return 0


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


fn test_aes_gpu(json_data: PythonObject, py: PythonObject) raises -> TestResult:
    var passed = 0
    var failed = 0
    var failures = List[String]()
    
    var count = Int(py=json_data.__len__())
    
    var sbox_host = alloc[Scalar[DType.uint8]](256)
    for i in range(256):
        sbox_host[i] = SBOX[i]
    
    var num_test_vectors = min(count, 100)
    
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
            
            var round_keys = expand_key_128(key_ptr)
            
            var total_bytes = 16
            var input_host = alloc[Scalar[DType.uint8]](total_bytes)
            var output_host = alloc[Scalar[DType.uint8]](total_bytes)
            
            for j in range(16):
                input_host[j] = pt_bytes_data[j]
            
            var input_buffer = ctx.enqueue_create_buffer[DType.uint8](total_bytes)
            var output_buffer = ctx.enqueue_create_buffer[DType.uint8](total_bytes)
            var round_keys_buffer = ctx.enqueue_create_buffer[DType.uint32](44)
            
            ctx.enqueue_copy(input_buffer, input_host)
            ctx.enqueue_copy(round_keys_buffer, round_keys)
            ctx.synchronize()
            
            var block_dim = 1
            var grid_dim = 1
            
            ctx.enqueue_function[aes_kernel, aes_kernel](
                input_buffer.unsafe_ptr(),
                output_buffer.unsafe_ptr(),
                round_keys_buffer.unsafe_ptr(),
                sbox_buffer.unsafe_ptr(),
                ROUNDS_128,
                1,
                grid_dim=grid_dim,
                block_dim=block_dim,
            )
            ctx.synchronize()
            
            ctx.enqueue_copy(output_host, output_buffer)
            ctx.synchronize()
            
            var correct = True
            for j in range(16):
                var expected_byte = hex_char_to_val(Int(expected_ct_hex.as_bytes()[j * 2])) << 4
                expected_byte |= hex_char_to_val(Int(expected_ct_hex.as_bytes()[j * 2 + 1]))
                if output_host[j] != expected_byte:
                    correct = False
                    break
            
            if correct:
                passed += 1
            else:
                failed += 1
                var got_hex = String("")
                for j in range(16):
                    got_hex += hex(Int(output_host[j]))[2:].rjust(2, '0')
                failures.append("AES-GPU " + name + ": expected " + expected_ct_hex + ", got " + got_hex)
            
            key_ptr.free()
            round_keys.free()
            input_host.free()
            output_host.free()
    
    sbox_host.free()
    
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
        print("Loading AES vectors")
        var aes_data = load_json("tests/vectors/aes.json", py)
        var aes_gpu_result = test_aes_gpu(aes_data, py)
        print_result("AES-128-GPU", aes_gpu_result)
        total_passed += aes_gpu_result.passed
        total_failed += aes_gpu_result.failed
        if aes_gpu_result.failed > 0:
            any_failures = True
    except e:
        print("AES-128-GPU [error] " + String(e))
        any_failures = True
    
    print()
    print("Total: " + String(total_passed) + " pass, " + String(total_failed) + " fail")
    
    if any_failures:
        print("Tests fail")
    else:
        print("Tests pass")
