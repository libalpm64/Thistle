from time import perf_counter
from collections import List
from thistle.blake3 import blake3_parallel_hash

# Test vectors for pattern: bytes([i % 251 for i in range(length)])
fn generate_test_data(length: Int) -> List[UInt8]:
    var data = List[UInt8](capacity=length)
    for i in range(length):
        data.append(UInt8(i % 251))
    return data^

fn main() raises:
    print("=" * 80)
    print("BLAKE3 Test Suite - Official Vectors")
    print("=" * 80)
    print()
    
    var passed = 0
    var failed = 0
    
    var data0 = generate_test_data(0)
    var result0 = blake3_parallel_hash(Span[UInt8](data0))
    var expected0 = SIMD[DType.uint8, 32](
        0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6,
        0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9, 0x49,
        0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7,
        0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62
    )
    var match0 = True
    for i in range(32):
        if result0[i] != expected0[i]:
            match0 = False
            break
    if match0:
        print("Test 1: 0 bytes (empty) - sucess")
        passed += 1
    else:
        print("Test 1: 0 bytes (empty) - failure")
        failed += 1
    
    var data1 = generate_test_data(1)
    var result1 = blake3_parallel_hash(Span[UInt8](data1))
    var expected1 = SIMD[DType.uint8, 32](
        0x2d, 0x3a, 0xde, 0xdf, 0xf1, 0x1b, 0x61, 0xf1,
        0x4c, 0x88, 0x6e, 0x35, 0xaf, 0xa0, 0x36, 0x73,
        0x6d, 0xcd, 0x87, 0xa7, 0x4d, 0x27, 0xb5, 0xc1,
        0x51, 0x02, 0x25, 0xd0, 0xf5, 0x92, 0xe2, 0x13
    )
    var match1 = True
    for i in range(32):
        if result1[i] != expected1[i]:
            match1 = False
            print("Test 2 mismatch at byte", i, ": got", result1[i], "expected", expected1[i])
            break
    if match1:
        print("Test 2: 1 byte - success")
        passed += 1
    else:
        print("Test 2: 1 byte - failure")
        failed += 1
    
    var data2 = generate_test_data(1024)
    var result2 = blake3_parallel_hash(Span[UInt8](data2))
    var expected2 = SIMD[DType.uint8, 32](
        0x42, 0x21, 0x47, 0x39, 0xf0, 0x95, 0xa4, 0x06,
        0xf3, 0xfc, 0x83, 0xde, 0xb8, 0x89, 0x74, 0x4a,
        0xc0, 0x0d, 0xf8, 0x31, 0xc1, 0x0d, 0xaa, 0x55,
        0x18, 0x9b, 0x5d, 0x12, 0x1c, 0x85, 0x5a, 0xf7
    )
    var match2 = True
    for i in range(32):
        if result2[i] != expected2[i]:
            match2 = False
            break
    if match2:
        print("Test 3: 1024 bytes (1 chunk) - success")
        passed += 1
    else:
        print("Test 3: 1024 bytes (1 chunk) - failure")
        failed += 1
    
    var data3 = generate_test_data(1025)
    var result3 = blake3_parallel_hash(Span[UInt8](data3))
    var expected3 = SIMD[DType.uint8, 32](
        0xd0, 0x02, 0x78, 0xae, 0x47, 0xeb, 0x27, 0xb3,
        0x4f, 0xae, 0xcf, 0x67, 0xb4, 0xfe, 0x26, 0x3f,
        0x82, 0xd5, 0x41, 0x29, 0x16, 0xc1, 0xff, 0xd9,
        0x7c, 0x8c, 0xb7, 0xfb, 0x81, 0x4b, 0x84, 0x44
    )
    var match3 = True
    for i in range(32):
        if result3[i] != expected3[i]:
            match3 = False
            print("Test 4 mismatch at byte", i, ": got", result3[i], "expected", expected3[i])
            break
    if match3:
        print("Test 4: 1025 bytes (1 chunk + 1) - success")
        passed += 1
    else:
        print("Test 4: 1025 bytes (1 chunk + 1) - failure")
        failed += 1
    
    var data4 = generate_test_data(65536)
    var result4 = blake3_parallel_hash(Span[UInt8](data4))
    var expected4 = SIMD[DType.uint8, 32](
        0x68, 0xd6, 0x47, 0xe6, 0x19, 0xa9, 0x30, 0xe7,
        0xb1, 0x08, 0x2f, 0x74, 0xf3, 0x34, 0xb0, 0xc6,
        0x5a, 0x31, 0x57, 0x25, 0x56, 0x9b, 0xdc, 0x12,
        0x3f, 0x0e, 0xe1, 0x18, 0x81, 0x71, 0x7b, 0xfe
    )
    var match4 = True
    for i in range(32):
        if result4[i] != expected4[i]:
            match4 = False
            break
    if match4:
        print("Test 5: 65536 bytes (64KB batch) - success")
        passed += 1
    else:
        print("Test 5: 65536 bytes (64KB batch) - failure")
        failed += 1
    
    var data5 = generate_test_data(65537)
    var result5 = blake3_parallel_hash(Span[UInt8](data5))
    var expected5 = SIMD[DType.uint8, 32](
        0x7c, 0x99, 0xf9, 0x84, 0x0a, 0x73, 0xdf, 0xcb,
        0x6e, 0x5b, 0xfe, 0x4f, 0xf6, 0xd1, 0x55, 0x8a,
        0xca, 0xb7, 0xe0, 0x15, 0x64, 0x07, 0x90, 0xc2,
        0x64, 0x11, 0x81, 0x8b, 0xdb, 0xe1, 0x7e, 0xca
    )
    var match5 = True
    for i in range(32):
        if result5[i] != expected5[i]:
            match5 = False
            print("Test 6 mismatch at byte", i, ": got", result5[i], "expected", expected5[i])
            break
    if match5:
        print("Test 6: 65537 bytes (64KB + 1) - success")
        passed += 1
    else:
        print("Test 6: 65537 bytes (64KB + 1) - failure")
        failed += 1
    
    var data6 = generate_test_data(131072)
    var result6 = blake3_parallel_hash(Span[UInt8](data6))
    var expected6 = SIMD[DType.uint8, 32](
        0x30, 0x6b, 0xab, 0xa9, 0x3b, 0x1a, 0x39, 0x3c,
        0xbd, 0x35, 0x17, 0x28, 0x37, 0xc9, 0x8b, 0x0f,
        0x59, 0xa4, 0x1f, 0x64, 0xe1, 0xb2, 0x68, 0x2a,
        0xe1, 0x02, 0xd8, 0xb2, 0x53, 0x4b, 0x9e, 0x1c
    )
    var match6 = True
    for i in range(32):
        if result6[i] != expected6[i]:
            match6 = False
            break
    if match6:
        print("Test 7: 131072 bytes (2 batches) - success")
        passed += 1
    else:
        print("Test 7: 131072 bytes (2 batches) - failure")
        failed += 1
    
    var data7 = generate_test_data(1048576)
    var result7 = blake3_parallel_hash(Span[UInt8](data7))
    var expected7 = SIMD[DType.uint8, 32](
        0x74, 0xcb, 0x44, 0x1f, 0xd0, 0x87, 0x76, 0x4c,
        0xa9, 0xc3, 0x69, 0x4d, 0xa7, 0x42, 0xeb, 0xe3,
        0x0c, 0xbe, 0xb3, 0x06, 0x0a, 0x17, 0x00, 0x9c,
        0xa8, 0x18, 0x25, 0xc7, 0xa8, 0xd1, 0x03, 0x43
    )
    var match7 = True
    for i in range(32):
        if result7[i] != expected7[i]:
            match7 = False
            break
    if match7:
        print("Test 8: 1048576 bytes (1MB, deep tree) - success")
        passed += 1
    else:
        print("Test 8: 1048576 bytes (1MB, deep tree) - failure")
        failed += 1
    
    print()
    print("=" * 80)
    print("Results: ", passed, "/8 tests passed")
    
    if failed == 0:
        print("All tests passed, cheers!")
    else:
        print("[failure]", failed, " tests failed - Check implementation!")
    print("=" * 80)
    
    if failed > 0:
        raise Error("Tests failed")
