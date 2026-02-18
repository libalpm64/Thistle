# Test file to diagnose UInt64 SIMD support in Mojo
# Issue: SIMD[DType.uint64, N] constructor fails with "constraint failed: expected a scalar type"

fn test_uint64_simd_basic():
    print("=== Testing UInt64 SIMD Support ===")
    print()
    
    # Test 1: Basic UInt64 scalar (should work)
    print("Test 1: Basic UInt64 scalar...")
    var scalar_u64: UInt64 = 0x123456789ABCDEF0
    print("  UInt64 scalar: 0x", scalar_u64, " [OK]")
    print()
    
    # Test 2: SIMD[DType.uint64, 1] - single element vector
    print("Test 2: SIMD[DType.uint64, 1] (single element)...")
    try:
        var vec1 = SIMD[DType.uint64, 1](0x123456789ABCDEF0)
        print("  SIMD[DType.uint64, 1]: 0x", vec1[0], " [OK]")
    except:
        print("  SIMD[DType.uint64, 1]: FAILED")
    print()
    
    # Test 3: SIMD[DType.uint64, 2] - 2 element vector
    print("Test 3: SIMD[DType.uint64, 2]...")
    try:
        var vec2 = SIMD[DType.uint64, 2](0x1111111111111111, 0x2222222222222222)
        print("  SIMD[DType.uint64, 2]: [0x", vec2[0], ", 0x", vec2[1], "] [OK]")
    except:
        print("  SIMD[DType.uint64, 2]: FAILED")
    print()
    
    # Test 4: SIMD[DType.uint64, 4] - 4 element vector (AVX2 width for 64-bit)
    print("Test 4: SIMD[DType.uint64, 4] (AVX2 width)...")
    try:
        var vec4 = SIMD[DType.uint64, 4](1, 2, 3, 4)
        print("  SIMD[DType.uint64, 4]: [", vec4[0], ", ", vec4[1], ", ", vec4[2], ", ", vec4[3], "] [OK]")
    except:
        print("  SIMD[DType.uint64, 4]: FAILED")
    print()
    
    # Test 5: Compare with UInt32 SIMD (should work)
    print("Test 5: SIMD[DType.uint32, 4] for comparison...")
    try:
        var vec32 = SIMD[DType.uint32, 4](0x11111111, 0x22222222, 0x33333333, 0x44444444)
        print("  SIMD[DType.uint32, 4]: [0x", vec32[0], ", 0x", vec32[1], ", 0x", vec32[2], ", 0x", vec32[3], "] [OK]")
    except:
        print("  SIMD[DType.uint32, 4]: FAILED")
    print()
    
    # Test 6: Check DType.uint64 properties
    print("Test 6: DType.uint64 properties...")
    # size_of is in sys.info module
    print()


fn test_simd_operations():
    print("=== Testing SIMD Operations on UInt64 ===")
    print()
    
    # Test if we can do operations on UInt64 SIMD
    print("Test: SIMD operations...")
    try:
        var a = SIMD[DType.uint64, 4](1, 2, 3, 4)
        var b = SIMD[DType.uint64, 4](10, 20, 30, 40)
        var c = a + b
        print("  Addition: [", c[0], ", ", c[1], ", ", c[2], ", ", c[3], "] [OK]")
        
        var d = a ^ b
        print("  XOR: [", d[0], ", ", d[1], ", ", d[2], ", ", d[3], "] [OK]")
        
        var e = a * b
        print("  Multiply: [", e[0], ", ", e[1], ", ", e[2], ", ", e[3], "] [OK]")
    except:
        print("  SIMD operations: FAILED")
    print()


fn test_rotate_on_simd():
    """Test if rotate_bits_left works on UInt64 SIMD."""
    from bit import rotate_bits_left
    
    print("=== Testing rotate_bits_left on UInt64 SIMD ===")
    print()
    
    # Test on scalar UInt64
    print("Test: rotate_bits_left on scalar UInt64...")
    var scalar: UInt64 = 0x123456789ABCDEF0
    var rotated = rotate_bits_left[shift=32](scalar)
    print("  Original: 0x", scalar)
    print("  Rotated left 32: 0x", rotated, " [OK]")
    print()
    
    # Test on SIMD UInt64
    print("Test: rotate_bits_left on SIMD[DType.uint64, 4]...")
    try:
        var vec = SIMD[DType.uint64, 4](0x1111111111111111, 0x2222222222222222, 0x3333333333333333, 0x4444444444444444)
        var rotated_vec = rotate_bits_left[shift=32](vec)
        print("  Rotated SIMD: [0x", rotated_vec[0], ", 0x", rotated_vec[1], ", 0x", rotated_vec[2], ", 0x", rotated_vec[3], "] [OK]")
    except:
        print("  rotate_bits_left on SIMD[DType.uint64, 4]: FAILED")
    print()


fn main():
    print("============================================================")
    print("        UInt64 SIMD Support Diagnostic Test")
    print("============================================================")
    print()
    
    test_uint64_simd_basic()
    test_simd_operations()
    test_rotate_on_simd()
    
    print("============================================================")
    print("                    Diagnostic Complete")
    print("============================================================")
