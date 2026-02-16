# ChaCha20 Performance Benchmark
# SPDX-License-Identifier: MIT

from time import perf_counter
from collections import List
from memory.unsafe_pointer import UnsafePointer, alloc
from builtin.type_aliases import MutExternalOrigin

from thistle.chacha20 import ChaCha20


fn print_speed_report(
    name: String, total_iters: Int, total_time: Float64, mb_per_op: Float64
):
    var ops_per_sec = Float64(total_iters) / total_time
    var mb_per_sec = ops_per_sec * mb_per_op
    print(" ", name, " Performance:")
    print("  Runtime:    ", total_time, "s")
    print("  Total Ops:  ", total_iters)
    print("  Throughput: ", ops_per_sec, " ops/sec")
    print("  Bandwidth:  ", mb_per_sec, " MB/s")


fn benchmark_encrypt(data_size_mb: Float64, duration: Float64) raises:
    """Benchmark ChaCha20 encryption with allocation."""
    var test_len = Int(data_size_mb * 1024 * 1024)

    # Pre-allocate input buffer
    var input_data = List[UInt8](capacity=test_len)
    for i in range(test_len):
        input_data.append(UInt8(i % 256))
    var input_span = Span[UInt8](input_data)

    # Key and nonce (test values)
    var key = SIMD[DType.uint8, 32](0)
    for i in range(32):
        key[i] = UInt8(i)

    var nonce = SIMD[DType.uint8, 12](0)
    for i in range(12):
        nonce[i] = UInt8(i)

    var cipher = ChaCha20(key, nonce)

    print("ChaCha20 Encryption Benchmark (", data_size_mb, "MB per iteration)...")

    var iter_count = 0
    var checksum: UInt64 = 0
    var start_time = perf_counter()

    while (perf_counter() - start_time) < duration:
        var result_ptr = cipher.encrypt(input_span)
        # checksum test to prevent complete optimization
        if result_ptr:
            for i in range(0, test_len, 1024):
                checksum = checksum + UInt64((result_ptr + i)[])
            result_ptr.free()
        iter_count += 1

    var end_time = perf_counter()
    # checksum test to prevent complete optimization
    if checksum == 0xDEADBEEF:
        print("Impossible")
    print_speed_report("ChaCha20 Encrypt", iter_count, end_time - start_time, data_size_mb)


fn benchmark_encrypt_inplace(data_size_mb: Float64, duration: Float64) raises:
    """Benchmark ChaCha20 in-place encryption (no allocation)."""
    var test_len = Int(data_size_mb * 1024 * 1024)

    var data = List[UInt8](capacity=test_len)
    for i in range(test_len):
        data.append(UInt8(i % 256))
    var data_span = Span[mut=True, UInt8](data)

    var key = SIMD[DType.uint8, 32](0)
    for i in range(32):
        key[i] = UInt8(i)

    var nonce = SIMD[DType.uint8, 12](0)
    for i in range(12):
        nonce[i] = UInt8(i)

    var cipher = ChaCha20(key, nonce)

    print("ChaCha20 In-Place Encryption Benchmark (", data_size_mb, "MB per iteration)...")

    var iter_count = 0
    var start_time = perf_counter()

    while (perf_counter() - start_time) < duration:
        cipher.encrypt_inplace(data_span)
        iter_count += 1

    var end_time = perf_counter()
    print_speed_report("ChaCha20 In-Place", iter_count, end_time - start_time, data_size_mb)


fn benchmark_block_function(iterations: Int) raises:
    """Benchmark raw block function performance."""
    from thistle.chacha20 import chacha20_block

    var key = SIMD[DType.uint8, 32](0)
    for i in range(32):
        key[i] = UInt8(i)

    var nonce = SIMD[DType.uint8, 12](0)
    for i in range(12):
        nonce[i] = UInt8(i)

    print("ChaCha20 Block Function Benchmark (", iterations, " iterations)...")

    var checksum: UInt64 = 0
    var start_time = perf_counter()

    for i in range(iterations):
        var block = chacha20_block(key, UInt32(i), nonce)
        # checksum test to prevent complete optimization
        checksum = checksum + UInt64(block[0]) + UInt64(block[63])

    var end_time = perf_counter()
    # checksum test to prevent complete optimization
    if checksum == 0xDEADBEEF:
        print("Impossible")
    var total_bytes = Float64(iterations * 64) / (1024 * 1024)
    print_speed_report("ChaCha20 Block", iterations, end_time - start_time, total_bytes / Float64(iterations))


fn main() raises:
    print("ChaCha20 Performance Benchmark Suite")

    comptime BENCH_DURATION = 10.0
    var test_size_mb = 50.0
    benchmark_encrypt(test_size_mb, BENCH_DURATION)
    print()

    benchmark_encrypt_inplace(test_size_mb, BENCH_DURATION)
    print()

    benchmark_block_function(1_000_000)
    print()

    print("Benchmark is done.")