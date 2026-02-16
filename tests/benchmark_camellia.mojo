from time import perf_counter_ns
from thistle.camellia import CamelliaCipher
from collections import List


fn main() raises:
    var iterations = 1_000_000

    var key = List[UInt8]()
    for i in range(16):
        key.append(i)
    var key_span = Span[UInt8](key)

    var data_simd = SIMD[DType.uint8, 16](
        0x01,
        0x23,
        0x45,
        0x67,
        0x89,
        0xAB,
        0xCD,
        0xEF,
        0xFE,
        0xDC,
        0xBA,
        0x98,
        0x76,
        0x54,
        0x32,
        0x10,
    )

    print("Camellia Benchmark (", iterations, " iterations)")
    print("Implementation: ARX-style with stack-based SIMD key storage")
    print("-" * 60)

    var cipher = CamelliaCipher(key_span)
    var data = data_simd
    
    # Warmup
    for _ in range(1000):
        data = cipher.encrypt(data)

    var start = perf_counter_ns()
    for _ in range(iterations):
        data = cipher.encrypt(data)
    var end = perf_counter_ns()
    var duration = (Float64(end) - Float64(start)) / 1e9

    print("Total Time:   ", duration, "s")
    print(
        "Throughput:   ",
        (Float64(iterations) * 16) / (duration * 1024 * 1024),
        " MB/s",
    )
    print("Per block:    ", (duration * 1e9) / Float64(iterations), "ns")
    print("-" * 60)
    print("Encrypted data[0]:", data[0])
