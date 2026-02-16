from std.time import perf_counter_ns
from thistle.sha2 import sha256_hash, sha512_hash
from thistle.sha3 import sha3_256
from collections import List


fn main():
    # 1 MiB data buffer
    var buffer_size = 1024 * 1024
    var data = List[UInt8](capacity=buffer_size)
    for i in range(buffer_size):
        data.append(UInt8(i % 256))

    var span = Span[UInt8](data)
    # 100 MiB per test
    var iters = 100

    print("Thistle Cryptography Speed Test (@O3)")

    # SHA-256
    print("Benchmarking SHA-256...")
    _ = sha256_hash(span)  # Warmup
    var start = perf_counter_ns()
    for _ in range(iters):
        _ = sha256_hash(span)
    var end = perf_counter_ns()
    var duration = Float64(end - start) / 1e9
    var mib_s = iters / duration
    print("  Speed: " + String(mib_s) + " MiB/s")

    # SHA-512
    print("Benchmarking SHA-512...")
    _ = sha512_hash(span)  # Warmup
    start = perf_counter_ns()
    for _ in range(iters):
        _ = sha512_hash(span)
    end = perf_counter_ns()
    duration = Float64(end - start) / 1e9
    mib_s = iters / duration
    print("  Speed: " + String(mib_s) + " MiB/s")

    # SHA3-256
    print("Benchmarking SHA3-256...")
    _ = sha3_256(span)  # Warmup
    start = perf_counter_ns()
    for _ in range(iters):
        _ = sha3_256(span)
    end = perf_counter_ns()
    duration = Float64(end - start) / 1e9
    mib_s = iters / duration
    print("  Speed: " + String(mib_s) + " MiB/s")
