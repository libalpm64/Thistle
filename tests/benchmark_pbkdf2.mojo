#!/usr/bin/env mojo

from time import perf_counter
from thistle.pbkdf2 import pbkdf2_hmac_sha256, pbkdf2_hmac_sha512
from thistle.sha2 import bytes_to_hex


fn benchmark_pbkdf2_sha256(
    name: String,
    password: Span[UInt8],
    salt: Span[UInt8],
    iterations: Int,
    dklen: Int,
    duration_seconds: Float64 = 5.0,
) -> Tuple[Int, Float64, Float64]:
    var count = 0
    var start = perf_counter()
    
    while perf_counter() - start < duration_seconds:
        _ = pbkdf2_hmac_sha256(password, salt, iterations, dklen)
        count += 1
    
    var end = perf_counter()
    var total_time = end - start
    var hashes_per_second = Float64(count) / total_time
    var time_per_hash_ms = (total_time / Float64(count)) * 1000.0 if count > 0 else 0.0
    
    return (count, hashes_per_second, time_per_hash_ms)


fn benchmark_pbkdf2_sha512(
    name: String,
    password: Span[UInt8],
    salt: Span[UInt8],
    iterations: Int,
    dklen: Int,
    duration_seconds: Float64 = 5.0,
) -> Tuple[Int, Float64, Float64]:
    var count = 0
    var start = perf_counter()
    
    while perf_counter() - start < duration_seconds:
        _ = pbkdf2_hmac_sha512(password, salt, iterations, dklen)
        count += 1
    
    var end = perf_counter()
    var total_time = end - start
    var hashes_per_second = Float64(count) / total_time
    var time_per_hash_ms = (total_time / Float64(count)) * 1000.0 if count > 0 else 0.0
    
    return (count, hashes_per_second, time_per_hash_ms)


def main():
    print("=" * 70)
    print("PBKDF2 Benchmark (Mojo Thistle)")
    print("=" * 70)
    print()
    
    var password = "password".as_bytes()
    var salt = "salt".as_bytes()
    var duration = 3.0
    
    print("PBKDF2-HMAC-SHA256:")
    print("-" * 50)
    
    var (c1, hps1, ms1) = benchmark_pbkdf2_sha256("1 iter", password, salt, 1, 32, duration)
    print("  1 iteration:")
    print("    " + String(c1) + " hashes in " + String(duration) + "s")
    print("    " + String(hps1) + " hashes/sec")
    print("    " + String(ms1) + " ms/hash")
    print()
    
    var (c2, hps2, ms2) = benchmark_pbkdf2_sha256("1000 iter", password, salt, 1000, 32, duration)
    print("  1000 iterations:")
    print("    " + String(c2) + " hashes in " + String(duration) + "s")
    print("    " + String(hps2) + " hashes/sec")
    print("    " + String(ms2) + " ms/hash")
    print()
    
    var (c3, hps3, ms3) = benchmark_pbkdf2_sha256("10000 iter", password, salt, 10000, 32, duration)
    print("  10000 iterations:")
    print("    " + String(c3) + " hashes in " + String(duration) + "s")
    print("    " + String(hps3) + " hashes/sec")
    print("    " + String(ms3) + " ms/hash")
    print()
    
    print("PBKDF2-HMAC-SHA512:")
    print("-" * 50)
    
    var (c4, hps4, ms4) = benchmark_pbkdf2_sha512("1 iter", password, salt, 1, 64, duration)
    print("  1 iteration:")
    print("    " + String(c4) + " hashes in " + String(duration) + "s")
    print("    " + String(hps4) + " hashes/sec")
    print("    " + String(ms4) + " ms/hash")
    print()
    
    var (c5, hps5, ms5) = benchmark_pbkdf2_sha512("1000 iter", password, salt, 1000, 64, duration)
    print("  1000 iterations:")
    print("    " + String(c5) + " hashes in " + String(duration) + "s")
    print("    " + String(hps5) + " hashes/sec")
    print("    " + String(ms5) + " ms/hash")
    print()
    
    var (c6, hps6, ms6) = benchmark_pbkdf2_sha512("10000 iter", password, salt, 10000, 64, duration)
    print("  10000 iterations:")
    print("    " + String(c6) + " hashes in " + String(duration) + "s")
    print("    " + String(hps6) + " hashes/sec")
    print("    " + String(ms6) + " ms/hash")
    print()
    
    print("=" * 70)
    print("Summary:")
    print("=" * 70)
    print(String("Test").ljust(30) + String("Hashes/sec").rjust(15) + String("ms/hash").rjust(12))
    print("-" * 70)
    print(String("PBKDF2-SHA256 (1 iter)").ljust(30) + String(hps1).rjust(15) + String(ms1).rjust(12))
    print(String("PBKDF2-SHA256 (1000 iter)").ljust(30) + String(hps2).rjust(15) + String(ms2).rjust(12))
    print(String("PBKDF2-SHA256 (10000 iter)").ljust(30) + String(hps3).rjust(15) + String(ms3).rjust(12))
    print(String("PBKDF2-SHA512 (1 iter)").ljust(30) + String(hps4).rjust(15) + String(ms4).rjust(12))
    print(String("PBKDF2-SHA512 (1000 iter)").ljust(30) + String(hps5).rjust(15) + String(ms5).rjust(12))
    print(String("PBKDF2-SHA512 (10000 iter)").ljust(30) + String(hps6).rjust(15) + String(ms6).rjust(12))
