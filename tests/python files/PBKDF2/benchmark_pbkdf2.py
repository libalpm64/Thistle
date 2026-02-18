#!/usr/bin/env python3
"""
PBKDF2 Benchmark Script
Compares performance of PBKDF2-HMAC-SHA256 and PBKDF2-HMAC-SHA512
"""

import hashlib
import time
from typing import Callable


def benchmark_pbkdf2(
    name: str,
    password: bytes,
    salt: bytes,
    iterations: int,
    dklen: int,
    duration_seconds: float = 5.0,
    hash_name: str = "sha256"
) -> dict:
    
    count = 0
    start = time.perf_counter()
    
    while time.perf_counter() - start < duration_seconds:
        hashlib.pbkdf2_hmac(hash_name, password, salt, iterations, dklen)
        count += 1
    
    end = time.perf_counter()
    total_time = end - start
    hashes_per_second = count / total_time
    
    return {
        "name": name,
        "iterations": iterations,
        "count": count,
        "total_time": total_time,
        "hashes_per_second": hashes_per_second,
        "time_per_hash_ms": (total_time / count) * 1000 if count > 0 else 0,
    }


def main():
    print("PBKDF2 Benchmark (Python hashlib)")
    print()
    
    password = b"password"
    salt = b"salt"
    
    test_cases = [
        ("PBKDF2-SHA256 (1 iter)", "sha256", 1, 32),
        ("PBKDF2-SHA256 (1000 iter)", "sha256", 1000, 32),
        ("PBKDF2-SHA256 (10000 iter)", "sha256", 10000, 32),
        ("PBKDF2-SHA512 (1 iter)", "sha512", 1, 64),
        ("PBKDF2-SHA512 (1000 iter)", "sha512", 1000, 64),
        ("PBKDF2-SHA512 (10000 iter)", "sha512", 10000, 64),
    ]
    
    results = []
    duration = 3.0
    
    for name, hash_name, iterations, dklen in test_cases:
        print(f"Benchmarking {name}...")
        result = benchmark_pbkdf2(
            name, password, salt, iterations, dklen, 
            duration_seconds=duration, hash_name=hash_name
        )
        results.append(result)
        print(f"  {result['count']} hashes in {result['total_time']:.3f}s")
        print(f"  {result['hashes_per_second']:.2f} hashes/sec")
        print(f"  {result['time_per_hash_ms']:.4f} ms/hash")
        print()
    
    print("Summary:")
    print(f"{'Test':<30} {'Hashes/sec':>15} {'ms/hash':>12}")
    for r in results:
        print(f"{r['name']:<30} {r['hashes_per_second']:>15.2f} {r['time_per_hash_ms']:>12.4f}")


if __name__ == "__main__":
    main()
