from time import perf_counter, perf_counter_ns
from collections import List
from algorithm import parallelize
from random import random_ui64, seed
from thistle.argon2 import Argon2id
from thistle.blake2b import Blake2b
from thistle.blake3 import blake3_parallel_hash
from thistle.camellia import CamelliaCipher
from thistle.chacha20 import ChaCha20
from thistle.kcipher2 import KCipher2
from thistle.sha2 import sha256_hash, sha512_hash
from thistle.sha3 import sha3_256


comptime _MiB = 1024 * 1024

fn generate_data(length: Int) -> List[UInt8]:
    var data = List[UInt8](capacity=length)
    for i in range(length):
        data.append(UInt8(i % 256))
    return data^


fn benchmark_sha256(data: List[UInt8], duration_secs: Float64) -> String:
    var span = Span[UInt8](data)
    _ = sha256_hash(span)
    var count = 0
    var start = perf_counter()
    while perf_counter() - start < duration_secs:
        _ = sha256_hash(span)
        count += 1
    var end = perf_counter()
    var duration = end - start
    var mb = Float64(len(data) * count) / _MiB
    var mbps = mb / duration
    return String(
        "sha256 | throughput: ",
        round(mbps, 6),
        " mb/s, hashes: ",
        count,
        ", time: ",
        round(duration, 4),
        "s"
    )


fn benchmark_sha512(data: List[UInt8], duration_secs: Float64) -> String:
    var span = Span[UInt8](data)
    _ = sha512_hash(span)
    var count = 0
    var start = perf_counter()
    while perf_counter() - start < duration_secs:
        _ = sha512_hash(span)
        count += 1
    var end = perf_counter()
    var duration = end - start
    var mb = Float64(len(data) * count) / _MiB
    var mbps = mb / duration
    return String(
        "sha512 | throughput: ",
        round(mbps, 6),
        " mb/s, hashes: ",
        count,
        ", time: ",
        round(duration, 4),
        "s"
    )


fn benchmark_sha3_256(data: List[UInt8], duration_secs: Float64) -> String:
    var span = Span[UInt8](data)
    _ = sha3_256(span)
    var count = 0
    var start = perf_counter()
    while perf_counter() - start < duration_secs:
        _ = sha3_256(span)
        count += 1
    var end = perf_counter()
    var duration = end - start
    var mb = Float64(len(data) * count) / _MiB
    var mbps = mb / duration
    return String(
        "sha3-256 | throughput: ",
        round(mbps, 6),
        " mb/s, hashes: ",
        count,
        ", time: ",
        round(duration, 4),
        "s"
    )


fn benchmark_blake2b(data: List[UInt8], duration_secs: Float64) -> String:
    var span = Span[UInt8](data)
    var count = 0
    var start = perf_counter()
    while perf_counter() - start < duration_secs:
        var c = Blake2b(32)
        c.update(span)
        _ = c.finalize()
        count += 1
    var end = perf_counter()
    var duration = end - start
    var mb = Float64(len(data) * count) / _MiB
    var mbps = mb / duration
    return String(
        "blake2b | throughput: ",
        round(mbps, 6),
        " mb/s, hashes: ",
        count,
        ", time: ",
        round(duration, 4),
        "s"
    )


fn benchmark_blake3(data: List[UInt8], duration_secs: Float64) -> String:
    var span = Span[UInt8](data)
    _ = blake3_parallel_hash(span)
    var count = 0
    var start = perf_counter()
    while perf_counter() - start < duration_secs:
        _ = blake3_parallel_hash(span)
        count += 1
    var end = perf_counter()
    var duration = end - start
    var mb = Float64(len(data) * count) / _MiB
    var mbps = mb / duration
    return String(
        "blake3 | throughput: ",
        round(mbps, 6),
        " mb/s, hashes: ",
        count,
        ", time: ",
        round(duration, 4),
        "s"
    )


fn benchmark_camellia(data_size: Int, duration_secs: Float64) -> String:
    var key = List[UInt8]()
    for i in range(16):
        key.append(UInt8(i))
    var cipher = CamelliaCipher(Span[UInt8](key))

    var data = List[UInt8](capacity=16)
    for i in range(16):
        data.append(UInt8(i % 256))
    var data_span = Span[UInt8](data)

    var checksum: UInt64 = 0
    var count = 0
    var start = perf_counter()
    while perf_counter() - start < duration_secs:
        var result = cipher.encrypt(data_span)
        checksum += UInt64(result[0])
        count += 1
    var end = perf_counter()
    var duration = end - start
    _ = checksum
    var mbps = Float64(count * 16) / _MiB / duration
    return String(
        "camellia | throughput: ",
        round(mbps, 6),
        " mb/s, blocks: ",
        count,
        ", time: ",
        round(duration, 4),
        "s"
    )


fn benchmark_chacha20(data_size: Int, duration_secs: Float64) -> String:
    var key = SIMD[DType.uint8, 32](0)
    for i in range(32):
        key[i] = UInt8(i)
    var nonce = SIMD[DType.uint8, 12](0)

    var data = List[UInt8](capacity=data_size)
    for i in range(data_size):
        data.append(UInt8(i % 256))
    var span = Span[mut=True, UInt8](data)

    var cipher = ChaCha20(key, nonce)

    var checksum: UInt64 = 0
    var count = 0
    var start = perf_counter()
    while perf_counter() - start < duration_secs:
        cipher.encrypt_inplace(span)
        checksum += UInt64(span[0])
        count += 1
    var end = perf_counter()
    var duration = end - start
    _ = checksum
    var mb = Float64(data_size * count) / _MiB
    var mbps = mb / duration
    return String(
        "chacha20 | throughput: ",
        round(mbps, 6),
        " mb/s, encrypts: ",
        count,
        ", time: ",
        round(duration, 4),
        "s"
    )


fn benchmark_kcipher2(data_size: Int, duration_secs: Float64) -> String:
    var key = SIMD[DType.uint32, 4](0, 0, 0, 0)
    var iv = SIMD[DType.uint32, 4](0, 0, 0, 0)
    var cipher = KCipher2(key, iv)

    var data = List[UInt8](capacity=data_size)
    for i in range(data_size):
        data.append(UInt8(i % 256))
    var span = Span[mut=True, UInt8](data)

    var count = 0
    var start = perf_counter()
    while perf_counter() - start < duration_secs:
        cipher.encrypt_inplace(span)
        cipher._init(key, iv)
        count += 1
    var end = perf_counter()
    var duration = end - start
    var mb = Float64(data_size * count) / _MiB
    var mbps = mb / duration
    return String(
        "kcipher2 | throughput: ",
        round(mbps, 6),
        " mb/s, encrypts: ",
        count,
        ", time: ",
        round(duration, 4),
        "s"
    )


fn benchmark_argon2(duration_secs: Float64) -> String:
    var password = String("password").as_bytes()
    var salt = String("saltsalt12345678").as_bytes()
    var ctx = Argon2id(salt, memory_size_kb=65536, iterations=3, parallelism=4)

    _ = ctx.hash(password)

    var count = 0
    var start = perf_counter()
    while perf_counter() - start < duration_secs:
        _ = ctx.hash(password)
        count += 1
    var end = perf_counter()
    var duration = end - start
    var hps = Float64(count) / duration
    return String(
        "argon2id | throughput: ",
        round(hps, 6),
        " h/s, hashes: ",
        count,
        ", time: ",
        round(duration, 4),
        "s"
    )


def main():
    print("Thistle benchmark:\n")
    print("Testing.... please wait for all the tests to conclude.\n")

    var data = generate_data(100 * _MiB)
    var duration = 5.0

    print(benchmark_sha256(data, duration))
    print(benchmark_sha512(data, duration))
    print(benchmark_sha3_256(data, duration))
    print(benchmark_blake2b(data, duration))
    print(benchmark_blake3(data, duration))
    print(benchmark_camellia(_MiB, duration))
    print(benchmark_chacha20(_MiB, duration))
    print(benchmark_kcipher2(_MiB, duration))
    print(benchmark_argon2(duration))

    print("\nAll benchmarks completed")
