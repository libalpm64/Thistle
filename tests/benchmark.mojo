from time import perf_counter, perf_counter_ns
from collections import List
from algorithm import parallelize
from random import random_ui64, seed
from math import ceildiv
from sys import has_accelerator

from thistle.argon2 import Argon2id
from thistle.blake2b import Blake2b
from thistle.blake3 import blake3_parallel_hash
from thistle.camellia import CamelliaCipher
from thistle.chacha20 import ChaCha20
from thistle.kcipher2 import KCipher2
from thistle.sha2 import sha256_hash, sha512_hash
from thistle.sha3 import sha3_256
from thistle.aes import AESKey, SBOX, cpu_aes_encrypt, ROUNDS_128, gf_mul2, gf_mul3
from memory import alloc
from utils import StaticTuple

comptime TEST_KEY: StaticTuple[UInt8, 16] = StaticTuple[UInt8, 16](
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
)
comptime TEST_PT: StaticTuple[UInt8, 16] = StaticTuple[UInt8, 16](
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
)
comptime TEST_CT: StaticTuple[UInt8, 16] = StaticTuple[UInt8, 16](
    0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97
)

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
    var mb = Float64(len(data) * count) / (1024 * 1024)
    var mbps = mb / duration
    return "sha256 | throughput: " + String(mbps)[:6] + " mb/s, hashes: " + String(count) + ", time: " + String(duration)[:4] + "s"


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
    var mb = Float64(len(data) * count) / (1024 * 1024)
    var mbps = mb / duration
    return "sha512 | throughput: " + String(mbps)[:6] + " mb/s, hashes: " + String(count) + ", time: " + String(duration)[:4] + "s"


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
    var mb = Float64(len(data) * count) / (1024 * 1024)
    var mbps = mb / duration
    return "sha3-256 | throughput: " + String(mbps)[:6] + " mb/s, hashes: " + String(count) + ", time: " + String(duration)[:4] + "s"


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
    var mb = Float64(len(data) * count) / (1024 * 1024)
    var mbps = mb / duration
    return "blake2b | throughput: " + String(mbps)[:6] + " mb/s, hashes: " + String(count) + ", time: " + String(duration)[:4] + "s"


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
    var mb = Float64(len(data) * count) / (1024 * 1024)
    var mbps = mb / duration
    return "blake3 | throughput: " + String(mbps)[:6] + " mb/s, hashes: " + String(count) + ", time: " + String(duration)[:4] + "s"


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
    var mbps = Float64(count * 16) / (1024 * 1024) / duration
    return "camellia | throughput: " + String(mbps)[:6] + " mb/s, blocks: " + String(count) + ", time: " + String(duration)[:4] + "s"


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
    var mb = Float64(data_size * count) / (1024 * 1024)
    var mbps = mb / duration
    return "chacha20 | throughput: " + String(mbps)[:6] + " mb/s, encrypts: " + String(count) + ", time: " + String(duration)[:4] + "s"


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
    var mb = Float64(data_size * count) / (1024 * 1024)
    var mbps = mb / duration
    return "kcipher2 | throughput: " + String(mbps)[:6] + " mb/s, encrypts: " + String(count) + ", time: " + String(duration)[:4] + "s"


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
    return "argon2id | throughput: " + String(hps)[:6] + " h/s, hashes: " + String(count) + ", time: " + String(duration)[:4] + "s"


fn benchmark_aes_cpu(duration_secs: Float64) raises -> String:
    var key = AESKey(TEST_KEY)
    var round_keys = key.round_keys()
    var pt_bytes = alloc[UInt8](16)

    # Warmup
    for _ in range(100):
        for i in range(16):
            pt_bytes.store(i, TEST_PT[i])
        cpu_aes_encrypt(pt_bytes, round_keys)

    var count = 0
    var start = perf_counter()
    while perf_counter() - start < duration_secs:
        for i in range(16):
            pt_bytes.store(i, TEST_PT[i])
        cpu_aes_encrypt(pt_bytes, round_keys)
        count += 1
    var end = perf_counter()
    var duration = end - start
    
    pt_bytes.free()
    
    var mbps = Float64(count * 16) / (1024 * 1024) / duration
    return "aes-128-cpu | throughput: " + String(mbps)[:6] + " mb/s, blocks: " + String(count) + ", time: " + String(duration)[:4] + "s"


fn benchmark_aes_gpu() raises -> String:
    @parameter
    if not has_accelerator():
        return "aes-128-gpu | (GPU not available)"
    
    from gpu.host import DeviceContext
    from thistle.aes_gpu import aes_kernel
    
    var key = AESKey(TEST_KEY)
    var round_keys = key.round_keys()

    var num_blocks = 131072
    var total_bytes = num_blocks * 16

    var input_host = alloc[Scalar[DType.uint8]](total_bytes)
    var output_host = alloc[Scalar[DType.uint8]](total_bytes)

    for i in range(total_bytes):
        input_host[i] = TEST_PT[i % 16]

    with DeviceContext() as ctx:
        var input_buffer = ctx.enqueue_create_buffer[DType.uint8](total_bytes)
        var output_buffer = ctx.enqueue_create_buffer[DType.uint8](total_bytes)
        var round_keys_buffer = ctx.enqueue_create_buffer[DType.uint32](44)
        
        var sbox_host = alloc[Scalar[DType.uint8]](256)
        for i in range(256):
            sbox_host[i] = SBOX[i]
        var sbox_buffer = ctx.enqueue_create_buffer[DType.uint8](256)

        ctx.enqueue_copy(input_buffer, input_host)
        ctx.enqueue_copy(round_keys_buffer, round_keys)
        ctx.enqueue_copy(sbox_buffer, sbox_host)
        ctx.synchronize()

        var block_dim = 256
        var grid_dim = ceildiv(num_blocks, block_dim)
        
        # Warmup
        ctx.enqueue_function[aes_kernel, aes_kernel](
            input_buffer.unsafe_ptr(),
            output_buffer.unsafe_ptr(),
            round_keys_buffer.unsafe_ptr(),
            sbox_buffer.unsafe_ptr(),
            ROUNDS_128,
            num_blocks,
            grid_dim=grid_dim,
            block_dim=block_dim,
        )
        ctx.synchronize()

        var iterations = 50
        var start = perf_counter()
        for _ in range(iterations):
            ctx.enqueue_function[aes_kernel, aes_kernel](
                input_buffer.unsafe_ptr(),
                output_buffer.unsafe_ptr(),
                round_keys_buffer.unsafe_ptr(),
                sbox_buffer.unsafe_ptr(),
                ROUNDS_128,
                num_blocks,
                grid_dim=grid_dim,
                block_dim=block_dim,
            )
            ctx.synchronize()
        var end = perf_counter()
        var duration = end - start

        var total_gb = Float64(iterations * total_bytes) / 1024.0 / 1024.0 / 1024.0
        var gbps = total_gb / duration
        
        input_host.free()
        output_host.free()
        sbox_host.free()
        
        return "aes-128-gpu | throughput: " + String(gbps)[:6] + " gb/s, iterations: " + String(iterations)


def main():
    print("Thistle benchmark:")
    print()
    print("Testing.... please wait for all the tests to conclude.")
    print()
    
    var data = generate_data(100 * 1024 * 1024)
    var duration = 2.0
    
    print(benchmark_sha256(data, duration))
    print(benchmark_sha512(data, duration))
    print(benchmark_sha3_256(data, duration))
    print(benchmark_blake2b(data, duration))
    print(benchmark_blake3(data, duration))
    print(benchmark_camellia(1024 * 1024, duration))
    print(benchmark_chacha20(1024 * 1024, duration))
    print(benchmark_kcipher2(1024 * 1024, duration))
    print(benchmark_aes_cpu(duration))
    print(benchmark_aes_gpu())
    print(benchmark_argon2(duration))
    
    print()
    print("All benchmarks completed")
