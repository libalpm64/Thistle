from std.time import perf_counter, perf_counter_ns
from std.collections import List
from max.algorithm import parallelize
from std.random import random_ui64, seed
from std.math import ceildiv
from std.sys import has_accelerator
from std.memory import Layout, alloc

from thistle.argon2 import Argon2id
from thistle.blake2b import Blake2b
from thistle.blake3 import blake3_parallel_hash
from thistle.camellia import (
    CamelliaCipher, camellia_encrypt_blocks, camellia_ctr_kernel
)
from thistle.chacha20 import ChaCha20
from thistle.kcipher2 import KCipher2
from thistle.sha2 import sha256_hash, sha512_hash
from thistle.sha_ni import sha256ni_hash, has_sha_ni
from thistle.sha3 import sha3_256
from thistle.aes import (
    AESKey, cpu_aes_ct_encrypt16, cpu_aes_ct_skey, ROUNDS_128, expand_key_128
)
from thistle.x25519 import x25519
from thistle.ed25519 import (
    ed25519_sign, ed25519_verify, ed25519_generate_public_key
)
from thistle.p256 import p256_ecdsa_sign
from thistle.p384 import p384_public_key, p384_ecdsa_sign
from thistle.utils import StackInlineArray
from std.utils import StaticTuple

comptime TEST_KEY: StaticTuple[UInt8, 16] = StaticTuple[UInt8, 16](
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
)
comptime TEST_PT: StaticTuple[UInt8, 16] = StaticTuple[UInt8, 16](
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
)
comptime TEST_CT: StaticTuple[UInt8, 16] = StaticTuple[UInt8, 16](
    0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97
)


def generate_data(length: Int) -> List[UInt8]:
    var data = List[UInt8](capacity=length)
    for i in range(length):
        data.append(UInt8(i % 256))
    return data^


def benchmark_x25519(duration_secs: Float64) raises -> String:
    var scalar = InlineArray[UInt8, 32](fill=0)
    var point = InlineArray[UInt8, 32](fill=0)
    var out = InlineArray[UInt8, 32](fill=0)
    for i in range(32):
        scalar[i] = UInt8(i + 1)
        point[i] = UInt8(9) if i == 0 else UInt8(0)
    var scalar_span = Span[UInt8, ...](unsafe_ptr=scalar.unsafe_ptr(), length=32)
    var point_span = Span[UInt8, ...](unsafe_ptr=point.unsafe_ptr(), length=32)
    x25519(scalar_span, point_span, Span[mut=True, UInt8, ...](out))
    var count = 0
    var start = perf_counter()
    while perf_counter() - start < duration_secs:
        x25519(scalar_span, point_span, Span[mut=True, UInt8, ...](out))
        scalar.unsafe_ptr().unsafe_store[volatile=True](0, out[0] | 8)
        count += 1
    var duration = perf_counter() - start
    var ops = Float64(count) / duration
    return (
        "x25519 | throughput: " + String(ops) + " ops/s, ops: " + String(count) + ", time: " + String(duration) + "s"
    )


def benchmark_p384(duration_secs: Float64) -> String:
    var scalar = InlineArray[UInt8, 48](fill=0)
    var out = InlineArray[UInt8, 97](fill=0)
    scalar[47] = 7
    var scalar_span = Span[UInt8, ...](scalar)
    _ = p384_public_key(scalar_span, Span[mut=True, UInt8, ...](out))
    var count = 0
    var start = perf_counter()
    while perf_counter() - start < duration_secs:
        _ = p384_public_key(scalar_span, Span[mut=True, UInt8, ...](out))
        count += 1
    var duration = perf_counter() - start
    var ops = Float64(count) / duration
    return (
        "p384-public-key | throughput: " + String(ops) + " ops/s, ops: " + String(count) + ", time: " + String(duration) + "s"
    )


def benchmark_ecdsa(duration_secs: Float64) -> String:
    var p256_key = InlineArray[UInt8, 32](fill=1)
    var p384_key = InlineArray[UInt8, 48](fill=1)
    var message = InlineArray[UInt8, 64](fill=7)
    var p256_sig = InlineArray[UInt8, 64](fill=0)
    var p384_sig = InlineArray[UInt8, 96](fill=0)
    var msg = Span[UInt8, ...](message)

    var p256_count = 0
    var start = perf_counter()
    while perf_counter() - start < duration_secs:
        _ = p256_ecdsa_sign(
            Span[UInt8, ...](p256_key),
            msg,
            Span[mut=True, UInt8, ...](unsafe_ptr=p256_sig.unsafe_ptr(), length=64)
        )
        p256_count += 1
    var p256_time = perf_counter() - start

    var p384_count = 0
    start = perf_counter()
    while perf_counter() - start < duration_secs:
        _ = p384_ecdsa_sign(
            Span[UInt8, ...](p384_key),
            msg,
            Span[mut=True, UInt8, ...](unsafe_ptr=p384_sig.unsafe_ptr(), length=96)
        )
        p384_count += 1
    var p384_time = perf_counter() - start

    return (
        "p256-ecdsa-sign | throughput: "
        + String(Float64(p256_count) / p256_time) + " ops/s\n"
        + "p384-ecdsa-sign | throughput: "
        + String(Float64(p384_count) / p384_time) + " ops/s"
    )


def benchmark_ed25519(duration_secs: Float64) raises -> String:
    var sk = InlineArray[UInt8, 32](fill=0)
    var pk = InlineArray[UInt8, 32](fill=0)
    var msg = InlineArray[UInt8, 64](fill=0)
    var sig = InlineArray[UInt8, 64](fill=0)
    for i in range(32):
        sk[i] = UInt8(i * 7 + 1)
    for i in range(64):
        msg[i] = UInt8(i)
    var sk_span = Span[UInt8, ...](unsafe_ptr=sk.unsafe_ptr(), length=32)
    var msg_span = Span[UInt8, ...](unsafe_ptr=msg.unsafe_ptr(), length=64)
    var sig_span = Span[UInt8, ...](unsafe_ptr=sig.unsafe_ptr(), length=64)
    var sig_out = Span[mut=True, UInt8, ...](
        unsafe_ptr=sig.unsafe_ptr(), length=64
    )
    var pk_span = Span[UInt8, ...](unsafe_ptr=pk.unsafe_ptr(), length=32)
    var pk_out = Span[mut=True, UInt8, ...](
        unsafe_ptr=pk.unsafe_ptr(), length=32
    )
    ed25519_generate_public_key(sk_span, pk_out)
    ed25519_sign(sk_span, msg_span, sig_out)

    var sign_count = 0
    var start = perf_counter()
    while perf_counter() - start < duration_secs:
        ed25519_sign(sk_span, msg_span, sig_out)
        sign_count += 1
    var sign_duration = perf_counter() - start
    var sign_ops = Float64(sign_count) / sign_duration

    ed25519_sign(sk_span, msg_span, sig_out)
    var verify_count = 0
    var verify_failures = 0
    start = perf_counter()
    while perf_counter() - start < duration_secs:
        if not ed25519_verify(pk_span, msg_span, sig_span):
            verify_failures += 1
        verify_count += 1
    var verify_duration = perf_counter() - start
    var verify_ops = Float64(verify_count) / verify_duration

    var result = (
        "ed25519-sign | throughput: " + String(sign_ops) + " ops/s, ops: " + String(sign_count) + ", time: " + String(sign_duration) + "s\n"
    )
    result += (
        "ed25519-verify | throughput: " + String(verify_ops) + " ops/s, ops: " + String(verify_count) + ", time: " + String(verify_duration) + "s"
    )
    if verify_failures > 0:
        result += " [" + String(verify_failures) + " FAILED VERIFICATIONS]"
    return result


def benchmark_sha256(data: List[UInt8], duration_secs: Float64) -> String:
    var span = Span[UInt8, ...](data)
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
    return (
        "sha256 | throughput: " + String(mbps) + " mb/s, hashes: " + String(count) + ", time: " + String(duration) + "s"
    )


def benchmark_sha256ni(data: List[UInt8], duration_secs: Float64) -> String:
    if not has_sha_ni():
        return "sha256-ni | (NI not available)"
    var span = Span[UInt8, ...](data)
    _ = sha256ni_hash(span)
    var count = 0
    var start = perf_counter()
    while perf_counter() - start < duration_secs:
        _ = sha256ni_hash(span)
        count += 1
    var end = perf_counter()
    var duration = end - start
    var mb = Float64(len(data) * count) / (1024 * 1024)
    var mbps = mb / duration
    return (
        "sha256-ni | throughput: " + String(mbps) + " mb/s, hashes: " + String(count) + ", time: " + String(duration) + "s"
    )


def benchmark_sha512(data: List[UInt8], duration_secs: Float64) -> String:
    var span = Span[UInt8, ...](data)
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
    return (
        "sha512 | throughput: " + String(mbps) + " mb/s, hashes: " + String(count) + ", time: " + String(duration) + "s"
    )


def benchmark_sha3_256(data: List[UInt8], duration_secs: Float64) -> String:
    var span = Span[UInt8, ...](data)
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
    return (
        "sha3-256 | throughput: " + String(mbps) + " mb/s, hashes: " + String(count) + ", time: " + String(duration) + "s"
    )


def benchmark_blake2b(data: List[UInt8], duration_secs: Float64) raises -> String:
    var span = Span[UInt8, ...](data)
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
    return (
        "blake2b | throughput: " + String(mbps) + " mb/s, hashes: " + String(count) + ", time: " + String(duration) + "s"
    )


def benchmark_blake3(data: List[UInt8], duration_secs: Float64) raises -> String:
    var span = Span[UInt8, ...](data)
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
    return (
        "blake3 | throughput: " + String(mbps) + " mb/s, hashes: " + String(count) + ", time: " + String(duration) + "s"
    )


def benchmark_camellia(data_size: Int, duration_secs: Float64) raises -> String:
    var key = List[UInt8]()
    for i in range(16):
        key.append(UInt8(i))
    var cipher = CamelliaCipher(Span[UInt8, ...](key))

    var nb = 32
    var blocks = alloc(Layout[UInt8](count=nb * 16)).unsafe_leak()
    for i in range(nb * 16):
        blocks.unsafe_store(i, UInt8(i % 256))

    for _ in range(100):
        camellia_encrypt_blocks(cipher, blocks, nb)

    var count = 0
    var start = perf_counter()
    while perf_counter() - start < duration_secs:
        camellia_encrypt_blocks(cipher, blocks, nb)
        count += nb
    var end = perf_counter()
    var duration = end - start

    blocks.unsafe_free()

    var mbps = Float64(count * 16) / (1024 * 1024) / duration
    return (
        "camellia | throughput: " + String(mbps) + " mb/s, blocks: " + String(count) + ", time: " + String(duration) + "s"
    )


def benchmark_camellia_ctr(duration_secs: Float64) raises -> String:
    var key = List[UInt8]()
    for i in range(16):
        key.append(UInt8(i))
    var cipher = CamelliaCipher(Span[UInt8, ...](key))

    var size = 64 * 1024
    var buf = alloc(Layout[UInt8](count=size)).unsafe_leak()
    for i in range(size):
        buf.unsafe_store(i, UInt8(i % 256))
    var nonce = alloc(Layout[UInt8](count=16)).unsafe_leak()
    for i in range(16):
        nonce.unsafe_store(i, UInt8(i * 3))

    camellia_ctr_kernel(buf, buf, cipher, size // 16, nonce)

    var count = 0
    var start = perf_counter()
    while perf_counter() - start < duration_secs:
        camellia_ctr_kernel(buf, buf, cipher, size // 16, nonce)
        count += 1
    var end = perf_counter()
    var duration = end - start

    buf.unsafe_free()
    nonce.unsafe_free()

    var mbps = Float64(count * size) / (1024 * 1024) / duration
    return (
        "camellia-ctr | throughput: " + String(mbps) + " mb/s, chunks: " + String(count) + ", time: " + String(duration) + "s"
    )


def benchmark_chacha20(data_size: Int, duration_secs: Float64) raises -> String:
    var key = SIMD[DType.uint8, 32](0)
    for i in range(32):
        key[i] = UInt8(i)
    var nonce = InlineArray[UInt8, 12](fill=0)
    
    var data = List[UInt8](capacity=data_size)
    for i in range(data_size):
        data.append(UInt8(i % 256))
    var span = Span[mut=True, UInt8](data)
    
    var cipher = ChaCha20(key, Span[UInt8, ...](nonce))
    
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
    return (
        "chacha20 | throughput: " + String(mbps) + " mb/s, encrypts: " + String(count) + ", time: " + String(duration) + "s"
    )


def benchmark_kcipher2(data_size: Int, duration_secs: Float64) -> String:
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
    return (
        "kcipher2 | throughput: " + String(mbps) + " mb/s, encrypts: " + String(count) + ", time: " + String(duration) + "s"
    )


def benchmark_argon2(duration_secs: Float64) raises -> String:
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
    return (
        "argon2id | throughput: " + String(hps) + " h/s, hashes: " + String(count) + ", time: " + String(duration) + "s"
    )


def benchmark_aes_cpu(duration_secs: Float64) raises -> String:
    var key = AESKey(TEST_KEY)
    var round_keys = key.round_keys()
    var skey = cpu_aes_ct_skey(round_keys, ROUNDS_128)
    var blocks = alloc(Layout[UInt8](count=256)).unsafe_leak()
    for i in range(256):
        blocks.unsafe_store(i, TEST_PT[i % 16])

    for _ in range(100):
        cpu_aes_ct_encrypt16(blocks, skey, ROUNDS_128)

    var count = 0
    var start = perf_counter()
    while perf_counter() - start < duration_secs:
        cpu_aes_ct_encrypt16(blocks, skey, ROUNDS_128)
        count += 16
    var end = perf_counter()
    var duration = end - start

    blocks.unsafe_free()

    var mbps = Float64(count * 16) / (1024 * 1024) / duration
    return (
        "aes-128-cpu | throughput: " + String(mbps) + " mb/s, blocks: " + String(count) + ", time: " + String(duration) + "s"
    )


def benchmark_aes_gpu_ecb() raises -> String:
    comptime
    if not has_accelerator():
        return "aes-128-gpu-ecb | (GPU not available)"
    
    from max.gpu.host import DeviceContext
    from thistle.aes_gpu import aes_gpu_kernel_ecb
    
    var key_ptr = alloc(Layout[UInt8](count=16)).unsafe_leak()
    for i in range(16):
        key_ptr.unsafe_store(i, TEST_KEY[i])
    var round_keys = expand_key_128(
        Span[UInt8, ...](unsafe_ptr=key_ptr, length=16)
    )
    var num_blocks = 131072
    var total_bytes = num_blocks * 16

    var input_host = alloc(Layout[Scalar[DType.uint8]](count=total_bytes)).unsafe_leak()
    var output_host = alloc(Layout[Scalar[DType.uint8]](count=total_bytes)).unsafe_leak()

    for i in range(total_bytes):
        input_host[unsafe_offset=i] = TEST_PT[i % 16]

    with DeviceContext() as ctx:
        var input_buffer = ctx.enqueue_create_buffer[DType.uint8](total_bytes)
        var output_buffer = ctx.enqueue_create_buffer[DType.uint8](total_bytes)
        var skey_host = cpu_aes_ct_skey(round_keys.ptr(), 10)
        var skey_buffer = ctx.enqueue_create_buffer[DType.uint64](88)
        ctx.enqueue_copy(skey_buffer, skey_host.unsafe_ptr())
        
        ctx.enqueue_copy(input_buffer, input_host)
        ctx.synchronize()

        var block_dim = 256
        var grid_dim = ceildiv(num_blocks, block_dim)
        
        ctx.enqueue_function[aes_gpu_kernel_ecb](
            input_buffer,
            output_buffer,
            skey_buffer,
            Int32(num_blocks),
            Int32(10),
            grid_dim=grid_dim,
            block_dim=block_dim
        )
        ctx.synchronize()

        var iterations = 50
        var start = perf_counter()
        for _ in range(iterations):
            ctx.enqueue_function[aes_gpu_kernel_ecb](
                input_buffer,
                output_buffer,
                skey_buffer,
                Int32(num_blocks),
                Int32(10),
                grid_dim=grid_dim,
                block_dim=block_dim
            )
            ctx.synchronize()
        var end = perf_counter()
        var duration = end - start

        var total_gb = Float64(iterations * total_bytes) / 1024.0 / 1024.0 / 1024.0
        var gbps = total_gb / duration
        
        input_host.unsafe_free()
        output_host.unsafe_free()
        key_ptr.unsafe_free()
        
        return (
            "aes-128-gpu-ecb | throughput: " + String(gbps) + " gb/s, iterations: " + String(iterations)
        )


def benchmark_aes_gpu_ctr() raises -> String:
    comptime
    if not has_accelerator():
        return "aes-128-gpu-ctr | (GPU not available)"
    
    from max.gpu.host import DeviceContext
    from thistle.aes_gpu import aes_gpu_kernel_ctr
    
    var key_ptr = alloc(Layout[UInt8](count=16)).unsafe_leak()
    for i in range(16):
        key_ptr.unsafe_store(i, TEST_KEY[i])
    var round_keys = expand_key_128(
        Span[UInt8, ...](unsafe_ptr=key_ptr, length=16)
    )
    var num_blocks = 131072
    var total_bytes = num_blocks * 16

    var input_host = alloc(Layout[Scalar[DType.uint8]](count=total_bytes)).unsafe_leak()
    var output_host = alloc(Layout[Scalar[DType.uint8]](count=total_bytes)).unsafe_leak()
    var nonce_host = alloc(Layout[Scalar[DType.uint8]](count=16)).unsafe_leak()

    for i in range(total_bytes):
        input_host[unsafe_offset=i] = TEST_PT[i % 16]
    for i in range(16):
        nonce_host[unsafe_offset=i] = 0

    with DeviceContext() as ctx:
        var input_buffer = ctx.enqueue_create_buffer[DType.uint8](total_bytes)
        var output_buffer = ctx.enqueue_create_buffer[DType.uint8](total_bytes)
        var skey_host = cpu_aes_ct_skey(round_keys.ptr(), 10)
        var skey_buffer = ctx.enqueue_create_buffer[DType.uint64](88)
        ctx.enqueue_copy(skey_buffer, skey_host.unsafe_ptr())
        var nonce_buffer = ctx.enqueue_create_buffer[DType.uint8](16)
        
        ctx.enqueue_copy(input_buffer, input_host)
        ctx.enqueue_copy(nonce_buffer, nonce_host)
        ctx.synchronize()

        var block_dim = 256
        var grid_dim = ceildiv(num_blocks, block_dim)
        
        ctx.enqueue_function[aes_gpu_kernel_ctr](
            input_buffer,
            output_buffer,
            skey_buffer,
            Int32(num_blocks),
            nonce_buffer,
            Int32(10),
            grid_dim=grid_dim,
            block_dim=block_dim
        )
        ctx.synchronize()

        var iterations = 50
        var start = perf_counter()
        for _ in range(iterations):
            ctx.enqueue_function[aes_gpu_kernel_ctr](
                input_buffer,
                output_buffer,
                skey_buffer,
                Int32(num_blocks),
                nonce_buffer,
                Int32(10),
                grid_dim=grid_dim,
                block_dim=block_dim
            )
            ctx.synchronize()
        var end = perf_counter()
        var duration = end - start

        var total_gb = Float64(iterations * total_bytes) / 1024.0 / 1024.0 / 1024.0
        var gbps = total_gb / duration
        
        input_host.unsafe_free()
        output_host.unsafe_free()
        nonce_host.unsafe_free()
        key_ptr.unsafe_free()
        
        return (
            "aes-128-gpu-ctr | throughput: " + String(gbps) + " gb/s, iterations: " + String(iterations)
        )


def benchmark_aes_gpu_gcm() raises -> String:
    comptime
    if not has_accelerator():
        return "aes-128-gpu-gcm | (GPU not available)"
    
    from max.gpu.host import DeviceContext
    from thistle.aes_gpu import aes_gpu_kernel_gcm_ctr
    
    var key_ptr = alloc(Layout[UInt8](count=16)).unsafe_leak()
    for i in range(16):
        key_ptr.unsafe_store(i, TEST_KEY[i])
    var round_keys = expand_key_128(
        Span[UInt8, ...](unsafe_ptr=key_ptr, length=16)
    )
    var num_blocks = 131072
    var total_bytes = num_blocks * 16

    var input_host = alloc(Layout[Scalar[DType.uint8]](count=total_bytes)).unsafe_leak()
    var output_host = alloc(Layout[Scalar[DType.uint8]](count=total_bytes)).unsafe_leak()
    var nonce_host = alloc(Layout[Scalar[DType.uint8]](count=16)).unsafe_leak()

    for i in range(total_bytes):
        input_host[unsafe_offset=i] = TEST_PT[i % 16]
    for i in range(16):
        nonce_host[unsafe_offset=i] = 0
    nonce_host[unsafe_offset=15] = 1

    with DeviceContext() as ctx:
        var input_buffer = ctx.enqueue_create_buffer[DType.uint8](total_bytes)
        var output_buffer = ctx.enqueue_create_buffer[DType.uint8](total_bytes)
        var skey_host = cpu_aes_ct_skey(round_keys.ptr(), 10)
        var skey_buffer = ctx.enqueue_create_buffer[DType.uint64](88)
        ctx.enqueue_copy(skey_buffer, skey_host.unsafe_ptr())
        var nonce_buffer = ctx.enqueue_create_buffer[DType.uint8](16)
        
        ctx.enqueue_copy(input_buffer, input_host)
        ctx.enqueue_copy(nonce_buffer, nonce_host)
        ctx.synchronize()

        var block_dim = 256
        var grid_dim = ceildiv(num_blocks, block_dim)
        
        ctx.enqueue_function[aes_gpu_kernel_gcm_ctr](
            input_buffer,
            output_buffer,
            skey_buffer,
            Int32(num_blocks),
            nonce_buffer,
            Int32(10),
            grid_dim=grid_dim,
            block_dim=block_dim
        )
        ctx.synchronize()

        var iterations = 50
        var start = perf_counter()
        for _ in range(iterations):
            ctx.enqueue_function[aes_gpu_kernel_gcm_ctr](
                input_buffer,
                output_buffer,
                skey_buffer,
                Int32(num_blocks),
                nonce_buffer,
                Int32(10),
                grid_dim=grid_dim,
                block_dim=block_dim
            )
            ctx.synchronize()
        var end = perf_counter()
        var duration = end - start

        var total_gb = Float64(iterations * total_bytes) / 1024.0 / 1024.0 / 1024.0
        var gbps = total_gb / duration
        
        input_host.unsafe_free()
        output_host.unsafe_free()
        nonce_host.unsafe_free()
        key_ptr.unsafe_free()
        
        return (
            "aes-128-gpu-gcm | throughput: " + String(gbps) + " gb/s, iterations: " + String(iterations)
        )


def main() raises:
    print("Thistle benchmark:")
    print()
    print("Testing.... please wait for all the tests to conclude.")
    print()
    
    var data = generate_data(100 * 1024 * 1024)
    var duration = 2.0
    
    print(benchmark_sha256(data, duration))
    if has_sha_ni():
        print(benchmark_sha256ni(data, duration))
    print(benchmark_sha512(data, duration))
    print(benchmark_sha3_256(data, duration))
    print(benchmark_blake2b(data, duration))
    print(benchmark_blake3(data, duration))
    print(benchmark_camellia(1024 * 1024, duration))
    print(benchmark_camellia_ctr(duration))
    print(benchmark_chacha20(1024 * 1024, duration))
    print(benchmark_kcipher2(1024 * 1024, duration))
    print(benchmark_aes_cpu(duration))
    comptime
    if has_accelerator():
        print(benchmark_aes_gpu_ecb())
        print(benchmark_aes_gpu_ctr())
        print(benchmark_aes_gpu_gcm())
    else:
        print("aes-128-gpu-ecb | (GPU not available)")
        print("aes-128-gpu-ctr | (GPU not available)")
        print("aes-128-gpu-gcm | (GPU not available)")
    print(benchmark_argon2(duration))
    print(benchmark_x25519(duration))
    print(benchmark_p384(duration))
    print(benchmark_ecdsa(duration))
    print(benchmark_ed25519(duration))

    print()
    print("All benchmarks completed")
