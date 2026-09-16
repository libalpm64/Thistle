from std.time import perf_counter, perf_counter_ns
from std.collections import List
from max.algorithm import parallelize
from std.random import random_ui64, seed
from std.math import ceildiv
from std.sys import has_accelerator, CompilationTarget
from std.memory import Layout, alloc

from thistle.argon2 import Argon2id
from thistle.blake2b import Blake2b
from thistle.blake3 import blake3_parallel_hash
from thistle.camellia import (
    CamelliaCipher, camellia_encrypt_blocks, camellia_ctr_kernel
)
from thistle.chacha20 import ChaCha20
from thistle.chacha20poly1305 import chacha20_poly1305_encrypt
from thistle.kcipher2 import KCipher2
from thistle.sha2 import sha256_hash, sha512_hash
from thistle.sha_ni import sha256ni_hash, has_sha_ni
from thistle.sha3 import sha3_256
from thistle.aes import (
    AESKey, cpu_aes_ct_encrypt16, cpu_aes_ct_skey, ROUNDS_128, expand_key_128
)
from thistle.aes_ni import has_aes_ni, x86_aes_ecb_kernel, AESGCMContext
from thistle.x25519 import x25519, x25519_public_key
from thistle.pbkdf2 import pbkdf2_hmac_sha256, pbkdf2_hmac_sha512
from thistle.tls_kdf import (
    tls12_prf_sha256_into,
    tls12_prf_sha384_into,
    tls13_derive_secret_sha256_into,
)
from thistle.ml_kem import (
    K_512, K_768, K_1024, SYMBYTES,
    INDCPA_PUBLICKEYBYTES_MAX, DECAPSKEYBYTES_MAX, CIPHERTEXTBYTES_MAX,
    mlkem_keygen_seed_into_k, mlkem_encaps_seed_into_k, mlkem_decaps_into_k
)
from thistle.ml_dsa import (
    MLDSAParams, params44, params65, params87,
    mldsa_private_key_from_seed, mldsa_sign_deterministic, mldsa_verify
)
from thistle.ed25519 import (
    Ed25519SigningKey, ed25519_verify, ed25519_generate_public_key
)
from thistle.p256 import (
    p256_public_key, p256_ecdsa_sign, p256_ecdsa_verify
)
from thistle.p384 import (
    p384_public_key, p384_ecdsa_sign, p384_ecdsa_verify
)
from thistle.utils import StackBuffer, StackInlineArray
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
    var sink = UInt8(0)
    var count = 0
    var start = perf_counter()
    while perf_counter() - start < duration_secs:
        x25519(scalar_span, point_span, Span[mut=True, UInt8, ...](out))
        sink ^= out[0]
        count += 1
    var duration = perf_counter() - start
    var generic_ops = Float64(count) / duration

    count = 0
    start = perf_counter()
    while perf_counter() - start < duration_secs:
        x25519_public_key(scalar_span, Span[mut=True, UInt8, ...](out))
        sink ^= out[0]
        count += 1
    var public_duration = perf_counter() - start
    var public_ops = Float64(count) / public_duration
    _ = sink
    return (
        "x25519-generic | throughput: " + String(generic_ops) + " ops/s, time: "
        + String(duration) + "s\n"
        + "x25519-public-key | throughput: " + String(public_ops) + " ops/s, time: "
        + String(public_duration) + "s"
    )


def benchmark_pbkdf2(duration_secs: Float64) raises -> String:
    var password = String("correct horse battery staple").as_bytes()
    var salt = String("0123456789abcdef").as_bytes()

    var count256 = 0
    var sink = UInt8(0)
    var start = perf_counter()
    while perf_counter() - start < duration_secs:
        var out = pbkdf2_hmac_sha256(password, salt, 10000, 32)
        sink ^= out[0]
        count256 += 1
    var duration256 = perf_counter() - start

    var count512 = 0
    start = perf_counter()
    while perf_counter() - start < duration_secs:
        var out = pbkdf2_hmac_sha512(password, salt, 10000, 64)
        sink ^= out[0]
        count512 += 1
    var duration512 = perf_counter() - start
    _ = sink
    return (
        "pbkdf2-sha256-10k | throughput: " + String(Float64(count256) / duration256)
        + " derivations/s\n"
        + "pbkdf2-sha512-10k | throughput: " + String(Float64(count512) / duration512)
        + " derivations/s"
    )


def benchmark_tls_kdf(duration_secs: Float64) raises -> String:
    var secret = InlineArray[UInt8, 32](fill=0)
    var seed_bytes = InlineArray[UInt8, 64](fill=0)
    var transcript_hash = InlineArray[UInt8, 32](fill=0)
    for i in range(32):
        secret[i] = UInt8(i + 1)
        transcript_hash[i] = UInt8(0xA0 + i)
    for i in range(64):
        seed_bytes[i] = UInt8(i)

    var tls12_label = String("master secret").as_bytes()
    var tls13_label = String("c hs traffic").as_bytes()
    var tls12_sha256_output = InlineArray[UInt8, 48](fill=0)
    var tls12_sha384_output = InlineArray[UInt8, 48](fill=0)
    var tls13_output = InlineArray[UInt8, 32](fill=0)
    var secret_span = Span[UInt8, ...](unsafe_ptr=secret.unsafe_ptr(), length=32)
    var seed_span = Span[UInt8, ...](unsafe_ptr=seed_bytes.unsafe_ptr(), length=64)
    var transcript_span = Span[UInt8, ...](unsafe_ptr=transcript_hash.unsafe_ptr(), length=32)
    var tls12_sha256_span = Span[mut=True, UInt8, ...](tls12_sha256_output)
    var tls12_sha384_span = Span[mut=True, UInt8, ...](tls12_sha384_output)
    var tls13_span = Span[mut=True, UInt8, ...](tls13_output)

    tls12_prf_sha256_into(secret_span, tls12_label, seed_span, tls12_sha256_span)
    tls12_prf_sha384_into(secret_span, tls12_label, seed_span, tls12_sha384_span)
    tls13_derive_secret_sha256_into(secret_span, tls13_label, transcript_span, tls13_span)

    var sink = UInt8(0)
    var tls12_sha256_count = 0
    var start = perf_counter()
    while perf_counter() - start < duration_secs:
        tls12_prf_sha256_into(secret_span, tls12_label, seed_span, tls12_sha256_span)
        sink ^= tls12_sha256_output[0]
        tls12_sha256_count += 1
    var tls12_sha256_duration = perf_counter() - start

    var tls12_sha384_count = 0
    start = perf_counter()
    while perf_counter() - start < duration_secs:
        tls12_prf_sha384_into(secret_span, tls12_label, seed_span, tls12_sha384_span)
        sink ^= tls12_sha384_output[0]
        tls12_sha384_count += 1
    var tls12_sha384_duration = perf_counter() - start

    var tls13_count = 0
    start = perf_counter()
    while perf_counter() - start < duration_secs:
        tls13_derive_secret_sha256_into(secret_span, tls13_label, transcript_span, tls13_span)
        sink ^= tls13_output[0]
        tls13_count += 1
    var tls13_duration = perf_counter() - start
    _ = sink

    return (
        "tls12-prf-sha256-48b | throughput: "
        + String(Float64(tls12_sha256_count) / tls12_sha256_duration)
        + " ops/s\n"
        + "tls12-prf-sha384-48b | throughput: "
        + String(Float64(tls12_sha384_count) / tls12_sha384_duration)
        + " ops/s\n"
        + "tls13-derive-secret-sha256-32b | throughput: "
        + String(Float64(tls13_count) / tls13_duration)
        + " ops/s"
    )


def benchmark_tls_aead(data_size: Int, duration_secs: Float64) raises -> String:
    var aes_key = InlineArray[UInt8, 16](fill=0x11)
    var chacha_key = InlineArray[UInt8, 32](fill=0x22)
    var nonce = InlineArray[UInt8, 12](fill=0x33)
    var aad = InlineArray[UInt8, 5](fill=0)
    var input = List[UInt8](unsafe_uninit_length=data_size)
    var aes_output = List[UInt8](unsafe_uninit_length=data_size)
    var chacha_output = List[UInt8](unsafe_uninit_length=data_size)
    var aes_tag = InlineArray[UInt8, 16](fill=0)
    var chacha_tag = InlineArray[UInt8, 16](fill=0)
    for i in range(data_size):
        input[i] = UInt8(i & 0xFF)

    var input_span = Span[UInt8, ...](input)
    var nonce_span = Span[UInt8, ...](nonce)
    var aad_span = Span[UInt8, ...](aad)
    var chacha_key_span = Span[UInt8, ...](chacha_key)
    var aes_output_span = Span[mut=True, UInt8, ...](aes_output)
    var chacha_output_span = Span[mut=True, UInt8, ...](chacha_output)
    var aes_tag_span = Span[mut=True, UInt8, ...](aes_tag)
    var chacha_tag_span = Span[mut=True, UInt8, ...](chacha_tag)
    var aes_ctx = AESGCMContext(Span[UInt8, ...](aes_key))

    aes_ctx.encrypt_into(nonce_span, input_span, aad_span, aes_output_span, aes_tag_span)
    chacha20_poly1305_encrypt(
        chacha_key_span, nonce_span, aad_span, input_span, chacha_output_span, chacha_tag_span
    )

    var sink = aes_output[0] ^ aes_tag[0] ^ chacha_output[0] ^ chacha_tag[0]
    var aes_count = 0
    var start = perf_counter()
    while perf_counter() - start < duration_secs:
        aes_ctx.encrypt_into(nonce_span, input_span, aad_span, aes_output_span, aes_tag_span)
        sink ^= aes_output[0] ^ aes_tag[0]
        aes_count += 1
    var aes_duration = perf_counter() - start

    var chacha_count = 0
    start = perf_counter()
    while perf_counter() - start < duration_secs:
        chacha20_poly1305_encrypt(
            chacha_key_span, nonce_span, aad_span, input_span, chacha_output_span, chacha_tag_span
        )
        sink ^= chacha_output[0] ^ chacha_tag[0]
        chacha_count += 1
    var chacha_duration = perf_counter() - start
    _ = sink

    var aes_gbps = Float64(aes_count * data_size) / aes_duration / 1_000_000_000.0
    var chacha_gbps = Float64(chacha_count * data_size) / chacha_duration / 1_000_000_000.0
    return (
        "aes-128-gcm-" + String(data_size) + "b | throughput: "
        + String(aes_gbps) + " gb/s\n"
        + "chacha20-poly1305-" + String(data_size) + "b | throughput: "
        + String(chacha_gbps) + " gb/s"
    )


def benchmark_mlkem_set[k: Int](label: String, duration_secs: Float64) raises -> String:
    var seed = StackBuffer[UInt8, 2 * SYMBYTES]()
    var message = StackBuffer[UInt8, SYMBYTES]()
    for i in range(2 * SYMBYTES):
        seed.push_unchecked(UInt8(i * 5 + 1))
    for i in range(SYMBYTES):
        message.push_unchecked(UInt8(i * 11 + 1))

    var ek = StackBuffer[UInt8, INDCPA_PUBLICKEYBYTES_MAX]()
    var dk = StackBuffer[UInt8, DECAPSKEYBYTES_MAX]()
    var ciphertext = StackBuffer[UInt8, CIPHERTEXTBYTES_MAX]()
    var shared = StackBuffer[UInt8, SYMBYTES]()
    var decapsulated = StackBuffer[UInt8, SYMBYTES]()
    var seed_span = Span[UInt8, ...](unsafe_ptr=seed.ptr(), length=seed.len())
    var message_span = Span[UInt8, ...](unsafe_ptr=message.ptr(), length=message.len())
    _ = mlkem_keygen_seed_into_k[k](ek, dk, seed_span)
    _ = mlkem_encaps_seed_into_k[k](
        ciphertext,
        shared,
        Span[UInt8, ...](unsafe_ptr=ek.ptr(), length=ek.len()),
        message_span,
    )

    var sink = UInt8(0)
    var count = 0
    var start = perf_counter()
    while perf_counter() - start < duration_secs:
        _ = mlkem_keygen_seed_into_k[k](ek, dk, seed_span)
        sink ^= ek[0]
        count += 1
    var keygen_count = count
    var keygen_duration = perf_counter() - start

    count = 0
    start = perf_counter()
    while perf_counter() - start < duration_secs:
        _ = mlkem_encaps_seed_into_k[k](
            ciphertext,
            shared,
            Span[UInt8, ...](unsafe_ptr=ek.ptr(), length=ek.len()),
            message_span,
        )
        sink ^= ciphertext[0]
        count += 1
    var encaps_count = count
    var encaps_duration = perf_counter() - start

    count = 0
    start = perf_counter()
    while perf_counter() - start < duration_secs:
        _ = mlkem_decaps_into_k[k](
            decapsulated,
            Span[UInt8, ...](unsafe_ptr=dk.ptr(), length=dk.len()),
            Span[UInt8, ...](unsafe_ptr=ciphertext.ptr(), length=ciphertext.len()),
        )
        sink ^= decapsulated[0]
        count += 1
    var decaps_count = count
    var decaps_duration = perf_counter() - start
    _ = sink
    return (
        label + " keygen | throughput: "
        + String(Float64(keygen_count) / keygen_duration) + " ops/s\n"
        + label + " encaps | throughput: "
        + String(Float64(encaps_count) / encaps_duration) + " ops/s\n"
        + label + " decaps | throughput: "
        + String(Float64(decaps_count) / decaps_duration) + " ops/s"
    )


def benchmark_mldsa_set(
    label: String, params: MLDSAParams, duration_secs: Float64
) raises -> String:
    var seed = List[UInt8](unsafe_uninit_length=32)
    var message = List[UInt8](unsafe_uninit_length=64)
    var context = List[UInt8]()
    for i in range(32):
        seed[i] = UInt8(i * 13 + 1)
    for i in range(64):
        message[i] = UInt8(i * 17 + 1)

    var private_key = mldsa_private_key_from_seed(Span[UInt8, ...](seed), params)
    var signature = mldsa_sign_deterministic(
        private_key, Span[UInt8, ...](message), Span[UInt8, ...](context)
    )

    var sink = UInt8(0)
    var count = 0
    var start = perf_counter()
    while perf_counter() - start < duration_secs:
        var key = mldsa_private_key_from_seed(Span[UInt8, ...](seed), params)
        sink ^= key.pub.raw[0]
        count += 1
    var keygen_count = count
    var keygen_duration = perf_counter() - start

    count = 0
    start = perf_counter()
    while perf_counter() - start < duration_secs:
        var sig = mldsa_sign_deterministic(
            private_key, Span[UInt8, ...](message), Span[UInt8, ...](context)
        )
        sink ^= sig[0]
        count += 1
    var sign_count = count
    var sign_duration = perf_counter() - start

    count = 0
    var verify_ok = True
    start = perf_counter()
    while perf_counter() - start < duration_secs:
        verify_ok = verify_ok and mldsa_verify(
            private_key.pub,
            Span[UInt8, ...](message),
            Span[UInt8, ...](signature),
            Span[UInt8, ...](context),
        )
        count += 1
    var verify_count = count
    var verify_duration = perf_counter() - start
    _ = sink
    var result = (
        label + " keygen | throughput: "
        + String(Float64(keygen_count) / keygen_duration) + " ops/s\n"
        + label + " sign-deterministic | throughput: "
        + String(Float64(sign_count) / sign_duration) + " ops/s\n"
        + label + " verify | throughput: "
        + String(Float64(verify_count) / verify_duration) + " ops/s"
    )
    if not verify_ok:
        result += " [FAILED VERIFICATION]"
    return result


def benchmark_p384(duration_secs: Float64) -> String:
    var scalar256 = InlineArray[UInt8, 32](fill=0)
    var out256 = InlineArray[UInt8, 65](fill=0)
    scalar256[31] = 7
    var scalar256_span = Span[UInt8, ...](scalar256)
    _ = p256_public_key(
        scalar256_span, Span[mut=True, UInt8, ...](out256)
    )
    var count256 = 0
    var start = perf_counter()
    while perf_counter() - start < duration_secs:
        _ = p256_public_key(
            scalar256_span, Span[mut=True, UInt8, ...](out256)
        )
        count256 += 1
    var duration256 = perf_counter() - start

    var scalar = InlineArray[UInt8, 48](fill=0)
    var out = InlineArray[UInt8, 97](fill=0)
    scalar[47] = 7
    var scalar_span = Span[UInt8, ...](scalar)
    _ = p384_public_key(scalar_span, Span[mut=True, UInt8, ...](out))
    var count = 0
    start = perf_counter()
    while perf_counter() - start < duration_secs:
        _ = p384_public_key(scalar_span, Span[mut=True, UInt8, ...](out))
        count += 1
    var duration = perf_counter() - start
    var ops = Float64(count) / duration
    return (
        "p256-public-key | throughput: "
        + String(Float64(count256) / duration256) + " ops/s, ops: "
        + String(count256) + ", time: " + String(duration256) + "s\n"
        + "p384-public-key | throughput: " + String(ops) + " ops/s, ops: " + String(count) + ", time: " + String(duration) + "s"
    )


def benchmark_ecdsa(duration_secs: Float64) -> String:
    var p256_key = InlineArray[UInt8, 32](fill=1)
    var p384_key = InlineArray[UInt8, 48](fill=1)
    var message = InlineArray[UInt8, 64](fill=7)
    var p256_sig = InlineArray[UInt8, 64](fill=0)
    var p384_sig = InlineArray[UInt8, 96](fill=0)
    var p256_pk = InlineArray[UInt8, 65](fill=0)
    var p384_pk = InlineArray[UInt8, 97](fill=0)
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

    _ = p256_public_key(
        Span[UInt8, ...](p256_key), Span[mut=True, UInt8, ...](p256_pk)
    )
    _ = p384_public_key(
        Span[UInt8, ...](p384_key), Span[mut=True, UInt8, ...](p384_pk)
    )
    var p256_verify_count = 0
    var p256_verify_failures = 0
    start = perf_counter()
    while perf_counter() - start < duration_secs:
        if not p256_ecdsa_verify(
            Span[UInt8, ...](p256_pk), msg, Span[UInt8, ...](p256_sig)
        ):
            p256_verify_failures += 1
        p256_verify_count += 1
    var p256_verify_time = perf_counter() - start

    var p384_verify_count = 0
    var p384_verify_failures = 0
    start = perf_counter()
    while perf_counter() - start < duration_secs:
        if not p384_ecdsa_verify(
            Span[UInt8, ...](p384_pk), msg, Span[UInt8, ...](p384_sig)
        ):
            p384_verify_failures += 1
        p384_verify_count += 1
    var p384_verify_time = perf_counter() - start

    var result = (
        "p256-ecdsa-sign | throughput: "
        + String(Float64(p256_count) / p256_time) + " ops/s\n"
        + "p384-ecdsa-sign | throughput: "
        + String(Float64(p384_count) / p384_time) + " ops/s\n"
        + "p256-ecdsa-verify | throughput: "
        + String(Float64(p256_verify_count) / p256_verify_time) + " ops/s\n"
        + "p384-ecdsa-verify | throughput: "
        + String(Float64(p384_verify_count) / p384_verify_time) + " ops/s"
    )
    if p256_verify_failures + p384_verify_failures > 0:
        result += " [" + String(p256_verify_failures + p384_verify_failures) + " FAILED VERIFICATIONS]"
    return result


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
    var signing_key = Ed25519SigningKey(sk_span)
    signing_key.sign(msg_span, sig_out)

    var sign_count = 0
    var start = perf_counter()
    while perf_counter() - start < duration_secs:
        signing_key.sign(msg_span, sig_out)
        sign_count += 1
    var sign_duration = perf_counter() - start
    var sign_ops = Float64(sign_count) / sign_duration

    signing_key.sign(msg_span, sig_out)
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


def benchmark_aes_ni(duration_secs: Float64) raises -> String:
    comptime if not CompilationTarget.is_x86():
        return "aes-128-ni | (x86 only)"
    if not has_aes_ni():
        return "aes-128-ni | (NI not available)"
    var key = AESKey(TEST_KEY)
    var round_keys = key.round_keys()
    var num_blocks = 65536
    var size = num_blocks * 16
    var input = alloc(Layout[UInt8](count=size)).unsafe_leak()
    var output = alloc(Layout[UInt8](count=size)).unsafe_leak()
    for i in range(size):
        input.unsafe_store(i, TEST_PT[i % 16])

    x86_aes_ecb_kernel(input, output, round_keys, num_blocks, ROUNDS_128)
    for i in range(16):
        if output.unsafe_load(i) != TEST_CT[i]:
            raise Error("AES-NI ECB benchmark self-test failed")
    var count = 0
    var start = perf_counter()
    while perf_counter() - start < duration_secs:
        x86_aes_ecb_kernel(input, output, round_keys, num_blocks, ROUNDS_128)
        count += 1
    var duration = perf_counter() - start
    var mbps = Float64(count * size) / (1024 * 1024) / duration

    input.unsafe_free()
    output.unsafe_free()
    return "aes-128-ni | throughput: " + String(mbps) + " mb/s, chunks: " + String(count) + ", time: " + String(duration) + "s"


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

        var block_dim = 64
        var grid_dim = ceildiv(ceildiv(num_blocks, 4), block_dim)
        
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

        var block_dim = 64
        var grid_dim = ceildiv(ceildiv(num_blocks, 4), block_dim)
        
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

        var block_dim = 64
        var grid_dim = ceildiv(ceildiv(num_blocks, 4), block_dim)
        
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
    print(benchmark_aes_ni(duration))
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
    print(benchmark_pbkdf2(duration))
    print(benchmark_tls_kdf(duration))
    print(benchmark_tls_aead(16 * 1024, duration))
    print(benchmark_tls_aead(64 * 1024, duration))
    print(benchmark_tls_aead(1024 * 1024, duration))
    print(benchmark_mlkem_set[K_512]("ml-kem-512", duration))
    print(benchmark_mlkem_set[K_768]("ml-kem-768", duration))
    print(benchmark_mlkem_set[K_1024]("ml-kem-1024", duration))
    print(benchmark_mldsa_set("ml-dsa-44", params44(), duration))
    print(benchmark_mldsa_set("ml-dsa-65", params65(), duration))
    print(benchmark_mldsa_set("ml-dsa-87", params87(), duration))
    print(benchmark_p384(duration))
    print(benchmark_ecdsa(duration))
    print(benchmark_ed25519(duration))

    print()
    print("All benchmarks completed")
