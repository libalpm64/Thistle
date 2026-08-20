"""
Dudect test (Reparaz/Balasch/Verbauwhede).
"""

from std.time import perf_counter_ns
from std.memory import UnsafePointer

from thistle.camellia import CamelliaCipher, camellia_encrypt_block
from thistle.kcipher2 import KCipher2
from thistle.chacha20 import ChaCha20
from thistle.aes import cpu_aes_encrypt, expand_key_128
from thistle.sha2 import sha256_hash, sha512_hash
from thistle.sha3 import sha3_256
from thistle.blake2b import blake2b_hash
from thistle.blake3 import blake3_hash
from thistle.pbkdf2 import hmac_sha256, hmac_sha384
from thistle.x25519 import x25519
from thistle.ed25519 import ed25519_sign
from thistle.p256 import p256_public_key, p256_ecdsa_sign
from thistle.p384 import p384_public_key, p384_ecdsa_sign
from thistle.ml_kem import mlkem512_keygen, mlkem512_encaps, mlkem512_decaps

comptime N_FAST = 100_000
comptime N_ASYM = 2_000
comptime BATCH = 16
comptime T_THRESHOLD = 4.5

struct Rng:
    var s: UInt64

    def __init__(out self, seed: UInt64):
        self.s = seed | 1

    @always_inline
    def next(mut self) -> UInt64:
        var x = self.s
        x ^= x >> 12
        x ^= x << 25
        x ^= x >> 27
        self.s = x
        return x * 0x2545F4914F6CDD1D

    def fill(mut self, mut buf: List[UInt8]):
        var i = 0
        while i < len(buf):
            var w = self.next()
            var j = 0
            while j < 8 and i < len(buf):
                buf[i] = UInt8((w >> UInt64(8 * j)) & 0xFF)
                i += 1
                j += 1


def _quicksort(mut a: List[Float64], lo: Int, hi: Int):
    if lo >= hi:
        return
    var pivot = a[(lo + hi) // 2]
    var i = lo
    var j = hi
    while i <= j:
        while a[i] < pivot:
            i += 1
        while a[j] > pivot:
            j -= 1
        if i <= j:
            var tmp = a[i]
            a[i] = a[j]
            a[j] = tmp
            i += 1
            j -= 1
    _quicksort(a, lo, j)
    _quicksort(a, i, hi)


def _welch_t(
    times: List[Float64], cls: List[Int], threshold: Float64
) -> Float64:
    var n0 = 0.0
    var n1 = 0.0
    var s0 = 0.0
    var s1 = 0.0
    for i in range(len(times)):
        if times[i] > threshold:
            continue
        if cls[i] == 0:
            n0 += 1.0
            s0 += times[i]
        else:
            n1 += 1.0
            s1 += times[i]
    if n0 < 2.0 or n1 < 2.0:
        return 0.0
    var m0 = s0 / n0
    var m1 = s1 / n1
    var v0 = 0.0
    var v1 = 0.0
    for i in range(len(times)):
        if times[i] > threshold:
            continue
        if cls[i] == 0:
            v0 += (times[i] - m0) * (times[i] - m0)
        else:
            v1 += (times[i] - m1) * (times[i] - m1)
    v0 /= n0 - 1.0
    v1 /= n1 - 1.0
    var denom = v0 / n0 + v1 / n1
    if denom <= 0.0:
        return 0.0
    return (m0 - m1) / (denom**0.5)


def _report(name: String, times: List[Float64], cls: List[Int]) -> Bool:
    var sorted_copy = List[Float64](capacity=len(times))
    for i in range(len(times)):
        sorted_copy.append(times[i])
    _quicksort(sorted_copy, 0, len(sorted_copy) - 1)

    var pcts = List[Float64]()
    pcts.append(1.0)
    pcts.append(0.99)
    pcts.append(0.95)
    pcts.append(0.90)
    pcts.append(0.75)

    var max_t = 0.0
    for c in range(len(pcts)):
        var idx = Int(Float64(len(sorted_copy) - 1) * pcts[c])
        var t = _welch_t(times, cls, sorted_copy[idx])
        if t < 0.0:
            t = -t
        if t > max_t:
            max_t = t

    var verdict = String("leak detected") if max_t > T_THRESHOLD else String(
        "ok"
    )
    var pad = name
    while pad.byte_length() < 46:
        pad += " "
    print(pad, "max |t| =", String(max_t)[byte=:6], "|", verdict)
    return max_t > T_THRESHOLD


def _classes(n: Int, mut rng: Rng) -> List[Int]:
    var cls = List[Int](capacity=n)
    for _ in range(n):
        cls.append(Int(rng.next() & 1))
    return cls^

# This is intentionally leaked
@no_inline
def _leaky(secret: UInt64) -> UInt64:
    var acc = secret
    var n = Int(secret & 0x3F)
    for _ in range(n):
        acc = acc * 0x9E3779B97F4A7C15 + 1
    return acc


def run_leaky_control(mut rng: Rng) -> Bool:
    var cls = _classes(N_FAST, rng)
    var secrets = List[UInt64](capacity=N_FAST)
    for i in range(N_FAST):
        secrets.append(0 if cls[i] == 0 else rng.next())
    var times = List[Float64](capacity=N_FAST)
    var sink: UInt64 = 0
    for i in range(N_FAST):
        var t0 = perf_counter_ns()
        for _ in range(BATCH):
            sink ^= _leaky(secrets[i])
        times.append(Float64(perf_counter_ns() - t0))
    if sink == 42:
        print("")
    return _report("leaky control (must fail)", times, cls)


def _fast_inputs(cls: List[Int], nbytes: Int, mut rng: Rng) -> List[UInt8]:
    var buf = List[UInt8](capacity=len(cls) * nbytes)
    for _ in range(len(cls) * nbytes):
        buf.append(0)
    for i in range(len(cls)):
        if cls[i] == 1:
            for j in range(nbytes):
                buf[i * nbytes + j] = UInt8(rng.next() & 0xFF)
    return buf^


def run_camellia_block(mut rng: Rng) raises -> Bool:
    var key = List[UInt8]()
    for i in range(16):
        key.append(UInt8(i * 7 + 3))
    var cipher = CamelliaCipher(Span[UInt8, ...](key))
    var cls = _classes(N_FAST, rng)
    var inp = _fast_inputs(cls, 16, rng)
    var times = List[Float64](capacity=N_FAST)
    var sink = SIMD[DType.uint8, 16](0)
    for i in range(N_FAST):
        var b = SIMD[DType.uint8, 16](0)
        for j in range(16):
            b[j] = inp[i * 16 + j]
        var t0 = perf_counter_ns()
        for _ in range(BATCH):
            sink ^= camellia_encrypt_block(cipher, b)
        times.append(Float64(perf_counter_ns() - t0))
    if sink[0] == 42:
        print("")
    return _report("camellia-128 block (fixed/random pt)", times, cls)


def run_kcipher2(mut rng: Rng) raises -> Bool:
    var cls = _classes(N_FAST // 2, rng)
    var keys = List[UInt64](capacity=len(cls) * 2)
    for i in range(len(cls)):
        keys.append(0 if cls[i] == 0 else rng.next())
        keys.append(0 if cls[i] == 0 else rng.next())
    var iv = SIMD[DType.uint32, 4](1, 2, 3, 4)
    var times = List[Float64](capacity=len(cls))
    var sink: UInt64 = 0
    for i in range(len(cls)):
        var key = SIMD[DType.uint32, 4](
            UInt32(keys[2 * i] & 0xFFFFFFFF), UInt32(keys[2 * i] >> 32),
            UInt32(keys[2 * i + 1] & 0xFFFFFFFF), UInt32(keys[2 * i + 1] >> 32),
        )
        var t0 = perf_counter_ns()
        for _ in range(8):
            var kc = KCipher2(key, iv)
            sink ^= kc.stream()
        times.append(Float64(perf_counter_ns() - t0))
    if sink == 42:
        print("")
    return _report("kcipher2 init&stream (fixed/random key)", times, cls)


def run_aes_sw(mut rng: Rng) raises -> Bool:
    var kb = List[UInt8]()
    for i in range(16):
        kb.append(UInt8(i + 1))
    var rk = expand_key_128(Span[UInt8, ...](kb))
    var cls = _classes(N_FAST, rng)
    var inp = _fast_inputs(cls, 16, rng)
    var times = List[Float64](capacity=N_FAST)
    var sink: UInt8 = 0
    var blk = List[UInt8]()
    for _ in range(16):
        blk.append(0)
    for i in range(N_FAST):
        var t0 = perf_counter_ns()
        for _ in range(BATCH):
            for j in range(16):
                blk[j] = inp[i * 16 + j]
            cpu_aes_encrypt(blk.unsafe_ptr(), rk.ptr(), 10)
            sink ^= blk[0]
        times.append(Float64(perf_counter_ns() - t0))
    if sink == 42:
        print("")
    return _report("aes-128 software (fixed/random pt)", times, cls)


def run_chacha20(mut rng: Rng) raises -> Bool:
    var cls = _classes(N_FAST, rng)
    var inp = _fast_inputs(cls, 32, rng)
    var nonce = SIMD[DType.uint8, 16](0)
    var times = List[Float64](capacity=N_FAST)
    var sink: UInt8 = 0
    var data = List[UInt8]()
    for _ in range(64):
        data.append(0)
    for i in range(N_FAST):
        var key = SIMD[DType.uint8, 32](0)
        for j in range(32):
            key[j] = inp[i * 32 + j]
        var t0 = perf_counter_ns()
        for _ in range(BATCH):
            var c = ChaCha20(key, nonce)
            var span = Span[mut=True, UInt8](data)
            c.encrypt_inplace(span)
            sink ^= data[0]
        times.append(Float64(perf_counter_ns() - t0))
    if sink == 42:
        print("")
    return _report("chacha20 (fixed/random key)", times, cls)


@always_inline
def _hash_first(which: Int, m: Span[UInt8, ...]) raises -> UInt8:
    if which == 0:
        return sha256_hash(m)[0]
    elif which == 1:
        return sha512_hash(m)[0]
    elif which == 2:
        return sha3_256(m)[0]
    elif which == 3:
        return blake2b_hash(m)[0]
    else:
        return blake3_hash(m)[0]


def _run_hash(which: Int, name: String, mut rng: Rng) raises -> Bool:
    var cls = _classes(N_FAST, rng)
    var inp = _fast_inputs(cls, 64, rng)
    var times = List[Float64](capacity=N_FAST)
    var sink: UInt8 = 0
    var msg = List[UInt8]()
    for _ in range(64):
        msg.append(0)
    for i in range(N_FAST):
        for j in range(64):
            msg[j] = inp[i * 64 + j]
        var t0 = perf_counter_ns()
        for _ in range(BATCH):
            sink ^= _hash_first(which, Span[UInt8, ...](msg))
        times.append(Float64(perf_counter_ns() - t0))
    if sink == 42:
        print("")
    return _report(name, times, cls)


def run_hmac(mut rng: Rng) raises -> Bool:
    # HMAC-SHA256, key fixed vs random
    var cls = _classes(N_FAST, rng)
    var inp = _fast_inputs(cls, 32, rng)
    var data = List[UInt8]()
    for i in range(32):
        data.append(UInt8(i))
    var times = List[Float64](capacity=N_FAST)
    var sink: UInt8 = 0
    var key = List[UInt8]()
    for _ in range(32):
        key.append(0)
    for i in range(N_FAST):
        for j in range(32):
            key[j] = inp[i * 32 + j]
        var t0 = perf_counter_ns()
        for _ in range(BATCH):
            var m = hmac_sha256(
                Span[UInt8, ...](key), Span[UInt8, ...](data)
            )
            sink ^= m[0]
        times.append(Float64(perf_counter_ns() - t0))
    if sink == 42:
        print("")
    return _report("hmac-sha256 (fixed/random key)", times, cls)


def run_hmac_sha384(mut rng: Rng) -> Bool:
    var cls = _classes(N_FAST, rng)
    var inp = _fast_inputs(cls, 48, rng)
    var data = List[UInt8](length=48, fill=0x5A)
    var times = List[Float64](capacity=N_FAST)
    var sink: UInt8 = 0
    var key = List[UInt8](length=48, fill=0)
    for i in range(N_FAST):
        for j in range(48):
            key[j] = inp[i * 48 + j]
        var t0 = perf_counter_ns()
        for _ in range(BATCH):
            var mac = hmac_sha384(
                Span[UInt8, ...](key), Span[UInt8, ...](data)
            )
            sink ^= mac[0]
        times.append(Float64(perf_counter_ns() - t0))
    if sink == 42:
        print("")
    return _report("hmac-sha384 (fixed/random key)", times, cls)


def _valid_scalar(nbytes: Int, mut rng: Rng, fixed: Bool) -> List[UInt8]:
    # nonzero and < group order, top byte forced into [1,0x7f]
    var s = List[UInt8]()
    for _ in range(nbytes):
        s.append(0)
    if fixed:
        s[nbytes - 1] = 0x2A
        s[0] = 0x11
    else:
        for j in range(nbytes):
            s[j] = UInt8(rng.next() & 0xFF)
        s[0] = UInt8((rng.next() % 0x7F) + 1)
    return s^


def run_x25519(mut rng: Rng) raises -> Bool:
    # secret scalar fixed / random, fixed base point
    var base = List[UInt8]()
    base.append(9)
    for _ in range(31):
        base.append(0)
    var cls = _classes(N_ASYM, rng)
    var times = List[Float64](capacity=N_ASYM)
    var out = List[UInt8]()
    for _ in range(32):
        out.append(0)
    var sink: UInt8 = 0
    for i in range(N_ASYM):
        var sc = List[UInt8]()
        for _ in range(32):
            sc.append(0)
        if cls[i] == 1:
            rng.fill(sc)
        else:
            sc[0] = 0x40
        var t0 = perf_counter_ns()
        x25519(
            Span[UInt8, ...](sc),
            Span[UInt8, ...](base),
            Span[mut=True, UInt8, ...](out),
        )
        times.append(Float64(perf_counter_ns() - t0))
        sink ^= out[0]
    if sink == 42:
        print("")
    return _report("x25519 scalar mult (fixed/random scalar)", times, cls)


def run_ed25519(mut rng: Rng) raises -> Bool:
    # signing key fixed / random
    var msg = List[UInt8]()
    for i in range(32):
        msg.append(UInt8(i))
    var cls = _classes(N_ASYM, rng)
    var times = List[Float64](capacity=N_ASYM)
    var sig = List[UInt8]()
    for _ in range(64):
        sig.append(0)
    var sink: UInt8 = 0
    for i in range(N_ASYM):
        var sk = List[UInt8]()
        for _ in range(32):
            sk.append(0)
        if cls[i] == 1:
            rng.fill(sk)
        else:
            sk[0] = 0x33
        var t0 = perf_counter_ns()
        ed25519_sign(
            Span[UInt8, ...](sk), Span[UInt8, ...](msg), sig.unsafe_ptr()
        )
        times.append(Float64(perf_counter_ns() - t0))
        sink ^= sig[0]
    if sink == 42:
        print("")
    return _report("ed25519 sign (fixed/random key)", times, cls)


def run_p256(mut rng: Rng) raises -> Bool:
    var cls = _classes(N_ASYM, rng)
    var times = List[Float64](capacity=N_ASYM)
    var out = List[UInt8]()
    for _ in range(65):
        out.append(0)
    var sink: UInt8 = 0
    for i in range(N_ASYM):
        var sc = _valid_scalar(32, rng, cls[i] == 0)
        var t0 = perf_counter_ns()
        var ok = p256_public_key(
            Span[UInt8, ...](sc), Span[mut=True, UInt8, ...](out)
        )
        times.append(Float64(perf_counter_ns() - t0))
        sink ^= out[0] ^ (UInt8(1) if ok else UInt8(0))
    if sink == 42:
        print("")
    return _report("p-256 scalar mult (fixed/random scalar)", times, cls)


def run_p384(mut rng: Rng) raises -> Bool:
    var cls = _classes(N_ASYM, rng)
    var times = List[Float64](capacity=N_ASYM)
    var out = List[UInt8]()
    for _ in range(97):
        out.append(0)
    var sink: UInt8 = 0
    for i in range(N_ASYM):
        var sc = _valid_scalar(48, rng, cls[i] == 0)
        var t0 = perf_counter_ns()
        var ok = p384_public_key(
            Span[UInt8, ...](sc), Span[mut=True, UInt8, ...](out)
        )
        times.append(Float64(perf_counter_ns() - t0))
        sink ^= out[0] ^ (UInt8(1) if ok else UInt8(0))
    if sink == 42:
        print("")
    return _report("p-384 scalar mult (fixed/random scalar)", times, cls)


def run_p256_sign(mut rng: Rng) -> Bool:
    var cls = _classes(N_ASYM, rng)
    var times = List[Float64](capacity=N_ASYM)
    var message = List[UInt8](length=32, fill=0xA5)
    var signature = List[UInt8](unsafe_uninit_length=64)
    var sink: UInt8 = 0
    for i in range(N_ASYM):
        var private_key = _valid_scalar(32, rng, cls[i] == 0)
        var t0 = perf_counter_ns()
        var ok = p256_ecdsa_sign(
            Span[UInt8, ...](private_key),
            Span[UInt8, ...](message),
            Span[mut=True, UInt8, ...](signature),
        )
        times.append(Float64(perf_counter_ns() - t0))
        sink ^= signature[0] ^ (UInt8(1) if ok else UInt8(0))
    if sink == 42:
        print("")
    return _report("p-256 ECDSA sign (fixed/random key)", times, cls)


def run_p384_sign(mut rng: Rng) -> Bool:
    var cls = _classes(N_ASYM, rng)
    var times = List[Float64](capacity=N_ASYM)
    var message = List[UInt8](length=48, fill=0xA5)
    var signature = List[UInt8](unsafe_uninit_length=96)
    var sink: UInt8 = 0
    for i in range(N_ASYM):
        var private_key = _valid_scalar(48, rng, cls[i] == 0)
        var t0 = perf_counter_ns()
        var ok = p384_ecdsa_sign(
            Span[UInt8, ...](private_key),
            Span[UInt8, ...](message),
            Span[mut=True, UInt8, ...](signature),
        )
        times.append(Float64(perf_counter_ns() - t0))
        sink ^= signature[0] ^ (UInt8(1) if ok else UInt8(0))
    if sink == 42:
        print("")
    return _report("p-384 ECDSA sign (fixed/random key)", times, cls)


def run_mlkem_decaps(mut rng: Rng) raises -> Bool:
    var kp = mlkem512_keygen()
    var ek = kp[0].copy()
    var dk = kp[1].copy()
    var enc = mlkem512_encaps(Span[UInt8, ...](ek))
    var good_ct = enc[0].copy()

    var cls = _classes(N_ASYM, rng)
    var times = List[Float64](capacity=N_ASYM)
    var sink: UInt8 = 0
    for i in range(N_ASYM):
        var ct = List[UInt8]()
        for j in range(len(good_ct)):
            ct.append(good_ct[j])
        if cls[i] == 1:
            # corrupt one random byte force implicit rejection
            var pos = Int(rng.next() % UInt64(len(ct)))
            ct[pos] = ct[pos] ^ 0xFF
        var t0 = perf_counter_ns()
        var res = mlkem512_decaps(
            Span[UInt8, ...](dk), Span[UInt8, ...](ct)
        )
        times.append(Float64(perf_counter_ns() - t0))
        sink ^= res[0][0]
    if sink == 42:
        print("")
    return _report("ml-kem-512 decaps (valid/corrupt ct)", times, cls)


def main() raises:
    print(
        "dudect harness: fast", N_FAST, "batch", BATCH, "| asym", N_ASYM,
        "| |t| threshold", T_THRESHOLD,
    )
    print("")
    var rng = Rng(0x1234567890ABCDEF)

    var control_leaked = run_leaky_control(rng)
    if not control_leaked:
        print("warning: harness did not detect the leaky control;")
        print("results below are not trustworthy on this machine.")
    print("")

    var any_leak = False

    print("symmetric:")
    if run_camellia_block(rng):
        any_leak = True
    if run_aes_sw(rng):
        any_leak = True
    if run_chacha20(rng):
        any_leak = True
    if run_kcipher2(rng):
        any_leak = True

    print("hashes/mac: ")
    if _run_hash(0, "sha-256 (fixed/random msg)", rng):
        any_leak = True
    if _run_hash(1, "sha-512 (fixed/random msg)", rng):
        any_leak = True
    if _run_hash(2, "sha3-256 (fixed/random msg)", rng):
        any_leak = True
    if _run_hash(3, "blake2b (fixed/random msg)", rng):
        any_leak = True
    if _run_hash(4, "blake3 (fixed/random msg)", rng):
        any_leak = True
    if run_hmac(rng):
        any_leak = True
    if run_hmac_sha384(rng):
        any_leak = True

    print("asymmetric:")
    if run_x25519(rng):
        any_leak = True
    if run_ed25519(rng):
        any_leak = True
    if run_p256(rng):
        any_leak = True
    if run_p384(rng):
        any_leak = True
    if run_p256_sign(rng):
        any_leak = True
    if run_p384_sign(rng):
        any_leak = True
    if run_mlkem_decaps(rng):
        any_leak = True

    print("")
    if any_leak:
        print("timing leak detected")
    else:
        print("no evidence of leaks by statistical analysis")
