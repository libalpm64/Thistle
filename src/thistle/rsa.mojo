"""RSA-PSS signing and verification, plus PKCS #1 v1.5 verification (RFC 8017, secs. 8.1 and
8.2).
"""

from std.collections import List, InlineArray
from std.memory import Pointer
from std.bit import rotate_bits_left, count_leading_zeros
from std.utils import StaticTuple
from std.sys import inlined_assembly
from .random import random_bytes
from .sha2 import (
    sha224_hash, sha256_hash, sha384_hash, sha512_hash,
    SHA256Context, sha256_update, sha256_final_to_buffer,
    SHA512Context, sha512_update, sha512_final_to_buffer
)

comptime _NL = 66
comptime SHA1: Int = 1
comptime SHA224: Int = 224
comptime SHA256: Int = 256
comptime SHA384: Int = 384
comptime SHA512: Int = 512


@always_inline
def _bn_zero() -> StaticTuple[UInt64, _NL]:
    var out = StaticTuple[UInt64, _NL]()
    comptime for i in range(_NL):
        out[i] = 0
    return out


def _sha1(data: Span[UInt8, ...]) -> InlineArray[UInt8, 20]:
    var h0: UInt32 = 0x67452301
    var h1: UInt32 = 0xEFCDAB89
    var h2: UInt32 = 0x98BADCFE
    var h3: UInt32 = 0x10325476
    var h4: UInt32 = 0xC3D2E1F0

    var n = len(data)
    var total = ((n + 9 + 63) // 64) * 64
    var padded = List[UInt8](capacity=total)
    for i in range(n):
        padded.append(data[i])
    padded.append(0x80)
    while len(padded) % 64 != 56:
        padded.append(0)
    var bits = UInt64(n) * 8
    for i in range(7, -1, -1):
        padded.append(UInt8((bits >> UInt64(8 * i)) & 0xFF))

    var w = InlineArray[UInt32, 80](fill=0)
    var off = 0
    while off < len(padded):
        for t in range(16):
            var b = off + t * 4
            w[t] = (
                (UInt32(padded[b]) << 24) | (UInt32(padded[b + 1]) << 16)
                | (UInt32(padded[b + 2]) << 8) | UInt32(padded[b + 3])
            )
        for t in range(16, 80):
            w[t] = rotate_bits_left[1](w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16])
        var a = h0
        var b = h1
        var c = h2
        var d = h3
        var e = h4
        for t in range(80):
            var f: UInt32
            var kk: UInt32
            if t < 20:
                f = (b & c) | (~b & d)
                kk = 0x5A827999
            elif t < 40:
                f = b ^ c ^ d
                kk = 0x6ED9EBA1
            elif t < 60:
                f = (b & c) | (b & d) | (c & d)
                kk = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                kk = 0xCA62C1D6
            var tmp = rotate_bits_left[5](a) + f + e + kk + w[t]
            e = d
            d = c
            c = rotate_bits_left[30](b)
            b = a
            a = tmp
        h0 += a
        h1 += b
        h2 += c
        h3 += d
        h4 += e
        off += 64

    var out = InlineArray[UInt8, 20](fill=0)
    var hs = InlineArray[UInt32, 5](fill=0)
    hs[0] = h0
    hs[1] = h1
    hs[2] = h2
    hs[3] = h3
    hs[4] = h4
    for i in range(5):
        out[4 * i] = UInt8((hs[i] >> 24) & 0xFF)
        out[4 * i + 1] = UInt8((hs[i] >> 16) & 0xFF)
        out[4 * i + 2] = UInt8((hs[i] >> 8) & 0xFF)
        out[4 * i + 3] = UInt8(hs[i] & 0xFF)
    return out^


def _hash_len(alg: Int) raises -> Int:
    if alg == SHA1:
        return 20
    if alg == SHA224:
        return 28
    if alg == SHA256:
        return 32
    if alg == SHA384:
        return 48
    if alg == SHA512:
        return 64
    raise Error("unsupported hash for RSA-PSS")


def _hash_into(alg: Int, data: Span[UInt8, ...], output: Pointer[mut=True, UInt8, _, address_space=_]
) raises -> Int:
    if alg == SHA256:
        var ctx = SHA256Context()
        sha256_update(ctx, data)
        sha256_final_to_buffer(ctx, output)
        return 32
    if alg == SHA512:
        var ctx = SHA512Context()
        sha512_update(ctx, data)
        sha512_final_to_buffer(ctx, output)
        return 64
    if alg == SHA1:
        var d1 = _sha1(data)
        for i in range(20):
            output[unsafe_offset=i] = d1[i]
        return 20
    var d: List[UInt8]
    if alg == SHA224:
        d = sha224_hash(data)
    elif alg == SHA256:
        d = sha256_hash(data)
    elif alg == SHA384:
        d = sha384_hash(data)
    elif alg == SHA512:
        d = sha512_hash(data)
    else:
        raise Error("unsupported hash for RSA-PSS")
    for i in range(len(d)):
        output[unsafe_offset=i] = d[i]
    return len(d)


def _mgf1(
    alg: Int,
    seed: Pointer[UInt8, _],
    seed_len: Int,
    mask_len: Int,
    output: Pointer[mut=True, UInt8, _, address_space=_]
) raises:
    var h_len = _hash_len(alg)
    var block = InlineArray[UInt8, 128](fill=0)
    var digest = InlineArray[UInt8, 64](fill=0)
    for i in range(seed_len):
        block[i] = seed[unsafe_offset=i]
    var done = 0
    var counter: UInt32 = 0
    # MGF1 hashes seed || I2OSP(counter, 4), with a big-endian counter (RFC 8017, Appendix B.2.1).
    while done < mask_len:
        block[seed_len] = UInt8((counter >> 24) & 0xFF)
        block[seed_len + 1] = UInt8((counter >> 16) & 0xFF)
        block[seed_len + 2] = UInt8((counter >> 8) & 0xFF)
        block[seed_len + 3] = UInt8(counter & 0xFF)
        _ = _hash_into(
            alg,
            Span[UInt8, ...](unsafe_ptr=block.unsafe_ptr(), length=seed_len + 4),
            digest.unsafe_ptr()
        )
        var take = mask_len - done
        if take > h_len:
            take = h_len
        for i in range(take):
            output[unsafe_offset=done + i] = digest[i]
        done += take
        counter += 1


def _emsa_pss_encode(
    message: Span[UInt8, ...],
    salt: Span[UInt8, ...],
    sha: Int,
    mgf_sha: Int,
    em_bits: Int,
    output: Pointer[mut=True, UInt8, _, address_space=_]
) raises -> Bool:
    """Encode EMSA-PSS with caller-supplied salt (RFC 8017, sec. 9.1.1)."""
    var h_len = _hash_len(sha)
    _ = _hash_len(mgf_sha)
    var em_len = (em_bits + 7) // 8
    if em_len < h_len + 2 or len(salt) > em_len - h_len - 2:
        return False

    var m_hash = InlineArray[UInt8, 64](fill=0)
    _ = _hash_into(sha, message, m_hash.unsafe_ptr())
    var mprime = InlineArray[UInt8, 534](fill=0)
    for i in range(h_len):
        mprime[8 + i] = m_hash[i]
    for i in range(len(salt)):
        mprime[8 + h_len + i] = salt[i]
    var h = InlineArray[UInt8, 64](fill=0)
    _ = _hash_into(
        sha,
        Span[UInt8, ...](unsafe_ptr=mprime.unsafe_ptr(), length=8 + h_len + len(salt)),
        h.unsafe_ptr()
    )

    var db_len = em_len - h_len - 1
    var db = InlineArray[UInt8, 528](fill=0)
    var ps_len = db_len - len(salt) - 1
    db[ps_len] = 1
    for i in range(len(salt)):
        db[ps_len + 1 + i] = salt[i]
    var mask = InlineArray[UInt8, 528](fill=0)
    _mgf1(mgf_sha, h.unsafe_ptr(), h_len, db_len, mask.unsafe_ptr())
    for i in range(db_len):
        output[unsafe_offset=i] = db[i] ^ mask[i]
    output[unsafe_offset=0] &= UInt8(0xFF) >> UInt8(8 * em_len - em_bits)
    for i in range(h_len):
        output[unsafe_offset=db_len + i] = h[i]
    output[unsafe_offset=em_len - 1] = 0xBC

    var mp = mprime.unsafe_ptr()
    for i in range(8 + h_len + len(salt)):
        mp.unsafe_store[volatile=True](i, UInt8(0))
    return True


def _digest_info_prefix_len(alg: Int) raises -> Int:
    if alg == SHA1:
        return 15
    if alg == SHA224 or alg == SHA256 or alg == SHA384 or alg == SHA512:
        return 19
    raise Error("unsupported hash for RSA PKCS#1 v1.5")


def _digest_info_prefix(
    alg: Int, output: Pointer[mut=True, UInt8, _, address_space=_]
) raises:
    var hex: String
    if alg == SHA1:
        hex = "3021300906052b0e03021a05000414"
    elif alg == SHA224:
        hex = "302d300d06096086480165030402040500041c"
    elif alg == SHA256:
        hex = "3031300d060960864801650304020105000420"
    elif alg == SHA384:
        hex = "3041300d060960864801650304020205000430"
    elif alg == SHA512:
        hex = "3051300d060960864801650304020305000440"
    else:
        raise Error("unsupported hash for RSA PKCS#1 v1.5")
    var bytes = hex.as_bytes()
    for i in range(hex.byte_length() // 2):
        var hi = bytes[2 * i]
        var lo = bytes[2 * i + 1]
        hi = hi - UInt8(48 if hi <= 57 else 87)
        lo = lo - UInt8(48 if lo <= 57 else 87)
        output[unsafe_offset=i] = (hi << 4) | lo


@always_inline
def _bn_ge(a: StaticTuple[UInt64, _NL], b: StaticTuple[UInt64, _NL], k: Int) -> Bool:
    for i in range(k - 1, -1, -1):
        if a[i] > b[i]:
            return True
        if a[i] < b[i]:
            return False
    return True


@always_inline
def _bn_ge_ct(
    a: StaticTuple[UInt64, _NL],
    b: StaticTuple[UInt64, _NL],
    k: Int
) -> Bool:
    var borrow: UInt64 = 0
    for i in range(k):
        var d = (UInt128(1) << 64)
            + UInt128(a[i])
            - UInt128(b[i])
            - UInt128(borrow)
        borrow = 1 - (d >> 64).cast[DType.uint64]()
    return borrow == 0


@always_inline
def _bn_sub(mut a: StaticTuple[UInt64, _NL], b: StaticTuple[UInt64, _NL], k: Int):
    var borrow: UInt64 = 0
    for i in range(k):
        var d = (UInt128(1) << 64) + UInt128(a[i]) - UInt128(b[i]) - UInt128(borrow)
        a[i] = d.cast[DType.uint64]()
        borrow = 1 - (d >> 64).cast[DType.uint64]()


@always_inline
def _bn_sub_copy(
    a: StaticTuple[UInt64, _NL], b: StaticTuple[UInt64, _NL], k: Int
) -> Tuple[StaticTuple[UInt64, _NL], UInt64]:
    var out = a
    var borrow: UInt64 = 0
    for i in range(k):
        var d = (UInt128(1) << 64) + UInt128(a[i]) - UInt128(b[i]) - UInt128(borrow)
        out[i] = d.cast[DType.uint64]()
        borrow = 1 - (d >> 64).cast[DType.uint64]()
    return out, borrow


@always_inline
def _bn_select(
    a: StaticTuple[UInt64, _NL],
    b: StaticTuple[UInt64, _NL],
    choice: UInt64,
    k: Int
) -> StaticTuple[UInt64, _NL]:
    var out = a
    var mask = inlined_assembly[
        "", UInt64, constraints="=r,0", has_side_effect=True
    ](UInt64(0) - (choice & UInt64(1)))
    for i in range(k):
        out[i] = a[i] ^ (mask & (a[i] ^ b[i]))
    return out


@always_inline
def _nonzero_choice(x: UInt64) -> UInt64:
    return (x | (UInt64(0) - x)) >> 63


@always_inline
def _bn_dbl_mod(mut a: StaticTuple[UInt64, _NL], n: StaticTuple[UInt64, _NL], k: Int):
    var carry: UInt64 = 0
    for i in range(k):
        var v = a[i]
        a[i] = (v << 1) | carry
        carry = v >> 63
    var reduced, borrow = _bn_sub_copy(a, n, k)
    var selected = _bn_select(a, reduced, carry | (borrow ^ UInt64(1)), k)
    for i in range(k):
        a[i] = selected[i]


@always_inline
def _mont_mul_k[K: Int](
    a: StaticTuple[UInt64, _NL],
    b: StaticTuple[UInt64, _NL],
    n: StaticTuple[UInt64, _NL],
    n0: UInt64
) -> StaticTuple[UInt64, _NL]:
    """CIOS Montgomery multiplication with two operand rows processed per iteration and
    separate carry chains.
    """
    var t = StaticTuple[UInt64, _NL]()
    comptime for z in range(K):
        t[z] = 0
    var t_hi: UInt64 = 0
    var i = 0
    while i < K:
        var x0 = a[i]
        var x1 = a[i + 1]

        var s0 = UInt128(x0) * UInt128(b[0]) + UInt128(t[0])
        var m0 = s0.cast[DType.uint64]() * n0
        var q0 = UInt128(m0) * UInt128(n[0]) + UInt128(s0.cast[DType.uint64]())
        var ca0 = s0 >> 64
        var cb0 = q0 >> 64

        var u = UInt128(x0) * UInt128(b[1]) + UInt128(t[1]) + ca0
        ca0 = u >> 64
        var v = UInt128(m0) * UInt128(n[1]) + UInt128(u.cast[DType.uint64]()) + cb0
        cb0 = v >> 64
        var tp = v.cast[DType.uint64]()

        var s1 = UInt128(x1) * UInt128(b[0]) + UInt128(tp)
        var m1 = s1.cast[DType.uint64]() * n0
        var q1 = UInt128(m1) * UInt128(n[0]) + UInt128(s1.cast[DType.uint64]())
        var ca1 = s1 >> 64
        var cb1 = q1 >> 64

        comptime for j in range(2, K):
            var u0 = UInt128(x0) * UInt128(b[j]) + UInt128(t[j]) + ca0
            ca0 = u0 >> 64
            var v0 = UInt128(m0) * UInt128(n[j]) + UInt128(u0.cast[DType.uint64]()) + cb0
            cb0 = v0 >> 64
            var u1 = UInt128(x1) * UInt128(b[j - 1]) + UInt128(v0.cast[DType.uint64]()) + ca1
            ca1 = u1 >> 64
            var v1 = UInt128(m1) * UInt128(n[j - 1]) + UInt128(u1.cast[DType.uint64]()) + cb1
            cb1 = v1 >> 64
            t[j - 2] = v1.cast[DType.uint64]()

        var w0 = UInt128(t_hi) + ca0 + cb0
        var u2 = UInt128(x1) * UInt128(b[K - 1]) + UInt128(w0.cast[DType.uint64]()) + ca1
        ca1 = u2 >> 64
        var v2 = UInt128(m1) * UInt128(n[K - 1]) + UInt128(u2.cast[DType.uint64]()) + cb1
        cb1 = v2 >> 64
        t[K - 2] = v2.cast[DType.uint64]()

        var w1 = (w0 >> 64) + ca1 + cb1
        t[K - 1] = w1.cast[DType.uint64]()
        t_hi = (w1 >> 64).cast[DType.uint64]()
        i += 2
    var reduced, borrow = _bn_sub_copy(t, n, K)
    var take = _nonzero_choice(t_hi) | (borrow ^ UInt64(1))
    return _bn_select(t, reduced, take, K)


def _mont_mul_any(
    a: StaticTuple[UInt64, _NL],
    b: StaticTuple[UInt64, _NL],
    n: StaticTuple[UInt64, _NL],
    n0: UInt64,
    k: Int
) -> StaticTuple[UInt64, _NL]:
    var t = _bn_zero()
    var t_hi: UInt64 = 0
    for i in range(k):
        var ai = a[i]
        var s = UInt128(ai) * UInt128(b[0]) + UInt128(t[0])
        var m = s.cast[DType.uint64]() * n0
        var s2 = UInt128(m) * UInt128(n[0]) + UInt128(s.cast[DType.uint64]())
        var ca = s >> 64
        var cb = s2 >> 64
        for j in range(1, k):
            var u = UInt128(ai) * UInt128(b[j]) + UInt128(t[j]) + ca
            ca = u >> 64
            var v = UInt128(m) * UInt128(n[j]) + UInt128(u.cast[DType.uint64]()) + cb
            t[j - 1] = v.cast[DType.uint64]()
            cb = v >> 64
        var w = UInt128(t_hi) + ca + cb
        t[k - 1] = w.cast[DType.uint64]()
        t_hi = (w >> 64).cast[DType.uint64]()
    var reduced, borrow = _bn_sub_copy(t, n, k)
    var take = _nonzero_choice(t_hi) | (borrow ^ UInt64(1))
    return _bn_select(t, reduced, take, k)


@always_inline
def _mont_sqr_k[K: Int](
    a: StaticTuple[UInt64, _NL],
    n: StaticTuple[UInt64, _NL],
    n0: UInt64
) -> StaticTuple[UInt64, _NL]:
    var t = InlineArray[UInt64, 2 * _NL + 2](fill=0)
    comptime for z in range(2 * K + 1):
        t[z] = 0

    comptime for i in range(K - 1):
        var ai = a[i]
        var carry: UInt64 = 0
        comptime for j in range(i + 1, K):
            var p = UInt128(ai) * UInt128(a[j]) + UInt128(t[i + j]) + UInt128(carry)
            t[i + j] = p.cast[DType.uint64]()
            carry = (p >> 64).cast[DType.uint64]()
        t[i + K] = carry

    var c: UInt64 = 0
    comptime for x in range(1, 2 * K):
        var v = t[x]
        t[x] = (v << 1) | c
        c = v >> 63

    var cd: UInt64 = 0
    comptime for i in range(K):
        var sq = UInt128(a[i]) * UInt128(a[i])
        var s0 = UInt128(t[2 * i]) + UInt128(sq.cast[DType.uint64]()) + UInt128(cd)
        t[2 * i] = s0.cast[DType.uint64]()
        var s1 = UInt128(t[2 * i + 1]) + (sq >> 64) + (s0 >> 64)
        t[2 * i + 1] = s1.cast[DType.uint64]()
        cd = (s1 >> 64).cast[DType.uint64]()
    t[2 * K] += cd

    var ehold: UInt64 = 0
    comptime for i in range(K):
        var m = t[i] * n0
        var carry: UInt64 = 0
        comptime for j in range(K):
            var p = UInt128(m) * UInt128(n[j]) + UInt128(t[i + j]) + UInt128(carry)
            t[i + j] = p.cast[DType.uint64]()
            carry = (p >> 64).cast[DType.uint64]()
        var s2 = UInt128(t[i + K]) + UInt128(carry) + UInt128(ehold)
        t[i + K] = s2.cast[DType.uint64]()
        ehold = (s2 >> 64).cast[DType.uint64]()

    var out = StaticTuple[UInt64, _NL]()
    comptime for i in range(K):
        out[i] = t[K + i]
    var reduced, borrow = _bn_sub_copy(out, n, K)
    var take = _nonzero_choice(t[2 * K] | ehold) | (borrow ^ UInt64(1))
    return _bn_select(out, reduced, take, K)


@always_inline
def _mont_sqr(
    a: StaticTuple[UInt64, _NL],
    n: StaticTuple[UInt64, _NL],
    n0: UInt64,
    k: Int
) -> StaticTuple[UInt64, _NL]:
    if k == 16:
        return _mont_sqr_k[16](a, n, n0)
    if k == 32:
        return _mont_sqr_k[32](a, n, n0)
    if k == 48:
        return _mont_sqr_k[48](a, n, n0)
    if k == 64:
        return _mont_mul_k[64](a, a, n, n0)
    return _mont_mul_any(a, a, n, n0, k)


@always_inline
def _mont_mul(
    a: StaticTuple[UInt64, _NL],
    b: StaticTuple[UInt64, _NL],
    n: StaticTuple[UInt64, _NL],
    n0: UInt64,
    k: Int
) -> StaticTuple[UInt64, _NL]:
    if k == 16:
        return _mont_mul_k[16](a, b, n, n0)
    if k == 32:
        return _mont_mul_k[32](a, b, n, n0)
    if k == 48:
        return _mont_mul_k[48](a, b, n, n0)
    if k == 64:
        return _mont_mul_k[64](a, b, n, n0)
    return _mont_mul_any(a, b, n, n0, k)


struct RsaPublicKey:
    """RSA public key with cached Montgomery parameters for signature verification."""
    var n: StaticTuple[UInt64, _NL]
    var k: Int
    var nb: Int
    var mod_bits: Int
    var n0: UInt64
    var rmod: StaticTuple[UInt64, _NL]
    var r2: StaticTuple[UInt64, _NL]
    var e: List[UInt8]

    def __init__(out self, modulus: Span[UInt8, ...], exponent: Span[UInt8, ...]) raises:
        var lead = 0
        while lead < len(modulus) and modulus[lead] == 0:
            lead += 1
        var nb = len(modulus) - lead
        if nb < 16 or nb > 528:
            raise Error("RSA modulus must be 128 to 4224 bits")
        if len(exponent) == 0 or len(exponent) > 64:
            raise Error("RSA exponent size unsupported")
        var exponent_lead = 0
        while exponent_lead < len(exponent) and exponent[exponent_lead] == 0:
            exponent_lead += 1
        if exponent_lead == len(exponent):
            raise Error("RSA exponent must be nonzero")
        var exponent_len = len(exponent) - exponent_lead
        if (exponent[len(exponent) - 1] & 1) == 0:
            raise Error("RSA exponent must be odd")
        if exponent_len == 1 and exponent[exponent_lead] < 3:
            raise Error("RSA exponent must be at least 3")
        if exponent_len > nb:
            raise Error("RSA exponent must be smaller than modulus")
        if exponent_len == nb:
            var exponent_ge_modulus = True
            for i in range(nb):
                if exponent[exponent_lead + i] < modulus[lead + i]:
                    exponent_ge_modulus = False
                    break
                if exponent[exponent_lead + i] > modulus[lead + i]:
                    break
            if exponent_ge_modulus:
                raise Error("RSA exponent must be smaller than modulus")
        self.nb = nb
        self.k = (nb + 7) // 8
        var k = self.k

        self.n = _bn_zero()
        for i in range(nb):
            var byte = UInt64(modulus[lead + nb - 1 - i])
            self.n[i >> 3] |= byte << UInt64(8 * (i & 7))
        if (self.n[0] & 1) == 0 or self.n[k - 1] == 0:
            raise Error("RSA modulus must be odd")

        var top = modulus[lead]
        var top_bits = 0
        while top != 0:
            top >>= 1
            top_bits += 1
        self.mod_bits = (nb - 1) * 8 + top_bits

        var n0 = self.n[0]
        var inv = n0
        for _ in range(5):
            inv = inv * (2 - n0 * inv)
        self.n0 = UInt64(0) - inv

        self.rmod = _bn_zero()
        if (self.n[k - 1] >> 63) != 0:
            _bn_sub(self.rmod, self.n, k)
        else:
            self.rmod[0] = 1
            for _ in range(64 * k):
                _bn_dbl_mod(self.rmod, self.n, k)
        self.r2 = self.rmod
        _bn_dbl_mod(self.r2, self.n, k)
        var target = 64 * k
        var top_bit = 63 - Int(count_leading_zeros(UInt64(target)))
        for bit in range(top_bit - 1, -1, -1):
            self.r2 = _mont_mul(self.r2, self.r2, self.n, self.n0, k)
            if (target >> bit) & 1 == 1:
                _bn_dbl_mod(self.r2, self.n, k)

        self.e = List[UInt8](capacity=exponent_len)
        for i in range(exponent_lead, len(exponent)):
            self.e.append(exponent[i])

    def _public_op(
        self,
        sig: Span[UInt8, ...],
        output: Pointer[mut=True, UInt8, _, address_space=_]
    ) raises -> Bool:
        var nb = self.nb
        var k = self.k
        if len(sig) != nb:
            return False
        var s = _bn_zero()
        for i in range(nb):
            var byte = UInt64(sig[nb - 1 - i])
            s[i >> 3] |= byte << UInt64(8 * (i & 7))
        if _bn_ge(s, self.n, k):
            return False

        var sm = _mont_mul(s, self.r2, self.n, self.n0, k)
        var acc = self.rmod
        var started = False
        for bi in range(len(self.e)):
            var eb = self.e[bi]
            for j in range(7, -1, -1):
                if started:
                    acc = _mont_sqr(acc, self.n, self.n0, k)
                if (eb >> UInt8(j)) & 1 == 1:
                    if started:
                        acc = _mont_mul(acc, sm, self.n, self.n0, k)
                    else:
                        acc = sm
                        started = True
        if not started:
            return False

        var one = _bn_zero()
        one[0] = 1
        var m = _mont_mul(acc, one, self.n, self.n0, k)
        for i in range(nb):
            var limb = m[(nb - 1 - i) >> 3]
            output[unsafe_offset=i] = UInt8((limb >> UInt64(8 * ((nb - 1 - i) & 7))) & 0xFF)
        return True

    def pss_verify(
        self,
        message: Span[UInt8, ...],
        signature: Span[UInt8, ...],
        sha: Int,
        mgf_sha: Int,
        salt_len: Int
    ) raises -> Bool:
        """Verify RSASSA-PSS and its encoded message (RFC 8017, secs. 8.1.2 and 9.1.2)."""
        var h_len = _hash_len(sha)
        _ = _hash_len(mgf_sha)
        if salt_len < 0:
            return False

        var nb = self.nb
        var em_bits = self.mod_bits - 1
        var em_len = (em_bits + 7) // 8
        if em_len < h_len + 2 or salt_len > em_len - h_len - 2:
            return False

        var em = InlineArray[UInt8, 528](fill=0)
        if not self._public_op(signature, em.unsafe_ptr()):
            return False
        var pad_diff: UInt8 = 0
        for i in range(nb - em_len):
            pad_diff |= em[i]
        var ep = em.unsafe_ptr().unsafe_offset((nb - em_len))

        pad_diff |= ep[unsafe_offset=em_len - 1] ^ UInt8(0xBC)

        var db_len = em_len - h_len - 1
        var h_ptr = ep.unsafe_offset(db_len)

        var top_mask = UInt8(0xFF) >> UInt8(8 * em_len - em_bits)
        pad_diff |= ep[unsafe_offset=0] & ~top_mask

        var db_mask = InlineArray[UInt8, 528](fill=0)
        _mgf1(mgf_sha, h_ptr, h_len, db_len, db_mask.unsafe_ptr())
        var db = InlineArray[UInt8, 528](fill=0)
        for i in range(db_len):
            db[i] = ep[unsafe_offset=i] ^ db_mask[i]
        db[0] &= top_mask

        var ps_len = db_len - salt_len - 1
        for i in range(ps_len):
            pad_diff |= db[i]
        pad_diff |= db[ps_len] ^ UInt8(0x01)
        if pad_diff != 0:
            return False

        var m_hash = InlineArray[UInt8, 64](fill=0)
        _ = _hash_into(sha, message, m_hash.unsafe_ptr())

        var mprime = InlineArray[UInt8, 534](fill=0)
        for i in range(8):
            mprime[i] = 0
        for i in range(h_len):
            mprime[8 + i] = m_hash[i]
        for i in range(salt_len):
            mprime[8 + h_len + i] = db[ps_len + 1 + i]
        var h2 = InlineArray[UInt8, 64](fill=0)
        _ = _hash_into(
            sha,
            Span[UInt8, ...](unsafe_ptr=mprime.unsafe_ptr(), length=8 + h_len + salt_len),
            h2.unsafe_ptr()
        )

        var diff: UInt8 = 0
        for i in range(h_len):
            diff |= h2[i] ^ h_ptr[unsafe_offset=i]
        return diff == 0


def _wipe_bn(mut value: StaticTuple[UInt64, _NL], k: Int):
    # StaticTuple indexing returns an element by value. Take the address of the
    # aggregate itself so the volatile stores target the caller's tuple storage.
    var ptr = Pointer(to=value).unsafe_bitcast[UInt64]()
    for i in range(k):
        ptr.unsafe_store[volatile=True](i, UInt64(0))


def _wipe_bn_table(
    mut table: StaticTuple[StaticTuple[UInt64, _NL], 16], k: Int
):
    var ptr = Pointer(to=table).unsafe_bitcast[UInt64]()
    for row in range(16):
        for i in range(k):
            ptr.unsafe_store[volatile=True](row * _NL + i, UInt64(0))


@always_inline
def _bn_sub_into(
    output: Pointer[mut=True, UInt64, _],
    a: Pointer[mut=False, UInt64, _], b: Pointer[mut=False, UInt64, _], k: Int
) -> UInt64:
    var borrow = UInt64(0)
    for i in range(k):
        var d = (UInt128(1) << 64) + UInt128(a[unsafe_offset=i]) - UInt128(b[unsafe_offset=i]) - UInt128(borrow)
        output[unsafe_offset=i] = UInt64(d)
        borrow = 1 - UInt64(d >> 64)
    return borrow


@always_inline
def _bn_select_inplace(
    a: Pointer[mut=True, UInt64, _], b: Pointer[mut=False, UInt64, _],
    choice: UInt64, k: Int
):
    var mask = inlined_assembly[
        "", UInt64, constraints="=r,0", has_side_effect=True
    ](UInt64(0) - (choice & UInt64(1)))
    for i in range(k):
        a[unsafe_offset=i] ^= mask & (a[unsafe_offset=i] ^ b[unsafe_offset=i])


@always_inline
def _bn_half_inplace(a: Pointer[mut=True, UInt64, _], k: Int, high: UInt64 = 0):
    var carry = high
    for i in range(k - 1, -1, -1):
        var limb = a[unsafe_offset=i]
        a[unsafe_offset=i] = (limb >> 1) | (carry << 63)
        carry = limb & 1


@always_inline
def _bn_half_mod_inplace(
    a: Pointer[mut=True, UInt64, _], n: Pointer[mut=False, UInt64, _], k: Int
):
    var mask = inlined_assembly[
        "", UInt64, constraints="=r,0", has_side_effect=True
    ](UInt64(0) - (a[unsafe_offset=0] & UInt64(1)))
    var carry = UInt64(0)
    for i in range(k):
        var sum = UInt128(a[unsafe_offset=i]) + UInt128(n[unsafe_offset=i] & mask) + UInt128(carry)
        a[unsafe_offset=i] = UInt64(sum)
        carry = UInt64(sum >> 64)
    _bn_half_inplace(a, k, carry)


@always_inline
def _bn_sub_mod_into(
    output: Pointer[mut=True, UInt64, _],
    a: Pointer[mut=False, UInt64, _], b: Pointer[mut=False, UInt64, _],
    n: Pointer[mut=False, UInt64, _], k: Int
):
    var borrow = _bn_sub_into(output, a, b, k)
    var mask = inlined_assembly[
        "", UInt64, constraints="=r,0", has_side_effect=True
    ](UInt64(0) - borrow)
    var carry = UInt64(0)
    for i in range(k):
        var sum = UInt128(output[unsafe_offset=i]) + UInt128(n[unsafe_offset=i] & mask) + UInt128(carry)
        output[unsafe_offset=i] = UInt64(sum)
        carry = UInt64(sum >> 64)


def _bn_inverse_odd(a: StaticTuple[UInt64, _NL], key: RsaPublicKey) -> Tuple[StaticTuple[UInt64, _NL], Bool]:
    """Compute a^-1 mod n for RSA blinding using masked binary extended GCD with a public
    iteration budget.
    """
    # Each active step removes at least one bit from the product of the GCD operands.
    # Twice the modulus bit width bounds the steps; completed states remain unchanged.
    # Addressable limbs avoid rebuilding StaticTuples in the hot loop.
    # Keep four state rows and four scratch rows alive until the final wipe.
    var state = InlineArray[UInt64, 4 * _NL](fill=0)
    var scratch = InlineArray[UInt64, 4 * _NL](fill=0)
    var u = state.unsafe_ptr()
    var v = u.unsafe_offset(_NL)
    var x = v.unsafe_offset(_NL)
    var y = x.unsafe_offset(_NL)
    var next_u = scratch.unsafe_ptr()
    var next_v = next_u.unsafe_offset(_NL)
    var next_x = next_v.unsafe_offset(_NL)
    var next_y = next_x.unsafe_offset(_NL)
    var n = Pointer(to=key.n).unsafe_bitcast[UInt64]()
    var ap = Pointer(to=a).unsafe_bitcast[UInt64]()
    var k = key.k
    for i in range(k):
        u[unsafe_offset=i] = ap[unsafe_offset=i]
        v[unsafe_offset=i] = n[unsafe_offset=i]
    x[unsafe_offset=0] = 1
    for _ in range(2 * 64 * k + 1):
        var borrow = _bn_sub_into(next_u, u, v, k)
        _ = _bn_sub_into(next_v, v, u, k)
        var u_even = (u[unsafe_offset=0] & 1) ^ UInt64(1)
        var v_even = (v[unsafe_offset=0] & 1) ^ UInt64(1)
        var both_odd = (u_even ^ 1) & (v_even ^ 1)
        var take_u = u_even | (both_odd & (borrow ^ 1))
        var take_v = (u_even ^ 1) & (v_even | (both_odd & borrow))
        _bn_select_inplace(next_u, u, u_even, k)
        _bn_select_inplace(next_v, v, v_even, k)
        _bn_half_inplace(next_u, k)
        _bn_half_inplace(next_v, k)
        _bn_sub_mod_into(next_x, x, y, n, k)
        _bn_sub_mod_into(next_y, y, x, n, k)
        _bn_select_inplace(next_x, x, u_even, k)
        _bn_select_inplace(next_y, y, v_even, k)
        _bn_half_mod_inplace(next_x, n, k)
        _bn_half_mod_inplace(next_y, n, k)
        _bn_select_inplace(u, next_u, take_u, k)
        _bn_select_inplace(v, next_v, take_v, k)
        _bn_select_inplace(x, next_x, take_u, k)
        _bn_select_inplace(y, next_y, take_v, k)
    var diff = v[unsafe_offset=0] ^ UInt64(1)
    var result = _bn_zero()
    var rp = Pointer(to=result).unsafe_bitcast[UInt64]()
    for i in range(k):
        if i > 0:
            diff |= v[unsafe_offset=i]
        rp[unsafe_offset=i] = y[unsafe_offset=i]
    for i in range(4 * _NL):
        state.unsafe_ptr().unsafe_store[volatile=True](i, UInt64(0))
        scratch.unsafe_ptr().unsafe_store[volatile=True](i, UInt64(0))
    return result, diff == 0


struct _RsaBlinding:
    var factor: StaticTuple[UInt64, _NL]
    var inverse: StaticTuple[UInt64, _NL]

    def __init__(out self, key: RsaPublicKey) raises:
        self.factor = _bn_zero()
        self.inverse = _bn_zero()
        # Rejection sampling gives a uniform blinding factor; OS randomness errors propagate.
        # Never fall back to an unblinded private operation.
        for _ in range(128):
            var bytes = random_bytes(key.nb)
            bytes[0] &= UInt8(0xFF) >> UInt8(8 * key.nb - key.mod_bits)
            var r = _bn_zero()
            for i in range(key.nb):
                r[i >> 3] |= UInt64(bytes[key.nb - 1 - i]) << UInt64(8 * (i & 7))
            var bp = bytes.unsafe_ptr()
            for i in range(len(bytes)):
                bp.unsafe_store[volatile=True](i, UInt8(0))
            var nonzero = UInt64(0)
            for i in range(key.k):
                nonzero |= r[i]
            if nonzero == 0 or _bn_ge(r, key.n, key.k):
                _wipe_bn(r, key.k)
                continue
            var inverse, valid = _bn_inverse_odd(r, key)
            if not valid:
                _wipe_bn(r, key.k)
                _wipe_bn(inverse, key.k)
                continue
            var base = _mont_mul(r, key.r2, key.n, key.n0, key.k)
            var acc = key.rmod
            for i in range(len(key.e)):
                for bit in range(7, -1, -1):
                    acc = _mont_sqr(acc, key.n, key.n0, key.k)
                    if (key.e[i] >> UInt8(bit)) & 1:
                        acc = _mont_mul(acc, base, key.n, key.n0, key.k)
            self.factor = acc
            self.inverse = _mont_mul(inverse, key.r2, key.n, key.n0, key.k)
            _wipe_bn(r, key.k)
            _wipe_bn(inverse, key.k)
            _wipe_bn(base, key.k)
            _wipe_bn(acc, key.k)
            return
        raise Error("RSA could not sample an invertible blinding factor")

    def __deinit__(deinit self):
        _wipe_bn(self.factor, _NL)
        _wipe_bn(self.inverse, _NL)

    def blind(self, input: StaticTuple[UInt64, _NL], key: RsaPublicKey) -> StaticTuple[UInt64, _NL]:
        return _mont_mul(input, self.factor, key.n, key.n0, key.k)

    def unblind(self, result: StaticTuple[UInt64, _NL], key: RsaPublicKey) -> StaticTuple[UInt64, _NL]:
        return _mont_mul(result, self.inverse, key.n, key.n0, key.k)


struct RsaPrivateKey:
    """RSA private key using message blinding and fixed-window private exponentiation."""
    var public: RsaPublicKey
    var d: InlineArray[UInt8, 528]

    def __init__(
        out self,
        modulus: Span[UInt8, ...],
        exponent: Span[UInt8, ...],
        private_exponent: Span[UInt8, ...]
    ) raises:
        self.public = RsaPublicKey(modulus, exponent)
        if self.public.mod_bits < 2048:
            raise Error("RSA signing requires a modulus of at least 2048 bits")
        self.d = InlineArray[UInt8, 528](fill=0)
        var lead = 0
        while lead < len(private_exponent) and private_exponent[lead] == 0:
            lead += 1
        var d_len = len(private_exponent) - lead
        if d_len == 0 or d_len > self.public.nb:
            raise Error("invalid RSA private exponent")
        var dbn = _bn_zero()
        for i in range(d_len):
            var byte = UInt64(private_exponent[lead + d_len - 1 - i])
            dbn[i >> 3] |= byte << UInt64(8 * (i & 7))
        if _bn_ge_ct(dbn, self.public.n, self.public.k):
            _wipe_bn(dbn, self.public.k)
            raise Error("RSA private exponent must be smaller than modulus")
        for i in range(d_len):
            self.d[self.public.nb - d_len + i] = private_exponent[lead + i]
        _wipe_bn(dbn, self.public.k)

    def __deinit__(deinit self):
        var ptr = self.d.unsafe_ptr()
        for i in range(528):
            ptr.unsafe_store[volatile=True](i, UInt8(0))

    def _private_op(
        self,
        encoded: Span[UInt8, ...],
        signature: Pointer[mut=True, UInt8, _, address_space=_]
    ) raises -> Bool:
        var nb = self.public.nb
        var k = self.public.k
        if len(encoded) != nb:
            return False
        var input = _bn_zero()
        for i in range(nb):
            var byte = UInt64(encoded[nb - 1 - i])
            input[i >> 3] |= byte << UInt64(8 * (i & 7))
        if _bn_ge(input, self.public.n, k):
            _wipe_bn(input, k)
            return False

        var blinding = _RsaBlinding(self.public)
        var blinded = blinding.blind(input, self.public)
        var result = _private_pow(self.public, self.d, blinded)
        result = blinding.unblind(result, self.public)
        for i in range(nb):
            var limb = result[(nb - 1 - i) >> 3]
            signature[unsafe_offset=i] = UInt8((limb >> UInt64(8 * ((nb - 1 - i) & 7))) & 0xFF)

        var recovered = InlineArray[UInt8, 528](fill=0)
        var sig_span = Span[UInt8, ...](unsafe_ptr=signature, length=nb)
        var valid = self.public._public_op(sig_span, recovered.unsafe_ptr())
        var diff = UInt8(0)
        for i in range(nb):
            diff |= recovered[i] ^ encoded[i]
        valid = valid and diff == 0
        if not valid:
            for i in range(nb):
                signature.unsafe_store[volatile=True](i, UInt8(0))

        _wipe_bn(input, k)
        _wipe_bn(blinded, k)
        _wipe_bn(result, k)
        return valid

    def pss_sign_with_salt(
        self,
        message: Span[UInt8, ...],
        salt: Span[UInt8, ...],
        sha: Int,
        mgf_sha: Int,
        signature: Span[mut=True, UInt8, ...]
    ) raises -> Bool:
        if len(signature) < self.public.nb:
            return False
        var em_bits = self.public.mod_bits - 1
        var em_len = (em_bits + 7) // 8
        var encoded = InlineArray[UInt8, 528](fill=0)
        try:
            if not _emsa_pss_encode(
                message,
                salt,
                sha,
                mgf_sha,
                em_bits,
                encoded.unsafe_ptr().unsafe_offset(self.public.nb - em_len),
            ):
                return False
            return self._private_op(
                Span[UInt8, ...](
                    unsafe_ptr=encoded.unsafe_ptr(), length=self.public.nb
                ),
                signature.unsafe_ptr(),
            )
        finally:
            var ep = encoded.unsafe_ptr()
            for i in range(self.public.nb):
                ep.unsafe_store[volatile=True](i, UInt8(0))

    def pss_sign(
        self,
        message: Span[UInt8, ...],
        sha: Int,
        mgf_sha: Int,
        salt_len: Int
    ) raises -> List[UInt8]:
        if salt_len < 0:
            raise Error("RSA-PSS salt length must be non-negative")
        var h_len = _hash_len(sha)
        _ = _hash_len(mgf_sha)
        var em_len = (self.public.mod_bits + 6) // 8
        if em_len < h_len + 2 or salt_len > em_len - h_len - 2:
            raise Error("RSA-PSS salt is too long for the modulus")
        var salt = random_bytes(salt_len)
        try:
            var signature = List[UInt8](unsafe_uninit_length=self.public.nb)
            if not self.pss_sign_with_salt(
                message,
                Span[UInt8, ...](salt),
                sha,
                mgf_sha,
                Span[mut=True, UInt8, ...](signature)
            ):
                raise Error("RSA-PSS signing failed")
            return signature^
        finally:
            var salt_ptr = salt.unsafe_ptr()
            for i in range(len(salt)):
                salt_ptr.unsafe_store[volatile=True](i, UInt8(0))


def _bn_reduce_bytes(
    data: Span[UInt8, ...], key: RsaPublicKey
) -> StaticTuple[UInt64, _NL]:
    var value = _bn_zero()
    for bi in range(len(data)):
        var byte = data[bi]
        for bit in range(7, -1, -1):
            var carry = UInt64((byte >> UInt8(bit)) & 1)
            for i in range(key.k):
                var next = value[i] >> 63
                value[i] = (value[i] << 1) | carry
                carry = next
            var reduced, borrow = _bn_sub_copy(value, key.n, key.k)
            var take = carry | (borrow ^ UInt64(1))
            value = _bn_select(value, reduced, take, key.k)
    return value


def _private_pow(
    key: RsaPublicKey,
    exponent: InlineArray[UInt8, 528],
    input: StaticTuple[UInt64, _NL],
    exponent_bytes: Int = 0
) -> StaticTuple[UInt64, _NL]:
    var base = _mont_mul(input, key.r2, key.n, key.n0, key.k)
    var table = StaticTuple[StaticTuple[UInt64, _NL], 16]()
    table[0] = key.rmod
    table[1] = base
    for i in range(2, 16):
        table[i] = _mont_mul(table[i - 1], base, key.n, key.n0, key.k)
    var acc = key.rmod
    for bi in range(key.nb if exponent_bytes == 0 else exponent_bytes):
        var byte = exponent[bi]
        for half in range(2):
            acc = _mont_sqr(acc, key.n, key.n0, key.k)
            acc = _mont_sqr(acc, key.n, key.n0, key.k)
            acc = _mont_sqr(acc, key.n, key.n0, key.k)
            acc = _mont_sqr(acc, key.n, key.n0, key.k)
            var digit = UInt64(byte >> UInt8(4 if half == 0 else 0)) & UInt64(0xF)
            var selected = table[0]
            for i in range(1, 16):
                var hit = _nonzero_choice(digit ^ UInt64(i)) ^ UInt64(1)
                selected = _bn_select(selected, table[i], hit, key.k)
            acc = _mont_mul(acc, selected, key.n, key.n0, key.k)
    var one = _bn_zero()
    one[0] = 1
    var result = _mont_mul(acc, one, key.n, key.n0, key.k)
    _wipe_bn(base, key.k)
    _wipe_bn(acc, key.k)
    _wipe_bn_table(table, key.k)
    return result


def _bn_mul_parts(
    a: StaticTuple[UInt64, _NL], a_len: Int,
    b: StaticTuple[UInt64, _NL], b_len: Int
) -> StaticTuple[UInt64, _NL]:
    var out = _bn_zero()
    for i in range(a_len):
        var carry = UInt64(0)
        for j in range(b_len):
            var product = UInt128(a[i]) * UInt128(b[j]) + UInt128(out[i + j]) + UInt128(carry)
            out[i + j] = product.cast[DType.uint64]()
            carry = (product >> 64).cast[DType.uint64]()
        out[i + b_len] = carry
    return out


def _bn_equal(
    a: StaticTuple[UInt64, _NL], b: StaticTuple[UInt64, _NL], k: Int
) -> Bool:
    var diff = UInt64(0)
    for i in range(k):
        diff |= a[i] ^ b[i]
    return diff == 0


struct _RsaExponentBlinding:
    var bytes: InlineArray[UInt8, 528]
    var length: Int

    def __init__(out self, key: RsaPublicKey, exponent: InlineArray[UInt8, 528]) raises:
        self.bytes = InlineArray[UInt8, 528](fill=0)
        self.length = key.nb + 16
        if self.length > 528 or key.k + 2 > _NL:
            raise Error("RSA CRT exponent blinding size unsupported")
        var random = random_bytes(16)
        var multiplier = _bn_zero()
        for i in range(16):
            multiplier[i >> 3] |= UInt64(random[i]) << UInt64(8 * (i & 7))
            random.unsafe_ptr().unsafe_store[volatile=True](i, UInt8(0))
        var one = _bn_zero()
        one[0] = 1
        var order, _ = _bn_sub_copy(key.n, one, key.k)
        var product = _bn_mul_parts(order, key.k, multiplier, 2)
        var carry = UInt64(0)
        for i in range(key.k + 2):
            var limb = UInt64(0)
            for j in range(8):
                var offset = i * 8 + j
                if offset < key.nb:
                    limb |= UInt64(exponent[key.nb - 1 - offset]) << UInt64(8 * j)
            var sum = UInt128(product[i]) + UInt128(limb) + UInt128(carry)
            product[i] = UInt64(sum)
            carry = UInt64(sum >> 64)
        for i in range(self.length):
            var offset = self.length - 1 - i
            self.bytes[i] = UInt8(product[offset >> 3] >> UInt64(8 * (offset & 7)))
        _wipe_bn(order, key.k)
        _wipe_bn(multiplier, 2)
        _wipe_bn(product, key.k + 2)

    def __deinit__(deinit self):
        for i in range(528):
            self.bytes.unsafe_ptr().unsafe_store[volatile=True](i, UInt8(0))


struct RsaCrtPrivateKey:
    """RSA CRT private key using two half-size exponentiations and Garner recombination."""
    var public: RsaPublicKey
    var p: RsaPublicKey
    var q: RsaPublicKey
    var dp: InlineArray[UInt8, 528]
    var dq: InlineArray[UInt8, 528]
    var qinv: StaticTuple[UInt64, _NL]

    def __init__(
        out self,
        modulus: Span[UInt8, ...], exponent: Span[UInt8, ...],
        prime1: Span[UInt8, ...], prime2: Span[UInt8, ...],
        exponent1: Span[UInt8, ...], exponent2: Span[UInt8, ...],
        coefficient: Span[UInt8, ...]
    ) raises:
        self.public = RsaPublicKey(modulus, exponent)
        if self.public.mod_bits < 2048:
            raise Error("RSA signing requires a modulus of at least 2048 bits")
        var three = InlineArray[UInt8, 1](fill=3)
        self.p = RsaPublicKey(prime1, Span[UInt8, ...](unsafe_ptr=three.unsafe_ptr(), length=1))
        self.q = RsaPublicKey(prime2, Span[UInt8, ...](unsafe_ptr=three.unsafe_ptr(), length=1))
        self.dp = InlineArray[UInt8, 528](fill=0)
        self.dq = InlineArray[UInt8, 528](fill=0)
        self.qinv = _bn_zero()
        if self.p.k + self.q.k > _NL:
            raise Error("RSA CRT factors are too large")

        var product = _bn_mul_parts(self.p.n, self.p.k, self.q.n, self.q.k)
        if not _bn_equal(product, self.public.n, _NL):
            _wipe_bn(product, _NL)
            raise Error("RSA CRT factors do not match the modulus")

        var dp_lead = 0
        while dp_lead < len(exponent1) and exponent1[dp_lead] == 0:
            dp_lead += 1
        var dq_lead = 0
        while dq_lead < len(exponent2) and exponent2[dq_lead] == 0:
            dq_lead += 1
        var dp_len = len(exponent1) - dp_lead
        var dq_len = len(exponent2) - dq_lead
        if dp_len == 0 or dp_len > self.p.nb or dq_len == 0 or dq_len > self.q.nb:
            raise Error("invalid RSA CRT exponent")
        for i in range(dp_len):
            self.dp[self.p.nb - dp_len + i] = exponent1[dp_lead + i]
        for i in range(dq_len):
            self.dq[self.q.nb - dq_len + i] = exponent2[dq_lead + i]
        var dp_bn = _bn_zero()
        var dq_bn = _bn_zero()
        for i in range(self.p.nb):
            dp_bn[i >> 3] |= UInt64(self.dp[self.p.nb - 1 - i]) << UInt64(8 * (i & 7))
        for i in range(self.q.nb):
            dq_bn[i >> 3] |= UInt64(self.dq[self.q.nb - 1 - i]) << UInt64(8 * (i & 7))
        var dp_ge_prime = _bn_ge_ct(dp_bn, self.p.n, self.p.k)
        var dq_ge_prime = _bn_ge_ct(dq_bn, self.q.n, self.q.k)
        if dp_ge_prime or dq_ge_prime:
            _wipe_bn(dp_bn, self.p.k)
            _wipe_bn(dq_bn, self.q.k)
            raise Error("RSA CRT exponent must be smaller than its prime")
        _wipe_bn(dp_bn, self.p.k)
        _wipe_bn(dq_bn, self.q.k)

        var qi_lead = 0
        while qi_lead < len(coefficient) and coefficient[qi_lead] == 0:
            qi_lead += 1
        var qi_len = len(coefficient) - qi_lead
        if qi_len == 0 or qi_len > self.p.nb:
            raise Error("invalid RSA CRT coefficient")
        for i in range(qi_len):
            var byte = UInt64(coefficient[qi_lead + qi_len - 1 - i])
            self.qinv[i >> 3] |= byte << UInt64(8 * (i & 7))
        if _bn_ge_ct(self.qinv, self.p.n, self.p.k):
            raise Error("RSA CRT coefficient must be smaller than prime1")

        var q_bytes = InlineArray[UInt8, 528](fill=0)
        for i in range(self.q.nb):
            var limb = self.q.n[(self.q.nb - 1 - i) >> 3]
            q_bytes[i] = UInt8((limb >> UInt64(8 * ((self.q.nb - 1 - i) & 7))) & 0xFF)
        var q_mod_p = _bn_reduce_bytes(
            Span[UInt8, ...](unsafe_ptr=q_bytes.unsafe_ptr(), length=self.q.nb), self.p
        )
        var check = _mont_mul(
            _mont_mul(q_mod_p, self.p.r2, self.p.n, self.p.n0, self.p.k),
            self.qinv, self.p.n, self.p.n0, self.p.k
        )
        var coefficient_diff = check[0] ^ UInt64(1)
        for i in range(1, self.p.k):
            coefficient_diff |= check[i]
        var qbp = q_bytes.unsafe_ptr()
        for i in range(self.q.nb):
            qbp.unsafe_store[volatile=True](i, UInt8(0))
        _wipe_bn(product, self.public.k)
        _wipe_bn(q_mod_p, self.p.k)
        _wipe_bn(check, self.p.k)
        if coefficient_diff != 0:
            raise Error("invalid RSA CRT coefficient")

    def __deinit__(deinit self):
        var dpp = self.dp.unsafe_ptr()
        var dqp = self.dq.unsafe_ptr()
        for i in range(528):
            dpp.unsafe_store[volatile=True](i, UInt8(0))
            dqp.unsafe_store[volatile=True](i, UInt8(0))
        _wipe_bn(self.qinv, self.p.k)
        _wipe_bn(self.p.n, self.p.k)
        _wipe_bn(self.p.rmod, self.p.k)
        _wipe_bn(self.p.r2, self.p.k)
        _wipe_bn(self.q.n, self.q.k)
        _wipe_bn(self.q.rmod, self.q.k)
        _wipe_bn(self.q.r2, self.q.k)
        self.p.n0 = 0
        self.q.n0 = 0

    def _private_op(
        self, encoded: Span[UInt8, ...],
        signature: Pointer[mut=True, UInt8, _, address_space=_]
    ) raises -> Bool:
        """Apply message and exponent blinding, exponentiate modulo p and q, and recombine with
        Garner. Wipe private-operation scratch before returning.
        """
        if len(encoded) != self.public.nb:
            return False
        # PSS encodings are already below n; decode and reject noncanonical inputs.
        var input = _bn_zero()
        for i in range(self.public.nb):
            input[i >> 3] |= UInt64(encoded[self.public.nb - 1 - i]) << UInt64(8 * (i & 7))
        if _bn_ge(input, self.public.n, self.public.k):
            _wipe_bn(input, self.public.k)
            return False
        var blinding = _RsaBlinding(self.public)
        var blinded = blinding.blind(input, self.public)
        var blinded_bytes = InlineArray[UInt8, 528](fill=0)
        for i in range(self.public.nb):
            blinded_bytes[i] = UInt8(blinded[(self.public.nb - 1 - i) >> 3] >> UInt64(8 * ((self.public.nb - 1 - i) & 7)))
        var blinded_span = Span[UInt8, ...](unsafe_ptr=blinded_bytes.unsafe_ptr(), length=self.public.nb)
        var mp = _bn_reduce_bytes(blinded_span, self.p)
        var mq = _bn_reduce_bytes(blinded_span, self.q)
        var dp = _RsaExponentBlinding(self.p, self.dp)
        var dq = _RsaExponentBlinding(self.q, self.dq)
        var m1 = _private_pow(self.p, dp.bytes, mp, dp.length)
        var m2 = _private_pow(self.q, dq.bytes, mq, dq.length)

        var m2_bytes = InlineArray[UInt8, 528](fill=0)
        for i in range(self.q.nb):
            var limb = m2[(self.q.nb - 1 - i) >> 3]
            m2_bytes[i] = UInt8((limb >> UInt64(8 * ((self.q.nb - 1 - i) & 7))) & 0xFF)
        var m2_mod_p = _bn_reduce_bytes(
            Span[UInt8, ...](unsafe_ptr=m2_bytes.unsafe_ptr(), length=self.q.nb), self.p
        )
        var h, borrow = _bn_sub_copy(m1, m2_mod_p, self.p.k)
        var h_plus_p = h
        var carry = UInt64(0)
        for i in range(self.p.k):
            var sum = UInt128(h[i]) + UInt128(self.p.n[i]) + UInt128(carry)
            h_plus_p[i] = sum.cast[DType.uint64]()
            carry = (sum >> 64).cast[DType.uint64]()
        h = _bn_select(h, h_plus_p, borrow, self.p.k)
        h = _mont_mul(
            _mont_mul(h, self.p.r2, self.p.n, self.p.n0, self.p.k),
            self.qinv, self.p.n, self.p.n0, self.p.k
        )

        var result = _bn_mul_parts(self.q.n, self.q.k, h, self.p.k)
        carry = 0
        for i in range(self.public.k):
            var addend = UInt64(0)
            if i < self.q.k:
                addend = m2[i]
            var sum = UInt128(result[i]) + UInt128(addend) + UInt128(carry)
            result[i] = sum.cast[DType.uint64]()
            carry = (sum >> 64).cast[DType.uint64]()
        result = blinding.unblind(result, self.public)
        for i in range(self.public.nb):
            var limb = result[(self.public.nb - 1 - i) >> 3]
            signature[unsafe_offset=i] = UInt8((limb >> UInt64(8 * ((self.public.nb - 1 - i) & 7))) & 0xFF)

        var recovered = InlineArray[UInt8, 528](fill=0)
        var valid = self.public._public_op(
            Span[UInt8, ...](unsafe_ptr=signature, length=self.public.nb), recovered.unsafe_ptr()
        )
        var diff = UInt8(0)
        for i in range(self.public.nb):
            diff |= recovered[i] ^ encoded[i]
        valid = valid and diff == 0
        if not valid:
            for i in range(self.public.nb):
                signature.unsafe_store[volatile=True](i, UInt8(0))

        _wipe_bn(input, self.public.k)
        _wipe_bn(blinded, self.public.k)
        for i in range(self.public.nb):
            blinded_bytes.unsafe_ptr().unsafe_store[volatile=True](i, UInt8(0))
        _wipe_bn(mp, self.p.k)
        _wipe_bn(mq, self.q.k)
        _wipe_bn(m1, self.p.k)
        _wipe_bn(m2, self.q.k)
        _wipe_bn(m2_mod_p, self.p.k)
        _wipe_bn(h, self.p.k)
        _wipe_bn(h_plus_p, self.p.k)
        _wipe_bn(result, self.public.k)
        var m2p = m2_bytes.unsafe_ptr()
        for i in range(self.q.nb):
            m2p.unsafe_store[volatile=True](i, UInt8(0))
        return valid

    def pss_sign_with_salt(
        self, message: Span[UInt8, ...], salt: Span[UInt8, ...],
        sha: Int, mgf_sha: Int,
        signature: Span[mut=True, UInt8, ...]
    ) raises -> Bool:
        if len(signature) < self.public.nb:
            return False
        var em_bits = self.public.mod_bits - 1
        var em_len = (em_bits + 7) // 8
        var encoded = InlineArray[UInt8, 528](fill=0)
        try:
            if not _emsa_pss_encode(
                message,
                salt,
                sha,
                mgf_sha,
                em_bits,
                encoded.unsafe_ptr().unsafe_offset(self.public.nb - em_len),
            ):
                return False
            return self._private_op(
                Span[UInt8, ...](
                    unsafe_ptr=encoded.unsafe_ptr(), length=self.public.nb
                ),
                signature.unsafe_ptr(),
            )
        finally:
            var ep = encoded.unsafe_ptr()
            for i in range(self.public.nb):
                ep.unsafe_store[volatile=True](i, UInt8(0))

    def pss_sign(
        self,
        message: Span[UInt8, ...],
        sha: Int,
        mgf_sha: Int,
        salt_len: Int
    ) raises -> List[UInt8]:
        if salt_len < 0:
            raise Error("RSA-PSS salt length must be non-negative")
        var h_len = _hash_len(sha)
        _ = _hash_len(mgf_sha)
        var em_len = (self.public.mod_bits + 6) // 8
        if em_len < h_len + 2 or salt_len > em_len - h_len - 2:
            raise Error("RSA-PSS salt is too long for the modulus")
        var salt = random_bytes(salt_len)
        try:
            var signature = List[UInt8](unsafe_uninit_length=self.public.nb)
            if not self.pss_sign_with_salt(
                message,
                Span[UInt8, ...](salt),
                sha,
                mgf_sha,
                Span[mut=True, UInt8, ...](signature)
            ):
                raise Error("RSA-PSS signing failed")
            return signature^
        finally:
            var salt_ptr = salt.unsafe_ptr()
            for i in range(len(salt)):
                salt_ptr.unsafe_store[volatile=True](i, UInt8(0))


def _pkcs1_v15_verify(
    key: RsaPublicKey,
    message: Span[UInt8, ...],
    signature: Span[UInt8, ...],
    sha: Int
) raises -> Bool:
    """Require exact EMSA-PKCS1-v1_5 padding and DigestInfo (RFC 8017, sec. 9.2)."""
    var h_len = _hash_len(sha)
    var prefix_len = _digest_info_prefix_len(sha)
    var t_len = prefix_len + h_len
    if key.nb < t_len + 11:
        return False

    var em = InlineArray[UInt8, 528](fill=0)
    if not key._public_op(signature, em.unsafe_ptr()):
        return False

    var ps_len = key.nb - t_len - 3
    var diff = em[0] | (em[1] ^ UInt8(1))
    for i in range(ps_len):
        diff |= em[2 + i] ^ UInt8(0xFF)
    diff |= em[2 + ps_len]

    var prefix = InlineArray[UInt8, 19](fill=0)
    _digest_info_prefix(sha, prefix.unsafe_ptr())
    for i in range(prefix_len):
        diff |= em[3 + ps_len + i] ^ prefix[i]

    var digest = InlineArray[UInt8, 64](fill=0)
    _ = _hash_into(sha, message, digest.unsafe_ptr())
    for i in range(h_len):
        diff |= em[3 + ps_len + prefix_len + i] ^ digest[i]
    return diff == 0


def rsa_pss_verify(
    modulus: Span[UInt8, ...],
    exponent: Span[UInt8, ...],
    message: Span[UInt8, ...],
    signature: Span[UInt8, ...],
    sha: Int,
    mgf_sha: Int,
    salt_len: Int
) raises -> Bool:
    """Verify an RSA-PSS signature with the selected hash, MGF1 hash, and salt length (RFC 8017,
    sec. 8.1.2).
    """
    var key: RsaPublicKey
    try:
        key = RsaPublicKey(modulus, exponent)
    except:
        return False
    return key.pss_verify(message, signature, sha, mgf_sha, salt_len)


def rsa_pss_sign_with_salt(
    modulus: Span[UInt8, ...],
    exponent: Span[UInt8, ...],
    private_exponent: Span[UInt8, ...],
    message: Span[UInt8, ...],
    salt: Span[UInt8, ...],
    sha: Int,
    mgf_sha: Int
) raises -> List[UInt8]:
    """Sign with RSA-PSS using caller-supplied salt and a blinded private operation (RFC 8017,
    sec. 8.1.1).
    """
    var key = RsaPrivateKey(modulus, exponent, private_exponent)
    var signature = List[UInt8](unsafe_uninit_length=key.public.nb)
    if not key.pss_sign_with_salt(
        message, salt, sha, mgf_sha, Span[mut=True, UInt8, ...](signature)
    ):
        raise Error("RSA-PSS signing failed")
    return signature^


def rsa_pss_sign(
    modulus: Span[UInt8, ...],
    exponent: Span[UInt8, ...],
    private_exponent: Span[UInt8, ...],
    message: Span[UInt8, ...],
    sha: Int,
    mgf_sha: Int,
    salt_len: Int
) raises -> List[UInt8]:
    """Sign with RSA-PSS using fresh random salt and a blinded private operation (RFC 8017, sec.
    8.1.1).
    """
    var key = RsaPrivateKey(modulus, exponent, private_exponent)
    return key.pss_sign(message, sha, mgf_sha, salt_len)


def rsa_pss_crt_sign_with_salt(
    modulus: Span[UInt8, ...], exponent: Span[UInt8, ...],
    prime1: Span[UInt8, ...], prime2: Span[UInt8, ...],
    exponent1: Span[UInt8, ...], exponent2: Span[UInt8, ...],
    coefficient: Span[UInt8, ...], message: Span[UInt8, ...],
    salt: Span[UInt8, ...], sha: Int, mgf_sha: Int
) raises -> List[UInt8]:
    """Sign with RSA-PSS using caller-supplied salt and a blinded CRT private operation (RFC
    8017, sec. 8.1.1).
    """
    var key = RsaCrtPrivateKey(
        modulus, exponent, prime1, prime2, exponent1, exponent2, coefficient
    )
    var signature = List[UInt8](unsafe_uninit_length=key.public.nb)
    if not key.pss_sign_with_salt(
        message, salt, sha, mgf_sha, Span[mut=True, UInt8, ...](signature)
    ):
        raise Error("RSA-PSS signing failed")
    return signature^


def rsa_pss_crt_sign(
    modulus: Span[UInt8, ...], exponent: Span[UInt8, ...],
    prime1: Span[UInt8, ...], prime2: Span[UInt8, ...],
    exponent1: Span[UInt8, ...], exponent2: Span[UInt8, ...],
    coefficient: Span[UInt8, ...], message: Span[UInt8, ...],
    sha: Int, mgf_sha: Int, salt_len: Int
) raises -> List[UInt8]:
    """Sign with RSA-PSS using fresh random salt and a blinded CRT private operation (RFC 8017,
    sec. 8.1.1).
    """
    var key = RsaCrtPrivateKey(
        modulus, exponent, prime1, prime2, exponent1, exponent2, coefficient
    )
    return key.pss_sign(message, sha, mgf_sha, salt_len)


def rsa_pss_sha256_sign(
    modulus: Span[UInt8, ...], exponent: Span[UInt8, ...],
    private_exponent: Span[UInt8, ...], message: Span[UInt8, ...]
) raises -> List[UInt8]:
    """Sign with RSA-PSS/SHA-256 and a fresh 32-byte salt (RFC 8017, sec. 8.1.1)."""
    return rsa_pss_sign(modulus, exponent, private_exponent, message, SHA256, SHA256, 32)


def rsa_pss_sha384_sign(
    modulus: Span[UInt8, ...], exponent: Span[UInt8, ...],
    private_exponent: Span[UInt8, ...], message: Span[UInt8, ...]
) raises -> List[UInt8]:
    """Sign with RSA-PSS/SHA-384 and a fresh 48-byte salt (RFC 8017, sec. 8.1.1)."""
    return rsa_pss_sign(modulus, exponent, private_exponent, message, SHA384, SHA384, 48)


def rsa_pss_sha512_sign(
    modulus: Span[UInt8, ...], exponent: Span[UInt8, ...],
    private_exponent: Span[UInt8, ...], message: Span[UInt8, ...]
) raises -> List[UInt8]:
    """Sign with RSA-PSS/SHA-512 and a fresh 64-byte salt (RFC 8017, sec. 8.1.1)."""
    return rsa_pss_sign(modulus, exponent, private_exponent, message, SHA512, SHA512, 64)


def rsa_pss_crt_sha256_sign(
    modulus: Span[UInt8, ...], exponent: Span[UInt8, ...],
    prime1: Span[UInt8, ...], prime2: Span[UInt8, ...],
    exponent1: Span[UInt8, ...], exponent2: Span[UInt8, ...],
    coefficient: Span[UInt8, ...], message: Span[UInt8, ...]
) raises -> List[UInt8]:
    """Sign with RSA-PSS/SHA-256 and a fresh 32-byte salt using CRT (RFC 8017, sec. 8.1.1)."""
    return rsa_pss_crt_sign(
        modulus, exponent, prime1, prime2, exponent1, exponent2,
        coefficient, message, SHA256, SHA256, 32
    )


def rsa_pss_crt_sha384_sign(
    modulus: Span[UInt8, ...], exponent: Span[UInt8, ...],
    prime1: Span[UInt8, ...], prime2: Span[UInt8, ...],
    exponent1: Span[UInt8, ...], exponent2: Span[UInt8, ...],
    coefficient: Span[UInt8, ...], message: Span[UInt8, ...]
) raises -> List[UInt8]:
    """Sign with RSA-PSS/SHA-384 and a fresh 48-byte salt using CRT (RFC 8017, sec. 8.1.1)."""
    return rsa_pss_crt_sign(
        modulus, exponent, prime1, prime2, exponent1, exponent2,
        coefficient, message, SHA384, SHA384, 48
    )


def rsa_pss_crt_sha512_sign(
    modulus: Span[UInt8, ...], exponent: Span[UInt8, ...],
    prime1: Span[UInt8, ...], prime2: Span[UInt8, ...],
    exponent1: Span[UInt8, ...], exponent2: Span[UInt8, ...],
    coefficient: Span[UInt8, ...], message: Span[UInt8, ...]
) raises -> List[UInt8]:
    """Sign with RSA-PSS/SHA-512 and a fresh 64-byte salt using CRT (RFC 8017, sec. 8.1.1)."""
    return rsa_pss_crt_sign(
        modulus, exponent, prime1, prime2, exponent1, exponent2,
        coefficient, message, SHA512, SHA512, 64
    )


def rsa_pss_sha256_verify(
    modulus: Span[UInt8, ...],
    exponent: Span[UInt8, ...],
    message: Span[UInt8, ...],
    signature: Span[UInt8, ...]
) raises -> Bool:
    """Verify RSA-PSS/SHA-256 with a 32-byte salt (RFC 8017, sec. 8.1.2)."""
    return rsa_pss_verify(modulus, exponent, message, signature, SHA256, SHA256, 32)


def rsa_pss_sha384_verify(
    modulus: Span[UInt8, ...],
    exponent: Span[UInt8, ...],
    message: Span[UInt8, ...],
    signature: Span[UInt8, ...]
) raises -> Bool:
    """Verify RSA-PSS/SHA-384 with a 48-byte salt (RFC 8017, sec. 8.1.2)."""
    return rsa_pss_verify(modulus, exponent, message, signature, SHA384, SHA384, 48)


def rsa_pss_sha512_verify(
    modulus: Span[UInt8, ...],
    exponent: Span[UInt8, ...],
    message: Span[UInt8, ...],
    signature: Span[UInt8, ...]
) raises -> Bool:
    """Verify RSA-PSS/SHA-512 with a 64-byte salt (RFC 8017, sec. 8.1.2)."""
    return rsa_pss_verify(modulus, exponent, message, signature, SHA512, SHA512, 64)


def rsa_pkcs1_v15_verify(
    modulus: Span[UInt8, ...],
    exponent: Span[UInt8, ...],
    message: Span[UInt8, ...],
    signature: Span[UInt8, ...],
    sha: Int
) raises -> Bool:
    """Verify PKCS #1 v1.5 signatures, requiring the selected DigestInfo prefix and exact padding
    (RFC 8017, secs. 8.2.2 and 9.2).
    """
    var key: RsaPublicKey
    try:
        key = RsaPublicKey(modulus, exponent)
    except:
        return False
    return _pkcs1_v15_verify(key, message, signature, sha)


def rsa_pkcs1_v15_sha1_verify(
    modulus: Span[UInt8, ...], exponent: Span[UInt8, ...],
    message: Span[UInt8, ...], signature: Span[UInt8, ...]
) raises -> Bool:
    """Verify a PKCS #1 v1.5 signature with SHA-1 (RFC 8017, sec. 8.2.2)."""
    return rsa_pkcs1_v15_verify(modulus, exponent, message, signature, SHA1)


def rsa_pkcs1_v15_sha256_verify(
    modulus: Span[UInt8, ...], exponent: Span[UInt8, ...],
    message: Span[UInt8, ...], signature: Span[UInt8, ...]
) raises -> Bool:
    """Verify a PKCS #1 v1.5 signature with SHA-256 (RFC 8017, sec. 8.2.2)."""
    return rsa_pkcs1_v15_verify(modulus, exponent, message, signature, SHA256)


def rsa_pkcs1_v15_sha384_verify(
    modulus: Span[UInt8, ...], exponent: Span[UInt8, ...],
    message: Span[UInt8, ...], signature: Span[UInt8, ...]
) raises -> Bool:
    """Verify a PKCS #1 v1.5 signature with SHA-384 (RFC 8017, sec. 8.2.2)."""
    return rsa_pkcs1_v15_verify(modulus, exponent, message, signature, SHA384)


def rsa_pkcs1_v15_sha512_verify(
    modulus: Span[UInt8, ...], exponent: Span[UInt8, ...],
    message: Span[UInt8, ...], signature: Span[UInt8, ...]
) raises -> Bool:
    """Verify a PKCS #1 v1.5 signature with SHA-512 (RFC 8017, sec. 8.2.2)."""
    return rsa_pkcs1_v15_verify(modulus, exponent, message, signature, SHA512)
