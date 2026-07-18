"""
RSASSA-PSS signature verification per RFC 8017
"""

from std.collections import List, InlineArray
from std.memory import UnsafePointer
from std.bit import rotate_bits_left, count_leading_zeros
from .sha2 import (
    sha224_hash, sha256_hash, sha384_hash, sha512_hash,
    SHA256Context, sha256_update, sha256_final_to_buffer,
    SHA512Context, sha512_update, sha512_final_to_buffer,
)

comptime _NL = 66
comptime SHA1: Int = 1
comptime SHA224: Int = 224
comptime SHA256: Int = 256
comptime SHA384: Int = 384
comptime SHA512: Int = 512


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

    var w = InlineArray[UInt32, 80](uninitialized=True)
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

    var out = InlineArray[UInt8, 20](uninitialized=True)
    var hs = InlineArray[UInt32, 5](uninitialized=True)
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
    return out


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


def _hash_into(alg: Int, data: Span[UInt8, ...], output: UnsafePointer[UInt8, MutAnyOrigin]) raises -> Int:
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
            output[i] = d1[i]
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
        output[i] = d[i]
    return len(d)


@always_inline
def _bn_ge(a: InlineArray[UInt64, _NL], b: InlineArray[UInt64, _NL], k: Int) -> Bool:
    for i in range(k - 1, -1, -1):
        if a[i] > b[i]:
            return True
        if a[i] < b[i]:
            return False
    return True


@always_inline
def _bn_sub(mut a: InlineArray[UInt64, _NL], b: InlineArray[UInt64, _NL], k: Int):
    var borrow: UInt64 = 0
    for i in range(k):
        var d = (UInt128(1) << 64) + UInt128(a[i]) - UInt128(b[i]) - UInt128(borrow)
        a[i] = d.cast[DType.uint64]()
        borrow = 1 - (d >> 64).cast[DType.uint64]()


@always_inline
def _bn_dbl_mod(mut a: InlineArray[UInt64, _NL], n: InlineArray[UInt64, _NL], k: Int):
    var carry: UInt64 = 0
    for i in range(k):
        var v = a[i]
        a[i] = (v << 1) | carry
        carry = v >> 63
    if carry != 0 or _bn_ge(a, n, k):
        _bn_sub(a, n, k)


@always_inline
def _mont_mul_k[K: Int](
    a: InlineArray[UInt64, _NL],
    b: InlineArray[UInt64, _NL],
    n: InlineArray[UInt64, _NL],
    n0: UInt64,
) -> InlineArray[UInt64, _NL]:
    var t = InlineArray[UInt64, _NL](uninitialized=True)
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
    if t_hi != 0 or _bn_ge(t, n, K):
        _bn_sub(t, n, K)
    return t


def _mont_mul_any(
    a: InlineArray[UInt64, _NL],
    b: InlineArray[UInt64, _NL],
    n: InlineArray[UInt64, _NL],
    n0: UInt64,
    k: Int,
) -> InlineArray[UInt64, _NL]:
    var t = InlineArray[UInt64, _NL](fill=0)
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
    if t_hi != 0 or _bn_ge(t, n, k):
        _bn_sub(t, n, k)
    return t


@always_inline
def _mont_sqr_k[K: Int](
    a: InlineArray[UInt64, _NL],
    n: InlineArray[UInt64, _NL],
    n0: UInt64,
) -> InlineArray[UInt64, _NL]:
    var t = InlineArray[UInt64, 2 * _NL + 2](uninitialized=True)
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

    var out = InlineArray[UInt64, _NL](uninitialized=True)
    comptime for i in range(K):
        out[i] = t[K + i]
    if t[2 * K] + ehold != 0 or _bn_ge(out, n, K):
        _bn_sub(out, n, K)
    return out


@always_inline
def _mont_sqr(
    a: InlineArray[UInt64, _NL],
    n: InlineArray[UInt64, _NL],
    n0: UInt64,
    k: Int,
) -> InlineArray[UInt64, _NL]:
    if k == 32:
        return _mont_sqr_k[32](a, n, n0)
    if k == 48:
        return _mont_sqr_k[48](a, n, n0)
    if k == 64:
        return _mont_mul_k[64](a, a, n, n0)
    return _mont_mul_any(a, a, n, n0, k)


@always_inline
def _mont_mul(
    a: InlineArray[UInt64, _NL],
    b: InlineArray[UInt64, _NL],
    n: InlineArray[UInt64, _NL],
    n0: UInt64,
    k: Int,
) -> InlineArray[UInt64, _NL]:
    if k == 32:
        return _mont_mul_k[32](a, b, n, n0)
    if k == 48:
        return _mont_mul_k[48](a, b, n, n0)
    if k == 64:
        return _mont_mul_k[64](a, b, n, n0)
    return _mont_mul_any(a, b, n, n0, k)


struct RsaPublicKey:
    var n: InlineArray[UInt64, _NL]
    var k: Int
    var nb: Int
    var mod_bits: Int
    var n0: UInt64
    var rmod: InlineArray[UInt64, _NL]
    var r2: InlineArray[UInt64, _NL]
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

        self.n = InlineArray[UInt64, _NL](fill=0)
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

        self.rmod = InlineArray[UInt64, _NL](fill=0)
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
        output: UnsafePointer[UInt8, MutAnyOrigin],
    ) raises -> Bool:
        var nb = self.nb
        var k = self.k
        if len(sig) != nb:
            return False
        var s = InlineArray[UInt64, _NL](fill=0)
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

        var one = InlineArray[UInt64, _NL](fill=0)
        one[0] = 1
        var m = _mont_mul(acc, one, self.n, self.n0, k)
        for i in range(nb):
            var limb = m[(nb - 1 - i) >> 3]
            output[i] = UInt8((limb >> UInt64(8 * ((nb - 1 - i) & 7))) & 0xFF)
        return True

    def pss_verify(
        self,
        message: Span[UInt8, ...],
        signature: Span[UInt8, ...],
        sha: Int,
        mgf_sha: Int,
        salt_len: Int,
    ) raises -> Bool:
        var h_len = _hash_len(sha)
        _ = _hash_len(mgf_sha)
        if salt_len < 0:
            return False

        var nb = self.nb
        var em_bits = self.mod_bits - 1
        var em_len = (em_bits + 7) // 8

        var em = InlineArray[UInt8, 528](uninitialized=True)
        if not self._public_op(signature, em.unsafe_ptr()):
            return False
        for i in range(nb - em_len):
            if em[i] != 0:
                return False
        var ep = em.unsafe_ptr() + (nb - em_len)

        if em_len < h_len + salt_len + 2:
            return False
        if ep[em_len - 1] != 0xBC:
            return False

        var db_len = em_len - h_len - 1
        var h_ptr = ep + db_len

        var top_mask = UInt8(0xFF) >> UInt8(8 * em_len - em_bits)
        if (ep[0] & ~top_mask) != 0:
            return False

        var db_mask = InlineArray[UInt8, 528](uninitialized=True)
        _mgf1(mgf_sha, h_ptr, h_len, db_len, db_mask.unsafe_ptr())
        var db = InlineArray[UInt8, 528](uninitialized=True)
        for i in range(db_len):
            db[i] = ep[i] ^ db_mask[i]
        db[0] &= top_mask

        var ps_len = db_len - salt_len - 1
        for i in range(ps_len):
            if db[i] != 0:
                return False
        if db[ps_len] != 0x01:
            return False

        var m_hash = InlineArray[UInt8, 64](uninitialized=True)
        _ = _hash_into(sha, message, m_hash.unsafe_ptr())

        var mprime = InlineArray[UInt8, 534](uninitialized=True)
        for i in range(8):
            mprime[i] = 0
        for i in range(h_len):
            mprime[8 + i] = m_hash[i]
        for i in range(salt_len):
            mprime[8 + h_len + i] = db[ps_len + 1 + i]
        var h2 = InlineArray[UInt8, 64](uninitialized=True)
        _ = _hash_into(
            sha,
            Span[UInt8, ...](ptr=mprime.unsafe_ptr(), length=8 + h_len + salt_len),
            h2.unsafe_ptr(),
        )

        var diff: UInt8 = 0
        for i in range(h_len):
            diff |= h2[i] ^ h_ptr[i]
        return diff == 0


def _mgf1(
    alg: Int,
    seed: UnsafePointer[UInt8, _],
    seed_len: Int,
    mask_len: Int,
    output: UnsafePointer[UInt8, MutAnyOrigin],
) raises:
    var h_len = _hash_len(alg)
    var block = InlineArray[UInt8, 128](fill=0)
    var digest = InlineArray[UInt8, 64](fill=0)
    for i in range(seed_len):
        block[i] = seed[i]
    var done = 0
    var counter: UInt32 = 0
    while done < mask_len:
        block[seed_len] = UInt8((counter >> 24) & 0xFF)
        block[seed_len + 1] = UInt8((counter >> 16) & 0xFF)
        block[seed_len + 2] = UInt8((counter >> 8) & 0xFF)
        block[seed_len + 3] = UInt8(counter & 0xFF)
        _ = _hash_into(
            alg,
            Span[UInt8, ...](ptr=block.unsafe_ptr(), length=seed_len + 4),
            digest.unsafe_ptr(),
        )
        var take = mask_len - done
        if take > h_len:
            take = h_len
        for i in range(take):
            output[done + i] = digest[i]
        done += take
        counter += 1


def rsa_pss_verify(
    modulus: Span[UInt8, ...],
    exponent: Span[UInt8, ...],
    message: Span[UInt8, ...],
    signature: Span[UInt8, ...],
    sha: Int,
    mgf_sha: Int,
    salt_len: Int,
) raises -> Bool:
    var key: RsaPublicKey
    try:
        key = RsaPublicKey(modulus, exponent)
    except:
        return False
    return key.pss_verify(message, signature, sha, mgf_sha, salt_len)


def rsa_pss_sha256_verify(
    modulus: Span[UInt8, ...],
    exponent: Span[UInt8, ...],
    message: Span[UInt8, ...],
    signature: Span[UInt8, ...],
) raises -> Bool:
    return rsa_pss_verify(modulus, exponent, message, signature, SHA256, SHA256, 32)


def rsa_pss_sha384_verify(
    modulus: Span[UInt8, ...],
    exponent: Span[UInt8, ...],
    message: Span[UInt8, ...],
    signature: Span[UInt8, ...],
) raises -> Bool:
    return rsa_pss_verify(modulus, exponent, message, signature, SHA384, SHA384, 48)


def rsa_pss_sha512_verify(
    modulus: Span[UInt8, ...],
    exponent: Span[UInt8, ...],
    message: Span[UInt8, ...],
    signature: Span[UInt8, ...],
) raises -> Bool:
    return rsa_pss_verify(modulus, exponent, message, signature, SHA512, SHA512, 64)
