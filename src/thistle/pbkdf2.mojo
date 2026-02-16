# SPDX-License-Identifier: MIT
#
# Copyright (c) 2026 Libalpm64, Lostlab Technologies.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


"""
PBKDF2 (Password-Based Key Derivation Function 2) Implementation in Mojo
SP 800-132 / FIPS 140-2 / RFC 8018
By Libalpm no attribution required
"""

from collections import List
from memory import UnsafePointer
from .sha2 import SHA256Context, sha256_update, sha256_final
from .sha2 import SHA512Context, sha512_update, sha512_final


fn hmac_sha256(key: Span[UInt8], data: Span[UInt8]) -> List[UInt8]:
    """
    Computes HMAC-SHA-256.
    """
    var k = List[UInt8]()
    if len(key) > 64:
        # Key too long, hash it
        var ctx = SHA256Context()
        sha256_update(ctx, key)
        k = sha256_final(ctx)
    else:
        # Copy key
        for i in range(len(key)):
            k.append(key[i])

    # Pad key with zeros if short
    while len(k) < 64:
        k.append(0)

    var ipad = List[UInt8](capacity=64)
    var opad = List[UInt8](capacity=64)

    for i in range(64):
        ipad.append(k[i] ^ 0x36)
        opad.append(k[i] ^ 0x5C)

    # Inner hash: H(ipad || data)
    var inner_ctx = SHA256Context()
    sha256_update(
        inner_ctx, Span[UInt8](ptr=ipad.unsafe_ptr(), length=len(ipad))
    )
    sha256_update(inner_ctx, data)
    var inner_hash = sha256_final(inner_ctx)

    # Outer hash: H(opad || inner_hash)
    var outer_ctx = SHA256Context()
    sha256_update(
        outer_ctx, Span[UInt8](ptr=opad.unsafe_ptr(), length=len(opad))
    )
    sha256_update(
        outer_ctx,
        Span[UInt8](ptr=inner_hash.unsafe_ptr(), length=len(inner_hash)),
    )
    return sha256_final(outer_ctx)


fn pbkdf2_hmac_sha256(
    password: Span[UInt8], salt: Span[UInt8], iterations: Int, dkLen: Int
) -> List[UInt8]:
    """
    Derives a key using PBKDF2 with HMAC-SHA-256.

    Args:
        password: The master password.
        salt: A salt value (recommended at least 64 bits/8 bytes).
        iterations: Iteration count (e.g., 1000, 10000).
        dkLen: Desired length of the derived key in bytes.

    Returns:
        The derived key as a List[UInt8].
    """
    # Prep HMAC key (password) pads
    var k = List[UInt8]()
    if len(password) > 64:
        var ctx = SHA256Context()
        sha256_update(ctx, password)
        k = sha256_final(ctx)
    else:
        for i in range(len(password)):
            k.append(password[i])
    while len(k) < 64:
        k.append(0)

    var ipad = List[UInt8](capacity=64)
    var opad = List[UInt8](capacity=64)
    for i in range(64):
        ipad.append(k[i] ^ 0x36)
        opad.append(k[i] ^ 0x5C)

    var derived_key = List[UInt8](capacity=dkLen)
    var hLen = 32
    var l = (dkLen + hLen - 1) // hLen

    for i in range(1, l + 1):
        # T_i calculation
        # U_1 = PRF(P, S || INT(i))
        var u_block: List[UInt8]

        # Inner U_1
        var ctx_in = SHA256Context()
        sha256_update(ctx_in, Span[UInt8](ipad))
        sha256_update(ctx_in, salt)
        # Append INT(i) - 4 bytes Big Endian
        var block_idx_bytes = List[UInt8](capacity=4)
        block_idx_bytes.append(UInt8((i >> 24) & 0xFF))
        block_idx_bytes.append(UInt8((i >> 16) & 0xFF))
        block_idx_bytes.append(UInt8((i >> 8) & 0xFF))
        block_idx_bytes.append(UInt8(i & 0xFF))
        sha256_update(ctx_in, Span[UInt8](block_idx_bytes))
        var inner_hash = sha256_final(ctx_in)

        # Outer U_1
        var ctx_out = SHA256Context()
        sha256_update(ctx_out, Span[UInt8](opad))
        sha256_update(ctx_out, Span[UInt8](inner_hash))
        u_block = sha256_final(ctx_out)

        # F = U_1
        var f_block = List[UInt8](capacity=32)
        for b in range(32):
            f_block.append(u_block[b])

        # U_2 ... U_c
        for _ in range(1, iterations):
            # HMAC(P, u_block)
            # Inner
            var ctx_in2 = SHA256Context()
            sha256_update(ctx_in2, Span[UInt8](ipad))
            sha256_update(ctx_in2, Span[UInt8](u_block))
            var inner_hash2 = sha256_final(ctx_in2)

            # Outer
            var ctx_out2 = SHA256Context()
            sha256_update(ctx_out2, Span[UInt8](opad))
            sha256_update(ctx_out2, Span[UInt8](inner_hash2))
            u_block = sha256_final(ctx_out2)

            # F ^ U
            for b in range(32):
                f_block[b] ^= u_block[b]

        # Append T_i to DK
        for b in range(len(f_block)):
            if len(derived_key) < dkLen:
                derived_key.append(f_block[b])

    return derived_key^


fn hmac_sha512(key: Span[UInt8], data: Span[UInt8]) -> List[UInt8]:
    """
    Computes HMAC-SHA-512.
    """
    var k = List[UInt8]()
    if len(key) > 128:
        # Key too long, hash it
        var ctx = SHA512Context()
        sha512_update(ctx, key)
        k = sha512_final(ctx)
    else:
        # Copy key
        for i in range(len(key)):
            k.append(key[i])

    # Pad key with zeros if short
    while len(k) < 128:
        k.append(0)

    var ipad = List[UInt8](capacity=128)
    var opad = List[UInt8](capacity=128)

    for i in range(128):
        ipad.append(k[i] ^ 0x36)
        opad.append(k[i] ^ 0x5C)

    # Inner hash: H(ipad || data)
    var inner_ctx = SHA512Context()
    sha512_update(inner_ctx, Span[UInt8](ipad))
    sha512_update(inner_ctx, data)
    var inner_hash = sha512_final(inner_ctx)

    # Outer hash: H(opad || inner_hash)
    var outer_ctx = SHA512Context()
    sha512_update(outer_ctx, Span[UInt8](opad))
    sha512_update(outer_ctx, Span[UInt8](inner_hash))
    return sha512_final(outer_ctx)


fn pbkdf2_hmac_sha512(
    password: Span[UInt8], salt: Span[UInt8], iterations: Int, dkLen: Int
) -> List[UInt8]:
    """
    Derives a key using PBKDF2 with HMAC-SHA-512.
    """
    # 1. Prepare HMAC key (password) pads
    var k = List[UInt8]()
    if len(password) > 128:
        var ctx = SHA512Context()
        sha512_update(ctx, password)
        k = sha512_final(ctx)
    else:
        for i in range(len(password)):
            k.append(password[i])
    while len(k) < 128:
        k.append(0)

    var ipad = List[UInt8](capacity=128)
    var opad = List[UInt8](capacity=128)
    for i in range(128):
        ipad.append(k[i] ^ 0x36)
        opad.append(k[i] ^ 0x5C)

    var derived_key = List[UInt8](capacity=dkLen)
    var hLen = 64
    var l = (dkLen + hLen - 1) // hLen

    for i in range(1, l + 1):
        # T_i calculation
        # U_1 = PRF(P, S || INT(i))
        var u_block: List[UInt8]

        # Inner U_1
        var ctx_in = SHA512Context()
        sha512_update(ctx_in, Span[UInt8](ipad))
        sha512_update(ctx_in, salt)
        # Append INT(i) - 4 bytes Big Endian
        var block_idx_bytes = List[UInt8](capacity=4)
        block_idx_bytes.append(UInt8((i >> 24) & 0xFF))
        block_idx_bytes.append(UInt8((i >> 16) & 0xFF))
        block_idx_bytes.append(UInt8((i >> 8) & 0xFF))
        block_idx_bytes.append(UInt8(i & 0xFF))
        sha512_update(ctx_in, Span[UInt8](block_idx_bytes))
        var inner_hash = sha512_final(ctx_in)

        # Outer U_1
        var ctx_out = SHA512Context()
        sha512_update(ctx_out, Span[UInt8](opad))
        sha512_update(ctx_out, Span[UInt8](inner_hash))
        u_block = sha512_final(ctx_out)

        # F = U_1
        var f_block = List[UInt8](capacity=64)
        for b in range(64):
            f_block.append(u_block[b])

        # U_2 ... U_c
        for _ in range(1, iterations):
            # HMAC(P, u_block)
            # Inner
            var ctx_in2 = SHA512Context()
            sha512_update(ctx_in2, Span[UInt8](ipad))
            sha512_update(ctx_in2, Span[UInt8](u_block))
            var inner_hash2 = sha512_final(ctx_in2)

            # Outer
            var ctx_out2 = SHA512Context()
            sha512_update(ctx_out2, Span[UInt8](opad))
            sha512_update(ctx_out2, Span[UInt8](inner_hash2))
            u_block = sha512_final(ctx_out2)

            # F ^ U
            for b in range(64):
                f_block[b] ^= u_block[b]

        # Append T_i to DK
        for b in range(len(f_block)):
            if len(derived_key) < dkLen:
                derived_key.append(f_block[b])

    return derived_key^
