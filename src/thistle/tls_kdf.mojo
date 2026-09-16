"""TLS 1.2 PRF and TLS 1.3 HKDF helpers."""

from std.collections import List
from std.memory import Pointer
from std.utils import StaticTuple

from .pbkdf2 import HMACSHA256State, HMACSHA384State
from .sha2 import (
    SHA256Context, SHA512Context,
    sha256_update, sha256_final_to_buffer,
    sha512_update, sha512_final_to_buffer,
)
from .utils import StackBuffer, volatile_wipe


comptime _SHA256_LEN = 32
comptime _SHA256_BLOCK = 64
comptime _SHA384_LEN = 48
comptime _SHA384_BLOCK = 128
comptime _HKDF_SHA256_MAX = 255 * _SHA256_LEN
comptime _TLS13_LABEL_PREFIX_LEN = 6
comptime _TLS13_HKDF_LABEL_MAX = 514
comptime _TLS13_LABEL_PREFIX = StaticTuple[UInt8, 6](0x74, 0x6C, 0x73, 0x31, 0x33, 0x20)


@always_inline
def _hmac_sha256_parts(
    ref hmac: HMACSHA256State, first: Span[UInt8, ...], second: Span[UInt8, ...],
    output: Pointer[mut=True, UInt8, _, address_space=_],
):
    var inner_hash = SHA256Context(hmac.inner_state)
    inner_hash.count = UInt64(_SHA256_BLOCK * 8)
    sha256_update(inner_hash, first)
    sha256_update(inner_hash, second)
    var inner_digest = StackBuffer[UInt8, _SHA256_LEN](fill=0)
    sha256_final_to_buffer(inner_hash, inner_digest.ptr())

    var outer_hash = SHA256Context(hmac.outer_state)
    outer_hash.count = UInt64(_SHA256_BLOCK * 8)
    sha256_update(
        outer_hash,
        Span[UInt8, ...](unsafe_ptr=inner_digest.ptr(), length=_SHA256_LEN),
    )
    sha256_final_to_buffer(outer_hash, output)
    volatile_wipe(inner_digest.ptr(), _SHA256_LEN)


@always_inline
def _hmac_sha256_parts(
    ref hmac: HMACSHA256State, first: Span[UInt8, ...], second: Span[UInt8, ...],
    third: Span[UInt8, ...],
    output: Pointer[mut=True, UInt8, _, address_space=_],
):
    var inner_hash = SHA256Context(hmac.inner_state)
    inner_hash.count = UInt64(_SHA256_BLOCK * 8)
    sha256_update(inner_hash, first)
    sha256_update(inner_hash, second)
    sha256_update(inner_hash, third)
    var inner_digest = StackBuffer[UInt8, _SHA256_LEN](fill=0)
    sha256_final_to_buffer(inner_hash, inner_digest.ptr())

    var outer_hash = SHA256Context(hmac.outer_state)
    outer_hash.count = UInt64(_SHA256_BLOCK * 8)
    sha256_update(
        outer_hash,
        Span[UInt8, ...](unsafe_ptr=inner_digest.ptr(), length=_SHA256_LEN),
    )
    sha256_final_to_buffer(outer_hash, output)
    volatile_wipe(inner_digest.ptr(), _SHA256_LEN)


@always_inline
def _hmac_sha384_parts(
    ref hmac: HMACSHA384State, first: Span[UInt8, ...], second: Span[UInt8, ...],
    output: Pointer[mut=True, UInt8, _, address_space=_],
):
    var digest_buffer = StackBuffer[UInt8, 64](fill=0)
    var inner_hash = SHA512Context(hmac.inner_state)
    inner_hash.count_low = UInt64(_SHA384_BLOCK * 8)
    sha512_update(inner_hash, first)
    sha512_update(inner_hash, second)
    sha512_final_to_buffer(inner_hash, digest_buffer.ptr())

    var outer_hash = SHA512Context(hmac.outer_state)
    outer_hash.count_low = UInt64(_SHA384_BLOCK * 8)
    sha512_update(
        outer_hash,
        Span[UInt8, ...](unsafe_ptr=digest_buffer.ptr(), length=_SHA384_LEN),
    )
    sha512_final_to_buffer(outer_hash, digest_buffer.ptr())
    for i in range(_SHA384_LEN):
        output.unsafe_store(i, digest_buffer[i])
    volatile_wipe(digest_buffer.ptr(), 64)


@always_inline
def _hmac_sha384_parts(
    ref hmac: HMACSHA384State, first: Span[UInt8, ...], second: Span[UInt8, ...],
    third: Span[UInt8, ...],
    output: Pointer[mut=True, UInt8, _, address_space=_],
):
    var digest_buffer = StackBuffer[UInt8, 64](fill=0)
    var inner_hash = SHA512Context(hmac.inner_state)
    inner_hash.count_low = UInt64(_SHA384_BLOCK * 8)
    sha512_update(inner_hash, first)
    sha512_update(inner_hash, second)
    sha512_update(inner_hash, third)
    sha512_final_to_buffer(inner_hash, digest_buffer.ptr())

    var outer_hash = SHA512Context(hmac.outer_state)
    outer_hash.count_low = UInt64(_SHA384_BLOCK * 8)
    sha512_update(
        outer_hash,
        Span[UInt8, ...](unsafe_ptr=digest_buffer.ptr(), length=_SHA384_LEN),
    )
    sha512_final_to_buffer(outer_hash, digest_buffer.ptr())
    for i in range(_SHA384_LEN):
        output.unsafe_store(i, digest_buffer[i])
    volatile_wipe(digest_buffer.ptr(), 64)


@always_inline
def _hkdf_extract_sha256(
    salt: Span[UInt8, ...], ikm: Span[UInt8, ...], output: Pointer[mut=True, UInt8, _, address_space=_]
):
    var hmac = HMACSHA256State(salt)
    hmac.hmac_into(ikm, output)


def hkdf_extract_sha256_into(
    salt: Span[UInt8, ...], ikm: Span[UInt8, ...], output: Span[mut=True, UInt8, ...]
) raises:
    """Write the 32-byte HKDF-Extract/SHA-256 PRK (RFC 5869, sec. 2.2)."""
    if len(output) < _SHA256_LEN:
        raise Error("HKDF-SHA256 extract output needs at least 32 bytes")
    _hkdf_extract_sha256(salt, ikm, output.unsafe_ptr())


def hkdf_extract_sha256(
    salt: Span[UInt8, ...], ikm: Span[UInt8, ...]
) -> List[UInt8]:
    """HKDF-Extract with SHA-256 (RFC 5869, sec. 2.2)."""
    var prk = List[UInt8](unsafe_uninit_length=_SHA256_LEN)
    _hkdf_extract_sha256(salt, ikm, prk.unsafe_ptr())
    return prk^


def hkdf_expand_sha256_into(
    prk: Span[UInt8, ...], info: Span[UInt8, ...], output: Span[mut=True, UInt8, ...]
) raises:
    """Write HKDF-Expand/SHA-256 output; output must not alias prk/info (RFC 5869, sec. 2.3)."""
    if len(prk) < _SHA256_LEN:
        raise Error("HKDF-SHA256 PRK must be at least 32 bytes")
    var length = len(output)
    if length > _HKDF_SHA256_MAX:
        raise Error("HKDF-SHA256 output length must not exceed 8160 bytes")
    if length == 0:
        return

    var hmac = HMACSHA256State(prk)
    var previous = StackBuffer[UInt8, _SHA256_LEN](fill=0)
    var block = StackBuffer[UInt8, _SHA256_LEN](fill=0)
    var counter = StackBuffer[UInt8, 1](fill=0)
    var block_count = (length + _SHA256_LEN - 1) // _SHA256_LEN
    var written = 0

    for block_index in range(1, block_count + 1):
        counter[0] = UInt8(block_index)
        if block_index == 1:
            _hmac_sha256_parts(
                hmac,
                info,
                Span[UInt8, ...](unsafe_ptr=counter.ptr(), length=1),
                block.ptr(),
            )
        else:
            _hmac_sha256_parts(
                hmac,
                Span[UInt8, ...](unsafe_ptr=previous.ptr(), length=_SHA256_LEN),
                info,
                Span[UInt8, ...](unsafe_ptr=counter.ptr(), length=1),
                block.ptr(),
            )

        var take = min(_SHA256_LEN, length - written)
        for i in range(take):
            output[written + i] = block[i]
        written += take
        if block_index < block_count:
            for i in range(_SHA256_LEN):
                previous[i] = block[i]

    volatile_wipe(previous.ptr(), _SHA256_LEN)
    volatile_wipe(block.ptr(), _SHA256_LEN)
    volatile_wipe(counter.ptr(), 1)


def hkdf_expand_sha256(
    prk: Span[UInt8, ...], info: Span[UInt8, ...], length: Int
) raises -> List[UInt8]:
    """HKDF-Expand with SHA-256 (RFC 5869, sec. 2.3)."""
    if length < 0 or length > _HKDF_SHA256_MAX:
        raise Error("HKDF-SHA256 output length must be between 0 and 8160 bytes")
    var output = List[UInt8](unsafe_uninit_length=length)
    hkdf_expand_sha256_into(
        prk, info, Span[mut=True, UInt8, ...](output)
    )
    return output^


def tls12_prf_sha256_into(
    secret: Span[UInt8, ...], label: Span[UInt8, ...], seed: Span[UInt8, ...],
    output: Span[mut=True, UInt8, ...]
) raises:
    """Write TLS 1.2 P_SHA256; output must not alias the inputs (RFC 5246, sec. 5)."""
    var length = len(output)
    if length == 0:
        return

    var hmac = HMACSHA256State(secret)
    var chain = StackBuffer[UInt8, _SHA256_LEN](fill=0)
    var next_chain = StackBuffer[UInt8, _SHA256_LEN](fill=0)
    var prf_block = StackBuffer[UInt8, _SHA256_LEN](fill=0)

    _hmac_sha256_parts(hmac, label, seed, chain.ptr())

    var output_offset = 0
    while output_offset < length:
        _hmac_sha256_parts(
            hmac,
            Span[UInt8, ...](unsafe_ptr=chain.ptr(), length=_SHA256_LEN),
            label,
            seed,
            prf_block.ptr(),
        )
        var copy_len = min(_SHA256_LEN, length - output_offset)
        for i in range(copy_len):
            output[output_offset + i] = prf_block[i]
        output_offset += copy_len
        if output_offset < length:
            hmac.hmac_into(
                Span[UInt8, ...](unsafe_ptr=chain.ptr(), length=_SHA256_LEN),
                next_chain.ptr(),
            )
            for i in range(_SHA256_LEN):
                chain[i] = next_chain[i]

    volatile_wipe(chain.ptr(), _SHA256_LEN)
    volatile_wipe(next_chain.ptr(), _SHA256_LEN)
    volatile_wipe(prf_block.ptr(), _SHA256_LEN)


def tls12_prf_sha256(
    secret: Span[UInt8, ...], label: Span[UInt8, ...], seed: Span[UInt8, ...], length: Int
) raises -> List[UInt8]:
    """Return the TLS 1.2 PRF using P_SHA256 (RFC 5246, sec. 5)."""
    if length < 0:
        raise Error("TLS 1.2 PRF output length must be non-negative")
    var output = List[UInt8](unsafe_uninit_length=length)
    tls12_prf_sha256_into(
        secret, label, seed, Span[mut=True, UInt8, ...](output)
    )
    return output^


def tls12_prf_sha384_into(
    secret: Span[UInt8, ...], label: Span[UInt8, ...], seed: Span[UInt8, ...],
    output: Span[mut=True, UInt8, ...]
) raises:
    """Write TLS 1.2 P_SHA384; output must not alias the inputs (RFC 5246, sec. 5)."""
    var length = len(output)
    if length == 0:
        return

    var hmac = HMACSHA384State(secret)
    var chain = StackBuffer[UInt8, _SHA384_LEN](fill=0)
    var next_chain = StackBuffer[UInt8, _SHA384_LEN](fill=0)
    var prf_block = StackBuffer[UInt8, _SHA384_LEN](fill=0)

    _hmac_sha384_parts(hmac, label, seed, chain.ptr())

    var output_offset = 0
    while output_offset < length:
        _hmac_sha384_parts(
            hmac,
            Span[UInt8, ...](unsafe_ptr=chain.ptr(), length=_SHA384_LEN),
            label,
            seed,
            prf_block.ptr(),
        )
        var copy_len = min(_SHA384_LEN, length - output_offset)
        for i in range(copy_len):
            output[output_offset + i] = prf_block[i]
        output_offset += copy_len
        if output_offset < length:
            hmac.hmac_into(
                Span[UInt8, ...](unsafe_ptr=chain.ptr(), length=_SHA384_LEN),
                next_chain.ptr(),
            )
            for i in range(_SHA384_LEN):
                chain[i] = next_chain[i]

    volatile_wipe(chain.ptr(), _SHA384_LEN)
    volatile_wipe(next_chain.ptr(), _SHA384_LEN)
    volatile_wipe(prf_block.ptr(), _SHA384_LEN)


def tls12_prf_sha384(
    secret: Span[UInt8, ...], label: Span[UInt8, ...], seed: Span[UInt8, ...], length: Int
) raises -> List[UInt8]:
    """Return the TLS 1.2 PRF using P_SHA384 (RFC 5246, sec. 5)."""
    if length < 0:
        raise Error("TLS 1.2 PRF output length must be non-negative")
    var output = List[UInt8](unsafe_uninit_length=length)
    tls12_prf_sha384_into(
        secret, label, seed, Span[mut=True, UInt8, ...](output)
    )
    return output^


def tls13_hkdf_expand_label_sha256_into(
    secret: Span[UInt8, ...], label: Span[UInt8, ...], context: Span[UInt8, ...],
    output: Span[mut=True, UInt8, ...]
) raises:
    """Write TLS 1.3 HKDF-Expand-Label/SHA-256 output (RFC 9846, sec. 7.1)."""
    var length = len(output)
    if length > 0xFFFF or length > _HKDF_SHA256_MAX:
        raise Error("TLS 1.3 HKDF output length is out of range")
    if len(label) < 1 or len(label) > 249:
        raise Error("TLS 1.3 label must be between 1 and 249 bytes")
    if len(context) > 255:
        raise Error("TLS 1.3 HKDF context must not exceed 255 bytes")

    var info = StackBuffer[UInt8, _TLS13_HKDF_LABEL_MAX]()
    info.push_unchecked(UInt8((length >> 8) & 0xFF))
    info.push_unchecked(UInt8(length & 0xFF))
    info.push_unchecked(UInt8(_TLS13_LABEL_PREFIX_LEN + len(label)))
    comptime for i in range(_TLS13_LABEL_PREFIX_LEN):
        info.push_unchecked(_TLS13_LABEL_PREFIX[i])
    for i in range(len(label)):
        info.push_unchecked(label[i])
    info.push_unchecked(UInt8(len(context)))
    for i in range(len(context)):
        info.push_unchecked(context[i])

    hkdf_expand_sha256_into(
        secret,
        Span[UInt8, ...](unsafe_ptr=info.ptr(), length=info.len()),
        output,
    )
    volatile_wipe(info.ptr(), info.len())


def tls13_hkdf_expand_label_sha256(
    secret: Span[UInt8, ...], label: Span[UInt8, ...], context: Span[UInt8, ...], length: Int
) raises -> List[UInt8]:
    """TLS 1.3 HKDF-Expand-Label with SHA-256 (RFC 9846, sec. 7.1)."""
    if length < 0 or length > 0xFFFF or length > _HKDF_SHA256_MAX:
        raise Error("TLS 1.3 HKDF output length is out of range")
    var result = List[UInt8](unsafe_uninit_length=length)
    tls13_hkdf_expand_label_sha256_into(
        secret, label, context, Span[mut=True, UInt8, ...](result)
    )
    return result^


def tls13_derive_secret_sha256_into(
    secret: Span[UInt8, ...], label: Span[UInt8, ...], transcript_hash: Span[UInt8, ...],
    output: Span[mut=True, UInt8, ...]
) raises:
    """Write TLS 1.3 Derive-Secret/SHA-256 (RFC 9846, sec. 7.1)."""
    if len(transcript_hash) != _SHA256_LEN:
        raise Error("TLS 1.3 SHA-256 transcript hash must be exactly 32 bytes")
    if len(output) != _SHA256_LEN:
        raise Error("TLS 1.3 SHA-256 derived secret output must be exactly 32 bytes")
    tls13_hkdf_expand_label_sha256_into(
        secret, label, transcript_hash, output
    )


def tls13_derive_secret_sha256(
    secret: Span[UInt8, ...], label: Span[UInt8, ...], transcript_hash: Span[UInt8, ...]
) raises -> List[UInt8]:
    """TLS 1.3 Derive-Secret for SHA-256 cipher suites (RFC 9846, sec. 7.1)."""
    if len(transcript_hash) != _SHA256_LEN:
        raise Error("TLS 1.3 SHA-256 transcript hash must be exactly 32 bytes")
    var output = List[UInt8](unsafe_uninit_length=_SHA256_LEN)
    tls13_derive_secret_sha256_into(secret, label, transcript_hash, Span[mut=True, UInt8, ...](output))
    return output^
