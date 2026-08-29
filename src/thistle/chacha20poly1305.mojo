"""Implements ChaCha20-Poly1305 and XChaCha20-Poly1305 from RFC 8439."""

from std.memory import bitcast
from std.memory.unsafe_pointer import Pointer
from std.collections import InlineArray
from .chacha20 import (
    ChaCha20, chacha20_block_core, simd_double_round, CHACHA_CONSTANTS, _chacha20_nonce_words
)
from .poly1305 import Poly1305
from .utils import volatile_wipe


def hchacha20(
    key: Span[UInt8, ...],
    input16: Span[UInt8, ...],
    output: Span[mut=True, UInt8, ...]
) raises:
    if len(key) != 32 or len(input16) != 16:
        raise Error("HChaCha20 needs a 32-byte key and 16-byte input")
    if len(output) < 32:
        raise Error("HChaCha20 output needs at least 32 writable bytes")
    var out_ptr = output.unsafe_ptr()
    var kw = key.unsafe_ptr().unsafe_bitcast[UInt32]().unsafe_load[width=8, alignment=1]()
    var iw = input16.unsafe_ptr().unsafe_bitcast[UInt32]().unsafe_load[width=4, alignment=1]()

    var row0 = CHACHA_CONSTANTS
    var row1 = SIMD[DType.uint32, 4](kw[0], kw[1], kw[2], kw[3])
    var row2 = SIMD[DType.uint32, 4](kw[4], kw[5], kw[6], kw[7])
    var row3 = iw

    comptime for _ in range(10):
        var dr = simd_double_round(row0, row1, row2, row3)
        row0 = dr[0]
        row1 = dr[1]
        row2 = dr[2]
        row3 = dr[3]

    out_ptr.unsafe_bitcast[UInt32]().unsafe_store[alignment=1](0, row0)
    (out_ptr.unsafe_offset(16)).unsafe_bitcast[UInt32]().unsafe_store[alignment=1](0, row3)


def _aead_tag(
    poly_key: Span[UInt8, ...],
    aad: Span[UInt8, ...],
    ciphertext: Span[UInt8, ...],
    output: Pointer[mut=True, UInt8, _, address_space=_]
) raises:
    var p = Poly1305(poly_key)
    var zeros16 = InlineArray[UInt8, 16](fill=0)
    var zp = zeros16.unsafe_ptr()
    p.update(aad)
    if len(aad) % 16 != 0:
        p.update(Span[UInt8, ...](unsafe_ptr=zp, length=16 - len(aad) % 16))
    p.update(ciphertext)
    if len(ciphertext) % 16 != 0:
        p.update(Span[UInt8, ...](unsafe_ptr=zp, length=16 - len(ciphertext) % 16))
    var lens = InlineArray[UInt8, 16](fill=0)
    lens.unsafe_ptr().unsafe_bitcast[UInt64]().unsafe_store[alignment=1](0, UInt64(len(aad)))
    (lens.unsafe_ptr().unsafe_offset(8)).unsafe_bitcast[UInt64]().unsafe_store[alignment=1](0, UInt64(len(ciphertext)))
    p.update(Span[UInt8, ...](unsafe_ptr=lens.unsafe_ptr(), length=16))
    p.finalize_into(
        Span[mut=True, UInt8, ...](unsafe_ptr=output, length=16)
    )


def _aead_core[encrypt: Bool](
    key: Span[UInt8, ...],
    nonce: Span[UInt8, ...],
    aad: Span[UInt8, ...],
    input: Span[UInt8, ...],
    output: Pointer[mut=True, UInt8, _, address_space=_],
    tag: Pointer[mut=True, UInt8, _, address_space=_]
) raises:
    var key_bytes = key.unsafe_ptr().unsafe_load[width=32, alignment=1](0)
    var nonce_bytes = InlineArray[UInt8, 12](fill=0)
    for i in range(12):
        nonce_bytes[i] = nonce[i]

    var kw = bitcast[DType.uint32, 8](key_bytes)
    var nonce_span = Span[UInt8, ...](nonce_bytes)
    var nw = _chacha20_nonce_words(nonce_span)
    var block0 = chacha20_block_core(kw, 0, nw)
    var poly_key = InlineArray[UInt8, 32](fill=0)
    poly_key.unsafe_ptr().unsafe_store[alignment=1](
        0, bitcast[DType.uint8, 64](block0).slice[32]()
    )
    var poly_key_span = Span[UInt8, ...](unsafe_ptr=poly_key.unsafe_ptr(), length=32)

    try:
        var cipher = ChaCha20(key_bytes, nonce_span, counter=1)
        var src = (
            input.unsafe_ptr()
            .unsafe_mut_cast[True]()
            .unsafe_origin_cast[MutAnyOrigin]()
        )
        cipher._stream_xor(src, output, len(input))

        comptime if encrypt:
            _aead_tag(
                poly_key_span,
                aad,
                Span[UInt8, ...](unsafe_ptr=output, length=len(input)),
                tag,
            )
        else:
            _aead_tag(poly_key_span, aad, input, tag)
    finally:
        volatile_wipe(poly_key.unsafe_ptr(), 32)
        volatile_wipe(
            Pointer(to=key_bytes).unsafe_mut_cast[True]().unsafe_bitcast[UInt8](),
            32
        )
        volatile_wipe(Pointer(to=kw).unsafe_mut_cast[True]().unsafe_bitcast[UInt8](), 32)
        volatile_wipe(
            Pointer(to=block0).unsafe_mut_cast[True]().unsafe_bitcast[UInt8](),
            64
        )


def chacha20_poly1305_encrypt(
    key: Span[UInt8, ...],
    nonce: Span[UInt8, ...],
    aad: Span[UInt8, ...],
    plaintext: Span[UInt8, ...],
    ciphertext: Span[mut=True, UInt8, ...],
    tag: Span[mut=True, UInt8, ...]
) raises:
    if len(key) != 32:
        raise Error("ChaCha20-Poly1305 key must be 32 bytes")
    if len(nonce) != 12:
        raise Error("ChaCha20-Poly1305 nonce must be 12 bytes")
    if len(ciphertext) < len(plaintext):
        raise Error("ChaCha20-Poly1305 ciphertext output is too small")
    if len(tag) < 16:
        raise Error("ChaCha20-Poly1305 tag output is too small")
    _aead_core[True](key, nonce, aad, plaintext, ciphertext.unsafe_ptr(), tag.unsafe_ptr())


def chacha20_poly1305_decrypt(
    key: Span[UInt8, ...],
    nonce: Span[UInt8, ...],
    aad: Span[UInt8, ...],
    ciphertext: Span[UInt8, ...],
    tag: Span[UInt8, ...],
    plaintext: Span[mut=True, UInt8, ...]
) raises -> Bool:
    if len(key) != 32:
        raise Error("ChaCha20-Poly1305 key must be 32 bytes")
    if len(nonce) != 12:
        raise Error("ChaCha20-Poly1305 nonce must be 12 bytes")
    if len(tag) != 16:
        return False
    if len(plaintext) < len(ciphertext):
        raise Error("ChaCha20-Poly1305 plaintext output is too small")

    var key_bytes = key.unsafe_ptr().unsafe_load[width=32, alignment=1](0)
    var nonce_bytes = InlineArray[UInt8, 12](fill=0)
    for i in range(12):
        nonce_bytes[i] = nonce[i]
    var kw = bitcast[DType.uint32, 8](key_bytes)
    var nonce_span = Span[UInt8, ...](nonce_bytes)
    var nw = _chacha20_nonce_words(nonce_span)
    var block0 = chacha20_block_core(kw, 0, nw)
    var poly_key = InlineArray[UInt8, 32](fill=0)
    poly_key.unsafe_ptr().unsafe_store[alignment=1](0, bitcast[DType.uint8, 64](block0).slice[32]())

    var expected = InlineArray[UInt8, 16](fill=0)
    try:
        _aead_tag(
            Span[UInt8, ...](unsafe_ptr=poly_key.unsafe_ptr(), length=32),
            aad,
            ciphertext,
            expected.unsafe_ptr()
        )
        var diff: UInt8 = 0
        for i in range(16):
            diff |= expected[i] ^ tag[i]
        if diff != 0:
            return False

        var cipher = ChaCha20(key_bytes, nonce_span, counter=1)
        var src = ciphertext.unsafe_ptr().unsafe_mut_cast[True]().unsafe_origin_cast[MutAnyOrigin]()
        cipher._stream_xor(src, plaintext.unsafe_ptr(), len(ciphertext))
        return True
    finally:
        volatile_wipe(poly_key.unsafe_ptr(), 32)
        volatile_wipe(expected.unsafe_ptr(), 16)
        volatile_wipe(
            Pointer(to=key_bytes).unsafe_mut_cast[True]().unsafe_bitcast[UInt8](),
            32
        )
        volatile_wipe(Pointer(to=kw).unsafe_mut_cast[True]().unsafe_bitcast[UInt8](), 32)
        volatile_wipe(
            Pointer(to=block0).unsafe_mut_cast[True]().unsafe_bitcast[UInt8](),
            64
        )


def xchacha20_poly1305_encrypt(
    key: Span[UInt8, ...],
    nonce: Span[UInt8, ...],
    aad: Span[UInt8, ...],
    plaintext: Span[UInt8, ...],
    ciphertext: Span[mut=True, UInt8, ...],
    tag: Span[mut=True, UInt8, ...]
) raises:
    if len(key) != 32:
        raise Error("XChaCha20-Poly1305 key must be 32 bytes")
    if len(nonce) != 24:
        raise Error("XChaCha20-Poly1305 nonce must be 24 bytes")
    if len(ciphertext) < len(plaintext):
        raise Error("XChaCha20-Poly1305 ciphertext output is too small")
    if len(tag) < 16:
        raise Error("XChaCha20-Poly1305 tag output is too small")
    var sub = _xchacha_subkey_nonce(key, nonce)
    var sp = sub.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin]()
    try:
        chacha20_poly1305_encrypt(
            Span[UInt8, ...](unsafe_ptr=sp, length=32),
            Span[UInt8, ...](unsafe_ptr=sp.unsafe_offset(32), length=12),
            aad,
            plaintext,
            ciphertext,
            tag
        )
    finally:
        for i in range(44):
            sp.unsafe_store[volatile=True](i, UInt8(0))


def xchacha20_poly1305_decrypt(
    key: Span[UInt8, ...],
    nonce: Span[UInt8, ...],
    aad: Span[UInt8, ...],
    ciphertext: Span[UInt8, ...],
    tag: Span[UInt8, ...],
    plaintext: Span[mut=True, UInt8, ...]
) raises -> Bool:
    if len(key) != 32:
        raise Error("XChaCha20-Poly1305 key must be 32 bytes")
    if len(nonce) != 24:
        raise Error("XChaCha20-Poly1305 nonce must be 24 bytes")
    if len(plaintext) < len(ciphertext):
        raise Error("XChaCha20-Poly1305 plaintext output is too small")
    var sub = _xchacha_subkey_nonce(key, nonce)
    var sp = sub.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin]()
    var ok = False
    try:
        ok = chacha20_poly1305_decrypt(
            Span[UInt8, ...](unsafe_ptr=sp, length=32),
            Span[UInt8, ...](unsafe_ptr=sp.unsafe_offset(32), length=12),
            aad,
            ciphertext,
            tag,
            plaintext
        )
    finally:
        for i in range(44):
            sp.unsafe_store[volatile=True](i, UInt8(0))
    return ok


def _xchacha_subkey_nonce(
    key: Span[UInt8, ...], nonce: Span[UInt8, ...]
) raises -> InlineArray[UInt8, 44]:
    var out = InlineArray[UInt8, 44](fill=0)
    hchacha20(
        key,
        Span[UInt8, ...](unsafe_ptr=nonce.unsafe_ptr(), length=16),
        Span[mut=True, UInt8, ...](unsafe_ptr=out.unsafe_ptr(), length=32)
    )
    for i in range(8):
        out[36 + i] = nonce[16 + i]
    return out^
