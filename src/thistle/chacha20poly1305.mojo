"""
ChaCha20-Poly1305 and XChaCha20-Poly1305 AEAD RFC 8439
"""

from std.memory import bitcast
from std.memory.unsafe_pointer import UnsafePointer
from std.collections import InlineArray
from .chacha20 import ChaCha20, chacha20_block_core, simd_double_round, CHACHA_CONSTANTS
from .poly1305 import Poly1305

comptime _ZEROS16 = InlineArray[UInt8, 16](fill=0)


def hchacha20(key: Span[UInt8, ...], input16: Span[UInt8, ...], output: UnsafePointer[UInt8, MutAnyOrigin]) raises:
    if len(key) < 32 or len(input16) < 16:
        raise Error("HChaCha20 needs a 32-byte key and 16-byte input")
    var kw = key.unsafe_ptr().bitcast[UInt32]().load[width=8, alignment=1]()
    var iw = input16.unsafe_ptr().bitcast[UInt32]().load[width=4, alignment=1]()

    var row0 = CHACHA_CONSTANTS
    var row1 = SIMD[DType.uint32, 4](kw[0], kw[1], kw[2], kw[3])
    var row2 = SIMD[DType.uint32, 4](kw[4], kw[5], kw[6], kw[7])
    var row3 = iw

    comptime for _ in range(10):
        var dr = simd_double_round(row0, row1, row2, row3)
        row0 = dr[0]; row1 = dr[1]; row2 = dr[2]; row3 = dr[3]

    output.bitcast[UInt32]().store[alignment=1](0, row0)
    (output + 16).bitcast[UInt32]().store[alignment=1](0, row3)


def _aead_tag(
    poly_key: Span[UInt8, ...],
    aad: Span[UInt8, ...],
    ciphertext: Span[UInt8, ...],
    output: UnsafePointer[UInt8, MutAnyOrigin],
) raises:
    var p = Poly1305(poly_key)
    var zp = _ZEROS16.unsafe_ptr()
    p.update(aad)
    if len(aad) % 16 != 0:
        p.update(Span[UInt8, ...](ptr=zp, length=16 - len(aad) % 16))
    p.update(ciphertext)
    if len(ciphertext) % 16 != 0:
        p.update(Span[UInt8, ...](ptr=zp, length=16 - len(ciphertext) % 16))
    var lens = InlineArray[UInt8, 16](uninitialized=True)
    lens.unsafe_ptr().bitcast[UInt64]().store[alignment=1](0, UInt64(len(aad)))
    (lens.unsafe_ptr() + 8).bitcast[UInt64]().store[alignment=1](0, UInt64(len(ciphertext)))
    p.update(Span[UInt8, ...](ptr=lens.unsafe_ptr(), length=16))
    p.finalize_into(output)


def _aead_core[encrypt: Bool](
    key: Span[UInt8, ...],
    nonce: Span[UInt8, ...],
    aad: Span[UInt8, ...],
    input: Span[UInt8, ...],
    output: UnsafePointer[UInt8, MutAnyOrigin],
    tag: UnsafePointer[UInt8, MutAnyOrigin],
) raises:
    var key_bytes = key.unsafe_ptr().load[width=32, alignment=1](0)
    var nonce_bytes = nonce.unsafe_ptr().load[width=12, alignment=1](0)

    var kw = bitcast[DType.uint32, 8](key_bytes)
    var nw = bitcast[DType.uint32, 3](nonce_bytes)
    var block0 = chacha20_block_core(kw, 0, nw)
    var poly_key = InlineArray[UInt8, 32](uninitialized=True)
    poly_key.unsafe_ptr().store[alignment=1](
        0, bitcast[DType.uint8, 64](block0).slice[32]()
    )
    var poly_key_span = Span[UInt8, ...](ptr=poly_key.unsafe_ptr(), length=32)

    var cipher = ChaCha20(key_bytes, nonce_bytes, counter=1)
    var src = input.unsafe_ptr().unsafe_mut_cast[True]().unsafe_origin_cast[MutAnyOrigin]()
    cipher._stream_xor(src, output, len(input))

    comptime if encrypt:
        _aead_tag(
            poly_key_span, aad,
            Span[UInt8, ...](ptr=output, length=len(input)), tag,
        )
    else:
        _aead_tag(poly_key_span, aad, input, tag)


def chacha20_poly1305_encrypt(
    key: Span[UInt8, ...],
    nonce: Span[UInt8, ...],
    aad: Span[UInt8, ...],
    plaintext: Span[UInt8, ...],
    ciphertext: UnsafePointer[UInt8, MutAnyOrigin],
    tag: UnsafePointer[UInt8, MutAnyOrigin],
) raises:
    if len(key) != 32:
        raise Error("ChaCha20-Poly1305 key must be 32 bytes")
    if len(nonce) != 12:
        raise Error("ChaCha20-Poly1305 nonce must be 12 bytes")
    _aead_core[True](key, nonce, aad, plaintext, ciphertext, tag)


def chacha20_poly1305_decrypt(
    key: Span[UInt8, ...],
    nonce: Span[UInt8, ...],
    aad: Span[UInt8, ...],
    ciphertext: Span[UInt8, ...],
    tag: Span[UInt8, ...],
    plaintext: UnsafePointer[UInt8, MutAnyOrigin],
) raises -> Bool:
    if len(key) != 32:
        raise Error("ChaCha20-Poly1305 key must be 32 bytes")
    if len(nonce) != 12:
        raise Error("ChaCha20-Poly1305 nonce must be 12 bytes")
    if len(tag) != 16:
        return False

    var key_bytes = key.unsafe_ptr().load[width=32, alignment=1](0)
    var nonce_bytes = nonce.unsafe_ptr().load[width=12, alignment=1](0)
    var kw = bitcast[DType.uint32, 8](key_bytes)
    var nw = bitcast[DType.uint32, 3](nonce_bytes)
    var block0 = chacha20_block_core(kw, 0, nw)
    var poly_key = InlineArray[UInt8, 32](uninitialized=True)
    poly_key.unsafe_ptr().store[alignment=1](
        0, bitcast[DType.uint8, 64](block0).slice[32]()
    )

    var expected = InlineArray[UInt8, 16](uninitialized=True)
    _aead_tag(
        Span[UInt8, ...](ptr=poly_key.unsafe_ptr(), length=32),
        aad, ciphertext, expected.unsafe_ptr(),
    )
    var diff: UInt8 = 0
    for i in range(16):
        diff |= expected[i] ^ tag[i]
    if diff != 0:
        return False

    var cipher = ChaCha20(key_bytes, nonce_bytes, counter=1)
    var src = ciphertext.unsafe_ptr().unsafe_mut_cast[True]().unsafe_origin_cast[MutAnyOrigin]()
    cipher._stream_xor(src, plaintext, len(ciphertext))
    return True


def xchacha20_poly1305_encrypt(
    key: Span[UInt8, ...],
    nonce: Span[UInt8, ...],
    aad: Span[UInt8, ...],
    plaintext: Span[UInt8, ...],
    ciphertext: UnsafePointer[UInt8, MutAnyOrigin],
    tag: UnsafePointer[UInt8, MutAnyOrigin],
) raises:
    if len(key) != 32:
        raise Error("XChaCha20-Poly1305 key must be 32 bytes")
    if len(nonce) != 24:
        raise Error("XChaCha20-Poly1305 nonce must be 24 bytes")
    var sub = _xchacha_subkey_nonce(key, nonce)
    var sp = sub.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin]()
    chacha20_poly1305_encrypt(
        Span[UInt8, ...](ptr=sp, length=32),
        Span[UInt8, ...](ptr=sp + 32, length=12),
        aad, plaintext, ciphertext, tag,
    )


def xchacha20_poly1305_decrypt(
    key: Span[UInt8, ...],
    nonce: Span[UInt8, ...],
    aad: Span[UInt8, ...],
    ciphertext: Span[UInt8, ...],
    tag: Span[UInt8, ...],
    plaintext: UnsafePointer[UInt8, MutAnyOrigin],
) raises -> Bool:
    if len(key) != 32:
        raise Error("XChaCha20-Poly1305 key must be 32 bytes")
    if len(nonce) != 24:
        raise Error("XChaCha20-Poly1305 nonce must be 24 bytes")
    var sub = _xchacha_subkey_nonce(key, nonce)
    var sp = sub.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin]()
    return chacha20_poly1305_decrypt(
        Span[UInt8, ...](ptr=sp, length=32),
        Span[UInt8, ...](ptr=sp + 32, length=12),
        aad, ciphertext, tag, plaintext,
    )


def _xchacha_subkey_nonce(key: Span[UInt8, ...], nonce: Span[UInt8, ...]) raises -> InlineArray[UInt8, 44]:
    var out = InlineArray[UInt8, 44](fill=0)
    hchacha20(
        key,
        Span[UInt8, ...](ptr=nonce.unsafe_ptr(), length=16),
        out.unsafe_ptr(),
    )
    for i in range(8):
        out[36 + i] = nonce[16 + i]
    return out
