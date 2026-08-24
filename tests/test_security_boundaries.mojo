from std.collections import List

from thistle.aes import AESExpandedKey
from thistle.argon2 import variable_length_hash_into
from thistle.blake2b import Blake2b
from thistle.chacha20poly1305 import (
    chacha20_poly1305_encrypt,
    hchacha20,
)
from thistle.chacha20 import ChaCha20
from thistle.ed25519 import (
    Ed25519SigningKey,
    ed25519_generate_public_key,
    ed25519_sign,
)
from thistle.p256 import p256_ecdsa_sign, p256_public_key
from thistle.p384 import p384_ecdsa_sign, p384_public_key
from thistle.pbkdf2 import (
    PBKDF2_SHA256_MAX_DKLEN,
    PBKDF2_SHA512_MAX_DKLEN,
    PBKDF2SHA256,
    PBKDF2SHA512,
    pbkdf2_hmac_sha256,
    pbkdf2_hmac_sha512,
)
from thistle.poly1305 import Poly1305
from thistle.x25519 import x25519, x25519_checked


def main() raises:
    var empty = List[UInt8]()
    var short = List[UInt8](length=15, fill=0)
    var rejected = False
    try:
        var key = AESExpandedKey(Span[UInt8, ...](short))
        _ = key
    except:
        rejected = True
    if not rejected:
        raise Error("AES accepted an undersized key")

    var argon_output = List[UInt8](length=4, fill=0)
    rejected = False
    try:
        variable_length_hash_into(
            5,
            Span[UInt8, ...](empty),
            Span[mut=True, UInt8, ...](argon_output),
        )
    except:
        rejected = True
    if not rejected:
        raise Error("Argon2 accepted an undersized destination")

    var blake_output = List[UInt8](length=31, fill=0)
    var blake = Blake2b(32)
    blake.update(Span[UInt8, ...](empty))
    rejected = False
    try:
        blake.finalize_into(Span[mut=True, UInt8, ...](blake_output))
    except:
        rejected = True
    if not rejected:
        raise Error("BLAKE2b accepted an undersized destination")

    var poly_key = List[UInt8](length=32, fill=0)
    var poly_output = List[UInt8](length=15, fill=0)
    var poly = Poly1305(Span[UInt8, ...](poly_key))
    rejected = False
    try:
        poly.finalize_into(Span[mut=True, UInt8, ...](poly_output))
    except:
        rejected = True
    if not rejected:
        raise Error("Poly1305 accepted an undersized destination")

    var key32 = List[UInt8](length=32, fill=1)
    var point32 = List[UInt8](length=32, fill=0)
    point32[0] = 9
    var output31 = List[UInt8](length=31, fill=0)
    rejected = False
    try:
        x25519(
            Span[UInt8, ...](key32),
            Span[UInt8, ...](point32),
            Span[mut=True, UInt8, ...](output31),
        )
    except:
        rejected = True
    if not rejected:
        raise Error("X25519 accepted an undersized destination")

    var zero_point = List[UInt8](length=32, fill=0)
    var x25519_output = List[UInt8](length=32, fill=0)
    rejected = False
    try:
        x25519_checked(
            Span[UInt8, ...](key32),
            Span[UInt8, ...](zero_point),
            Span[mut=True, UInt8, ...](x25519_output),
        )
    except:
        rejected = True
    if not rejected:
        raise Error("X25519 checked API accepted an all-zero shared secret")

    var input16 = List[UInt8](length=16, fill=0)
    rejected = False
    try:
        hchacha20(
            Span[UInt8, ...](key32),
            Span[UInt8, ...](input16),
            Span[mut=True, UInt8, ...](output31),
        )
    except:
        rejected = True
    if not rejected:
        raise Error("HChaCha20 accepted an undersized destination")

    var chacha_key = SIMD[DType.uint8, 32](0)
    var oversized_nonce = List[UInt8](length=16, fill=0)
    rejected = False
    try:
        var invalid_cipher = ChaCha20(
            chacha_key, Span[UInt8, ...](oversized_nonce)
        )
        _ = invalid_cipher
    except:
        rejected = True
    if not rejected:
        raise Error("ChaCha20 accepted a nonce longer than 12 bytes")

    var nonce_a = List[UInt8](length=12, fill=0)
    var nonce_b = List[UInt8](length=12, fill=0)
    nonce_b[11] = 1
    var zeros = List[UInt8](length=64, fill=0)
    var stream_a = List[UInt8](length=64, fill=0)
    var stream_b = List[UInt8](length=64, fill=0)
    var cipher_a = ChaCha20(chacha_key, Span[UInt8, ...](nonce_a))
    var cipher_b = ChaCha20(chacha_key, Span[UInt8, ...](nonce_b))
    var stream_a_span = Span[mut=True, UInt8, ...](stream_a)
    var stream_b_span = Span[mut=True, UInt8, ...](stream_b)
    cipher_a.encrypt_into(
        Span[UInt8, ...](zeros), stream_a_span
    )
    cipher_b.encrypt_into(
        Span[UInt8, ...](zeros), stream_b_span
    )
    var nonce_affects_stream = False
    for i in range(64):
        nonce_affects_stream |= stream_a[i] != stream_b[i]
    if not nonce_affects_stream:
        raise Error("ChaCha20 ignored the final nonce byte")

    # The final UInt32 counter value is valid once, but the reusable context
    # must remember exhaustion so a later call cannot reuse counter zero.
    var last_counter_cipher = ChaCha20(
        chacha_key, Span[UInt8, ...](nonce_a), UInt32(0xFFFFFFFF)
    )
    var one_byte = List[UInt8](length=1, fill=0)
    var one_byte_out = List[UInt8](length=1, fill=0)
    var one_byte_out_span = Span[mut=True, UInt8, ...](one_byte_out)
    last_counter_cipher.encrypt_into(
        Span[UInt8, ...](one_byte), one_byte_out_span
    )
    rejected = False
    try:
        last_counter_cipher.encrypt_into(
            Span[UInt8, ...](one_byte), one_byte_out_span
        )
    except:
        rejected = True
    if not rejected:
        raise Error("ChaCha20 reused its counter after exhaustion")

    var ed_private = List[UInt8](length=32, fill=1)
    var ed_public_short = List[UInt8](length=31, fill=0)
    rejected = False
    try:
        ed25519_generate_public_key(
            Span[UInt8, ...](ed_private),
            Span[mut=True, UInt8, ...](ed_public_short),
        )
    except:
        rejected = True
    if not rejected:
        raise Error("Ed25519 accepted an undersized public-key destination")

    var ed_signature_short = List[UInt8](length=63, fill=0)
    rejected = False
    try:
        ed25519_sign(
            Span[UInt8, ...](ed_private),
            Span[UInt8, ...](empty),
            Span[mut=True, UInt8, ...](ed_signature_short),
        )
    except:
        rejected = True
    if not rejected:
        raise Error("Ed25519 accepted an undersized signature destination")

    var ed_key = Ed25519SigningKey(Span[UInt8, ...](ed_private))
    if ed_key.public_key_into(
        Span[mut=True, UInt8, ...](ed_public_short)
    ):
        raise Error("Ed25519 key object accepted an undersized public-key destination")
    rejected = False
    try:
        ed_key.sign(
            Span[UInt8, ...](empty),
            Span[mut=True, UInt8, ...](ed_signature_short),
        )
    except:
        rejected = True
    if not rejected:
        raise Error("Ed25519 key object accepted an undersized signature destination")

    var empty_salt = List[UInt8]()
    rejected = False
    try:
        _ = pbkdf2_hmac_sha256(
            Span[UInt8, ...](empty),
            Span[UInt8, ...](empty_salt),
            1,
            PBKDF2_SHA256_MAX_DKLEN + 1,
        )
    except:
        rejected = True
    if not rejected:
        raise Error("PBKDF2-SHA256 accepted an oversized derived key")

    rejected = False
    try:
        _ = pbkdf2_hmac_sha512(
            Span[UInt8, ...](empty),
            Span[UInt8, ...](empty_salt),
            1,
            PBKDF2_SHA512_MAX_DKLEN + 1,
        )
    except:
        rejected = True
    if not rejected:
        raise Error("PBKDF2-SHA512 accepted an oversized derived key")

    var pbkdf256 = PBKDF2SHA256(Span[UInt8, ...](empty))
    rejected = False
    try:
        _ = pbkdf256.derive(Span[UInt8, ...](empty_salt), 0, 32)
    except:
        rejected = True
    if not rejected:
        raise Error("PBKDF2-SHA256 context accepted zero iterations")

    var pbkdf512 = PBKDF2SHA512(Span[UInt8, ...](empty))
    rejected = False
    try:
        _ = pbkdf512.derive(Span[UInt8, ...](empty_salt), 0, 64)
    except:
        rejected = True
    if not rejected:
        raise Error("PBKDF2-SHA512 context accepted zero iterations")

    var nonce = List[UInt8](length=12, fill=0)
    var plaintext = List[UInt8](length=16, fill=0)
    var ciphertext = List[UInt8](length=15, fill=0)
    var tag = List[UInt8](length=16, fill=0)
    rejected = False
    try:
        chacha20_poly1305_encrypt(
            Span[UInt8, ...](key32),
            Span[UInt8, ...](nonce),
            Span[UInt8, ...](empty),
            Span[UInt8, ...](plaintext),
            Span[mut=True, UInt8, ...](ciphertext),
            Span[mut=True, UInt8, ...](tag),
        )
    except:
        rejected = True
    if not rejected:
        raise Error("ChaCha20-Poly1305 accepted an undersized destination")

    var p256_private = List[UInt8](length=32, fill=0)
    p256_private[31] = 1
    var p384_private = List[UInt8](length=48, fill=0)
    p384_private[47] = 1
    var p256_output = List[UInt8](length=64, fill=0)
    var p384_output = List[UInt8](length=96, fill=0)
    if p256_public_key(
        Span[UInt8, ...](p256_private),
        Span[mut=True, UInt8, ...](p256_output),
    ):
        raise Error("P-256 public-key API accepted an undersized destination")
    if p384_public_key(
        Span[UInt8, ...](p384_private),
        Span[mut=True, UInt8, ...](p384_output),
    ):
        raise Error("P-384 public-key API accepted an undersized destination")

    var short_signature = List[UInt8](length=63, fill=0)
    var short_signature384 = List[UInt8](length=95, fill=0)
    if p256_ecdsa_sign(
        Span[UInt8, ...](p256_private),
        Span[UInt8, ...](plaintext),
        Span[mut=True, UInt8, ...](short_signature),
    ):
        raise Error("P-256 signing accepted an undersized destination")
    if p384_ecdsa_sign(
        Span[UInt8, ...](p384_private),
        Span[UInt8, ...](plaintext),
        Span[mut=True, UInt8, ...](short_signature384),
    ):
        raise Error("P-384 signing accepted an undersized destination")

    print("Security boundary tests passed")
