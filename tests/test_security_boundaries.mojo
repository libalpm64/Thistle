from std.collections import List

from thistle.aes import AESExpandedKey
from thistle.argon2 import variable_length_hash_into
from thistle.chacha20poly1305 import (
    chacha20_poly1305_encrypt,
    hchacha20,
)
from thistle.p256 import p256_ecdsa_sign, p256_public_key
from thistle.p384 import p384_ecdsa_sign, p384_public_key
from thistle.x25519 import x25519


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
