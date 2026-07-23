"""
Thistle public API.
"""

from .sha2 import sha224_hash, sha256_hash, sha384_hash, sha512_hash
from .sha2 import SHA256Context, SHA512Context
from .sha3 import sha3_224, sha3_256, sha3_384, sha3_512, shake128, shake256
from .sha_ni import sha256ni_hash, has_sha_ni
from .blake2b import blake2b_hash, blake2b_hash_keyed, Blake2b
from .blake3 import blake3_hash, blake3_parallel_hash, Hasher

from .pbkdf2 import hmac_sha256, hmac_sha384, hmac_sha512
from .pbkdf2 import pbkdf2_hmac_sha256, pbkdf2_hmac_sha512
from .argon2 import Argon2id, argon2id_hash_string

from .aes import AESKey, expand_key_128, expand_key_192, expand_key_256
from .aes_ni import has_aes_ni, aes_gcm_ctr_kernel, aes_gcm_encrypt, aes_gcm_decrypt, AESGCMContext
from .aes_gpu import aes_gpu_kernel_ecb, aes_gpu_kernel_ctr, aes_gpu_kernel_gcm_ctr
from .camellia import CamelliaCipher
from .chacha20 import ChaCha20, chacha20_block
from .poly1305 import Poly1305, poly1305_mac
from .chacha20poly1305 import (
    chacha20_poly1305_encrypt, chacha20_poly1305_decrypt,
    xchacha20_poly1305_encrypt, xchacha20_poly1305_decrypt,
    hchacha20,
)
from .kcipher2 import KCipher2

from .x25519 import x25519, x25519_public_key, x25519_keygen
from .ed25519 import ed25519_generate_public_key, ed25519_sign, ed25519_verify, Ed25519SigningKey
from .p256 import (
    p256_public_key, p256_ecdh, p256_keygen,
    p256_ecdsa_sign, p256_ecdsa_sign_digest,
    p256_ecdsa_verify, p256_ecdsa_verify_digest,
    p256_ecdsa_sign_der, p256_ecdsa_verify_der,
    P256_SIZE, P256_POINT_SIZE, P256_SIGNATURE_SIZE,
)
from .p384 import (
    p384_public_key, p384_ecdh, p384_keygen,
    p384_ecdsa_sign, p384_ecdsa_sign_digest,
    p384_ecdsa_verify, p384_ecdsa_verify_digest,
    p384_ecdsa_sign_der, p384_ecdsa_verify_der,
    P384_SIZE, P384_POINT_SIZE, P384_SIGNATURE_SIZE,
)
from .rsa import (
    RsaPublicKey, RsaPrivateKey, RsaCrtPrivateKey,
    rsa_pss_verify, rsa_pss_sha256_verify,
    rsa_pss_sha384_verify, rsa_pss_sha512_verify,
    rsa_pss_sign, rsa_pss_sign_with_salt,
    rsa_pss_sha256_sign, rsa_pss_sha384_sign, rsa_pss_sha512_sign,
    rsa_pss_crt_sign, rsa_pss_crt_sign_with_salt,
    rsa_pss_crt_sha256_sign, rsa_pss_crt_sha384_sign,
    rsa_pss_crt_sha512_sign,
    rsa_pkcs1_v15_verify, rsa_pkcs1_v15_sha1_verify,
    rsa_pkcs1_v15_sha256_verify, rsa_pkcs1_v15_sha384_verify,
    rsa_pkcs1_v15_sha512_verify,
)

from .ml_kem import mlkem512_keygen, mlkem768_keygen, mlkem1024_keygen
from .ml_kem import mlkem512_encaps, mlkem768_encaps, mlkem1024_encaps
from .ml_kem import mlkem512_decaps, mlkem768_decaps, mlkem1024_decaps
from .ml_kem import (
    MLKEM512_PUBLICKEYBYTES, MLKEM512_SECRETKEYBYTES, MLKEM512_CIPHERTEXTBYTES,
    MLKEM768_PUBLICKEYBYTES, MLKEM768_SECRETKEYBYTES, MLKEM768_CIPHERTEXTBYTES,
    MLKEM1024_PUBLICKEYBYTES, MLKEM1024_SECRETKEYBYTES, MLKEM1024_CIPHERTEXTBYTES,
    MLKEM_BYTES,
)
from .ml_dsa import mldsa44_keygen, mldsa65_keygen, mldsa87_keygen
from .ml_dsa import mldsa_sign, mldsa_sign_hedged, mldsa_sign_deterministic, mldsa_verify
from .ml_dsa import mldsa44_public_key, mldsa65_public_key, mldsa87_public_key
from .ml_dsa import (
    MLDSA44_PUBLICKEYBYTES, MLDSA44_SECRETKEYBYTES, MLDSA44_BYTES,
    MLDSA65_PUBLICKEYBYTES, MLDSA65_SECRETKEYBYTES, MLDSA65_BYTES,
    MLDSA87_PUBLICKEYBYTES, MLDSA87_SECRETKEYBYTES, MLDSA87_BYTES,
)

from .random import random_bytes, random_fill

from . import fips

comptime VERSION = "1.0.4"
