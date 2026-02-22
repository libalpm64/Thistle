# ===----------------------------------------------------------------------=== #
# Thistle Cryptography Library
# Primary API Entry Point
# ===----------------------------------------------------------------------=== #

from . import fips
from .blake2b import blake2b_hash, Blake2b
from .blake3 import blake3_hash, blake3_parallel_hash, Hasher
from .argon2 import Argon2id, argon2id_hash_string
from .camellia import CamelliaCipher
from .pbkdf2 import pbkdf2_hmac_sha256, pbkdf2_hmac_sha512
from .sha2 import sha256_hash, sha512_hash
from .sha3 import sha3_256, sha3_512
from .kcipher2 import KCipher2
from .random import random_bytes, random_fill
from .ml_dsa_native import mldsa44_keypair_internal, mldsa44_signature, mldsa44_verify
from .ml_dsa_native import MLDSA44_SECRETKEYBYTES, MLDSA44_PUBLICKEYBYTES, MLDSA44_BYTES
from .ml_dsa_native import MLD_ERR_OK, bytes_to_hex_str

comptime VERSION = "1.0.2"
comptime AUTHOR = "Libalpm64, Lostlab Technologies"
