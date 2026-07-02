# Thistle public API

from . import fips
from .aes import AESKey, expand_key_128, expand_key_192, expand_key_256, SBOX, ROUNDS_128
from .aes import gf_mul2, gf_mul3, sbox_lookup, sub_word
from .aes import ttable0, ttable1, ttable2, ttable3
from .aes_gpu import aes_gpu_kernel_ecb, aes_gpu_kernel_ctr, aes_gpu_kernel_gcm
from .aes_ni import has_aes_ni, has_x86_aes_ni, has_arm_crypto
from .aes_ni import arm_aes_encrypt_128, arm_aes_encrypt_192, arm_aes_encrypt_256
from .aes_ni import x86_aes_encrypt_128, x86_aes_encrypt_256
from .blake2b import blake2b_hash, Blake2b
from .blake3 import blake3_hash, blake3_parallel_hash, Hasher
from .argon2 import Argon2id, argon2id_hash_string
from .camellia import CamelliaCipher
from .pbkdf2 import pbkdf2_hmac_sha256, pbkdf2_hmac_sha512
from .sha2 import sha256_hash, sha512_hash
from .sha3 import sha3_256, sha3_512
from .kcipher2 import KCipher2
from .random import random_bytes, random_fill
from .ml_dsa import mldsa44_keygen, mldsa65_keygen, mldsa87_keygen
from .ml_dsa import mldsa_sign, mldsa_verify
from .ml_dsa import MLDSA44_SECRETKEYBYTES, MLDSA44_PUBLICKEYBYTES, MLDSA44_BYTES
from .ml_kem import mlkem512_keygen, mlkem768_keygen, mlkem1024_keygen
from .ml_kem import mlkem512_encaps, mlkem768_encaps, mlkem1024_encaps
from .ml_kem import mlkem512_decaps, mlkem768_decaps, mlkem1024_decaps

comptime VERSION = "1.0.4"
comptime AUTHOR = "Libalpm64, Lostlab Technologies"
