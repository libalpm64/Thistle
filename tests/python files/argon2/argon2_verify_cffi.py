from argon2 import low_level
import hashlib

def test_argon2_cffi():
    pwd = b"password"
    salt = b"somesalt"
    secret = b"\x03" * 8
    ad = b"\x04" * 12
    
    # Argon2id
    # time_cost=2, memory_cost=1024, parallelism=1, hash_len=32, version=0x13 (19)
    hash = low_level.hash_secret_raw(
        secret=pwd,
        salt=salt,
        time_cost=2,
        memory_cost=1024,
        parallelism=1,
        hash_len=32,
        type=low_level.Type.ID,
        version=19
    )
    print(f"Argon2 Tag (no secret/ad): {hash.hex()}")

if __name__ == "__main__":
    test_argon2_cffi()
