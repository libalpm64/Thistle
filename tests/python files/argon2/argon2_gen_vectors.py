from argon2 import low_level
import binascii

def generate_vectors():
    params = [
        # (p, m, t, version, type)
        (1, 1024, 2, 0x13, low_level.Type.ID),
        (4, 2048, 3, 0x13, low_level.Type.ID),
        (1, 1024, 2, 0x10, low_level.Type.ID),
    ]
    
    pwd = b"password"
    salt = b"somesalt"
    
    print("Argon2 Mojo Test Vectors")
    print("========================")
    
    for p, m, t, v, type_ in params:
        tag = low_level.hash_secret_raw(
            secret=pwd,
            salt=salt,
            time_cost=t,
            memory_cost=m,
            parallelism=p,
            hash_len=32,
            type=type_,
            version=v
        )
        type_str = "ID" if type_ == low_level.Type.ID else "D" if type_ == low_level.Type.D else "I"
        print(f"CASE: p={p}, m={m}, t={t}, v={hex(v)}, type={type_str}")
        print(f"PWD: {pwd.decode()}")
        print(f"SALT: {salt.decode()}")
        print(f"TAG: {tag.hex()}")
        print("-" * 20)

if __name__ == "__main__":
    generate_vectors()
