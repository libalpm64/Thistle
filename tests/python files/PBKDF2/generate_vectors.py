#!/usr/bin/env python3
"""
PBKDF2 Test Vector Generator
Generates test vectors for PBKDF2-HMAC-SHA256 and PBKDF2-HMAC-SHA512
Based on RFC 6070 and NIST SP 800-132
"""

import hashlib
import json
import os

def pbkdf2_sha256(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password, salt, iterations, dklen)

def pbkdf2_sha512(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    return hashlib.pbkdf2_hmac('sha512', password, salt, iterations, dklen)

def generate_vectors():
    vectors = {
        "sha256": [],
        "sha512": []
    }
    
    test_cases = [
        (b"password", b"salt", 1, 20),
        (b"password", b"salt", 2, 20),
        (b"password", b"salt", 4096, 20),
        (b"passwordPASSWORDpassword", b"saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25),
        (b"pass\x00word", b"sa\x00lt", 4096, 16),
        (b"password", b"salt", 1, 32),
        (b"password", b"salt", 1, 64),
        (b"test", b"test", 1000, 32),
        (b"test", b"test", 1000, 64),
        (b"", b"salt", 1, 32),
        (b"password", b"", 1, 32),
        (b"longpassword" * 10, b"salt", 100, 32),
        (b"pwd", b"salt" * 20, 10, 48),
    ]
    
    for password, salt, iterations, dklen in test_cases:
        dk256 = pbkdf2_sha256(password, salt, iterations, dklen)
        vectors["sha256"].append({
            "password": password.hex(),
            "password_ascii": password.decode('latin-1', errors='replace') if all(b < 128 for b in password) else None,
            "salt": salt.hex(),
            "iterations": iterations,
            "dklen": dklen,
            "derived_key": dk256.hex()
        })
        
        dk512 = pbkdf2_sha512(password, salt, iterations, dklen)
        vectors["sha512"].append({
            "password": password.hex(),
            "password_ascii": password.decode('latin-1', errors='replace') if all(b < 128 for b in password) else None,
            "salt": salt.hex(),
            "iterations": iterations,
            "dklen": dklen,
            "derived_key": dk512.hex()
        })
    
    return vectors

def main():
    vectors = generate_vectors()
    
    output_dir = os.path.dirname(os.path.abspath(__file__))
    vectors_dir = os.path.join(os.path.dirname(output_dir), "..", "PBKDF2_vectors")
    os.makedirs(vectors_dir, exist_ok=True)
    
    with open(os.path.join(vectors_dir, "pbkdf2_sha256_vectors.json"), "w") as f:
        json.dump(vectors["sha256"], f, indent=2)
    
    with open(os.path.join(vectors_dir, "pbkdf2_sha512_vectors.json"), "w") as f:
        json.dump(vectors["sha512"], f, indent=2)
    
    print(f"Generated {len(vectors['sha256'])} SHA-256 vectors")
    print(f"Generated {len(vectors['sha512'])} SHA-512 vectors")
    print(f"Output directory: {vectors_dir}")

if __name__ == "__main__":
    main()