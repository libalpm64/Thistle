import json
import binascii
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("Error: 'cryptography' library not found. Please install it with 'pip install cryptography'.")
    exit(1)

def generate_camellia_vectors():
    test_cases = []
    
    # 1. Official RFC 3713 Vectors (Basic 128-bit)
    # Key: 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
    # Plaintext: 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
    # Ciphertext: 67 67 31 38 54 96 69 73 08 57 06 56 48 ea be 43
    test_cases.append({
        "name": "RFC 3713 128-bit",
        "key": "0123456789abcdeffedcba9876543210",
        "plaintext": "0123456789abcdeffedcba9876543210",
        "ciphertext": "67673138549669730857065648eabe43"
    })

    # 2. 192-bit Key
    # Key: 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10 00 11 22 33 44 55 66 77
    # Plaintext: 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
    # Expected Ciphertext (calculated via cryptography library)
    key_192 = binascii.unhexlify("0123456789abcdeffedcba98765432100011223344556677")
    pt = binascii.unhexlify("0123456789abcdeffedcba9876543210")
    cipher = Cipher(algorithms.Camellia(key_192), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ct_192 = encryptor.update(pt) + encryptor.finalize()
    test_cases.append({
        "name": "192-bit Key",
        "key": binascii.hexlify(key_192).decode(),
        "plaintext": binascii.hexlify(pt).decode(),
        "ciphertext": binascii.hexlify(ct_192).decode()
    })

    # 3. 256-bit Key
    key_256 = binascii.unhexlify("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff")
    cipher = Cipher(algorithms.Camellia(key_256), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ct_256 = encryptor.update(pt) + encryptor.finalize()
    test_cases.append({
        "name": "256-bit Key",
        "key": binascii.hexlify(key_256).decode(),
        "plaintext": binascii.hexlify(pt).decode(),
        "ciphertext": binascii.hexlify(ct_256).decode()
    })

    # 4. Large Data Set (Iterative or Randomized)
    for i in range(10):
        key = binascii.unhexlify(f"{i:02x}" * 16)
        plaintext = binascii.unhexlify(f"{(i+1):02x}" * 16)
        cipher = Cipher(algorithms.Camellia(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        test_cases.append({
            "name": f"Generated Case {i}",
            "key": binascii.hexlify(key).decode(),
            "plaintext": binascii.hexlify(plaintext).decode(),
            "ciphertext": binascii.hexlify(ciphertext).decode()
        })

    with open('tests/camellia_test_vectors', 'w') as f:
        json.dump(test_cases, f, indent=4)
    print(f"Generated {len(test_cases)} test vectors in tests/camellia_test_vectors")

if __name__ == "__main__":
    generate_camellia_vectors()
