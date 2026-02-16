import json
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def generate_vectors(count=100):
    vectors = []
    backend = default_backend()
    
    key_lengths = [16, 24, 32]
    
    for _ in range(count):
        key_len = secrets.choice(key_lengths)
        key = secrets.token_bytes(key_len)
        plaintext = secrets.token_bytes(16)
        
        cipher = Cipher(algorithms.Camellia(key), modes.ECB(), backend=backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        vectors.append({
            "key": key.hex(),
            "plaintext": plaintext.hex(),
            "ciphertext": ciphertext.hex()
        })
    
    return vectors

if __name__ == "__main__":
    print("Generating 100 random Camellia test vectors...")
    vectors = generate_vectors(100)
    
    output_path = "tests/camellia_random_vectors.json"
    with open(output_path, "w") as f:
        json.dump(vectors, f, indent=2)
    
    print(f"Successfully saved vectors to {output_path}")
