import argon2
import time

def main():
    password = b"password"
    salt = b"saltsalt"
    duration = 5
    
    hasher = argon2.PasswordHasher(
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=argon2.low_level.Type.ID
    )

    print(f"Starting throughput test for {duration} seconds...")
    
    count = 0
    start_time = time.perf_counter()
    
    while time.perf_counter() - start_time < duration:
        hasher.hash(password, salt=salt)
        count += 1
    
    end_time = time.perf_counter()
    total_time = end_time - start_time
    hashes_per_second = count / total_time

    print("Results:")
    print(f"Total Hashes:      {count}")
    print(f"Total Time:        {total_time:.4f} seconds")
    print(f"Throughput:        {hashes_per_second:.2f} hashes/sec")

if __name__ == "__main__":
    main()