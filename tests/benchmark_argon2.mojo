from thistle.argon2 import Argon2id
from time import perf_counter


def main():
    var password = String("password").as_bytes()
    var salt = String("saltsalt").as_bytes()
    
    var duration = 5.0
    
    var ctx = Argon2id(
        salt,
        memory_size_kb=65536,
        iterations=3,
        parallelism=4
    )

    print("Starting throughput test for", duration, "seconds...")
    
    var count = 0
    var start = perf_counter()
    
    while perf_counter() - start < duration:
        _ = ctx.hash(password)
        count += 1
    
    var end = perf_counter()
    var total_time = end - start
    var hashes_per_second = Float64(count) / total_time

    print("Results:")
    print("Total Hashes:     ", count)
    print("Total Time:       ", total_time, "seconds")
    print("Throughput:       ", hashes_per_second, "hashes/sec")

