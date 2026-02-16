import hashlib
import time

data = b"\x00" * (1024 * 1024)
iters = 100

print("Python hashlib Benchmark")

start = time.perf_counter()
for _ in range(iters):
    _ = hashlib.sha256(data).digest()
end = time.perf_counter()
duration = end - start
print(f"SHA-256 Speed: {iters / duration:.2f} MiB/s")

start = time.perf_counter()
for _ in range(iters):
    _ = hashlib.sha3_256(data).digest()
end = time.perf_counter()
duration = end - start
print(f"SHA3-256 Speed: {iters / duration:.2f} MiB/s")
