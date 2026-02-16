from sys import external_call
from sys.ffi import c_int, c_ssize_t, get_errno
from memory import UnsafePointer
from collections import List
from time import perf_counter_ns

comptime AF_ALG = 38
comptime SOCK_SEQPACKET = 5
comptime SOL_ALG = 279
comptime ALG_SET_KEY = 1

"""
Failed Syscall Test (Most Linux Distros don't expose the crypto interface it's internal use).
"""

@fieldwise_init
struct sockaddr_alg:
    var salg_family: UInt16
    var salg_type: SIMD[DType.uint8, 14]
    var salg_feat: UInt32
    var salg_mask: UInt32
    var salg_name: SIMD[DType.uint8, 64]

    fn __init__(out self, type_name: String, alg_name: String):
        self.salg_family = AF_ALG
        self.salg_type = SIMD[DType.uint8, 14](0)
        var t_bytes = type_name.as_bytes()
        for i in range(min(len(t_bytes), 14)):
            self.salg_type[i] = t_bytes[i]
        self.salg_feat = 0
        self.salg_mask = 0
        self.salg_name = SIMD[DType.uint8, 64](0)
        var a_bytes = alg_name.as_bytes()
        for i in range(min(len(a_bytes), 64)):
            self.salg_name[i] = a_bytes[i]


def main():
    var fd = external_call["socket", c_int](
        c_int(AF_ALG), c_int(SOCK_SEQPACKET), c_int(0)
    )

    if fd < 0:
        print("AF_ALG Socket failed.")
        return
    print("Socket opened. FD:", fd)

    var sa = sockaddr_alg("skcipher", "ecb(camellia)")
    var sa_ptr = UnsafePointer[sockaddr_alg](to=sa)

    var bind_res = external_call["bind", c_int](fd, sa_ptr, c_int(88))
    if bind_res < 0:
        print("Bind failed. Result:", bind_res, "errno:", get_errno())
        _ = external_call["close", c_int](fd)
        return
    print("Bind successful.")

    var key = List[UInt8]()
    for i in range(16):
        key.append(i)
    var key_ptr = UnsafePointer[UInt8](to=key[0])

    var setkey_res = external_call["setsockopt", c_int](
        fd, c_int(SOL_ALG), c_int(ALG_SET_KEY), key_ptr, c_int(16)
    )
    if setkey_res < 0:
        print("Setkey failed.")
        _ = external_call["close", c_int](fd)
        return
    print("Key set.")

    var null_ptr = UnsafePointer[UInt8, MutExternalOrigin]()
    var op_fd = external_call["accept", c_int](fd, null_ptr, null_ptr)

    if op_fd < 0:
        print("Accept failed.")
        _ = external_call["close", c_int](fd)
        return
    print("Session accepted. OP_FD:", op_fd)

    print("Starting benchmark...")
    var data = SIMD[DType.uint8, 16](0)
    var data_ptr = UnsafePointer[SIMD[DType.uint8, 16]](to=data)
    var op_fd_int = Int(op_fd)

    comptime ITERATIONS = 100000
    var start = perf_counter_ns()

    for _ in range(ITERATIONS):
        _ = external_call["write", c_ssize_t](op_fd_int, data_ptr, 16)
        _ = external_call["read", c_ssize_t](op_fd_int, data_ptr, 16)

    var end = perf_counter_ns()

    var total_time_ms = Float64(end - start) / 1e6
    var seconds = total_time_ms / 1000.0
    var total_mb = (Float64(ITERATIONS) * 16.0) / 1024.0 / 1024.0

    print("--- Results ---")
    print("Time:", total_time_ms, "ms")
    print("Throughput:", total_mb / seconds, "MB/s")

    _ = external_call["close", c_int](op_fd)
    _ = external_call["close", c_int](fd)