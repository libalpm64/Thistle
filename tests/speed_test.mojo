from time import perf_counter
from blake3 import blake3_parallel_hash
from collections import List


fn print_speed_report(
    name: String, total_iters: Int, total_time: Float64, mb_per_op: Float64
):
    var ops_per_sec = Float64(total_iters) / total_time
    var mb_per_sec = ops_per_sec * mb_per_op
    print("  Runtime:    ", total_time, "s")
    print("  Total Ops:  ", total_iters)
    print("  Throughput: ", ops_per_sec, " ops/sec")
    print("  Bandwidth:  ", mb_per_sec, " MB/s")


fn main() raises:
    comptime BENCH_DURATION = 30.0
    var test_size_mb = 100.0
    var test_len = Int(test_size_mb * 1024 * 1024)

    # Pre-allocate input buffer
    var input_data = List[UInt8](capacity=test_len)
    for i in range(test_len):
        input_data.append(UInt8(i % 256))
    var input_span = Span[UInt8](input_data)

    print(
        "Starting BLAKE3 speed benchmark (",
        test_size_mb,
        "MB per iteration)...",
    )

    var iter_count = 0
    var start_time = perf_counter()

    while (perf_counter() - start_time) < BENCH_DURATION:
        var hash_res = blake3_parallel_hash(input_span)
        # prevent compiler from optimizing away (DCE)
        _ = hash_res
        iter_count += 1

    var end_time = perf_counter()
    print_speed_report(
        "BLAKE3", iter_count, end_time - start_time, test_size_mb
    )
