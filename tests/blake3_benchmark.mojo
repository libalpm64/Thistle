from time import perf_counter_ns
from collections import List
from random import random_ui64, seed
from thistle.blake3 import blake3_parallel_hash
from math import sqrt
from algorithm import parallelize

fn generate_fixed_data(length: Int) -> List[UInt8]:
    var data = List[UInt8](capacity=length)
    for _ in range(length):
        data.append(0)
    return data^

fn measure_throughput() raises:
    comptime BATCH_SIZE = 128 * 1024 * 1024
    # Num Of Cores
    comptime NUM_WORKERS = 8
    
    print("Starting Throughput Test...")
    
    var data = generate_fixed_data(BATCH_SIZE)
    var data_span = Span(data)

    var start = perf_counter_ns()
    
    @parameter
    fn worker(i: Int):
        # Prevent compiler from nuking this
        _ = blake3_parallel_hash(data_span)

    parallelize[worker](NUM_WORKERS)
    
    var end = perf_counter_ns()
    
    var total_seconds = Float64(end - start) / 1_000_000_000.0
    var total_bytes = Float64(BATCH_SIZE) * Float64(NUM_WORKERS)
    var gbs = (total_bytes / 1_000_000_000.0) / total_seconds

    print("Throughput: ", gbs, " GB/s")
    print("Total Time: ", total_seconds, " s")
    print("Total Data: ", total_bytes / 1_000_000_000.0, " GB")

fn main() raises:
    seed() 
    
    comptime DATA_SIZE = 1024 * 1024
    comptime TRIALS = 30000 
    
    var data_a = generate_fixed_data(DATA_SIZE)
    var data_b = generate_fixed_data(DATA_SIZE)
    
    var times_a = List[Float64]()
    var times_b = List[Float64]()

    print("Running Differential Timing Test (" + String(TRIALS) + " trials)...")

    for i in range(TRIALS):
        var coin = random_ui64(0, 1)
        var data_span = Span(data_a) if coin == 0 else Span(data_b)
        
        var start = perf_counter_ns()
        _ = blake3_parallel_hash(data_span)
        var end = perf_counter_ns()
        
        if coin == 0:
            times_a.append(Float64(end - start))
        else:
            times_b.append(Float64(end - start))

    var mean_a: Float64 = 0
    var mean_b: Float64 = 0
    
    for t in times_a: mean_a += t
    for t in times_b: mean_b += t
    
    mean_a /= len(times_a)
    mean_b /= len(times_b)

    var var_a: Float64 = 0
    var var_b: Float64 = 0
    for t in times_a: var_a += (t - mean_a)**2
    for t in times_b: var_b += (t - mean_b)**2
    
    var_a /= (len(times_a) - 1)
    var_b /= (len(times_b) - 1)

    var t_stat = (mean_a - mean_b) / sqrt(var_a/len(times_a) + var_b/len(times_b))

    print("T-Statistic: ", t_stat)

    measure_throughput()