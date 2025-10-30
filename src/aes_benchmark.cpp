#include "aes_benchmark.h"
#include <algorithm>
#include <numeric>

AESBenchmark::AESBenchmark(IAES& iaes) : aes_(iaes) {}

Stats AESBenchmark::benchmark_algorithm(const Block& block, size_t iterations, size_t warmup_iterations)
{
    //why not an array? because we need to reserve a non-fixed size of elements at runtime
    std::vector<double> timings;
    timings.reserve(iterations);

    // Warmup phase
    for (size_t i = 0; i < warmup_iterations; ++i)
    {
        aes_.encrypt_block(block);
    }

    // Benchmarking phase
    for (size_t i = 0; i < iterations; ++i)
    {
        auto start = std::chrono::high_resolution_clock::now();
        aes_.encrypt_block(block);
        auto end = std::chrono::high_resolution_clock::now();

        double duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        timings.push_back(duration_ns);
    }

    // Calculate statistics
    double min_time = *std::min_element(timings.begin(), timings.end());
    double max_time = *std::max_element(timings.begin(), timings.end());
    double avg_time = std::accumulate(timings.begin(), timings.end(), 0.0) / iterations;

    std::sort(timings.begin(), timings.end());
    double median_time = (iterations % 2 == 0) ?
                         (timings[iterations / 2 - 1] + timings[iterations / 2]) / 2 :
                         timings[iterations / 2];

    double sq_sum = std::inner_product(timings.begin(), timings.end(), timings.begin(), 0.0);
    double stddev_time = std::sqrt(sq_sum / iterations - avg_time * avg_time);

    double total_data_mb = static_cast<double>(BLOCK_SIZE * iterations) / (1024 * 1024);
    double total_time_s = std::accumulate(timings.begin(), timings.end(), 0.0) / 1e9;
    double avg_throughput_mb_s = total_data_mb / total_time_s;

    double latency_ns = avg_time;
    double cpu_frequency_ghz = 3.0;//to be computed well
    double avg_cycles_per_byte = (latency_ns * cpu_frequency_ghz) / BLOCK_SIZE;

    return Stats{
        min_time,
        max_time,
        avg_time,
        median_time,
        stddev_time,
        avg_throughput_mb_s,
        latency_ns,
        avg_cycles_per_byte
    };
}

