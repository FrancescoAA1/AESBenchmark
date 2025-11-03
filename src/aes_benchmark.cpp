#include "aes_benchmark.h"
#include <algorithm>
#include <numeric>
#include <iostream>
#include <vector>
#include <chrono>
#include <cmath>
#include <functional>

using namespace std;


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

    return compute_stats(timings);
}

Stats AESBenchmark::compute_stats(const std::vector<double>& timings)
{
    Stats stats{};  // will hold the results

    if (timings.empty())
        return stats;

    // Calculate statistics
    double min_time = *std::min_element(timings.begin(), timings.end());
    double max_time = *std::max_element(timings.begin(), timings.end());
    double avg_time = std::accumulate(timings.begin(), timings.end(), 0.0) / timings.size();

    std::vector<double> sorted_timings = timings;
    std::sort(sorted_timings.begin(), sorted_timings.end());
    double median_time = (sorted_timings.size() % 2 == 0) ?
                         (sorted_timings[sorted_timings.size() / 2 - 1] + sorted_timings[sorted_timings.size() / 2]) / 2 :
                         sorted_timings[sorted_timings.size() / 2];

    double sq_sum = std::inner_product(timings.begin(), timings.end(), timings.begin(), 0.0);
    double stddev_time = std::sqrt(sq_sum / timings.size() - avg_time * avg_time);

    double total_data_mb = static_cast<double>(BLOCK_SIZE * timings.size()) / (1024 * 1024);
    double total_time_s = std::accumulate(timings.begin(), timings.end(), 0.0) / 1e9;
    double avg_throughput_mb_s = total_data_mb / total_time_s;

    double latency_ns = avg_time;
    double cpu_frequency_ghz = 3.0; // to be measured precisely
    double avg_cycles_per_byte = (latency_ns * cpu_frequency_ghz) / BLOCK_SIZE;

    // Store computed values in the struct before returning
    stats.min_time_ns = min_time;
    stats.max_time_ns = max_time;
    stats.avg_time_ns = avg_time;
    stats.median_time_ns = median_time;
    stats.stddev_time_ns = stddev_time;
    stats.avg_throughput_mb_s = avg_throughput_mb_s;
    stats.latency_ns = latency_ns;
    stats.avg_cycles_per_byte = avg_cycles_per_byte;

    return stats;
}

Stats AESBenchmark::benchmark_step(AESOperation step, const Block& block, 
                                   size_t iterations, size_t warmup_iterations)
{
    std::vector<double> timings;
    timings.reserve(iterations);

    // Identify concrete AES implementation
    auto* aes_naive  = dynamic_cast<AesNaive*>(&aes_);
    auto* aes_ttable = dynamic_cast<AesTTable*>(&aes_);
    auto* aes_ni     = dynamic_cast<AesAESNI*>(&aes_);

    // Define the operation function (captures AES instance)
    std::function<void(State&)> op_func;

    if (aes_naive) {
        op_func = [&](State& st) {
            switch(step) {
                case AESOperation::SubBytes:       aes_naive->sub_bytes(st); break;
                case AESOperation::ShiftRows:      aes_naive->shift_rows(st); break;
                case AESOperation::MixColumns:     aes_naive->mix_columns(st); break;
                case AESOperation::AddRoundKey:    aes_naive->add_round_key(st, aes_naive->get_round_key(0)); break;
                case AESOperation::MixColumnsFast: aes_naive->mix_columns_fast(st); break;
                case AESOperation::InvSubBytes:    aes_naive->inv_sub_bytes(st); break;
                case AESOperation::InvShiftRows:   aes_naive->inv_shift_rows(st); break;
                case AESOperation::InvMixColumns:  aes_naive->inv_mix_columns(st); break;
                case AESOperation::KeyExpansion:   aes_naive->key_expansion(aes_naive->key_); break;
                case AESOperation::GFMul:          aes_naive->GF_mul(0x57, 0x83); break;
                case AESOperation::EncryptBlock:  aes_naive->encrypt_block(block); break;
            }
        };
    } 
    else {
        // For TTable and NI, provide empty lambda
        op_func = [](State&) {};
    }

// WARMUP PHASE
    for (size_t i = 0; i < warmup_iterations; ++i) {
        if (aes_naive) {
            State st = aes_naive->bytes_to_state(block);
            op_func(st);
        }
        else {
            cout << "Benchmarking step not implemented for this AES implementation.\n";
        }
    }

    // BENCHMARKING PHASE
    for (size_t i = 0; i < iterations; ++i) {
        State st; 
        if (aes_naive) 
        {
            st = aes_naive->bytes_to_state(block);

        auto start = std::chrono::high_resolution_clock::now();
        op_func(st);
        auto end = std::chrono::high_resolution_clock::now();

        timings.push_back(std::chrono::duration<double, std::nano>(end - start).count());
        }
        else {
            cout << "Benchmarking step not implemented for this AES implementation.\n";
        }
    }

    return compute_stats(timings);
}