#if defined(_WIN32)
    #include <intrin.h>
       #include <windows.h>
       #include <basetsd.h>
#elif defined(__linux__)
    #include <x86intrin.h>
        #include <pthread.h>
    #include <sched.h>
#else
    #error "RDTSC timing OR Thread affinity not supported on this platform"
#endif

#include <iostream>


inline void pin_thread_to_cpu0() {
#if defined(_WIN32)
    DWORD_PTR mask = 1;
    if (SetThreadAffinityMask(GetCurrentThread(), mask) == 0) {
        std::cerr << "Warning: failed to set thread affinity on Windows\n";
    }
#elif defined(__linux__)
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset); // CPU 0
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0) {
        std::cerr << "Warning: failed to set thread affinity on Linux/Unix\n";
    }
#endif
}


#include "aes_benchmark.h"
#include <algorithm>
#include <numeric>
#include <iostream>
#include <vector>
#include <chrono>
#include <cmath>
#include <functional>



using namespace std;

inline double cycles_to_ns(uint64_t cycles, double cpu_ghz = 3.0) {
    return static_cast<double>(cycles) / cpu_ghz; // cycles / GHz = ns
}

AESBenchmark::AESBenchmark(IAES& iaes) : aes_(iaes) {}

Stats AESBenchmark::benchmark_algorithm(const Block& block, size_t iterations, size_t warmup_iterations, bool encrypt)
{
    std::vector<double> timings;
    timings.reserve(iterations);

    // Select operation (MSVC-safe)
    std::function<void(const Block&)> operation;
    if (encrypt)
        operation = [&](const Block& b) 
        { 
            Block out = aes_.encrypt_block(b); 
            //Without black_hole, an optimizing compiler might notice
            // that encrypt_block/decrypt_block results are never used
            // and skip the calls entirely, giving a wrong benchmark
            sink(out);
        };
    else
        operation = [&](const Block &b)
        { 
            Block out = aes_.decrypt_block(b); 
            sink(out);
        };

    pin_thread_to_cpu0();

    // --- Warmup phase ---
    for (size_t i = 0; i < warmup_iterations; ++i)
        operation(block);

    // --- Benchmarking phase ---
    for (size_t i = 0; i < iterations; ++i)
    {
        uint64_t start_cycles = __rdtsc();
        operation(block);
        uint64_t end_cycles = __rdtsc();

        double duration_ns = cycles_to_ns(end_cycles - start_cycles, 3.0);

        timings.push_back(duration_ns);
    }

    return compute_stats(timings);
}

Stats AESBenchmark::compute_stats(const std::vector<double>& timings) {
    Stats stats{};

    if (timings.empty())
        return stats;

    std::vector<double> sorted_timings = timings;
    std::sort(sorted_timings.begin(), sorted_timings.end());

    size_t n = sorted_timings.size();


    auto percentile = [&](double p) -> double {
        double idx = p * (n - 1);
        size_t i = static_cast<size_t>(idx);
        double frac = idx - i;
        if (i + 1 < n)
            return sorted_timings[i] * (1.0 - frac) + sorted_timings[i + 1] * frac;
        else
            return sorted_timings[i];
    };

    double p05 = percentile(0.05);
    double p25 = percentile(0.25);
    double p50 = percentile(0.50);
    double p75 = percentile(0.75);
    double p95 = percentile(0.95);

    double iqr = p75 - p25;

    // Compute outlier bounds
    double lower_fence = p25 - 3 * iqr;
    double upper_fence = p75 + 3 * iqr;

    std::vector<double> outliers_low, outliers_high;
    for (double v : sorted_timings) {
        if (v < lower_fence)
            outliers_low.push_back(v);
        else if (v > upper_fence)
            outliers_high.push_back(v);
    }

    std::vector<double> trimmed;
    for (double v : sorted_timings) {
        if (v >= p05 && v <= p95)
            trimmed.push_back(v);
    }

    double sum = std::accumulate(trimmed.begin(), trimmed.end(), 0.0);
    double mean_time = sum / trimmed.size();
    double sq_sum = std::inner_product(trimmed.begin(), trimmed.end(), trimmed.begin(), 0.0);
    double stddev_time = std::sqrt(sq_sum / trimmed.size() - mean_time * mean_time);

    double total_data_mb = static_cast<double>(BLOCK_SIZE * trimmed.size()) / (1024 * 1024);
    double total_time_s = std::accumulate(trimmed.begin(), trimmed.end(), 0.0) / 1e9;
    double avg_throughput_mb_s = total_data_mb / total_time_s;

    double latency_ns = mean_time;
    double cpu_frequency_ghz = 3.0;
    double avg_cycles_per_byte = (latency_ns * cpu_frequency_ghz) / BLOCK_SIZE;

    stats.p05_time_ns = p05;
    stats.p25_time_ns = p25;
    stats.median_time_ns = p50;
    stats.p75_time_ns = p75;
    stats.p95_time_ns = p95;
    stats.iqr_ns = iqr;
    stats.mean_time_ns = mean_time;
    stats.stddev_time_ns = stddev_time;
    stats.avg_throughput_mb_s = avg_throughput_mb_s;
    stats.avg_cycles_per_byte = avg_cycles_per_byte;
    stats.outliers_low = std::move(outliers_low);
    stats.outliers_high = std::move(outliers_high);

    return stats;
}


Stats AESBenchmark::benchmark_step(AESOperation step, const Block &block, size_t iterations, size_t warmup_iterations)
{
    std::vector<double> timings;
    timings.reserve(iterations);

    // Identify concrete AES implementation
    auto* aes_naive  = dynamic_cast<AesNaive*>(&aes_);
    auto* aes_ttable = dynamic_cast<AesTTable*>(&aes_);
    auto* aes_ni     = dynamic_cast<AesAESNI*>(&aes_);

    // Define the operation function (captures AES instance)
    std::function<void(State&)> op_func;
    State st{}; // Initialize state outside the loop

    if (aes_naive)
    {
        st = aes_naive->bytes_to_state(block); // Initialize once

        op_func = [&](State &s)
        {
            switch (step)
            {
            case AESOperation::SubBytes:
                aes_naive->sub_bytes(s);
                break;
            case AESOperation::ShiftRows:
                aes_naive->shift_rows(s);
                break;
            case AESOperation::MixColumns:
                aes_naive->mix_columns(s);
                break;
            case AESOperation::AddRoundKey:
                aes_naive->add_round_key(s, aes_naive->get_round_key(0));
                break;
            case AESOperation::MixColumnsFast:
                aes_naive->mix_columns_fast(st);
                break;
            case AESOperation::InvSubBytes:
                aes_naive->inv_sub_bytes(st);
                break;
            case AESOperation::InvShiftRows:
                aes_naive->inv_shift_rows(st);
                break;
            case AESOperation::InvMixColumns:
                aes_naive->inv_mix_columns(st);
                break;
            case AESOperation::KeyExpansionNaive:
                aes_naive->key_expansion(aes_naive->key_);
                break;
                // case AESOperation::GFMul:          aes_naive->GF_mul(0x57, 0x83); break;

            case AESOperation::EncryptBlock:
                aes_naive->encrypt_block(block);
                break;
            case AESOperation::DecryptBlock:
                aes_naive->decrypt_block(block);
            default:
                break;
            }
        };
    }
    else if (aes_ttable)
    {
        op_func = [&](State &)
        {
            switch (step)
            {
            case AESOperation::InitTables:
                aes_ttable->initTables();
                break;
            case AESOperation::KeyExpansionTTable:
                aes_ttable->key_expansion(aes_ttable->key_);
                break;

            case AESOperation::EncryptBlock:
                aes_ttable->encrypt_block(block);
                break;
            case AESOperation::DecryptBlock:
                aes_ttable->decrypt_block(block);
                break;

            default:
                break;
            }
        };
    }
    else if (aes_ni)
    {
        op_func = [&](State &)
        {
            switch (step)
            {
            case AESOperation::KeyExpansionNI:
                aes_ni->expand_key(aes_ni->key_, aes_ni->enc_keys_);
                break;
            case AESOperation::KeyDecryptNI:
                aes_ni->expand_key_decrypt(aes_ni->dec_keys_, aes_ni->enc_keys_);
                break;

            case AESOperation::EncryptBlock:
                aes_ni->encrypt_block(block);
                break;
            case AESOperation::DecryptBlock:
                aes_ni->decrypt_block(block);
                break;

            default:
                break;
            }
        };
    }
    else
    {
        op_func = [](State &) {};
    }

    // WARMUP PHASE
    for (size_t i = 0; i < warmup_iterations; ++i)
    {
        op_func(st);
    }

    // BENCHMARKING PHASE
    for (size_t i = 0; i < iterations; ++i)
    {
        auto start = std::chrono::high_resolution_clock::now();
        op_func(st);
        auto end = std::chrono::high_resolution_clock::now();

        timings.push_back(std::chrono::duration<double, std::nano>(end - start).count());
    }
    return compute_stats(timings);
}

Stats AESBenchmark::benchmark_encrypt(const Block& block, size_t iterations, size_t warmup_iterations)
{
    return benchmark_algorithm(block, iterations, warmup_iterations, true);
}

Stats AESBenchmark::benchmark_decrypt(const Block &block, size_t iterations, size_t warmup_iterations)
{
    return benchmark_algorithm(block, iterations, warmup_iterations, false);
}