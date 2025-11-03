#pragma once
#include <cstdint>
#include <chrono>
#include <vector>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>
#include <algorithm>
#include "aes_constants.h"
#include "aes_aesni.h"
#include "aes.h"
#include "aes_ttable.h"
#include "aes_naive.h"

struct Stats
{
    double min_time_ns;
    double max_time_ns;
    double avg_time_ns;

    double median_time_ns;
    double stddev_time_ns;

    double avg_throughput_mb_s;
    double latency_ns;
    double avg_cycles_per_byte;

    // std::string to_string(const std::string& aes_name) const
    // {
    //     return aes_name +
    //     std::to_string(min_time_ns) + "," +
    //     std::to_string(max_time_ns) + "," +
    //     std::to_string(avg_time_ns) + "," +
    //     std::to_string(median_time_ns) + "," +
    //     std::to_string(stddev_time_ns) + "," +
    //     std::to_string(avg_throughput_mb_s) + "," +
    //     std::to_string(latency_ns) + "," +
    //     std::to_string(avg_cycles_per_byte) + "\n";
    // }

std::string to_string(const std::string &aes_name) const
{
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);

    oss << aes_name << "\r\n"
        << "Min(ns): " << min_time_ns << "ns \r\n"
        << "Max(ns): " << max_time_ns << "ns \r\n"
        << "Avg(ns): " << avg_time_ns << "ns \r\n"
        << "Median(ns): " << median_time_ns << "ns \r\n"
        << "StdDev(ns): " << stddev_time_ns << "ns \r\n"
        << "Throughput(MB/s): " << avg_throughput_mb_s << "ns \r\n"
        << "Latency(ns): " << latency_ns << "ns \r\n"
        << "Cycles/byte: " << avg_cycles_per_byte << "ns \n";

    return oss.str();
}
};

enum class AESOperation {

    //Common operations
    EncryptBlock,
    DecryptBlock,

    //AES Naive operations

    //Encrytpion
    SubBytes,
    ShiftRows,
    MixColumns,
    MixColumnsFast,
    AddRoundKey,
    KeyExpansionNaive,

    //Decryption
    InvSubBytes,
    InvShiftRows,
    InvMixColumns,

    //Helpers
    GFMul,

    //AES TTable operations
    InitTables,
    KeyExpansionTTable,

    //AES-NI operations
    KeyExpansionNI,
    KeyDecryptNI,
};

class AESBenchmark
{
public:
    AESBenchmark(IAES &iaes);

    // Benchmark a specific step method of AesNaive
    Stats benchmark_step(AESOperation step, const Block& block, 
                                   size_t iterations, size_t warmup_iterations);

    Stats benchmark_encrypt(const Block& block, size_t iterations, size_t warmup_iterations);
    Stats benchmark_decrypt(const Block& block, size_t iterations, size_t warmup_iterations);

private:
    IAES &aes_;

    Stats compute_stats(const std::vector<double> &timings);

    // Runs the benchmark on the provided block for a given number of iterations and warmup iterations
    // thanks to the interface the function works for both AesNaive and AesTTable and Aes-NI implementations
    Stats benchmark_algorithm(const Block &block, size_t iterations, size_t warmup_iterations, bool encrypt);
};