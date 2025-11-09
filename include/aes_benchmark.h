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

// Comprehensive benchmarking system for AES implementations that
// measures performance metrics and allows micro-benchmarking of individual AES operations

struct Stats {
    double p05_time_ns;        // 5th percentile
    double p25_time_ns;        // 25th percentile
    double median_time_ns;     // 50th percentile
    double p75_time_ns;        // 75th percentile
    double p95_time_ns;        // 95th percentile
    double iqr_ns;             // Interquartile range
    double mean_time_ns;       // Arithmetic mean
    double stddev_time_ns;     // Standard deviation
    double avg_throughput_mb_s; // Throughput in MB/s
    double avg_cycles_per_byte; // Estimated CPU cycles per byte processed

    std::string to_string(const std::string &aes_name) const {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2);

        oss << aes_name << "\r\n"
            << "  5th percentile:  " << p05_time_ns << " ns\r\n"
            << "  25th percentile: " << p25_time_ns << " ns\r\n"
            << "  Median:          " << median_time_ns << " ns\r\n"
            << "  75th percentile: " << p75_time_ns << " ns\r\n"
            << "  95th percentile: " << p95_time_ns << " ns\r\n"
            << "  IQR:             " << iqr_ns << " ns\r\n"
            << "  Mean:            " << mean_time_ns << " ns\r\n"
            << "  Stddev:          " << stddev_time_ns << " ns\r\n"
            << "  Avg throughput:  " << avg_throughput_mb_s << " MB/s\r\n"
            << "  Cycles/byte:     " << avg_cycles_per_byte << "\r\n";

        return oss.str();
    }
};

//This allows for micro-benchmarking since
//AESBenchmark cannot access directly AES member functions

enum class AESOperation {
    // Common operations
    EncryptBlock,
    DecryptBlock,

    // AES Naive operations
    SubBytes,
    ShiftRows,
    MixColumns,
    MixColumnsFast,
    AddRoundKey,
    KeyExpansionNaive,

    InvSubBytes,
    InvShiftRows,
    InvMixColumns,

    // AES TTable operations
    InitTables,
    KeyExpansionTTable,

    // AES-NI operations
    KeyExpansionNI,
    KeyDecryptNI,
};

// Helper function to convert AESOperation to string
inline std::string to_string(AESOperation op) {
    switch(op) {
        case AESOperation::EncryptBlock:       return "EncryptBlock";
        case AESOperation::DecryptBlock:       return "DecryptBlock";

        case AESOperation::SubBytes:           return "SubBytes";
        case AESOperation::ShiftRows:          return "ShiftRows";
        case AESOperation::MixColumns:         return "MixColumns";
        case AESOperation::MixColumnsFast:     return "MixColumnsFast";
        case AESOperation::AddRoundKey:        return "AddRoundKey";
        case AESOperation::KeyExpansionNaive:  return "KeyExpansionNaive";

        case AESOperation::InvSubBytes:        return "InvSubBytes";
        case AESOperation::InvShiftRows:       return "InvShiftRows";
        case AESOperation::InvMixColumns:      return "InvMixColumns";

        case AESOperation::InitTables:         return "InitTables";
        case AESOperation::KeyExpansionTTable: return "KeyExpansionTTable";

        case AESOperation::KeyExpansionNI:     return "KeyExpansionNI";
        case AESOperation::KeyDecryptNI:       return "KeyDecryptNI";

        default: return "Unknown Operation";
    }
}


class AESBenchmark
{
public:
    AESBenchmark(IAES &iaes);

    // Benchmark a specific step method of AesNaive
    Stats benchmark_step(AESOperation step, const Block& block, size_t iterations, size_t warmup_iterations);

    // Macro-benchmark complete encryption/decryption
    Stats benchmark_encrypt(const Block& block, size_t iterations, size_t warmup_iterations);
    Stats benchmark_decrypt(const Block& block, size_t iterations, size_t warmup_iterations);

private:
    // Reference to AES implementation under test
    IAES &aes_;

    // Statistical analysis of timing data 
    //Python is used in this project only data visualization
    Stats compute_stats(const std::vector<double> &timings, double cpu_freq);

    // Runs the benchmark on the provided block for a given number of iterations and warmup iterations
    // thanks to the interface the function works for both AesNaive and AesTTable and Aes-NI implementations
    Stats benchmark_algorithm(const Block &block, size_t iterations, size_t warmup_iterations, bool encrypt);

    // Compiler optimization barrier preventing dead code elimination
    inline void sink(const Block& value)
    {
        (void)value;
    }
};