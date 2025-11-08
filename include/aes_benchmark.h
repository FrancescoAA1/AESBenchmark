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

struct Stats {
    double p05_time_ns;
    double p25_time_ns;
    double median_time_ns;
    double p75_time_ns;
    double p95_time_ns;
    double iqr_ns;
    double mean_time_ns;
    double stddev_time_ns;
    double avg_throughput_mb_s;
    double avg_cycles_per_byte;

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

// aes_benchmark.h

#pragma once
#include <string>

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

    // Helpers
    GFMul,

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

        case AESOperation::GFMul:              return "GFMul";

        case AESOperation::InitTables:         return "InitTables";
        case AESOperation::KeyExpansionTTable: return "KeyExpansionTTable";

        case AESOperation::KeyExpansionNI:     return "KeyExpansionNI";
        case AESOperation::KeyDecryptNI:       return "KeyDecryptNI";

        default: return "UnknownOp";
    }
}


class AESBenchmark
{
public:
    AESBenchmark(IAES &iaes);

    // Benchmark a specific step method of AesNaive
    Stats benchmark_step(AESOperation step, const Block& block, size_t iterations, size_t warmup_iterations);

    Stats benchmark_encrypt(const Block& block, size_t iterations, size_t warmup_iterations);
    Stats benchmark_decrypt(const Block& block, size_t iterations, size_t warmup_iterations);

private:
    IAES &aes_;

    Stats compute_stats(const std::vector<double> &timings);

    // Runs the benchmark on the provided block for a given number of iterations and warmup iterations
    // thanks to the interface the function works for both AesNaive and AesTTable and Aes-NI implementations
    Stats benchmark_algorithm(const Block &block, size_t iterations, size_t warmup_iterations, bool encrypt);

    inline void sink(const Block& value)
    {
        (void)value;
    }
};