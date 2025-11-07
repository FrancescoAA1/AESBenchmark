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
    std::vector<double> outliers_low;
    std::vector<double> outliers_high;

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
            << "  Stddev:          " << stddev_time_ns << " ns\r\n";

        // Add outliers inline to the same string
        oss << print_outliers(outliers_low, "Low outliers");
        oss << print_outliers(outliers_high, "High outliers");

        oss << "  Avg throughput:  " << avg_throughput_mb_s << " MB/s\r\n"
            << "  Cycles/byte:     " << avg_cycles_per_byte << "\r\n";

        return oss.str();
    }

private:
    // Helper function returning a string (not printing)
    static std::string print_outliers(const std::vector<double>& outliers, const std::string& label) {
        std::ostringstream oss;
        oss << "  " << label << " (" << outliers.size() << "): ";
        if (outliers.empty()) {
            oss << "none\r\n";
        } else {
            size_t limit = std::min<size_t>(outliers.size(), 10); // limit to 10
            for (size_t i = 0; i < limit; ++i) {
                oss << std::fixed << std::setprecision(2) << outliers[i] << "ns ";
            }
            if (outliers.size() > 10) oss << "... (" << outliers.size() - 10 << " more)";
            oss << "\r\n";
        }
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