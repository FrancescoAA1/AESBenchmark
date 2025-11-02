#pragma once
#include <cstdint>
#include <chrono>
#include <vector>
#include <iostream>
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
        return aes_name + "Min(ns)" + std::to_string(min_time_ns) + "\r\n" +
               "Max(ns)" + std::to_string(max_time_ns) + "\r\n" +
               "Avg(ns)" + std::to_string(avg_time_ns) + "\r\n" +
               "Median(ns)" + std::to_string(median_time_ns) + "\r\n" +
               "StdDev(ns)" + std::to_string(stddev_time_ns) + "\r\n" +
               "Throughput(MB/s)" + std::to_string(avg_throughput_mb_s) + "\r\n" +
               "Latency(ns)" + std::to_string(latency_ns) + "\r\n" +
               "Cycles/byte" + std::to_string(avg_cycles_per_byte) + "\n";
    }
};

class AESBenchmark
{
public:
    AESBenchmark(IAES &iaes);

    // Runs the benchmark on the provided block for a given number of iterations and warmup iterations
    // thanks to the interface the function works for both AesNaive and AesTTable and Aes-NI implementations
    Stats benchmark_algorithm(const Block &block, size_t iterations, size_t warmup_iterations);

private:
    IAES &aes_;
};