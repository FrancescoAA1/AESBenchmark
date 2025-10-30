#include <iostream>
#include <vector>

#include <fstream>
#include <array>
#include <cstdint>
#include <cstdio>

#include <chrono>

#include <aes_naive.h>
#include <aes_ttable.h>
#include <aes_aesni.h>
#include <aes_fileio.h>
#include <aes_benchmark.h>

#include "aes_constants.h"
#include <bench_aes.h>

using namespace std;

using Byte = std::uint8_t;

int main()
{

     //---------------- Test AES-128 Naive (aes.h) ---------------

     cout << "\n=== AES-128 Naive Test ===\n \n";

     Key key = {
         0x7A, 0x1F, 0x93, 0x04,
         0xC5, 0xE2, 0x9B, 0x16,
         0xA8, 0x3C, 0x5E, 0xF1,
         0x7D, 0x44, 0x11, 0x9E};

     Block block = {
         'H', 'a', 's', 't',
         'a', ' ', 'l', 'a',
         ' ', 'v', 'i', 's',
         't', 'a', '!', '!'};

     const size_t iterations = 1000;
     const size_t warmup_iterations = 1000;

     // ---------- AES-Naive ----------
     AesNaive aes_naive(key);
     AESBenchmark benchmark_naive(aes_naive);
     auto stats_naive = benchmark_naive.benchmark_algorithm(block, iterations, warmup_iterations);

     cout << "=== AES-Naive Benchmark ===\n";
     cout << stats_naive.to_string("AES-Naive,");

     // ---------- AES-TTable ----------
     AesTTable aes_ttable(key);
     AESBenchmark benchmark_ttable(aes_ttable);
     auto stats_ttable = benchmark_ttable.benchmark_algorithm(block, iterations, warmup_iterations);

     cout << "\n=== AES-TTable Benchmark ===\n";
     cout << stats_ttable.to_string("AES-TTable,");

     // ---------- AES-NI ----------
     if (!AesAESNI::cpu_has_aesni())
     {
          cout << "\nAES-NI not supported on this CPU.\n";
     }
     else
     {
          AesAESNI aes_ni(key);
          AESBenchmark benchmark_ni(aes_ni);
          auto stats_ni = benchmark_ni.benchmark_algorithm(block, iterations, warmup_iterations);

          cout << "\n=== AES-NI Benchmark ===\n";
          cout << stats_ni.to_string("AES-NI,");
     }

     run_aes_bench();

     return 0;
}
