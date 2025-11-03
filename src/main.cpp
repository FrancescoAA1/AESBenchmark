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

     const size_t iterations = 100000;
     const size_t warmup_iterations = 10000;

     // ---------- AES-Naive ----------
     AesNaive aes_naive(key);
     AESBenchmark benchmark_naive(aes_naive);
     auto stats_naive_enc = benchmark_naive.benchmark_encrypt(block, iterations, warmup_iterations);
     auto stats_naive_dec = benchmark_naive.benchmark_decrypt(block, iterations, warmup_iterations);

     auto stats_naive_subbytes = benchmark_naive.benchmark_step(AESOperation::SubBytes, block, iterations, warmup_iterations);
     auto stats_naive_shiftrows = benchmark_naive.benchmark_step(AESOperation::ShiftRows, block, iterations, warmup_iterations);
     auto stats_naive_mixcolumns = benchmark_naive.benchmark_step(AESOperation::MixColumns, block, iterations, warmup_iterations);
     auto stats_naive_addroundkey = benchmark_naive.benchmark_step(AESOperation::AddRoundKey, block, iterations, warmup_iterations);
     auto stats_naive_mixcolumnsfast = benchmark_naive.benchmark_step(AESOperation::MixColumnsFast, block, iterations, warmup_iterations);
     auto stats_naive_invsubbytes = benchmark_naive.benchmark_step(AESOperation::InvSubBytes, block, iterations, warmup_iterations);
     auto stats_naive_invshiftrows = benchmark_naive.benchmark_step(AESOperation::InvShiftRows, block, iterations, warmup_iterations);
     auto stats_naive_invmixcolumns = benchmark_naive.benchmark_step(AESOperation::InvMixColumns, block, iterations, warmup_iterations);
     auto stats_naive_keyexpansion = benchmark_naive.benchmark_step(AESOperation::KeyExpansionNaive, block, iterations, warmup_iterations);
     
     //to be checked --> gives error
     //auto stats_naive_gfmul = benchmark_naive.benchmark_step(AESOperation::GFMul, block, iterations, warmup_iterations);

     cout << "=== AES-Naive Encrpytion Benchmark ===\n";
     cout << stats_naive_enc.to_string("AES-Naive Full Encryption,");

     cout << "=== AES-Naive Decryption Benchmark ===\n";
     cout << stats_naive_enc.to_string("AES-Naive Full Encryption,");

     cout << "\nSubBytes Step Benchmark:\n";
     cout << stats_naive_subbytes.to_string("AES-Naive SubBytes,");

     cout << "\nShiftRows Step Benchmark:\n";
     cout << stats_naive_shiftrows.to_string("AES-Naive ShiftRows,");

     cout << "\nMixColumns Step Benchmark:\n";
     cout << stats_naive_mixcolumns.to_string("AES-Naive MixColumns,");

     cout << "\nMixColumnsFast Step Benchmark:\n";
     cout << stats_naive_mixcolumnsfast.to_string("AES-Naive MixColumnsFast,");

          cout << "\nAddRoundKey Step Benchmark:\n";
     cout << stats_naive_addroundkey.to_string("AES-Naive AddRoundKey,");

     cout << "\nInvSubBytes Step Benchmark:\n";
     cout << stats_naive_invsubbytes.to_string("AES-Naive InvSubBytes,");


     // ---------- AES-TTable ----------
     AesTTable aes_ttable(key);
     AESBenchmark benchmark_ttable(aes_ttable);
     auto stats_ttable_enc = benchmark_ttable.benchmark_encrypt(block, iterations, warmup_iterations);
     auto stats_ttable_dec = benchmark_ttable.benchmark_decrypt(block, iterations, warmup_iterations);

     auto stats_ttable_initTables = benchmark_ttable.benchmark_step(AESOperation::InitTables, block, iterations, warmup_iterations);
     auto stats_ttable_keyExp = benchmark_ttable.benchmark_step(AESOperation::KeyExpansionTTable, block, iterations, warmup_iterations);

     cout << "\nSubBytes Step Benchmark:\n";
     //cout << stats_ttable_subbytes.to_string("AES-TTable SubBytes,");

     cout << "\n=== AES-TTable Full Benchmark ===\n";
     cout << stats_ttable_enc.to_string("AES-TTable Full Encryption,");

     cout << "\n=== AES-TTable Full Benchmark ===\n";
     cout << stats_ttable_dec.to_string("AES-TTable Full Decryption,");

     cout << "\nInitTables Step Benchmark:\n";
     cout << stats_ttable_initTables.to_string("AES-TTable InitTables,");

     cout << "\nKeyExpansion Step Benchmark:\n";
     cout << stats_ttable_keyExp.to_string("AES-TTable KeyExp,");

     // ---------- AES-NI ----------
     if (!AesAESNI::cpu_has_aesni())
     {
          cout << "\nAES-NI not supported on this CPU.\n";
     }
     else
     {
          AesAESNI aes_ni(key);
          AESBenchmark benchmark_ni(aes_ni);
          auto stats_ni_enc = benchmark_ni.benchmark_encrypt(block, iterations, warmup_iterations);
          auto stats_ni_dec = benchmark_ni.benchmark_decrypt(block, iterations, warmup_iterations);

          auto stats_ni_keyExp = benchmark_ni.benchmark_step(AESOperation::KeyExpansionNI, block, iterations, warmup_iterations);
          auto stats_ni_keyDec = benchmark_ni.benchmark_step(AESOperation::KeyDecryptNI, block, iterations, warmup_iterations);

          cout << "\n=== AES-NI Full Benchmark ===\n";
          cout << stats_ni_enc.to_string("AES-NI Full Encryption,");

          cout << "\n=== AES-NI Full Benchmark ===\n";
          cout << stats_ni_dec.to_string("AES-NI Full Decryption,");

          cout << "\nKeyExpansion Step Benchmark:\n";
          cout << stats_ni_keyExp.to_string("AES-NI KeyExp,");

          cout << "\nKeyDecryption Step Benchmark:\n";
          cout << stats_ni_keyDec.to_string("AES-NI KeyDec,");         
     }

     return 0;
}
