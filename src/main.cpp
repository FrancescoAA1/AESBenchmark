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


void print_block(const Block &block)
{   
    for (auto b : block)
        std::printf("%02X ", b);
    
    std::cout << std::endl;
}

void write_csv_row(std::ofstream &out, const std::string &impl, const std::string &op, const Stats &s)
{
    out << impl << "," 
        << op << "," 
        << s.avg_time_ns << ","
        << s.min_time_ns << ","
        << s.max_time_ns << ","
        << s.stddev_time_ns
        << "\n";
}


int main()
{
     // =========== SETUP ============

     Key key = {
         0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00};

     Block block = {
         0, 0, 0, 0,
         0, 0, 0, 0,
         0, 0, 0, 0,
         0, 0, 0, 0};

     const size_t iterations = 10000;
     const size_t warmup_iterations = 1000;

     // ============= BENCHMARKING ==============

     // ---------- AES-Naive ----------
     AesNaive aes_naive(key);

     //Following the test proposed in the book "The Design of Rijndael"
     Block ciphertext = aes_naive.encrypt_block(block);
     //print_block(ciphertext);

     ciphertext = aes_naive.encrypt_block(ciphertext);
     //print_block(ciphertext);

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
     cout << stats_naive_enc.to_string("AES-Naive Full Decryption,");

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

     //Following the test proposed in the book "The Design of Rijndael"
     ciphertext = aes_ttable.encrypt_block(block);
     //print_block(ciphertext);

     ciphertext = aes_ttable.encrypt_block(ciphertext);
     //print_block(ciphertext);

     AESBenchmark benchmark_ttable(aes_ttable);
     auto stats_ttable_enc = benchmark_ttable.benchmark_encrypt(block, iterations, warmup_iterations);
     auto stats_ttable_dec = benchmark_ttable.benchmark_decrypt(block, iterations, warmup_iterations);

     auto stats_ttable_initTables = benchmark_ttable.benchmark_step(AESOperation::InitTables, block, iterations, warmup_iterations);
     auto stats_ttable_keyExp = benchmark_ttable.benchmark_step(AESOperation::KeyExpansionTTable, block, iterations, warmup_iterations);

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

          //Following the test proposed in the book "The Design of Rijndael"
          ciphertext = aes_ttable.encrypt_block(block);
          //print_block(ciphertext);

          ciphertext = aes_ttable.encrypt_block(ciphertext);
          //print_block(ciphertext);

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

     // =========== FILE ENCRYPTION/DECRYPTION ==============

     // Filenames
//     std::string input_file  = "input.jpg";
//     std::string encrypted_file = "output_encrypted.jpg";
//     std::string decrypted_file = "output_decrypted.jpg";

    // Create file IO object
//     AesFileIo aes_io;

//     std::cout << "Encrypting file..." << std::endl;
//     aes_io.encrypt_file(input_file, encrypted_file, key);

//     std::cout << "Decrypting file..." << std::endl;
//     aes_io.decrypt_file(encrypted_file, decrypted_file, key);

//     std::cout << "Done. Check " << encrypted_file << " and " << decrypted_file << std::endl;


     //GRAPH CREATION

     std::ofstream csv_file("benchmark_results.csv");
     csv_file << "Implementation,Operation,Avg_ns,Min_ns,Max_ns,StdDev_ns\n";

     write_csv_row(csv_file, "AES-Naive", "Full Encryption", stats_naive_enc);
     write_csv_row(csv_file, "AES-Naive", "Full Decryption", stats_naive_dec);
     write_csv_row(csv_file, "AES-Naive", "SubBytes", stats_naive_subbytes);
     write_csv_row(csv_file, "AES-Naive", "ShiftRows", stats_naive_shiftrows);
     write_csv_row(csv_file, "AES-Naive", "MixColumns", stats_naive_mixcolumns);
     write_csv_row(csv_file, "AES-Naive", "MixColumnsFast", stats_naive_mixcolumnsfast);
     write_csv_row(csv_file, "AES-Naive", "AddRoundKey", stats_naive_addroundkey);
     write_csv_row(csv_file, "AES-Naive", "InvSubBytes", stats_naive_invsubbytes);

     csv_file.close();

     std::ofstream csv_file2("benchmark_AES.csv");
     csv_file2 << "Implementation,Operation,Avg_ns,Min_ns,Max_ns,StdDev_ns\n";

     write_csv_row(csv_file2, "AES-Naive", "Encryption", stats_naive_enc);
     write_csv_row(csv_file2, "AES-Naive", "Decryption", stats_naive_dec);
     write_csv_row(csv_file2, "AES-TTable", "Encryption", stats_ttable_enc);
     write_csv_row(csv_file2, "AES-TTable", "Decryption", stats_ttable_dec);
     // write_csv_row(csv_file2, "AES-NI", "Encryption", stats_ni_);
     // write_csv_row(csv_file2, "AES-NI", "Decryption", stats_ni_dec);

     csv_file2.close();

     std::system("python ..\\src\\plot_benchmark.py");

     return 0;
}
