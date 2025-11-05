#include <iostream>
#include <vector>

#include <fstream>
#include <filesystem>
#include <array>
#include <cstdint>
#include <cstdio>

#include <chrono>

#include <aes_naive.h>
#include <aes_ttable.h>
#include <aes_aesni.h>
#include <aes_fileio.h>
#include <aes_benchmark.h>
#include <aes_naive_int.h>
//#include <aes_botan_wrapper.h>

#include "aes_constants.h"
#include <bench_aes.h>

using namespace std;
using namespace std::filesystem;

using Byte = std::uint8_t;


inline std::string block_to_string(const Block &b) {
    std::ostringstream oss;
    for (auto byte : b)
        oss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)byte;
    return oss.str();
}

std::string are_equal(const Block &block1, const Block &block2)
{
    return (block1 == block2) ? "Success: " + block_to_string(block1) + "\r\n" : "Fail: " + block_to_string(block1);
}

void test_aes_roundtrip(IAES &aes, const Block &plain, const Block &expected1, const Block &expected2) {

    // Encrypt once
    Block ct1 = aes.encrypt_block(plain);
    std::cout << "Encrypt 1: " << are_equal(ct1, expected1) << "\n";

    // Encrypt again
    Block ct2 = aes.encrypt_block(ct1);
    std::cout << "Encrypt 2: " << are_equal(ct2, expected2) << "\n";

    // Decrypt once
    Block pt1 = aes.decrypt_block(ct2);
    std::cout << "Decrypt 1: " << are_equal(pt1, expected1) << "\n";

    // Decrypt again
    Block pt2 = aes.decrypt_block(pt1);
    std::cout << "Decrypt 2: " << are_equal(pt2, plain) << "\n";
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

    //Obtained after encrypting block with key
     Block block1 = {
         0x66, 0xE9, 0x4B, 0xD4,
         0xEF, 0x8A, 0x2C, 0x3B,
         0x88, 0x4C, 0xFA, 0x59,
         0xCA, 0x34, 0x2B, 0x2E};

    //Obtained after encrypting block1 with key
     Block block2 = {
         0xF7, 0x95, 0xBD, 0x4A,
         0x52, 0xE2, 0x9E, 0xD7,
         0x13, 0xD3, 0x13, 0xFA,
         0x20, 0xE9, 0x8D, 0xBC};

     const size_t iterations = 10000;
     const size_t warmup_iterations = 1000;

     // ============= BENCHMARKING ==============

     // ---------- AES-Naive ----------
     AesNaive aes_naive(key);

     // Following the test proposed in the book "The Design of Rijndael"
    test_aes_roundtrip(aes_naive, block, block1, block2);


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

     // to be checked --> gives error
     // auto stats_naive_gfmul = benchmark_naive.benchmark_step(AESOperation::GFMul, block, iterations, warmup_iterations);

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

     // Following the test proposed in the book "The Design of Rijndael"
    test_aes_roundtrip(aes_ttable, block, block1, block2);

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

     AesAESNI aes_ni(key);

     // Following the test proposed in the book "The Design of Rijndael"
     test_aes_roundtrip(aes_ni, block, block1, block2);

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

     // ---------- AES-128 4XInt ----------
    AESNaiveInt aes_int(key);

    // Following the test proposed in the book "The Design of Rijndael"
    test_aes_roundtrip(aes_int, block, block1, block2);

    // Benchmark AES-128 4XInt
    AESBenchmark benchmark_int(aes_int);
    auto stats_int_enc = benchmark_int.benchmark_encrypt(block, iterations, warmup_iterations);
    auto stats_int_dec = benchmark_int.benchmark_decrypt(block, iterations, warmup_iterations);

    // Print benchmark results
    cout << "\n=== AES-128 4XInt Full Benchmark ===\n";
    cout << stats_int_enc.to_string("AES-128 4XInt Full Encryption,");

    cout << "\n=== AES-128 4XInt Full Benchmark ===\n";
    cout << stats_int_dec.to_string("AES-128 4XInt Full Decryption,");


    // AesBotanWrapper aes_botan(key);
    // test_aes_roundtrip(aes_botan, block, block1, block2);

    // std::cout << "\n=== AES-Botan Benchmark ===\n";

    // AESBenchmark benchmark_botan(aes_botan);
    // auto stats_botan_enc = benchmark_botan.benchmark_encrypt(block, iterations, warmup_iterations);
    // auto stats_botan_dec = benchmark_botan.benchmark_decrypt(block, iterations, warmup_iterations);

    // std::cout << stats_botan_enc.to_string("AES-Botan Encryption,");
    // std::cout << stats_botan_dec.to_string("AES-Botan Decryption,");

     // GRAPH CREATION

     path benchmark_result = path("..") / "benchmark" / "benchmark_results.csv";
     std::ofstream csv_file(benchmark_result);
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

     path benchmark_path = path("..") / "benchmark" / "benchmark_AES.csv";
     std::ofstream csv_file2(benchmark_path);
     csv_file2 << "Implementation,Operation,Avg_ns,Min_ns,Max_ns,StdDev_ns\n";

     write_csv_row(csv_file2, "AES-Naive", "Encryption", stats_naive_enc);
     write_csv_row(csv_file2, "AES-Naive", "Decryption", stats_naive_dec);
     write_csv_row(csv_file2, "AES-TTable", "Encryption", stats_ttable_enc);
     write_csv_row(csv_file2, "AES-TTable", "Decryption", stats_ttable_dec);
     write_csv_row(csv_file2, "AES-NI", "Encryption", stats_ni_enc);
     write_csv_row(csv_file2, "AES-NI", "Decryption", stats_ni_dec);

     csv_file2.close();

     path py_script = path("..") / "src" / "plot_benchmark.py";
     string command = "python " + py_script.string();
     int result = system(command.c_str());

     // =========== FILE ENCRYPTION/DECRYPTION ==============

     path input_file = path("..") / "file" / "input.jpg";
     path encrypted_file = path("..") / "file" / "output_encrypted.jpg";
     path decrypted_file = path("..") / "file" / "output_decrypted.jpg";

     AesFileIo file_io;

     std::cout << "Encrypting with AES-Naive...\n";
    file_io.encrypt_file(input_file.string(), encrypted_file.string(), aes_naive);

     std::cout << "Decrypting with AES-Naive...\n";

     file_io.decrypt_file(encrypted_file.string(), decrypted_file.string(), aes_naive);

     return 0;
}
