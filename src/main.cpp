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
#include <aes_botan_wrapper.h>
#include "aes_constants.h"

using namespace std;
using namespace std::filesystem;

using Byte = std::uint8_t;

//Helper Functions

//Prints a block
inline std::string block_to_string(const Block &b) {
    std::ostringstream oss;
    for (auto byte : b)
        oss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)byte;
    return oss.str();
}

//Checks if two blocks are equal (used for testing purposes)
std::string are_equal(const Block &block1, const Block &block2)
{
    return (block1 == block2) ? "Success: " + block_to_string(block1) + "\r\n"
                              : "Fail: " + block_to_string(block1);
}

//To write benchmarking results on a CSV file for reproducibility and data visualization
void write_csv_row(std::ofstream &out, const std::string &impl, const std::string &op, const Stats &s)
{
    out << std::fixed << std::setprecision(4);
    out << impl << ","
        << op << ","
        << s.p05_time_ns << ","
        << s.p25_time_ns << ","
        << s.median_time_ns << ","
        << s.p75_time_ns << ","
        << s.p95_time_ns << ","
        << s.iqr_ns << ","
        << s.mean_time_ns << ","
        << s.stddev_time_ns << ","
        << s.avg_throughput_mb_s << ","
        << s.avg_cycles_per_byte << "\n";
}

//Function that wraps all operations from benchmarking to logging
//For AES implementations
void benchmark_aes_to_csv(const std::string &name, IAES &aes, const Block &block, size_t iterations, size_t warmup, std::ofstream &csv)
{
    AESBenchmark benchmark(aes);

    auto stats_enc = benchmark.benchmark_encrypt(block, iterations, warmup);
    auto stats_dec = benchmark.benchmark_decrypt(block, iterations, warmup);

    std::cout << "\n=== " << name << " Benchmark ===\n";
    std::cout << stats_enc.to_string(name + " Encryption,");
    std::cout << stats_dec.to_string(name + " Decryption,");

    write_csv_row(csv, name, "Encryption", stats_enc);
    write_csv_row(csv, name, "Decryption", stats_dec);
}

//Function that wraps all operations from benchmarking to logging
//For AES single steps
void benchmark_aes_steps_to_csv(const std::string &name, IAES &aes, const Block &block, size_t iterations, size_t warmup, std::ofstream &csv, const std::vector<AESOperation> &ops)
{
    AESBenchmark benchmark(aes);

    for (auto op : ops)
    {
        Stats stats = benchmark.benchmark_step(op, block, iterations, warmup);
        std::string op_name = to_string(op);

        std::cout << "\n=== " << name << " Step: " << op_name << " ===\n";
        std::cout << stats.to_string(name + " " + op_name + ",");

        write_csv_row(csv, name, op_name, stats);
    }
}

//Performs testing by encrypting block plain -> encrypting the result again and then it decrypts twice
//For each operation it checks that the resulting vector corresponds to the ones provided in the parameters
void test_aes_roundtrip(IAES &aes, const Block &plain, const Block &expected1, const Block &expected2)
{
    Block ct1 = aes.encrypt_block(plain);
    std::cout << "Encrypt 1: " << are_equal(ct1, expected1);

    Block ct2 = aes.encrypt_block(ct1);
    std::cout << "Encrypt 2: " << are_equal(ct2, expected2);

    Block pt1 = aes.decrypt_block(ct2);
    std::cout << "Decrypt 1: " << are_equal(pt1, expected1);

    Block pt2 = aes.decrypt_block(pt1);
    std::cout << "Decrypt 2: " << are_equal(pt2, plain)  << "\n";
}

//AES File Encryption and Decryption to test the algorithms with differents blocks (and measure the throughput)
void encrypt_decrypt_file(AesFileIo &file_io,const std::filesystem::path &input_file, const std::filesystem::path &encrypted_file, const std::filesystem::path &decrypted_file, IAES &aes, const std::string &name)
{
    std::cout << "Encrypting with " << name << "...\n";
    file_io.encrypt_file(input_file.string(), encrypted_file.string(), aes);

    std::cout << "Decrypting with " << name << "...\n";
    file_io.decrypt_file(encrypted_file.string(), decrypted_file.string(), aes);

    std::cout << "----------------------------------------\n";
}


int main()
{
    // =========== SETUP ============  
    Key key = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; 
    Block block = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    Block block1 = {0x66, 0xE9, 0x4B, 0xD4, 0xEF, 0x8A, 0x2C, 0x3B, 0x88, 0x4C, 0xFA, 0x59, 0xCA, 0x34, 0x2B, 0x2E};
    Block block2 = {0xF7, 0x95, 0xBD, 0x4A, 0x52, 0xE2, 0x9E, 0xD7, 0x13, 0xD3, 0x13, 0xFA, 0x20, 0xE9, 0x8D, 0xBC};

    const size_t iterations = 100000;
    const size_t warmup = 10000;

    // ============= AES INSTANCES ==============
    AesNaive aes_naive(key);
    AesTTable aes_ttable(key);
    AesAESNI aes_ni(key);
    AESNaiveInt aes_int(key);
    AesBotanWrapper aes_botan(key);

    // === Round-trip correctness tests ===
    test_aes_roundtrip(aes_naive, block, block1, block2);
    test_aes_roundtrip(aes_ttable, block, block1, block2);
    test_aes_roundtrip(aes_ni, block, block1, block2);
    test_aes_roundtrip(aes_int, block, block1, block2);
    test_aes_roundtrip(aes_botan, block, block1, block2);

    // ============= FILE ENCRYPTION/DECRYPTION ==============
    path input_file = path("..") / "file" / "input.jpg";
    path encrypted_file = path("..") / "file" / "output_encrypted.jpg";
    path decrypted_file = path("..") / "file" / "output_decrypted.jpg";

    AesFileIo file_io;

    encrypt_decrypt_file(file_io, input_file, encrypted_file, decrypted_file, aes_naive, "AES-Naive");
    encrypt_decrypt_file(file_io, input_file, encrypted_file, decrypted_file, aes_ttable, "AES-TTable");
    encrypt_decrypt_file(file_io, input_file, encrypted_file, decrypted_file, aes_ni, "AES-NI");
    encrypt_decrypt_file(file_io, input_file, encrypted_file, decrypted_file, aes_int, "AES-Naive-Int");
    encrypt_decrypt_file(file_io, input_file, encrypted_file, decrypted_file, aes_botan, "AES-Botan");

    // ============= BENCHMARK FULL AES ==============

    std::filesystem::path benchmark_dir = "../benchmark";
    std::filesystem::create_directories(benchmark_dir);

    std::ofstream csv("../benchmark/benchmark_results.csv");
    csv << "Implementation,Operation,P05_ns,P25_ns,Median_ns,P75_ns,P95_ns,IQR_ns,Mean_ns,StdDev_ns,Avg_Throughput_MB_s,Avg_Cycles_per_Byte\n";

    benchmark_aes_to_csv("AES-Naive", aes_naive, block, iterations, warmup, csv);
    benchmark_aes_to_csv("AES-TTable", aes_ttable, block, iterations, warmup, csv);
    benchmark_aes_to_csv("AES-NI", aes_ni, block, iterations, warmup, csv);
    benchmark_aes_to_csv("AES-Naive-Int", aes_int, block, iterations, warmup, csv);
    benchmark_aes_to_csv("AES-Botan", aes_botan, block, iterations, warmup, csv);

    csv.close();

    // ============= BENCHMARK AES STEPS ==============

    std::ofstream step_csv("../benchmark/benchmark_AES.csv");
    step_csv << "Implementation,Operation,P05_ns,P25_ns,Median_ns,P75_ns,P95_ns,IQR_ns,Mean_ns,StdDev_ns,Avg_Throughput_MB_s,Avg_Cycles_per_Byte\n";

    // AES-Naive steps
    benchmark_aes_steps_to_csv("AES-Naive", aes_naive, block, iterations, warmup, step_csv, {
        AESOperation::SubBytes, AESOperation::ShiftRows, AESOperation::MixColumns,
        AESOperation::MixColumnsFast, AESOperation::AddRoundKey,
        AESOperation::InvSubBytes, AESOperation::InvShiftRows,
        AESOperation::InvMixColumns, AESOperation::KeyExpansionNaive
    });

    // AES-TTable steps
    benchmark_aes_steps_to_csv("AES-TTable", aes_ttable, block, iterations, warmup, step_csv, {
        AESOperation::InitTables, AESOperation::KeyExpansionTTable
    });

    // AES-NI steps
    benchmark_aes_steps_to_csv("AES-NI", aes_ni, block, iterations, warmup, step_csv, {
        AESOperation::KeyExpansionNI, AESOperation::KeyDecryptNI
    });

    step_csv.close();

    // ============= GRAPH CREATION ==============

    path py_script = path("..") / "src" / "plot_benchmark.py";
    string command = "python " + py_script.string();
    system(command.c_str());

    return 0;
}
