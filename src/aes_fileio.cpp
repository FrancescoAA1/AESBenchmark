#include "aes_fileio.h"
#include <chrono>
#include <fstream>
#include <iomanip>
#include <ctime>
#include<thread>

#if defined(_WIN32)
    #include <intrin.h>
       #include <windows.h>
       #include <basetsd.h>
#elif defined(__linux__)
    #include <x86intrin.h>
        #include <pthread.h>
    #include <sched.h>
#else
    #error "RDTSC timing OR Thread affinity not supported on this platform"
#endif

#include <iostream>

static double get_cpu_frequency_ghz()
{
    // Measure CPU frequency dynamically (simple calibration)
    using namespace std::chrono;
    uint64_t start = __rdtsc();
    auto t1 = high_resolution_clock::now();
    std::this_thread::sleep_for(milliseconds(200));
    uint64_t end = __rdtsc();
    auto t2 = high_resolution_clock::now();
    double elapsed_s = duration<double>(t2 - t1).count();
    return (end - start) / (elapsed_s * 1e9);
}

static void append_csv_log(const std::string &filename,
                           const std::string &algorithm,
                           const std::string &operation,
                           double total_cycles,
                           double cpu_freq_ghz,
                           size_t total_bytes)
{
    double total_time_s = total_cycles / (cpu_freq_ghz * 1e9);
    double throughput_mb_s = (total_bytes / (1024.0 * 1024.0)) / total_time_s;

    // Current timestamp
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);

    std::ofstream csv(filename, std::ios::app);
    csv << std::fixed << std::setprecision(4)
        << std::put_time(std::localtime(&now_c), "%F %T") << ","
        << algorithm << ","
        << operation << ","
        << total_cycles << ","
        << cpu_freq_ghz << ","
        << throughput_mb_s << "\n";
}

void AesFileIo::encrypt_file(const std::string &input_filename,
                             const std::string &output_filename,
                             IAES &aes)
{
    std::cout << "SHA256 of " << input_filename << ": "
              << tinysha256::SHA256::file_hash_hex(input_filename.c_str()) << "\n";

    std::ifstream in(input_filename, std::ios::binary);
    std::ofstream out(output_filename, std::ios::binary);

    if (!in || !out) {
        std::perror("Error opening files");
        return;
    }

    double total_cycles = 0;
    size_t total_bytes = 0;
    auto cpu_freq_ghz = get_cpu_frequency_ghz();

    std::array<Byte, BLOCK_SIZE> buf{};
    while (true) {
        in.read(reinterpret_cast<char *>(buf.data()), BLOCK_SIZE);
        std::streamsize n = in.gcount();

        if (n == 0) break;

        if (n < BLOCK_SIZE) {
            Byte pad = BLOCK_SIZE - n;
            for (std::streamsize i = n; i < BLOCK_SIZE; i++)
                buf[i] = pad;
        }

        uint64_t start_cycles = __rdtsc();
        auto encrypted_block = aes.encrypt_block(buf);
        uint64_t end_cycles = __rdtsc();

        total_cycles += (end_cycles - start_cycles);
        total_bytes += BLOCK_SIZE;

        out.write(reinterpret_cast<const char *>(encrypted_block.data()), BLOCK_SIZE);

        if (n < BLOCK_SIZE) break;
    }

    in.close();
    out.close();

    append_csv_log(input_filename + "_results.csv", "AES", "Encrypt",
                   total_cycles, cpu_freq_ghz, total_bytes);

    std::cout << "Encryption throughput logged.\n";
}

void AesFileIo::decrypt_file(const std::string &input_filename,
                             const std::string &output_filename,
                             IAES &aes)
{
    std::ifstream in(input_filename, std::ios::binary);
    std::ofstream out(output_filename, std::ios::binary);

    if (!in || !out) {
        std::perror("Error opening files");
        return;
    }

    double total_cycles = 0;
    size_t total_bytes = 0;
    auto cpu_freq_ghz = get_cpu_frequency_ghz();

    std::array<Byte, BLOCK_SIZE> buf{};
    std::array<Byte, BLOCK_SIZE> decrypted_block{};

    while (in.read(reinterpret_cast<char *>(buf.data()), BLOCK_SIZE) || in.gcount() > 0) {
        std::streamsize n = in.gcount();
        if (n != BLOCK_SIZE) {
            std::cerr << "Encrypted file corrupted or not a multiple of block size!\n";
            return;
        }

        uint64_t start_cycles = __rdtsc();
        decrypted_block = aes.decrypt_block(buf);
        uint64_t end_cycles = __rdtsc();

        total_cycles += (end_cycles - start_cycles);
        total_bytes += BLOCK_SIZE;

        if (in.peek() == EOF) {
            Byte pad = decrypted_block[BLOCK_SIZE - 1];
            if (pad < 1 || pad > BLOCK_SIZE) {
                std::cerr << "Invalid padding!\n";
                return;
            }
            out.write(reinterpret_cast<const char *>(decrypted_block.data()), BLOCK_SIZE - pad);
        } else {
            out.write(reinterpret_cast<const char *>(decrypted_block.data()), BLOCK_SIZE);
        }
    }

    in.close();
    out.close();

    append_csv_log(input_filename + "_results.csv", "AES", "Decrypt",
                   total_cycles, cpu_freq_ghz, total_bytes);

    std::cout << "Decryption throughput logged.\n";
}
