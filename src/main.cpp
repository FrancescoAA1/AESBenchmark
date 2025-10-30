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

#include "aes_constants.h"

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

 Block plaintext = {
        'H', 'a', 's', 't',
        'a', ' ', 'l', 'a',
        ' ', 'v', 'i', 's',
        't', 'a', '!', '!'
    };

    // ---------- AES-Naive ----------
    AesNaive aes_naive(key);

    auto start = std::chrono::high_resolution_clock::now();
    Block ciphertext_naive = aes_naive.encrypt_block(plaintext);
    auto end = std::chrono::high_resolution_clock::now();

    cout << "[AES-Naive] Encryption took "
         << std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count()
         << " ns.\n";

    start = std::chrono::high_resolution_clock::now();
    Block decrypted_naive = aes_naive.decrypt_block(ciphertext_naive);
    end = std::chrono::high_resolution_clock::now();

    cout << "[AES-Naive] Decryption took "
         << std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count()
         << " ns.\n";

    // Verify
    cout << "Decrypted text: ";
    for (auto b : decrypted_naive) cout << static_cast<char>(b);
    cout << "\n\n";

    // ---------- AES-TTable ----------
    AesTTable aes_ttable(key);

    start = std::chrono::high_resolution_clock::now();
    Block ciphertext_ttable = aes_ttable.encrypt_block(plaintext);
    end = std::chrono::high_resolution_clock::now();

    cout << "[AES-TTable] Encryption took "
         << std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count()
         << " ns.\n";

    start = std::chrono::high_resolution_clock::now();
    Block decrypted_ttable = aes_ttable.decrypt_block(ciphertext_ttable);
    end = std::chrono::high_resolution_clock::now();

    cout << "[AES-TTable] Decryption took "
         << std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count()
         << " ns.\n";

    cout << "Decrypted text: ";
    for (auto b : decrypted_ttable) cout << static_cast<char>(b);
    cout << "\n";


    if (!aesni::cpu_has_aesni()) { std::puts("No AES-NI"); return 1; }

    uint8_t key_ni[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t pt [16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    uint8_t ct [16];

    std::puts("AES-NI test:");
    
    aesni::AES128KeySchedule ks{};
    aesni::expand_key(key_ni, ks);
    aesni::encrypt_block(ks, pt, ct);

     aesni::AES128KeySchedule dks{};
     aesni::expand_key_decrypt(ks, dks);
     uint8_t decrypted_ni[16];
     aesni::decrypt_block(dks, ct, decrypted_ni);

    for (auto b : ct) std::printf("%02x", b);
    cout << "\n"; // Expected: 69c4e0d86a7b0430d8cdb78070b4c55a
    for (auto b : decrypted_ni) std::printf("%02x", b);
    std::puts(""); // Expected: 00112233445566778899aabbccddeeff

    AesFileIo fileIo;
    start = std::chrono::high_resolution_clock::now();
    fileIo.encrypt_file();
    end = std::chrono::high_resolution_clock::now();
     cout << "File Encryption 6415 blocks with AES-Naive took: "
           << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count()
           << " microseconds.\n";
     start = std::chrono::high_resolution_clock::now();
     fileIo.decrypt_file();
     end = std::chrono::high_resolution_clock::now();
      cout << "File Decryption 6416 blocks with AES-NI took: "
            << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count()
            << " microseconds.\n";

    return 0;
}
