#pragma once
#include <cstdint>
#include <array>
#include <vector>
#include <stdexcept>
#include <immintrin.h> // AES-NI intrinsics
#include "aes.h"
#include "aes_constants.h"

using Byte = std::uint8_t;
using Word = std::array<Byte, N_ROWS>;
using State = std::array<std::array<Byte, N_COLS>, N_ROWS>;
using Key = std::array<Byte, BLOCK_SIZE>;
using ExpandedKey = std::array<Word, EXPANDED_KEY_WORDS>;
using Block = std::array<Byte, BLOCK_SIZE>;

// Hardware-accelerated AES implementation that requires CPU with AES-NI support

class AesAESNI : public IAES
{
    // Allow internal access for micro-benchmarking
    friend class AESBenchmark;  
    
public:
    // Initialize with 128-bit key and expand using AESKEYGENASSIST
    explicit AesAESNI(const Key &key);

    Block encrypt_block(const Block &block);
    Block decrypt_block(const Block &block);

    //We have to check CPUID for AES-NI support before using this implementation
    static bool cpu_has_aesni();

private:

    // Stores round keys as 128-bit XMM registers for direct use in instructions
    struct AES128KeySchedule {
        __m128i round[11]; // 11 round keys (as usual for aes128)
    };

    // Encryption round keys
    AES128KeySchedule enc_keys_;
     // Decryption round keys
    AES128KeySchedule dec_keys_; 
    Key key_;

    void expand_key(const Key &key, AES128KeySchedule &ks);
    
    // Generate decryption keys from encryption schedule
    void expand_key_decrypt(const AES128KeySchedule &enc, AES128KeySchedule &dec);

    // Data conversion between C++ array types and XMM registers
    // Load block to XMM
    static __m128i block_to_m128i(const Block &block);
    // Store XMM to block
    static Block m128i_to_block(__m128i reg);
};