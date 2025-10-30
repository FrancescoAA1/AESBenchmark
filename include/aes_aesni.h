#pragma once
#include <cstdint>
#include <array>
#include <vector>
#include <immintrin.h> // AES-NI intrinsics
#include "aes.h"
#include "aes_constants.h"

using Byte = std::uint8_t;
using Word = std::array<Byte, N_ROWS>;
using State = std::array<std::array<Byte, N_COLS>, N_ROWS>;
using Key = std::array<Byte, BLOCK_SIZE>;
using ExpandedKey = std::array<Word, EXPANDED_KEY_WORDS>;
using Block = std::array<Byte, BLOCK_SIZE>;

class AesAESNI : public IAES
{
public:
    explicit AesAESNI(const Key &key);

    // Matches AesNaive block interface
    // Encrypt exactly one 16-byte block (AES-128, 10 rounds)
    Block encrypt_block(const Block &block);
    // Decrypt one 16-byte block (AES-128, 10 rounds)
    Block decrypt_block(const Block &block);

        // Returns true if the running CPU supports AES-NI (CPUID ECX bit 25).
    static bool cpu_has_aesni();

private:
    // AES-NI round keys
    struct AES128KeySchedule {
        __m128i round[11]; // 11 round keys
    };

    AES128KeySchedule enc_keys_;
    AES128KeySchedule dec_keys_;

    Key key_; // original key for reference

    // AES-NI helpers
    void expand_key(const Key &key, AES128KeySchedule &ks);
    // Build decryption round keys from an existing encryption key schedule.
    void expand_key_decrypt(const AES128KeySchedule &enc, AES128KeySchedule &dec);

    // Conversion helpers to match AesNaive interface
    static __m128i block_to_m128i(const Block &block);
    static Block m128i_to_block(__m128i reg);
};