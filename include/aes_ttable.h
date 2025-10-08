// NOTE: Given the similarity of the AES and AES-TTable classes, we will soon create a common base class to avoid code duplication

// aes_ttable.h
#pragma once
#include <cstdint>
#include <array>
#include <vector>

// Including constants for tables and sizes
#include "aes_constants.h"

// Type aliases
using Byte = std::uint8_t;
using Word = std::array<Byte, N_ROWS>;
using Bit32Word = std::array<uint32_t, WORD_BYTES>;

// No need to use State, we work with 4 uint32_t words
using Key = std::array<Byte, BLOCK_SIZE>;
using RoundKeys = std::array<uint32_t, EXPANDED_KEY_WORDS>;
using Block = std::array<Byte, BLOCK_SIZE>; // Need to internally convert each block to 4 uint32_t words

class AesTTable
{
public:
    explicit AesTTable(const Key &key);

    // Main functions
    // We will be timing their execution time in main.cpp
    std::vector<Byte> encrypt_message(const std::vector<Byte> &message);
    std::vector<Byte> decrypt_message(const std::vector<Byte> &ciphertext);

private:
    Key key_;
    RoundKeys round_keys_;

    // Decryption round keys computed from encryption round keys
    RoundKeys decryption_keys_;

    // Lookup tables
    static const std::array<Byte, S_BOX_SIZE> S_BOX;
    static const std::array<Byte, S_BOX_SIZE> INV_S_BOX;
    static std::array<std::uint32_t, T_TABLE_SIZE> T0, T1, T2, T3;
    static std::array<std::uint32_t, T_TABLE_SIZE> Td0, Td1, Td2, Td3;
    static const std::array<Word, NUM_ROUNDS> RCON;

    // Operations

    // Initialize T and Td tables
    void initTables();

    // Key expansion
    RoundKeys key_expansion(const Key &key);

    // Derive decryption keys from encryption keys
    RoundKeys AesTTable::decryption_keys(const RoundKeys &enc_keys);

    // Helpers

    // Adding as many padding bytes as needed to make the message a multiple of BLOCK_SIZE
    std::vector<Byte> pad_message(const std::vector<Byte> &message);

    // Removing the padding bytes after decryption
    std::vector<Byte> unpad_message(const std::vector<Byte> &message);

    static inline Byte xtime(Byte a)
    {
        return static_cast<Byte>((a << 1) ^ ((a & 0x80u) ? 0x1Bu : 0x00u));
    }

    static inline Byte gfmul(Byte a, Byte b)
    {
        Byte res = 0;
        while (b)
        {
            if (b & 1u)
                res = static_cast<Byte>(res ^ a);
            a = xtime(a);
            b >>= 1;
        }

        return res;
    }

    // Used for block to words and words to block conversions in encrypt_block and decrypt_block
    // since we work with 4 uint32_t words internally
    static Bit32Word block_to_words(const Block &block);
    static Block words_to_block(const Bit32Word &words);

    // Block encryption/decryption used by encrypt_message and decrypt_message for each 16-byte block
    Block encrypt_block(const Block &block);
    Block decrypt_block(const Block &block);

    // Printers

    // Print a single T-table for debugging purposes
    void print_Ttable(const std::array<uint32_t, 256> &table, const std::string &name);

    // Print all round keys for debugging purposes
    void AesTTable::printAllKeys(const RoundKeys &keys, int numRounds, const std::string &name);
};
