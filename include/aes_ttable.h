#pragma once
#include <cstdint>
#include <array>
#include <vector>

// Including constants for tables and sizes
#include "aes_constants.h"
#include "aes.h"

// Type aliases
using Byte = std::uint8_t;
using Word = std::array<Byte, N_ROWS>;
using Bit32Word = std::array<uint32_t, WORD_BYTES>;

// No need to use State, we work with 4 uint32_t words
using Key = std::array<Byte, BLOCK_SIZE>;
using RoundKeys = std::array<uint32_t, EXPANDED_KEY_WORDS>;
using Block = std::array<Byte, BLOCK_SIZE>; // Need to internally convert each block to 4 uint32_t words

class AesTTable : public IAES
{
    // Allowing only AESBenchmark to call private member functions for benchmarking purposes
    friend class AESBenchmark;
        
public:
    explicit AesTTable(const Key &key);

    // Block encryption/decryption used by encrypt_message and decrypt_message for each 16-byte block
    Block encrypt_block(const Block &block);
    Block decrypt_block(const Block &block);

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
       RoundKeys decryption_keys(const RoundKeys &enc_keys);
    // Helpers

    // Used for block to words and words to block conversions in encrypt_block and decrypt_block
    // since we work with 4 uint32_t words internally
    static Bit32Word block_to_words(const Block &block);
    static Block words_to_block(const Bit32Word &words);

    // Printers

    // Print a single T-table for debugging purposes
    void print_Ttable(const std::array<uint32_t, 256> &table, const std::string &name);

    // Print all round keys for debugging purposes
   // Replace this line "void AesTTable::printAllKeys(const RoundKeys &keys, int numRounds, const std::string &name);"
    void printAllKeys(const RoundKeys &keys, int numRounds, const std::string &name); 
};
