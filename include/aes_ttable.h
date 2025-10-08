// aes_ttable.h
#pragma once
#include<cstdint>
#include<array>
#include<vector>

#include "aes_constants.h"


// Type aliases
using Byte = std::uint8_t;
using Word = std::array<Byte, N_ROWS>;
using Bit32Word = std::array<uint32_t, WORD_BYTES>;
//No need to use State, we work with 4 uint32_t words
using Key = std::array<Byte, BLOCK_SIZE>;
using RoundKeys = std::array<uint32_t, EXPANDED_KEY_WORDS>;
using Block = std::array<Byte, BLOCK_SIZE>; //Need to internally convert each block to 4 uint32_t words

class AesTTable {
public:
     explicit AesTTable(const Key& key);

    //Main functions
    std::vector<Byte> encrypt_message(const std::vector<Byte>& message);
    std::vector<Byte> decrypt_message(const std::vector<Byte>& ciphertext);
    
private:

    Key key_;
    RoundKeys round_keys_;

    void print_Ttable(const std::array<uint32_t, 256>& table, const std::string& name);

    // Lookup tables
    static const std::array<Byte, S_BOX_SIZE> S_BOX;
    static const std::array<Byte, S_BOX_SIZE> INV_S_BOX;
    static std::array<std::uint32_t, T_TABLE_SIZE> T0, T1, T2, T3;
    static std::array<std::uint32_t, T_TABLE_SIZE> Td0, Td1, Td2, Td3;
    static const std::array<Word, NUM_ROUNDS> RCON;


    // Operations
    void initTables();
    RoundKeys key_expansion(const Key& key);


    //Helpers

    std::vector<Byte> pad_message(const std::vector<Byte>& message);
    std::vector<Byte> unpad_message(const std::vector<Byte>& message);

    static inline Byte xtime(Byte a){
        return static_cast<Byte>((a << 1)^ ((a & 0x80u) ? 0x1Bu : 0x00u));
    }

    static inline Byte gfmul(Byte a, Byte b){
        Byte res = 0;
        while (b){
            if (b & 1u) res = static_cast<Byte>(res ^ a);
            a = xtime(a);
            b >>= 1;
        }

        return res;
    }

    static Bit32Word block_to_words(const Block &block);
    static Block words_to_block(const Bit32Word &words);

    //Block encryption/decryption
    Block encrypt_block(const Block& block);
    Block decrypt_block(const Block& block);    
};

