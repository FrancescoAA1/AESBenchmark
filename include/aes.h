//Header guards
#pragma once

#ifndef AES_H
#define AES_H

#include <cstdint>
#include <array>
#include <vector>


//Constants
constexpr int BLOCK_SIZE = 16;
constexpr int N_ROWS = 4;
constexpr int N_COLS = 4;
constexpr int NUM_ROUNDS = 10;
constexpr int KEY_WORDS = 4;
constexpr int EXPANDED_KEY_WORDS = (NUM_ROUNDS+1)*KEY_WORDS;
constexpr int S_BOX_SIZE = 256;

//Aliases for clarity
using Byte = std::uint8_t;
using Word = std::array<Byte, N_ROWS>;
using State = std::array<std::array<Byte, N_COLS>, N_ROWS>;
using Key = std::array<Byte, BLOCK_SIZE>;
using ExpandedKey = std::array<Key, EXPANDED_KEY_WORDS>; 
using Block = std::array<Byte, BLOCK_SIZE>;


class AES {
    public:
        
    //Constructor
    explicit AES(const std::array<Byte, BLOCK_SIZE>& key);

    //Main functions
    std::vector<Byte> encrypt_message(const std::vector<Byte>& message);
    std::vector<Byte> decrypt_message(const std::vector<Byte>& ciphertext);

    private:

    //Constants
    static const std::array<Byte, S_BOX_SIZE> S_BOX;
    static const std::array<Byte, S_BOX_SIZE> INV_S_BOX;
    static const std::array<std::array<Byte, N_ROWS>, N_COLS> MIX_COL_MATRIX;
    static const std::array<std::array<Byte, N_ROWS>, N_COLS> MIX_COL_MATRIX_INV;
    static const std::array<Word, NUM_ROUNDS> RCON;

    //State and Words are temporary, they do not constitue class fields
    std::array<Byte, BLOCK_SIZE> key_;
    ExpandedKey round_keys_;

    //Operations on the state
    void sub_bytes(State& state);
    void inv_sub_bytes(State& state);
    void shift_rows(State& state);
    void inv_shift_rows(State& state);
    void mix_columns(State& state);
    void inv_mix_columns(State& state);
    void add_round_key(State& state, const Key& key);

    //Key expansion 
    ExpandedKey key_expansion(const Block& key);
    Word rotate_word(const Word& word);
    Word sub_word_bytes(const Word& word);

    // Helpers
    State bytes_to_state(const Block& block);
    std::array<Byte, BLOCK_SIZE> state_to_bytes(const State& state);
    std::vector<Byte> pad_message(const std::vector<Byte>& message);
    std::vector<Byte> unpad_message(const std::vector<Byte>& message);

    static Byte GF_mul(Byte a, Byte b);
    static Byte Xtime(Byte a);

    //Block encryption/decryption
    std::array<Byte, BLOCK_SIZE> encrypt_block(const Block& block);
    std::array<Byte, BLOCK_SIZE> decrypt_block(const Block& block);    
};

#endif