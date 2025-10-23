// Header guards
#ifndef AesNaive_H
#define AesNaive_H

#include <cstdint>
#include <array>
#include <vector>

// Including constants for tables and sizes
#include "aes_constants.h"
#include "aes.h"

// Aliases for clarity
using Byte = std::uint8_t;
using Word = std::array<Byte, N_ROWS>;
using State = std::array<std::array<Byte, N_COLS>, N_ROWS>;
using Key = std::array<Byte, BLOCK_SIZE>;
using ExpandedKey = std::array<Word, EXPANDED_KEY_WORDS>;
using Block = std::array<Byte, BLOCK_SIZE>;

class AesNaive : public IAES
{
public:
    // Constructor
    explicit AesNaive(const Key &key);

    // Main functions used externally
    // We will be timing their execution time in main.cpp
    std::vector<Byte> encrypt_message(const std::vector<Byte> &message);
    std::vector<Byte> decrypt_message(const std::vector<Byte> &ciphertext);

private:
    // Constants
    static const std::array<Byte, S_BOX_SIZE> S_BOX;
    static const std::array<Byte, S_BOX_SIZE> INV_S_BOX;
    static const std::array<std::array<Byte, N_ROWS>, N_COLS> MIX_COL_MATRIX;
    static const std::array<std::array<Byte, N_ROWS>, N_COLS> MIX_COL_MATRIX_INV;
    static const std::array<Word, NUM_ROUNDS> RCON;

    // State and Words are temporary, they do not constitue class fields
    Key key_;
    // RoundKey Array containing 44 words (4 words for each of the 11 round keys)
    ExpandedKey round_keys_;

    // Operations on the state
    void sub_bytes(State &state);
    void inv_sub_bytes(State &state);
    void shift_rows(State &state);
    void inv_shift_rows(State &state);
    void mix_columns(State &state);
    void mix_columns_fast(State &state);
    void inv_mix_columns(State &state);
    void add_round_key(State &state, const Key &key);

    // Key expansion
    ExpandedKey key_expansion(const Key &key);

    // Key schedule helper functions
    Word rotate_word(const Word &word);
    Word sub_word_bytes(const Word &word);

    // Combines 4 words from the expanded key into a single round key
    Key get_round_key(int round);

    // Helpers

    // Used to convert between Block and State representations
    State bytes_to_state(const Block &block);
    std::array<Byte, BLOCK_SIZE> state_to_bytes(const State &state);

    // Adding as many padding bytes as needed to make the message a multiple of BLOCK_SIZE
    std::vector<Byte> pad_message(const std::vector<Byte> &message);

    // Removing the padding bytes after decryption
    std::vector<Byte> unpad_message(const std::vector<Byte> &message);

    // Used to perform multiplication in GF(2^8) in MixColumns and InvMixColumns
    // Can be implemented as an inline function //REFACTOR
    static Byte GF_mul(Byte a, Byte b);
    static Byte Xtime(Byte a);

    // Block encryption/decryption used by encrypt_message and decrypt_message for each 16-byte block
    Block encrypt_block(const Block &block);
    Block decrypt_block(const Block &block);
};

#endif