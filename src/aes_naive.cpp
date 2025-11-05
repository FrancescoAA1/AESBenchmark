
#include <vector>
#include <array>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include "../include/aes_naive.h"
#include "../include/aes_constants.h"

using namespace std;

// Byte substitution table - constructed with multiplicative inverse of each byte in the
//  finite field GF(2^8) + Affine transformation

constexpr std::array<Byte, S_BOX_SIZE> AesNaive::S_BOX = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

constexpr std::array<Byte, S_BOX_SIZE> AesNaive::INV_S_BOX = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

// RCON : for 10 round constant in AesNaive-128, words with first byte non-zero
// The RC values come from successive powers of 2 in GF(2^8)
// RC[i]=2i ^−1mod(x^8+x^4+x^3+x+1)

constexpr std::array<std::array<Byte, KEY_WORDS>, NUM_ROUNDS> AesNaive::RCON = {{{0x01, 0x00, 0x00, 0x00},
                                                                            {0x02, 0x00, 0x00, 0x00},
                                                                            {0x04, 0x00, 0x00, 0x00},
                                                                            {0x08, 0x00, 0x00, 0x00},
                                                                            {0x10, 0x00, 0x00, 0x00},
                                                                            {0x20, 0x00, 0x00, 0x00},
                                                                            {0x40, 0x00, 0x00, 0x00},
                                                                            {0x80, 0x00, 0x00, 0x00},
                                                                            {0x1B, 0x00, 0x00, 0x00},
                                                                            {0x36, 0x00, 0x00, 0x00}}};

// MixColumns transformation matrix: each column of the state is multiplied by this matrix

constexpr std::array<std::array<Byte, N_COLS>, N_ROWS> AesNaive::MIX_COL_MATRIX = {{{0x02, 0x03, 0x01, 0x01},
                                                                               {0x01, 0x02, 0x03, 0x01},
                                                                               {0x01, 0x01, 0x02, 0x03},
                                                                               {0x03, 0x01, 0x01, 0x02}}};

// Inverse MixColumns transformation matrix: each column of the state is multiplied by this matrix

constexpr std::array<std::array<Byte, N_COLS>, N_ROWS> AesNaive::MIX_COL_MATRIX_INV = {{{0x0e, 0x0b, 0x0d, 0x09},
                                                                                   {0x09, 0x0e, 0x0b, 0x0d},
                                                                                   {0x0d, 0x09, 0x0e, 0x0b},
                                                                                   {0x0b, 0x0d, 0x09, 0x0e}}};

// Constructor
// We assign the key and generate the round keys using key expansion
AesNaive::AesNaive(const Key &key) : key_(key)
{
    round_keys_ = key_expansion(key_);
}

// First operation of the encryption process (in the looping rounds)
//  For each byte of the state matrix, substitute it with the corresponding byte in the S-Box
void AesNaive::sub_bytes(State &state)
{
    for (int row = 0; row < N_ROWS; row++)
    {
        for (int col = 0; col < N_COLS; col++)
        {
            state[row][col] = S_BOX[state[row][col]];
        }
    }
}

// For each byte of the state matrix, substitute it with the corresponding byte in the Inverse S-Box
void AesNaive::inv_sub_bytes(State &state)
{
    for (int row = 0; row < N_ROWS; row++)
    {
        for (int col = 0; col < N_COLS; col++)
        {
            state[row][col] = INV_S_BOX[state[row][col]];
        }
    }
}

// Second operation of the encryption process (in the looping rounds)

//NOTE: SLOWER THAN MIX COLUMNS BECAUSE OF ROTATE!!!

// void AesNaive::shift_rows(State &state)
// {
//     // Row 1: shift left by 1
//     Byte tmp = state[1][0];
//     state[1][0] = state[1][1];
//     state[1][1] = state[1][2];
//     state[1][2] = state[1][3];
//     state[1][3] = tmp;

//     // Row 2: shift left by 2
//     std::swap(state[2][0], state[2][2]);
//     std::swap(state[2][1], state[2][3]);

//     // Row 3: shift left by 3 (or right by 1)
//     tmp = state[3][3];
//     state[3][3] = state[3][2];
//     state[3][2] = state[3][1];
//     state[3][1] = state[3][0];
//     state[3][0] = tmp;
// }

void AesNaive::shift_rows(State &state)
{
    // Row 0: No shift

    // Row 1: Shift left by 1

    // std::rotate(begin, middle, end) rotates the range [begin, end)
    // in such a way that the element pointed by middle becomes the new first element.
    rotate(state[1].begin(), state[1].begin() + 1, state[1].end());

    // Row 2: Shift left by 2
    rotate(state[2].begin(), state[2].begin() + 2, state[2].end());

    // Row 3: Shift left by 3 (or right by 1)
    rotate(state[3].begin(), state[3].begin() + 3, state[3].end());
}

void AesNaive::inv_shift_rows(State &state)
{
    // Row 0: No shift

    // Row 1: Shift right by 1
    rotate(state[1].begin(), state[1].begin() + 3, state[1].end());

    // Row 2: Shift right by 2
    rotate(state[2].begin(), state[2].begin() + 2, state[2].end());

    // Row 3: Shift right by 3 (or left by 1)
    rotate(state[3].begin(), state[3].begin() + 1, state[3].end());
}

// Third operation of the encryption process (in the looping rounds)

// Each column of the state is multiplied by a fixed polynomial c(x)= {03}x^3 + {01}x^2 + {01}x + {02}
// The mix col matrix in the AesNaive class contains the coefficients of this polynomial
void AesNaive::mix_columns(State &state)
{
    for (int col = 0; col < N_COLS; col++)
    {
        Byte s0 = state[0][col];
        Byte s1 = state[1][col];
        Byte s2 = state[2][col];
        Byte s3 = state[3][col];

        state[0][col] = GF_mul(s0, MIX_COL_MATRIX[0][0]) ^ GF_mul(s1, MIX_COL_MATRIX[0][1]) ^ GF_mul(s2, MIX_COL_MATRIX[0][2]) ^ GF_mul(s3, MIX_COL_MATRIX[0][3]);
        state[1][col] = GF_mul(s0, MIX_COL_MATRIX[1][0]) ^ GF_mul(s1, MIX_COL_MATRIX[1][1]) ^ GF_mul(s2, MIX_COL_MATRIX[1][2]) ^ GF_mul(s3, MIX_COL_MATRIX[1][3]);
        state[2][col] = GF_mul(s0, MIX_COL_MATRIX[2][0]) ^ GF_mul(s1, MIX_COL_MATRIX[2][1]) ^ GF_mul(s2, MIX_COL_MATRIX[2][2]) ^ GF_mul(s3, MIX_COL_MATRIX[2][3]);
        state[3][col] = GF_mul(s0, MIX_COL_MATRIX[3][0]) ^ GF_mul(s1, MIX_COL_MATRIX[3][1]) ^ GF_mul(s2, MIX_COL_MATRIX[3][2]) ^ GF_mul(s3, MIX_COL_MATRIX[3][3]);
    }
}

// This is the well-known fast formulation that’s equivalent to multiplying by the AesNaive matrix [[2,3,1,1], …] in GF(2⁸), but way shorter and quicker.
void AesNaive::mix_columns_fast(State &state)
{
    for (int c = 0; c < 4; ++c)
    {
        Byte a0 = state[0][c];
        Byte a1 = state[1][c];
        Byte a2 = state[2][c];
        Byte a3 = state[3][c];

        // XOR of the entire column
        Byte t = a0 ^ a1 ^ a2 ^ a3;

        // MixColumns core: uses xtime (multiply by 2 in GF(2^8))
        state[0][c] = a0 ^ t ^ Xtime(a0 ^ a1);
        state[1][c] = a1 ^ t ^ Xtime(a1 ^ a2);
        state[2][c] = a2 ^ t ^ Xtime(a2 ^ a3);
        state[3][c] = a3 ^ t ^ Xtime(a3 ^ a0);
        
    }
}

void AesNaive::inv_mix_columns(State &state)
{
    for (int col = 0; col < N_COLS; col++)
    {
        Byte s0 = state[0][col];
        Byte s1 = state[1][col];
        Byte s2 = state[2][col];
        Byte s3 = state[3][col];

        state[0][col] = GF_mul(s0, MIX_COL_MATRIX_INV[0][0]) ^ GF_mul(s1, MIX_COL_MATRIX_INV[0][1]) ^ GF_mul(s2, MIX_COL_MATRIX_INV[0][2]) ^ GF_mul(s3, MIX_COL_MATRIX_INV[0][3]);
        state[1][col] = GF_mul(s0, MIX_COL_MATRIX_INV[1][0]) ^ GF_mul(s1, MIX_COL_MATRIX_INV[1][1]) ^ GF_mul(s2, MIX_COL_MATRIX_INV[1][2]) ^ GF_mul(s3, MIX_COL_MATRIX_INV[1][3]);
        state[2][col] = GF_mul(s0, MIX_COL_MATRIX_INV[2][0]) ^ GF_mul(s1, MIX_COL_MATRIX_INV[2][1]) ^ GF_mul(s2, MIX_COL_MATRIX_INV[2][2]) ^ GF_mul(s3, MIX_COL_MATRIX_INV[2][3]);
        state[3][col] = GF_mul(s0, MIX_COL_MATRIX_INV[3][0]) ^ GF_mul(s1, MIX_COL_MATRIX_INV[3][1]) ^ GF_mul(s2, MIX_COL_MATRIX_INV[3][2]) ^ GF_mul(s3, MIX_COL_MATRIX_INV[3][3]);
    }
}

// XORing each byte of the state with the corresponding byte of the round key
void AesNaive::add_round_key(State &state, const Key &key)
{
    for (int row = 0; row < N_ROWS; row++)
    {
        for (int col = 0; col < N_COLS; col++)
        {
            state[row][col] ^= key[col * N_ROWS + row];
        }
    }
}

// Combines 4 words from the expanded key into a single round key
Key AesNaive::get_round_key(int round)
{

    Key round_key{};

    for (int col = 0; col < N_COLS; ++col)
    {
        for (int row = 0; row < N_ROWS; ++row)
        {
            round_key[col * N_ROWS + row] = round_keys_[round * 4 + col][row];
        }
    }
    return round_key;
}

ExpandedKey AesNaive::key_expansion(const Key &key)
{
    /*
        1) Initialize the first 4 words (W[0..3]) directly from the key
        2) For words W[i] where i >= 4:
        a) If i mod 4 == 0:
          - Rotate the previous word (rotate_word)
          - Substitute bytes using S-Box (sub_words)
          - XOR with RCON[i//4 - 1]
        b) Otherwise:
          - XOR the previous word with the word 4 positions earlier
        3) Repeat until 44 words are generated (11 round keys × 4 words each)
        4) Each round key is 4×4 bytes, used in AddRoundKey for encryption and decryption.
    */

    ExpandedKey expanded_key{}; // 44 words //TO BE FIXED!!!

    // Step 1: Initialize W[0..3] from the key
    for (int i = 0; i < KEY_WORDS; ++i)
    {
        for (int j = 0; j < N_ROWS; ++j)
        {
            expanded_key[i][j] = key[i * N_ROWS + j];
        }
    }

    // Step 2: Generate W[i] for i >= 4
    for (int i = KEY_WORDS; i < EXPANDED_KEY_WORDS; ++i)
    {
        Word temp = expanded_key[i - 1]; // previous word

        if (i % KEY_WORDS == 0)
        {
            // a) i mod 4 == 0: rotate, substitute, XOR with RCON
            temp = rotate_word(temp);
            temp = sub_word_bytes(temp);
            for (int j = 0; j < N_ROWS; ++j)
            {
                temp[j] ^= RCON[i / KEY_WORDS - 1][j];
            }
        }

        // b) Otherwise XOR with word 4 positions earlier
        for (int j = 0; j < N_ROWS; ++j)
        {
            expanded_key[i][j] = expanded_key[i - KEY_WORDS][j] ^ temp[j];
        }
    }

    return expanded_key;
}

Word AesNaive::rotate_word(const Word &word)
{
    Word rotated = word;
    // Rotating left by 1 position
    // Used for key expansion when i mod 4 == 0
    std::rotate(rotated.begin(), rotated.begin() + 1, rotated.end());
    return rotated;
}

Word AesNaive::sub_word_bytes(const Word &word)
{
    Word subbed = word;
    for (int i = 0; i < N_ROWS; i++)
    {
        // Substituting each byte in the word with the corresponding byte in the S-Box
        // Using static_cast to ensure we are using uint8_t as index
        // C++ treats char as signed int by default
        subbed[i] = S_BOX[static_cast<std::uint8_t>(subbed[i])];
    }

    return subbed;
}

// Helpers

// Converting a flat 16-byte array (the block) into a 4*4 State Matrix
State AesNaive::bytes_to_state(const Block &block)
{
    State state{};

    for (int i = 0; i < BLOCK_SIZE; i++)
    {
        int row = i % N_ROWS;
        int col = i / N_ROWS;

        state[row][col] = block[i];
    }

    return state;
}

// Converting a 4*4 State Matrix into a flat 16-byte array
std::array<Byte, BLOCK_SIZE> AesNaive::state_to_bytes(const State &state)
{
    Block block{};

    for (int col = 0; col < N_COLS; col++)
    {
        for (int row = 0; row < N_ROWS; row++)
        {
            block[col * N_ROWS + row] = state[row][col];
        }
    }

    return block;
}


/*We rotate 1 bit to the left then look at first bit
if it is 1 we need to xor with 0x1B (which is the modolus x^8 + x^4 + x^3 + x + 1)
otherwise we do nothing (ie xor with 0x00)

Perform static casting to ensure we are still working with uint8_t
*/
Byte AesNaive::Xtime(Byte a)
{
    return static_cast<Byte>(((a << 1) & 0xFF) ^ ((a & 0x80) ? 0x1B : 0x00));
}

Byte AesNaive::GF_mul(Byte a, Byte b)
{
    if (b == 1)
        return a;
    if (b == 2)
        return Xtime(a);
    if (b == 3)
        return Xtime(a) ^ a;
    if (b == 9)
        return Xtime(Xtime(Xtime(a))) ^ a;
    if (b == 11)
        return Xtime(Xtime(Xtime(a))) ^ Xtime(a) ^ a;
    if (b == 13)
        return Xtime(Xtime(Xtime(a))) ^ Xtime(Xtime(a)) ^ a;
    if (b == 14)
        return Xtime(Xtime(Xtime(a))) ^ Xtime(Xtime(a)) ^ Xtime(a);
    throw std::runtime_error("Unsupported GF multiplication");

    return 0;
}

// Block encryption/decryption
std::array<Byte, BLOCK_SIZE> AesNaive::encrypt_block(const Block &block)
{
    State state = bytes_to_state(block);

    // Initial round key addition
    // Get round key is used to extract the first round key as a Word array
    add_round_key(state, get_round_key(0));

    // Main rounds where we do sub_bytes, shift_rows, mix_columns, add_round_key
    for (int round = 1; round < NUM_ROUNDS; round++)
    {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        //Alternatively, we can use the faster version of mix_columns
        // mix_columns_fast(state);
        add_round_key(state, get_round_key(round));
    }

    // Final round (no mix_columns)
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, get_round_key(NUM_ROUNDS));

    return state_to_bytes(state);
}

// The decryption process is the reverse of encryption
std::array<Byte, BLOCK_SIZE> AesNaive::decrypt_block(const Block &block)
{
    State state = bytes_to_state(block);

    add_round_key(state, get_round_key(NUM_ROUNDS));

    for (int round = NUM_ROUNDS - 1; round >= 1; round--)
    {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, get_round_key(round));
        inv_mix_columns(state);
    }

    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, get_round_key(0));

    return state_to_bytes(state);
}
