#include <vector>
#include <array>
#include <cstdint>
#include <stdexcept>

#include <iostream>
#include <iomanip>

#include "../include/aes_ttable.h"
#include "../include/aes_constants.h"

using namespace std;

// Byte substitution table - constructed with multiplicative inverse of each byte in the
//  finite field GF(2^8) + Affine transformation

constexpr std::array<Byte, S_BOX_SIZE> AesTTable::S_BOX = {
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

constexpr std::array<Byte, S_BOX_SIZE> AesTTable::INV_S_BOX = {
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

// RCON : for 10 round constant in aes-128, words with first byte non-zero
// The RC values come from successive powers of 2 in GF(2^8)
// RC[i]=2i ^−1mod(x^8+x^4+x^3+x+1)

constexpr std::array<std::array<Byte, KEY_WORDS>, NUM_ROUNDS> AesTTable::RCON = {{{0x01, 0x00, 0x00, 0x00},
                                                                                  {0x02, 0x00, 0x00, 0x00},
                                                                                  {0x04, 0x00, 0x00, 0x00},
                                                                                  {0x08, 0x00, 0x00, 0x00},
                                                                                  {0x10, 0x00, 0x00, 0x00},
                                                                                  {0x20, 0x00, 0x00, 0x00},
                                                                                  {0x40, 0x00, 0x00, 0x00},
                                                                                  {0x80, 0x00, 0x00, 0x00},
                                                                                  {0x1B, 0x00, 0x00, 0x00},
                                                                                  {0x36, 0x00, 0x00, 0x00}}};

// T-Tables Declaration
std::array<std::uint32_t, T_TABLE_SIZE> AesTTable::T0;
std::array<std::uint32_t, T_TABLE_SIZE> AesTTable::T1;
std::array<std::uint32_t, T_TABLE_SIZE> AesTTable::T2;
std::array<std::uint32_t, T_TABLE_SIZE> AesTTable::T3;
std::array<std::uint32_t, T_TABLE_SIZE> AesTTable::Td0;
std::array<std::uint32_t, T_TABLE_SIZE> AesTTable::Td1;
std::array<std::uint32_t, T_TABLE_SIZE> AesTTable::Td2;
std::array<std::uint32_t, T_TABLE_SIZE> AesTTable::Td3;

AesTTable::AesTTable(const Key &key) : key_(key)
{
    round_keys_ = key_expansion(key);

    // Initialize T and Td tables
    initTables();

    // print_Ttable(T0, "T0");
    // print_Ttable(T1, "T1");
    // print_Ttable(T2, "T2");
    // print_Ttable(T3, "T3");
    // print_Ttable(Td0, "Td0");
    // print_Ttable(Td1, "Td1");
    // print_Ttable(Td2, "Td2");
    // print_Ttable(Td3, "Td3");

    // Compute decryption keys from encryption keys. This step requires the T-tables to be initialized first
    decryption_keys_ = decryption_keys(round_keys_);

    // printAllKeys(round_keys_, NUM_ROUNDS, "encryption keys");
    // printAllKeys(decryption_keys_, NUM_ROUNDS, "decryption keys");
}


// Operations

void AesTTable::initTables()
{
    // Precompute T and Td tables
    // As many iterations as there are possible byte values (0-255)
    for (int i = 0; i < T_TABLE_SIZE; ++i)
    {
        // SubByte value from S-Box
        uint8_t s = S_BOX[i];

        // Multiply by 2 and 3 in GF(2^8)
        uint8_t s2 = gfmul(s, 0x02);
        uint8_t s3 = gfmul(s, 0x03);

        // Construct the T0 entry as a 32-bit word
        // Each byte corresponds to a column in the MixColumns matrix multiplication
        T0[i] = (static_cast<uint32_t>(s2) << 24) |
                (static_cast<uint32_t>(s) << 16) |
                (static_cast<uint32_t>(s) << 8) |
                (static_cast<uint32_t>(s3));

        // Rotate T0 to get T1, T2, T3
        T1[i] = ((T0[i] << 24) | (T0[i] >> 8)) & 0xFFFFFFFF;
        T2[i] = ((T0[i] << 16) | (T0[i] >> 16)) & 0xFFFFFFFF;
        T3[i] = ((T0[i] << 8) | (T0[i] >> 24)) & 0xFFFFFFFF;

        // Now for the inverse tables Td0, Td1, Td2, Td3 using INV_S_BOX and multiplications by 9, 11, 13, 14
        uint8_t si = INV_S_BOX[i];
        uint8_t s9 = gfmul(si, 0x09);
        uint8_t sb = gfmul(si, 0x0b);
        uint8_t sd = gfmul(si, 0x0d);
        uint8_t se = gfmul(si, 0x0e);

        // Construct the Td0 entry as a 32-bit word
        // Each byte corresponds to a column in the InvMixColumns matrix multiplication
        Td0[i] = (static_cast<uint32_t>(se) << 24) |
                 (static_cast<uint32_t>(s9) << 16) |
                 (static_cast<uint32_t>(sd) << 8) |
                 (static_cast<uint32_t>(sb));

        Td1[i] = ((Td0[i] << 24) | (Td0[i] >> 8)) & 0xFFFFFFFF;
        Td2[i] = ((Td0[i] << 16) | (Td0[i] >> 16)) & 0xFFFFFFFF;
        Td3[i] = ((Td0[i] << 8) | (Td0[i] >> 24)) & 0xFFFFFFFF;
    }
}

// Key expansion for AES-128 expands a 16-byte key into 44 words (4 bytes each)
RoundKeys AesTTable::key_expansion(const Key &key)
{
    RoundKeys roundKeys{};

    for (int i = 0; i < 4; ++i)
    {
        // Each word is constructed from 4 bytes of the original key
        roundKeys[i] = (static_cast<uint32_t>(key[4 * i + 0]) << 24) |
                       (static_cast<uint32_t>(key[4 * i + 1]) << 16) |
                       (static_cast<uint32_t>(key[4 * i + 2]) << 8) |
                       (static_cast<uint32_t>(key[4 * i + 3]) << 0);
    }

    for (int i = 4; i < EXPANDED_KEY_WORDS; ++i)
    {
        // Temp variable to hold the previous word
        uint32_t temp = roundKeys[i - 1];

        if (i % 4 == 0)
        {

            // Rotate the bytes in the word (left shift by 8 bits)
            temp = (temp << 8) | (temp >> 24);

            // Apply S-Box to each byte in the word
            temp = (static_cast<uint32_t>(S_BOX[(temp >> 24) & 0xFF]) << 24) |
                   (static_cast<uint32_t>(S_BOX[(temp >> 16) & 0xFF]) << 16) |
                   (static_cast<uint32_t>(S_BOX[(temp >> 8) & 0xFF]) << 8) |
                   (static_cast<uint32_t>(S_BOX[(temp) & 0xFF]) << 0);

            // XOR with the round constant
            temp ^= (static_cast<uint32_t>(RCON[(i / 4) - 1][0]) << 24);
        }

        // XOR with the word 4 positions earlier
        roundKeys[i] = roundKeys[i - 4] ^ temp;
    }

    return roundKeys;
}

// Helpers

// Convert 16-byte block to 4 uint32_t words
Bit32Word AesTTable::block_to_words(const Block &block)
{
    Bit32Word words{};
    for (int i = 0; i < 4; ++i)
    {
        words[i] = (static_cast<uint32_t>(block[4 * i + 0]) << 24) |
                   (static_cast<uint32_t>(block[4 * i + 1]) << 16) |
                   (static_cast<uint32_t>(block[4 * i + 2]) << 8) |
                   (static_cast<uint32_t>(block[4 * i + 3]) << 0);
    }
    return words;
}

// Convert 4 uint32_t words back to 16-byte block
Block AesTTable::words_to_block(const Bit32Word &words)
{
    Block block{};
    for (int i = 0; i < 4; ++i)
    {
        block[4 * i + 0] = static_cast<Byte>((words[i] >> 24) & 0xFF);
        block[4 * i + 1] = static_cast<Byte>((words[i] >> 16) & 0xFF);
        block[4 * i + 2] = static_cast<Byte>((words[i] >> 8) & 0xFF);
        block[4 * i + 3] = static_cast<Byte>((words[i]) & 0xFF);
    }
    return block;
}

Block AesTTable::encrypt_block(const Block &block)
{
    Bit32Word state = block_to_words(block);

    // Initial AddRoundKey
    for (int i = 0; i < 4; ++i)
    {
        state[i] ^= round_keys_[i];
    }

    for (int round = 1; round < NUM_ROUNDS; ++round)
    {
        Bit32Word tmp{};
        for (int i = 0; i < 4; ++i)
        {
            // Extract bytes from the state words
            uint8_t a0 = (state[i] >> 24) & 0xFF;
            uint8_t a1 = (state[(i + 1) % 4] >> 16) & 0xFF;
            uint8_t a2 = (state[(i + 2) % 4] >> 8) & 0xFF;
            uint8_t a3 = (state[(i + 3) % 4]) & 0xFF;

            // Precomputed T-Table lookup and AddRoundKey
            tmp[i] = T0[a0] ^ T1[a1] ^ T2[a2] ^ T3[a3] ^ round_keys_[4 * round + i];
        }
        state = tmp;
    }

    Bit32Word tmp{};
    // Last round (no MixColumns)
    for (int i = 0; i < 4; ++i)
    {
        uint8_t a0 = (state[i] >> 24) & 0xFF;
        uint8_t a1 = (state[(i + 1) % 4] >> 16) & 0xFF;
        uint8_t a2 = (state[(i + 2) % 4] >> 8) & 0xFF;
        uint8_t a3 = (state[(i + 3) % 4]) & 0xFF;

        // subBytes and ShiftRows
        tmp[i] = (static_cast<uint32_t>(S_BOX[a0]) << 24) |
                 (static_cast<uint32_t>(S_BOX[a1]) << 16) |
                 (static_cast<uint32_t>(S_BOX[a2]) << 8) |
                 (static_cast<uint32_t>(S_BOX[a3]));

        // AddRoundKey
        tmp[i] ^= round_keys_[4 * NUM_ROUNDS + i];
    }
    state = tmp;

    return words_to_block(state);
}

RoundKeys AesTTable::decryption_keys(const RoundKeys &enc_keys)
{
    RoundKeys dec_keys{};

    // Copy first and last round keys
    for (int i = 0; i < 4; ++i)
    {
        dec_keys[i] = enc_keys[i];
        dec_keys[(NUM_ROUNDS) * 4 + i] = enc_keys[NUM_ROUNDS * 4 + i];
    }

    // Apply InvMixColumns to all intermediate round keys
    for (int i = 4; i < NUM_ROUNDS * 4; ++i)
    {
        uint32_t w = enc_keys[i];
        uint8_t b0 = (w >> 24);
        uint8_t b1 = (w >> 16) & 0xFF;
        uint8_t b2 = (w >> 8) & 0xFF;
        uint8_t b3 = w & 0xFF;

        dec_keys[i] = Td0[S_BOX[b0]] ^ Td1[S_BOX[b1]] ^ Td2[S_BOX[b2]] ^ Td3[S_BOX[b3]];
    }

    return dec_keys;
}

Block AesTTable::decrypt_block(const Block &block)
{
    // Convert 16-byte block to 4 uint32_t words
    Bit32Word state = block_to_words(block);
    Bit32Word tmp{};

    int nr = NUM_ROUNDS;

    // Initial AddRoundKey with last round key
    for (int i = 0; i < 4; ++i)
    {
        state[i] ^= decryption_keys_[(nr) * 4 + i];
    }

    // Main rounds (InvShiftRows + InvSubBytes + InvMixColumns + AddRoundKey)
    for (int round = nr - 1; round > 0; --round)
    {
        for (int i = 0; i < 4; ++i)
        {
            // Extract bytes from the state words
            uint8_t a0 = (state[i] >> 24) & 0xFF;
            uint8_t a1 = (state[(i + 3) % 4] >> 16) & 0xFF;
            uint8_t a2 = (state[(i + 2) % 4] >> 8) & 0xFF;
            uint8_t a3 = (state[(i + 1) % 4]) & 0xFF;

            // Precomputed Td-Table lookup and AddRoundKey
            tmp[i] = Td0[a0] ^ Td1[a1] ^ Td2[a2] ^ Td3[a3] ^ decryption_keys_[4 * round + i];
        }
        state = tmp;
    }

    // Last round: InvSubBytes + InvShiftRows + AddRoundKey (no MixColumns)
    for (int i = 0; i < 4; ++i)
    {
        uint8_t a0 = (state[i] >> 24) & 0xFF;
        uint8_t a1 = (state[(i + 3) % 4] >> 16) & 0xFF;
        uint8_t a2 = (state[(i + 2) % 4] >> 8) & 0xFF;
        uint8_t a3 = (state[(i + 1) % 4]) & 0xFF;

        tmp[i] = (static_cast<uint32_t>(INV_S_BOX[a0]) << 24) |
                 (static_cast<uint32_t>(INV_S_BOX[a1]) << 16) |
                 (static_cast<uint32_t>(INV_S_BOX[a2]) << 8) |
                 (static_cast<uint32_t>(INV_S_BOX[a3]));

        tmp[i] ^= decryption_keys_[i]; // initial round key
    }

    state = tmp;

    return words_to_block(state);
}

void AesTTable::printAllKeys(const RoundKeys &keys, int numRounds, const std::string &name)
{
    std::cout << "=== " << name << " ===\n";
    for (int round = 0; round <= numRounds; ++round)
    {
        std::cout << "Round " << round << " Key: ";
        for (int i = 0; i < 4; ++i)
        {
            // Printing a single word in hex format at the time
            uint32_t word = keys[round * 4 + i];

            // setw is used to set the width of the output to 8 characters
            // setfill is used to fill the empty spaces with '0'
            std::cout << "0x"
                      << std::hex << std::setw(8) << std::setfill('0')
                      << word << " ";
        }
        std::cout << std::dec << "\n";
    }
    std::cout << "====================\n";
}

void AesTTable::print_Ttable(const std::array<uint32_t, T_TABLE_SIZE> &table, const std::string &name)
{
    std::cout << name << " = {\n";
    for (int i = 0; i < T_TABLE_SIZE; ++i)
    {
        std::cout << "0x" << std::hex << std::setw(8) << std::setfill('0')
                  << table[i];
        if (i != 255)
        {
            std::cout << ", ";
        }

        if ((i + 1) % 8 == 0)
        {
            std::cout << "\n";
        }
    }

    std::cout << "};\n"
              << std::dec;
}