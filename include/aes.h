#pragma once
#include <cstdint>
#include <array>
#include <vector>

#include "aes_constants.h"

// Aliases for clarity
using Byte = std::uint8_t;
using Word = std::array<Byte, N_ROWS>;
using State = std::array<std::array<Byte, N_COLS>, N_ROWS>;
using Key = std::array<Byte, BLOCK_SIZE>;
using ExpandedKey = std::array<Word, EXPANDED_KEY_WORDS>;
using Block = std::array<Byte, BLOCK_SIZE>;

class IAES
{
    public:

     virtual ~IAES() = default;

    std::vector<Byte> encrypt_message(const std::vector<Byte>& message);
    std::vector<Byte> decrypt_message(const std::vector<Byte>& ciphertext);

    protected:

    virtual Block encrypt_block(const Block& block) = 0;
    virtual Block decrypt_block(const Block& block) = 0;

    std::vector<Byte> pad_message(const std::vector<Byte>& message);
    std::vector<Byte> unpad_message(const std::vector<Byte>& message);

    static inline Byte xtime(Byte a) {
        return static_cast<Byte>((a << 1) ^ ((a & 0x80u) ? 0x1Bu : 0x00u));
    }

    static inline Byte gfmul(Byte a, Byte b) {
        Byte res = 0;
        while (b) {
            if (b & 1u) res ^= a;
            a = xtime(a);
            b >>= 1;
        }
        return res;
    }
}