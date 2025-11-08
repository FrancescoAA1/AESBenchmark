#pragma once
#include <cstdint>
#include <array>
#include <vector>

#include "aes_constants.h"

// aes.h provides common type aliases and the abstract base class IAES, 
//which defines the interface for all AES implementations.

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

    //Virtual member functions: to be implemented by the classes who derive IAES
    //Represent the common public interface
    // Encrypts a single 16-byte block
    virtual Block encrypt_block(const Block& block) = 0;
    // Decrypts a single 16-byte block
    virtual Block decrypt_block(const Block& block) = 0;

    protected:

    //Used in MixColumns (AesNaive, AesNaiveInt, AesTtable) for Galois Field multiplication 
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
};
