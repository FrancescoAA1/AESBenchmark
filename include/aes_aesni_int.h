#pragma once
#include <array>
#include <cstdint>
#include <immintrin.h>

// AES-128 using AES-NI, block presented as four 32-bit words (little-endian).
class AES128U32 {

    public:
        using Word = std::uint32_t;
        using Block = std::array<Word, 4>;


        AES128U32() = default;
        explicit AES128U32(const Block& key) { set_key(key); }


        // Set/expand 128-bit key provided as 4x uint32_t words.
        void set_key(const Block& key);


        // Encrypt/Decrypt one 16-byte block given/returned as four 32-bit words.
        void encrypt_block(const Block& in, Block& out) const;
        void decrypt_block(const Block& in, Block& out) const;


        // In-place variants
        void encrypt_block_inplace(Block& inout) const { Block tmp; encrypt_block(inout, tmp); inout = tmp; }
        void decrypt_block_inplace(Block& inout) const { Block tmp; decrypt_block(inout, tmp); inout = tmp; }


        // Optional: quick runtime check (best-effort) that AES-NI is available.
        static bool cpu_supports_aesni();

    private:
        alignas(16) __m128i erk_[11]{}; // encryption round keys 0..10
        alignas(16) __m128i drk_[11]{}; // decryption round keys 0..10
};