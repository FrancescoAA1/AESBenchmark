#pragma once
#include <cstdint>
#include <immintrin.h> // or <wmmintrin.h>

namespace aesni {

struct AES128KeySchedule {
    __m128i round[11]; // round[0]..round[10]
};

// Returns true if the running CPU supports AES-NI (CPUID ECX bit 25).
bool cpu_has_aesni();

// Expand a 128-bit key into 11 round keys.
void expand_key(const uint8_t key[16], AES128KeySchedule& ks);

// Build decryption round keys from an existing encryption key schedule.
void expand_key_decrypt(const AES128KeySchedule& enc, AES128KeySchedule& dec);

// Decrypt one 16-byte block (AES-128, 10 rounds).
void decrypt_block(const AES128KeySchedule& dec,
                   const uint8_t in[16],
                   uint8_t out[16]);

// Encrypt exactly one 16-byte block (AES-128, 10 rounds).
void encrypt_block(const AES128KeySchedule& ks,
                   const uint8_t in[16],
                   uint8_t out[16]);

} // namespace aesni
