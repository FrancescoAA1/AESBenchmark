// aes_aesni.cpp
#include "aes_aesni.h"
#include <wmmintrin.h>
#include <cstdint>
#include <vector>

// =============================
// 1. Key Expansion with AES-NI
// =============================
// - Use _mm_aeskeygenassist_si128() to generate round keys
// - Store round keys as __m128i roundKeys[11]


// =============================
// 2. AESNI methods
// =============================
// - Constructor: AESNI(const std::vector<uint8_t>& key) { keyExpansion(key); }
// - encryptBlock(in[16], out[16])
//   1. Load plaintext into __m128i
//   2. Round 0: XOR with roundKeys[0]
//   3. Rounds 1-9: state = _mm_aesenc_si128(state, roundKeys[i])
//   4. Final round: state = _mm_aesenclast_si128(state, roundKeys[10])
//   5. Store state back to out
// - decryptBlock() (optional: use _mm_aesdec_si128)
