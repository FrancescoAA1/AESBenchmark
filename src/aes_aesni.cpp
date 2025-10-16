
#include "../include/aes_aesni.h"

#if defined(_MSC_VER)
  #include <intrin.h>
  static inline void cpuid_ex(int out[4], int leaf, int subleaf = 0) {
    __cpuidex(out, leaf, subleaf);
  }
#else
  #include <cpuid.h>
  static inline void cpuid_ex(int out[4], int leaf, int subleaf = 0) {
    __cpuid_count(leaf, subleaf, out[0], out[1], out[2], out[3]);
  }
#endif

namespace aesni {

bool cpu_has_aesni() {
    int r[4];
    cpuid_ex(r, 1);
    // ECX bit 25 indicates AES-NI support
    return (r[2] & (1 << 25)) != 0;
}

static inline __m128i key_assist(__m128i t1, __m128i t2) {
    t2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3,3,3,3));
    t1 = _mm_xor_si128(t1, _mm_slli_si128(t1, 4));
    t1 = _mm_xor_si128(t1, _mm_slli_si128(t1, 4));
    t1 = _mm_xor_si128(t1, _mm_slli_si128(t1, 4));
    return _mm_xor_si128(t1, t2);
}

void expand_key(const uint8_t key_bytes[16], AES128KeySchedule& ks) {
    __m128i k = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key_bytes));
    ks.round[0] = k;

    __m128i t;

    t = _mm_aeskeygenassist_si128(k, 0x01); k = key_assist(k, t); ks.round[1]  = k;
    t = _mm_aeskeygenassist_si128(k, 0x02); k = key_assist(k, t); ks.round[2]  = k;
    t = _mm_aeskeygenassist_si128(k, 0x04); k = key_assist(k, t); ks.round[3]  = k;
    t = _mm_aeskeygenassist_si128(k, 0x08); k = key_assist(k, t); ks.round[4]  = k;
    t = _mm_aeskeygenassist_si128(k, 0x10); k = key_assist(k, t); ks.round[5]  = k;
    t = _mm_aeskeygenassist_si128(k, 0x20); k = key_assist(k, t); ks.round[6]  = k;
    t = _mm_aeskeygenassist_si128(k, 0x40); k = key_assist(k, t); ks.round[7]  = k;
    t = _mm_aeskeygenassist_si128(k, 0x80); k = key_assist(k, t); ks.round[8]  = k;
    t = _mm_aeskeygenassist_si128(k, 0x1B); k = key_assist(k, t); ks.round[9]  = k;
    t = _mm_aeskeygenassist_si128(k, 0x36); k = key_assist(k, t); ks.round[10] = k;
}

void expand_key_decrypt(const AES128KeySchedule& enc, AES128KeySchedule& dec) {
    dec.round[0] = enc.round[10];
    for (int i = 1; i < 10; ++i) {
        dec.round[i] = _mm_aesimc_si128(enc.round[10 - i]);
    }
    dec.round[10] = enc.round[0];
}

void decrypt_block(const AES128KeySchedule& dec,
                   const uint8_t in[16],
                   uint8_t out[16]) {
    __m128i m = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
    m = _mm_xor_si128(m, dec.round[0]);            // AddRoundKey with last enc key
    for (int r = 1; r < 10; ++r)                   // 9 middle rounds
        m = _mm_aesdec_si128(m, dec.round[r]);
    m = _mm_aesdeclast_si128(m, dec.round[10]);    // final round
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out), m);
}

void encrypt_block(const AES128KeySchedule& ks,
                   const uint8_t in[16],
                   uint8_t out[16]) {
    __m128i m = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
    m = _mm_xor_si128(m, ks.round[0]);           // AddRoundKey
    for (int r = 1; r < 10; ++r)                 // Rounds 1..9
        m = _mm_aesenc_si128(m, ks.round[r]);
    m = _mm_aesenclast_si128(m, ks.round[10]);   // Round 10 (no MixColumns)
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out), m);
}

} // namespace aesni
