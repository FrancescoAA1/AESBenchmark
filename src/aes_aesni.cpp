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


static inline __m128i key_assist(__m128i t1, __m128i t2) {
    t2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3,3,3,3));
    t1 = _mm_xor_si128(t1, _mm_slli_si128(t1, 4));
    t1 = _mm_xor_si128(t1, _mm_slli_si128(t1, 4));
    t1 = _mm_xor_si128(t1, _mm_slli_si128(t1, 4));
    return _mm_xor_si128(t1, t2);
}

__m128i AesAESNI::block_to_m128i(const Block &block) {
    return _mm_loadu_si128(reinterpret_cast<const __m128i*>(block.data()));
}

Block AesAESNI::m128i_to_block(__m128i reg) {
    Block out;
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out.data()), reg);
    return out;
}

bool AesAESNI::cpu_has_aesni() {
    int r[4];
    cpuid_ex(r, 1);
    return (r[2] & (1 << 25)) != 0;
}


void AesAESNI::expand_key(const Key &key, AES128KeySchedule &ks) {
    __m128i k = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key.data()));
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

void AesAESNI::expand_key_decrypt(const AES128KeySchedule& enc, AES128KeySchedule& dec) {
    dec.round[0] = enc.round[10];
    for (int i = 1; i < 10; ++i)
        dec.round[i] = _mm_aesimc_si128(enc.round[10 - i]);
    dec.round[10] = enc.round[0];
}


AesAESNI::AesAESNI(const Key &key) : key_(key) {
    expand_key(key_, enc_keys_);
    expand_key_decrypt(enc_keys_, dec_keys_);
}


Block AesAESNI::encrypt_block(const Block &block) {
    __m128i m = block_to_m128i(block);
    m = _mm_xor_si128(m, enc_keys_.round[0]);
    for (int r = 1; r < 10; ++r)
        m = _mm_aesenc_si128(m, enc_keys_.round[r]);
    m = _mm_aesenclast_si128(m, enc_keys_.round[10]);
    return m128i_to_block(m);
}

Block AesAESNI::decrypt_block(const Block &block) {
    __m128i m = block_to_m128i(block);
    m = _mm_xor_si128(m, dec_keys_.round[0]);
    for (int r = 1; r < 10; ++r)
        m = _mm_aesdec_si128(m, dec_keys_.round[r]);
    m = _mm_aesdeclast_si128(m, dec_keys_.round[10]);
    return m128i_to_block(m);
}
