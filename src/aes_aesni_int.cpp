#include "../include/aes_aesni_int.h"

    inline __m128i load_u32x4(const AES128U32::Block& b) {
        return _mm_loadu_si128(reinterpret_cast<const __m128i*>(b.data()));
    }
    inline void store_u32x4(AES128U32::Block& b, __m128i v) {
        _mm_storeu_si128(reinterpret_cast<__m128i*>(b.data()), v);
    }

    // Expand from previous key using AESKEYGENASSIST round constant rcon.
    inline __m128i key_expand_assist(__m128i prev, int rcon) {
        __m128i t = _mm_aeskeygenassist_si128(prev, rcon);
        t = _mm_shuffle_epi32(t, _MM_SHUFFLE(3,3,3,3));
        __m128i x = prev;
        x = _mm_xor_si128(x, _mm_slli_si128(x, 4));
        x = _mm_xor_si128(x, _mm_slli_si128(x, 4));
        x = _mm_xor_si128(x, _mm_slli_si128(x, 4));
        return _mm_xor_si128(x, t);
    }
    

    void AES128U32::set_key(const Block& key) {
        // Encryption round keys
        erk_[0] = load_u32x4(key);
        erk_[1] = key_expand_assist(erk_[0], 0x01);
        erk_[2] = key_expand_assist(erk_[1], 0x02);
        erk_[3] = key_expand_assist(erk_[2], 0x04);
        erk_[4] = key_expand_assist(erk_[3], 0x08);
        erk_[5] = key_expand_assist(erk_[4], 0x10);
        erk_[6] = key_expand_assist(erk_[5], 0x20);
        erk_[7] = key_expand_assist(erk_[6], 0x40);
        erk_[8] = key_expand_assist(erk_[7], 0x80);
        erk_[9] = key_expand_assist(erk_[8], 0x1B);
        erk_[10] = key_expand_assist(erk_[9], 0x36);

        // Decryption round keys: first and last are swapped; middle use AESIMC.
        drk_[0] = erk_[10];
        
        for (int i = 1; i < 10; ++i) {
            drk_[i] = _mm_aesimc_si128(erk_[10 - i]);
        }

        drk_[10] = erk_[0];
    }


    void AES128U32::encrypt_block(const Block& in, Block& out) const {
        __m128i m = load_u32x4(in);
        m = _mm_xor_si128(m, erk_[0]);
        for (int r = 1; r < 10; ++r) {
            m = _mm_aesenc_si128(m, erk_[r]);
        }
        m = _mm_aesenclast_si128(m, erk_[10]);
        store_u32x4(out, m);
    }


    void AES128U32::decrypt_block(const Block& in, Block& out) const {
        __m128i m = load_u32x4(in);
        m = _mm_xor_si128(m, drk_[0]);
        for (int r = 1; r < 10; ++r) {
            m = _mm_aesdec_si128(m, drk_[r]);
        }
        m = _mm_aesdeclast_si128(m, drk_[10]);
        store_u32x4(out, m);
    }


    // Best-effort CPUID check for AES-NI (x86/x64). Returns false on non-x86.
    bool AES128U32::cpu_supports_aesni() {
        #if defined(__x86_64__) || defined(_M_X64) || defined(__i386) || defined(_M_IX86)
            unsigned eax, ebx, ecx, edx;
        #if defined(_MSC_VER)
            int regs[4];
            __cpuid(reinterpret_cast<int*>(regs), 1);
            ecx = static_cast<unsigned>(regs[2]);
        #else
            __asm__ __volatile__ ("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1));
        #endif
            return (ecx & (1u << 25)) != 0; // ECX.AES (bit 25)
        #else        
            return false;
        #endif
    }