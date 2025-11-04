#pragma once
#include <array>
#include <cstdint>
#include <vector>
#include <cstring>

class AES128Words {

    friend class AESBenchmark;
        
public:
    using u8  = std::uint8_t;
    using u32 = std::uint32_t;

    // One 128-bit block as 4 columns (column-major). Each word packs bytes:
    // MSB..LSB = row0,row1,row2,row3 for that column.
    using Block4x32 = std::array<u32, 4>;

    // Construct with a 16-byte key.
    explicit AES128Words(const u8 key[16]);

    // Encrypt/decrypt a single block in-place (4x u32).
    void encrypt(Block4x32 &state) const;
    void decrypt(Block4x32 &state) const;

    // Convenience overloads for 16-byte buffers (in/out can alias).
    void encrypt_bytes(const u8 in[16], u8 out[16]) const;
    void decrypt_bytes(const u8 in[16], u8 out[16]) const;

    // Helpers to convert between bytes <-> words (big-endian inside each word).
    static Block4x32 bytes_to_words_be(const u8 in[16]);
    static void      words_to_bytes_be(const Block4x32 &state, u8 out[16]);

    static inline void sub_bytes(Block4x32 &S);
    static inline void shift_rows(Block4x32 &S);
    static inline void mix_columns(Block4x32 &S);

    static inline void inv_mix_columns(Block4x32 &S);
    static inline void inv_shift_rows(Block4x32 &S);
    static inline void inv_sub_bytes(Block4x32 &S);

private:
    // Round keys as 4x32 words per round (11 round keys for AES-128).
    using RoundKey4x32 = std::array<u32, 4>;
    std::array<RoundKey4x32, 11> rk_; // rk_[0]..rk_[10]

    // Core round operations in "word layout"
    static inline u8  sbox(u8 x);
    static inline u8  inv_sbox(u8 x);
    static inline u8  xtime(u8 x); // multiply by 2 in GF(2^8)
    static inline u8  gf_mul(u8 a, u8 b); // generic GF(2^8) multiply

    static inline u32 pack(u8 r0, u8 r1, u8 r2, u8 r3);
    static inline u8  b0(u32 w); // row0 (MSB)
    static inline u8  b1(u32 w);
    static inline u8  b2(u32 w);
    static inline u8  b3(u32 w); // row3 (LSB)

    static inline u32 sub_bytes_word(u32 w);
    
    static inline u32 mix_column(u32 w);
    
    static inline void add_round_key(Block4x32 &S, const RoundKey4x32 &RK);

    // Inverse transforms
    static inline u32 inv_mix_column(u32 w);
    

    // Key schedule
    static RoundKey4x32 make_roundkey_from_words(u32 w0,u32 w1,u32 w2,u32 w3);
    void expand_key_128(const u8 key[16]);
};
