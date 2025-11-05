#pragma once
#include <array>
#include <cstdint>
#include "aes.h" // brings IAES, Byte, Block, Key, constants

// Naive integer (table-free except S-Box) AES-128 that implements IAES.
class AESNaiveInt final : public IAES {
    friend class AESBenchmark;
public:
    explicit AESNaiveInt(const Key& key);
    ~AESNaiveInt() override = default;

    Block encrypt_block(const Block& block) override;
    Block decrypt_block(const Block& block) override;

private:
    using u8  = std::uint8_t;
    using u32 = std::uint32_t;

    // ---- Round keys (11 × 4 words for AES-128) ----
    using RoundKey4x32 = std::array<u32, 4>;
    std::array<RoundKey4x32, 11> rk_{};

    // ---- Helpers ----
    static inline u8 sbox(u8 x);
    static inline u8 inv_sbox(u8 x);
    static inline u8 xtime8(u8 x);
    static inline u8 gf_mul(u8 a, u8 b);

    static inline u32 pack(u8 r0,u8 r1,u8 r2,u8 r3);
    static inline u8  b0(u32 w);
    static inline u8  b1(u32 w);
    static inline u8  b2(u32 w);
    static inline u8  b3(u32 w);

    static inline u32 sub_bytes_word(u32 w);
    static void       sub_bytes(std::array<u32,4>& S);
    static void       shift_rows(std::array<u32,4>& S);
    static u32        mix_column(u32 w);
    static void       mix_columns(std::array<u32,4>& S);
    static void       add_round_key(std::array<u32,4>& S, const RoundKey4x32& RK);

    // inverse
    static u32        inv_mix_column(u32 w);
    static void       inv_mix_columns(std::array<u32,4>& S);
    static void       inv_shift_rows(std::array<u32,4>& S);
    static void       inv_sub_bytes(std::array<u32,4>& S);

    // key schedule
    static RoundKey4x32 make_roundkey_from_words(u32 w0,u32 w1,u32 w2,u32 w3);
    void expand_key_128(const u8 key[16]);

    // block ↔ words (column-major, big-endian per word to match AES spec)
    static std::array<u32,4> bytes_to_words_be(const u8 in[16]);
    static void words_to_bytes_be(const std::array<u32,4>& state, u8 out[16]);

    // core encrypt/decrypt operating on word state
    void encrypt_words(std::array<u32,4>& S) const;
    void decrypt_words(std::array<u32,4>& S) const;
};
