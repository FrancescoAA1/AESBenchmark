// aes_ttable.h
#pragma once
#include<cstdint>
#include<vector>

class AESTTable {
private:
    // Round keys (44 words for AES-128)
    std::vector<uint32_t> roundKeys;

    // Lookup tables (static)
    static const uint8_t S[256];         // S-box
    static const uint8_t InvS[256];   // inverse S-box
    static uint32_t T0[256], T1[256], T2[256], T3[256];
    static bool tablesInit;

    // Helpers
    static inline uint8_t xtime(uint8_t a);
    static inline uint8_t gfmul(uint8_t a, uint8_t b);
    static void initTables();
    void keyExpansion(const std::vector<uint8_t>& key);

public:

//Constructor
    explicit AESTTable(const std::vector<uint8_t>& key);
// Block encryption
    void encryptBlock(const uint8_t in[16], uint8_t out[16]) const;
// Block decryption
    void decryptBlock(const uint8_t in [16], uint8_t out[16]) const;
};