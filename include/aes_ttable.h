// aes_ttable.h
#pragma once
#include<cstdint>
#include<array>
#include<vector>

// Constants
constexpr int T_TABLE_SIZE = 256;

// Type aliases
using Byte = std::uint8_t;
using Word = std::array<Byte, N_ROWS>;
using State = std::array<std::array<Byte, N_COLS>, N_ROWS>;
using Key = std::array<Byte, BLOCK_SIZE>;
using ExpandedKey = std::array<std::uint32_t, EXPANDED_KEY_WORDS>;
using Block = std::array<Byte, BLOCK_SIZE>;

class AesTTable {
public:
     explicit AesTTable(const Key& key);
    ~AesTTable() = default;

     // Add the path of our picture
     void EncryptionFile(); //to implement
     void DecryptionFile(); //to implement

     // One Block operations(using internally for test)
    //  void encryptBlock(const uint8_t in[16], uint8_t out[16]) const;
    //  void decryptBlock(const uint8_t in[16], uint8_t out[16]) const;

     Block encrypt_block(const Block& in) const;
     Block decrypt_block(const Block& in) const;
    
private:
    // Round key (AES 128 bit--44 words of 32 bits)

    Key key_;
    ExpandedKey roundKeys;

    // Lookup tables (static)
    static const std::array<Byte, S_BOX_SIZE> S_BOX;
    static const std::array<Byte, S_BOX_SIZE> INV_S_BOX;
    static std::array<std::uint32_t, T_TABLE_SIZE> T0, T1, T2, T3;
    static std::array<std::uint32_t, T_TABLE_SIZE> Td0, Td1, Td2, Td3;
    static bool tablesInit;


    static inline Byte xtime(Byte a){
        return static_cast<Byte>((a << 1)^ ((a & 0x80u) ? 0x1Bu : 0x00u));
    }

    static inline Byte gfmul(Byte a, Byte b){
        Byte res = 0;
        while (b){
            if (b & 1u) res = static_cast<Byte>(res ^ a);
            a = xtime(a);
            b >>= 1;
        }

        return res;
    }

    static void initTables();// build T/Td tables once
    // Key expansion
    void key_expansion(const Key& key);
};

