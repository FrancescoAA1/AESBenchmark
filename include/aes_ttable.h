// aes_ttable.h
#pragma once
#include<cstdint>
#include<vector>

using Byte = std::uint8_t;

class AesTTable {
public:
     explicit AesTTable(const std::vector<Byte>& key);
    ~AesTTable() = default;

     // Add the path of our picture
     void EncryptionFile();
     void DecryptionFile();

     // One Block operations(using internally for test)
     void encryptBlock(const uint8_t in[16], uint8_t out[16]) const;
     void decryptBlock(const uint8_t in[16], uint8_t out[16]) const;
    
private:
    // Round key (AES 128 bit--44 words of 32 bits)

     std::vector<uint32_t> roundKeys;

    // Lookup tables (static)
    static const uint8_t SBOX[256];         // S-box
    static const uint8_t Inv_SBOX[256];   // inverse S-box
    static uint32_t T0[256], T1[256], T2[256], T3[256];    // Encrypt table
    static uint32_t Td0[256], Td1[256], Td2[256], Td3[256]; // decrypt table
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
    }
    static void initTables();// build T/Td tables once
    void keyExpansion(const std::vector<Byte>& key); // expand key to roundKeys

};

