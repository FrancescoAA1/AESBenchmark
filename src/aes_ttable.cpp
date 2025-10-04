// aes_ttable.cpp

#include<aes_ttable.h>
#include<fstream>
#include <stdexcept>
#include<iomanip>
#include<arrary>
#include<cstring>
#include<cstdio>
#include<vector>



// =====  fill AES S-box, complete 256 entries (from 0x63 down to 0x16). it is standard AES 128 bites
const Byte AesTTable::SBOX[256] =
{   0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16

};
// ===== Inverse S-box (used for decryption) =====
const Byte AesTTable::Inv_SBOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

// static table & init flag
uint32_t AesTTable::T0[256];
uint32_t AesTTable::T1[256];
uint32_t AesTTable::T2[256];
uint32_t AesTTable::T3[256];
uint32_t AesTTable::Td0[256];
uint32_t AesTTable::Td1[256];
uint32_t AesTTable::Td2[256];
uint32_t AesTTable::Td3[256];
bool AesTTable::tablesInit = false;


// ===== Initialize T-tables :forward + inverse
void AesTTable::initTables() {
    if (tablesInit) return;

    //  fill T0..T3 using S-box + MixColumns math
    for (int x = 0; x < 256; ++x) {
        uint8_t s = SBOX[x];
        uint8_t s2 = gfmul(s, 2);
        uint8_t s3 = gfmul(s, 3);
// Forward table encode SubByte + ShiftRows + MixColumns
        T0[x] = (static_cast<uint32_t>(s2) << 24) |
                (static_cast<uint32_t>(s) << 16) |
                (static_cast<uint32_t>(s) << 8) |
                (static_cast<uint32_t>(s3));

        T1[x] = (static_cast<uint32_t>(s3) << 24) |
                (static_cast<uint32_t>(s2) << 16) |
                (static_cast<uint32_t>(s) << 8) |
                (static_cast<uint32_t>(s));

        T2[x] = (static_cast<uint32_t>(s) << 24) |
                (static_cast<uint32_t>(s3) << 16) |
                (static_cast<uint32_t>(s2) << 8) |
                (static_cast<uint32_t>(s));

        T3[x] = (static_cast<uint32_t>(s) << 24) |
                (static_cast<uint32_t>(s) << 16) |
                (static_cast<uint32_t>(s3) << 8) |
                (static_cast<uint32_t>(s2));



// Inverse table  InvSubByte + InvShitRow + InvMixColumns
        Byte si = Inv_SBOX[x];
        Byte s9 = gfmul(si, 9);
        Byte sb = gfmul(si, 11);
        Byte sd = gfmul(si, 13);
        Byte se = gfmul(si, 14);

        Td0[x] = (static_cast<uint32_t>(se) << 24) |
                 (static_cast<uint32_t>(s9) << 16) |
                 (static_cast<uint32_t>(sd) << 8) |
                 (static_cast<uint32_t>(sb));

        Td1[x] = (static_cast<uint32_t>(sb) << 24) |
                 (static_cast<uint32_t>(se) << 16) |
                 (static_cast<uint32_t>(s9) << 8) |
                 (static_cast<uint32_t>(sd));


        Td2[x] = (static_cast<uint32_t>(sd) << 24) |
                 (static_cast<uint32_t>(sb) << 16) |
                 (static_cast<uint32_t>(se) << 8) |
                 (static_cast<uint32_t>(s9));

        Td3[x] = (static_cast<uint32_t>(s9) << 24) |
                 (static_cast<uint32_t>(sd) << 16) |
                 (static_cast<uint32_t>(se) << 8) |
                 (static_cast<uint32_t>(se));
    }
    tablesInit = true;
}


AesTTable::AesTTable(const std::vector<uint8_t>& key) {
    if (key.size() != 16) throw std::runtime_error("Key must be 16 bytes");
    if (!tablesInit) initTables(); // build T0....T3 tables once
    keyExpansion(key);       // Expand and store roundKeys
}

// Key schedule (AES 128 bits to 44 words)
void AesTTable::keyExpansion(const std::vector<uint8_t>& key) {

    roundKeys.resize(44);
// first 4 words from key bytes
    for(int i = 0; i < 4; ++i){
        roundKeys[i] = (static_cast<uint32_t>(key[4*i+0])<< 24) |
                       (static_cast<uint32_t>(key[4*i+1])<< 16) |
                       (static_cast<uint32_t>(key[4*i+2]) << 8) | 
                       (static_cast<uint32_t>(key[4*i+3]) << 0);
    }
 //Rcon[1] = 0x01,Rcon[2] = 0x02,Rcon[3] = 0x04
//doubling each time in GF(2^8), with the irreducible polynomial
//x^8 + x^4 + x^3 + x + 1, add 'u(hexadecimal)' mean unsigned integer literal,C++ teats literal as signed int by default
//AES deal with *bitwise ' operation <<, XOR may generate unexpect error results
//
    static const uint32_t Rcon[10] = {
        0x01000000u,0x02000000u,0x04000000u,0x08000000u,0x10000000u,
        0x20000000u,0x40000000u,0x80000000u,0x1B000000u,0x36000000u
    };
    for (int i = 4; i < 44; ++i) {
        uint32_t temp = roundKeys[i-1];
        if (i % 4 == 0) {
            // RotWord
            temp = (temp << 8) | (temp >> 24);

            // SubWord
            temp = (static_cast<uint32_t>(SBOX[(temp >> 24) & 0xFF]) << 24) |
                   (static_cast<uint32_t>(SBOX[(temp >> 16) & 0xFF]) << 16) |
                   (static_cast<uint32_t>(SBOX[(temp >> 8)  & 0xFF]) << 8) |
                   (static_cast<uint32_t>(SBOX[(temp     )  & 0xFF]) <<  0);

            // XOR Rcon
            temp ^= Rcon[(i/4) - 1];
        }
        roundKeys[i] = roundKeys[i-4] ^ temp;
    }
}

// Encrypt a single 16-byte block using T table
void AesTTable::encryptBlock(const uint8_t in[16], uint8_t out[16]) const {

    // 1. Load input into s0..s3
    // 2. Initial AddRoundKey
    // 3. Rounds 1..9 with T-tables
    // 4. Final round with S-box + ShiftRows + AddRoundKey
    // 5. Store output
// Load state into 4 words
    uint32_t s0 = (in[0]<<24)|(in[1]<<16)|(in[2]<<8)|in[3];
    uint32_t s1 = (in[4]<<24)|(in[5]<<16)|(in[6]<<8)|in[7];
    uint32_t s2 = (in[8]<<24)|(in[9]<<16)|(in[10]<<8)|in[11];
    uint32_t s3 = (in[12]<<24)|(in[13]<<16)|(in[14]<<8)|in[15];

    // Initial round key (word 0..3)
    s0 ^= roundKeys[0];
    s1 ^= roundKeys[1];
    s2 ^= roundKeys[2];
    s3 ^= roundKeys[3];

    // 9 main rounds (T-tables)
    for (int r = 1; r <= 9; ++r) {
        uint32_t t0 =T0[(s0 >> 24)] ^
            T1[(s1 >> 16) & 0xFF] ^
            T2[(s2 >> 8) & 0xFF] ^
            T3[(s3     ) & 0xFF] ^
            roundKeys[4*r + 0];

        uint32_t t1 =T0[(s1 >> 24)] ^
            T1[(s2 >> 16)& 0xFF] ^
            T2[(s3 >> 8) & 0xFF] ^
            T3[(s0     ) & 0xFF] ^
            roundKeys[4*r + 1];

        uint32_t t2 = T0[(s2 >> 24)] ^
            T1[(s3 >> 16) & 0xFF] ^
            T2[(s0 >> 8) & 0xFF] ^
            T3[(s1     ) & 0xFF] ^
            roundKeys[4*r + 2];

        uint32_t t3 = T0[(s3 >> 24)] ^
            T1[(s0 >> 16) & 0xFF] ^
            T2[(s1 >> 8) & 0xFF] ^
            T3[(s2     ) & 0xFF] ^
            roundKeys[4*r + 3];

        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }

    // Final round (no MixColumns, only S-box + ShiftRows + AddRoundKey)
    uint32_t o0 =
        (static_cast<uint32_t>(SBOX[(s0 >> 24)]) << 24) ^
        (static_cast<uint32_t>(SBOX[(s1 >> 16) & 0xFF])<< 16) ^
        (static_cast<uint32_t>(SBOX[(s2 >> 8) & 0xFF])  << 8) ^
        (static_cast<uint32_t>(SBOX[(s3     ) & 0xFF])      ) ^
        roundKeys[40];

    uint32_t o1 =
        (static_cast<uint32_t>(SBOX[(s1 >> 24)]) << 24) ^
        (static_cast<uint32_t>(SBOX[(s2 >> 16) & 0xFF])<< 16) ^
        (static_cast<uint32_t>(SBOX[(s3 >> 8) & 0xFF])  << 8) ^
        (static_cast<uint32_t>(SBOX[(s0     ) & 0xFF])      ) ^
        roundKeys[41];

    uint32_t o2 =
        (static_cast<uint32_t>(SBOX[(s2 >> 24)]) << 24) ^
        (static_cast<uint32_t>(SBOX[(s3 >> 16) & 0xFF])<< 16) ^
        (static_cast<uint32_t>(SBOX[(s0 >> 8)  & 0xFF]) << 8) ^
        (static_cast<uint32_t>(SBOX[(s1     )  & 0xFF]))      ^
        roundKeys[42];

    uint32_t o3 =
        (static_cast<uint32_t>(SBOX[(s3 >> 24)]) << 24) ^
        (static_cast<uint32_t>(SBOX[(s0 >> 16) & 0xFF])<< 16) ^
        (static_cast<uint32_t>(SBOX[(s1 >> 8) & 0xFF])  << 8) ^
        (static_cast<uint32_t>(SBOX[(s2     ) & 0xFF])      ) ^
        roundKeys[43];

    // Store output as 16 bytes
    out[ 0] = static_cast<Byte>(o0 >> 24); out[ 1] = static_cast<Byte>(o0 >> 16);
    out[ 2] = static_cast<Byte>(o0 >>  8); out[ 3] = static_cast<Byte>(o0      );
    out[ 4] = static_cast<Byte>(o1 >> 24); out[ 5] = static_cast<Byte>(o1 >> 16);
    out[ 6] = static_cast<Byte>(o1 >>  8); out[ 7] = static_cast<Byte>(o1      );
    out[ 8] = static_cast<Byte>(o2 >> 24); out[ 9] = static_cast<Byte>(o2 >> 16);
    out[10] = static_cast<Byte>(o2 >>  8); out[11] = static_cast<Byte>(o2      );
    out[12] = static_cast<Byte>(o3 >> 24); out[13] = static_cast<Byte>(o3 >> 16);
    out[14] = static_cast<Byte>(o3 >>  8); out[15] = static_cast<Byte>(o3      );
}

//  Decrypt single 16-byte block using inverse T-table
void AesTTable::decryptBlock(const uint8_t in[16], uint8_t out[16]) const {
    // Load state into 4 words
    uint32_t s0 = (in[0]<<24)|(in[1]<<16)|(in[2]<<8)|in[3];
    uint32_t s1 = (in[4]<<24)|(in[5]<<16)|(in[6]<<8)|in[7];
    uint32_t s2 = (in[8]<<24)|(in[9]<<16)|(in[10]<<8)|in[11];
    uint32_t s3 = (in[12]<<24)|(in[13]<<16)|(in[14]<<8)|in[15];

    // Initial AddRoundKey (last round keys)
    s0 ^= roundKeys[40];
    s1 ^= roundKeys[41];
    s2 ^= roundKeys[42];
    s3 ^= roundKeys[43];

    // 9 main inverse rounds (T-tables)
    for (int r = 9; r >= 1; --r) {
        uint32_t t0 =
            Td0[(s0 >> 24)      ] ^
            Td1[(s3 >> 16)& 0xFF] ^
            Td2[(s2 >> 8) & 0xFF] ^
            Td3[(s1     ) & 0xFF] ^
            roundKeys[4*r + 0];

        uint32_t t1 =
            Td0[(s1 >> 24)]        ^
            Td1[(s0 >> 16) & 0xFF] ^
            Td2[(s3 >> 8) & 0xFF]  ^
            Td3[(s2      ) & 0xFF] ^
            roundKeys[4*r + 1];

        uint32_t t2 =
            Td0[(s2 >> 24)] ^
            Td1[(s1 >> 16) & 0xFF] ^
            Td2[(s0 >> 8) & 0xFF]  ^
            Td3[(s3     )& 0xFF]   ^
            roundKeys[4*r + 2];

        uint32_t t3 =
            Td0[s3 >> 24] ^
            Td1[(s2 >> 16)& 0xFF] ^
            Td2[(s1 >> 8) & 0xFF] ^
            Td3[(s0     ) & 0xFF] ^
            roundKeys[4* + 3];

        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }

    // Final round (no InvMixColumns, only InvSubBytes + InvShiftRows + AddRoundKey)
    uint32_t o0 =
        (static_cast<uint32_t>(Inv_SBOX[(s0 >> 24)]) << 24) ^
        (static_cast<uint32_t>(Inv_SBOX[(s3 >> 16) & 0xFF]) << 16) ^
        (static_cast<uint32_t>(Inv_SBOX[(s2 >>  8)  & 0xFF]) << 8) ^
        (static_cast<uint32_t>(Inv_SBOX[(s1      ) & 0xFF])      ) ^
        roundKeys[0];

    uint32_t o1 =
        (static_cast<uint32_t>(Inv_SBOX[(s1 >> 24)]) << 24) ^
        (static_cast<uint32_t>(Inv_SBOX[(s0 >> 16) & 0xFF]) << 16) ^
        (static_cast<uint32_t>(Inv_SBOX[(s3 >> 8) & 0xFF]) << 8) ^
        (static_cast<uint32_t>(Inv_SBOX[(s2     ) & 0xFF])     ) ^
        roundKeys[1];

    uint32_t o2 =
        (static_cast<uint32_t>(Inv_SBOX[(s2 >> 24)]) << 24) ^
        (static_cast<uint32_t>(Inv_SBOX[(s1 >> 16) & 0xFF]) << 16) ^
        (static_cast<uint32_t>(Inv_SBOX[(s0 >> 8) & 0xFF]) << 8) ^
        (static_cast<uint32_t>(Inv_SBOX[(s3     ) & 0xFF])      )^
        roundKeys[2];

    uint32_t o3 =
        (static_cast<uint32_t>(Inv_SBOX[(s3 >> 24)]) << 24) ^
        (static_cast<uint32_t>(Inv_SBOX[(s2 >> 16) & 0xFF])<< 16) ^
        (static_cast<uint32_t>(Inv_SBOX[(s1 >> 8) & 0xFF]) << 8) ^
        (static_cast<uint32_t>(Inv_SBOX[(s0     ) & 0xFF])    ) ^
        roundKeys[3];

    // Store output
    out[ 0] = static_cast<Byte>(o0 >> 24); out[ 1] = static_cast<Byte>(o0 >> 16);
    out[ 2] = static_cast<Byte>(o0 >>  8); out[ 3] = static_cast<Byte>(o0      );
    out[ 4] = static_cast<Byte>(o1 >> 24); out[ 5] = static_cast<Byte>(o1 >> 16);
    out[ 6] = static_cast<Byte>(o1 >>  8); out[ 7] = static_cast<Byte>(o1      );
    out[ 8] = static_cast<Byte>(o2 >> 24); out[ 9] = static_cast<Byte>(o2 >> 16);
    out[10] = static_cast<Byte>(o2 >>  8); out[11] = static_cast<Byte>(o2      );
    out[12] = static_cast<Byte>(o3 >> 24); out[13] = static_cast<Byte>(o3 >> 16);
    out[14] = static_cast<Byte>(o3 >>  8); out[15] = static_cast<Byte>(o3      );
}

void AesTTable::EncryptionFile(){
    std::array<Byte,16> buf{}, out{};
    std::ifstream f("..\\src\\input.jpg", std::ios::binary);
    std::ofstream g("..\\src\\output_ttable.jpg", std::ios::binary);
    if (!f || !g) { std::perror("open"); return; }

}

