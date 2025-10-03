#include <iostream>
#include <iomanip>

#include <iostream>
#include <vector>
#include <fstream>
#include <array>
#include <cstdint>
#include <cstdio>   
#include <cstddef>

#include "..\include\aes_naive.h"

using namespace std;

// === AES S-box and Rcon ===
static constexpr Byte SBOX[256] = {
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
};

static constexpr Byte RCON[10] = {
    0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36
};

// === small helpers ===
static inline std::array<Byte,4> rot_word(std::array<Byte,4> w) {
    return { w[1], w[2], w[3], w[0] };
}
static inline void sub_word_inplace(std::array<Byte,4>& w) {
    w[0] = SBOX[w[0]];
    w[1] = SBOX[w[1]];
    w[2] = SBOX[w[2]];
    w[3] = SBOX[w[3]];
}

static inline void printByte(Byte b) {
    std::cout << "0X"
              << std::uppercase << std::hex
              << std::setw(2) << std::setfill('0')  
              << static_cast<unsigned>(b); // avoid sign/width issues
    std::cout << std::dec << " "; // restore if you print numbers later
}

AesNaive::AesNaive(Byte* bytes, unsigned int length) {
    key_ = new Byte[16] {};
    for (unsigned int i = 0; i < length && i < 16; ++i) {
        key_[i] = bytes[i];
    }
    //data_ = createState("0123456789abcdef", 16);
    // Initialize the state with the provided chars
    
}

void AesNaive::DecryptFile() {

    // Implement file decryption here
    return;
}

void AesNaive::EncryptFile() {
    // Implement file encryption here
    Byte *state = new Byte[16] {};
    std::array<Byte, 16> buf{};                 // will hold up to 16 bytes
    std::array<Byte,16> cipher{};

    if (!data_) createState(); // ensure data_ is initialized

    std::ifstream f("..\\src\\input.jpg", std::ios::binary);
    std::ofstream out("..\\src\\output.jpg", std::ios::binary); 

    const auto roundKeys = key_expansion(); // 11 × 16 bytes

    if (!f || !out) { std::perror("open"); return; }

    bool end_of_file = false;
    bool need_final_pad = false;  
    for(;;)
    {
        f.read(reinterpret_cast<char*>(buf.data()), buf.size());
        std::streamsize n = f.gcount();             // how many bytes were actually read
        
        if (need_final_pad) {                  // emit the extra 0x10...0x10 block
            buf.fill(16);
            n = 16;
            end_of_file = true;
            need_final_pad = false;
        } else if (n == 16) {                  // full block; if EOF now, schedule extra pad block
            if (f.peek() == std::char_traits<char>::eof())
            need_final_pad = true;
        } else if (n > 0) {                    // short last block → pad it
            Byte pad = static_cast<Byte>(16 - n);
            for (size_t i = static_cast<size_t>(n); i < 16; ++i) buf[i] = pad;
                n = 16;
                end_of_file = true;
        } else {                               // n == 0 and no pending pad → done
            break;
        }
        
        //for (std::streamsize i = 0; i < n; ++i){
        //    std::printf("0X%02X%s", static_cast<unsigned>(buf[i]),
        //        (i + 1 == n) ? "\n" : " ");
        //}

        // Copy buf into state (column-major)
        std::copy(buf.begin(), buf.end(), state);

        setstatefromblock(state, 16);

        addRoundKey(data_, roundKeys[0]);
        // 9 main rounds
        for (int round = 1; round <= 9; ++round) {
            subBytes(data_);
            shiftRows(data_);
            mixColumns(data_);
            addRoundKey(data_, roundKeys[round]);
        }
        // final round (no MixColumns)
        subBytes(data_);
        shiftRows(data_);
        addRoundKey(data_, roundKeys[10]);

        // Collect cipher text from state (column-major)
        for (int c = 0, k = 0; c < 4; ++c)
            for (int r = 0; r < 4; ++r, ++k)
                cipher[k] = data_[r][c];
        
        out.write(reinterpret_cast<const char*>(cipher.data()), cipher.size());
        
        if (end_of_file) break;
       
    }
    f.close();
    out.close();
    return;
}

void AesNaive::setstatefromblock(Byte* bytes, unsigned int length) {
    // Replace the following with your code
    int n = 4; // AES block size is 4x4
    for(int r = 0; r < n; r++){
        for(int c = 0; c < n; c++){
            data_[r][c] = bytes[c * n + r]; // column-major
        }
    }
    return;
}
// Task 1(a).  Implement this function
Byte ** AesNaive::createState() {
    // Replace the following with your code
    int n = 4; // AES block size is 4x4
    Byte **state = new Byte*[n];
    for(int i = 0; i < n; i++){
        state[i] = new Byte[n];
    }
    // Initialize state to zero
    data_ = state;
    return state;
}

// Task 1(b).  Implement this function
void AesNaive::displayState(Byte **c) {
    // Write your code here
    int n = 4; // AES block size is 4x4
    for(int i = 0; i < n; i++){
        for(int j = 0; j < n; j++){
            //cout << c[i][j] << " ";
            //cout << static_cast<int>(c[i][j]) << " ";
            printByte(c[i][j]);
        }
        cout << endl;
    }
}

void AesNaive::subBytes(Byte** state) const {
    for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 4; ++c) {
            state[r][c] = SBOX[state[r][c]];
        }
    }
}

void AesNaive::shiftRows(Byte** state) const {
    // Row 0: unchanged

    // Row 1: rotate left by 1 -> [b, c, d, a]
    {
        Byte a = state[1][0], b = state[1][1], c = state[1][2], d = state[1][3];
        state[1][0] = b; state[1][1] = c; state[1][2] = d; state[1][3] = a;
    }

    // Row 2: rotate left by 2 -> [c, d, a, b]
    {
        Byte a = state[2][0], b = state[2][1], c = state[2][2], d = state[2][3];
        state[2][0] = c; state[2][1] = d; state[2][2] = a; state[2][3] = b;
    }

    // Row 3: rotate left by 3 (== right by 1) -> [d, a, b, c]
    {
        Byte a = state[3][0], b = state[3][1], c = state[3][2], d = state[3][3];
        state[3][0] = d; state[3][1] = a; state[3][2] = b; state[3][3] = c;
    }
}

static inline Byte Xtime(Byte a) {
    unsigned v = static_cast<unsigned>(a);
    return static_cast<Byte>( ((v << 1) & 0xFFu) ^ ((v & 0x80u) ? 0x1Bu : 0x00u) );
}

// This is the well-known fast formulation that’s equivalent to multiplying by the AES matrix [[2,3,1,1], …] in GF(2⁸), but way shorter and quicker.
void AesNaive::mixColumns(Byte** s) const {
    for (int c = 0; c < 4; ++c) {
        Byte a0 = s[0][c], a1 = s[1][c], a2 = s[2][c], a3 = s[3][c];
        Byte t  = static_cast<Byte>(a0 ^ a1 ^ a2 ^ a3);
        Byte u0 = a0, u1 = a1, u2 = a2, u3 = a3;

        s[0][c] = static_cast<Byte>(a0 ^ t ^ Xtime(static_cast<Byte>(u0 ^ u1)));
        s[1][c] = static_cast<Byte>(a1 ^ t ^ Xtime(static_cast<Byte>(u1 ^ u2)));
        s[2][c] = static_cast<Byte>(a2 ^ t ^ Xtime(static_cast<Byte>(u2 ^ u3)));
        s[3][c] = static_cast<Byte>(a3 ^ t ^ Xtime(static_cast<Byte>(u3 ^ u0)));
    }
}

// Generate 44 words then pack into 11 round keys (AES-128).
// Uses this->key_ (16 bytes). Column-major packing to 16-byte round keys.
std::vector<std::array<Byte,16>> AesNaive::key_expansion() const {
    // 44 words of 4 bytes each
    std::array<std::array<Byte,4>, 44> W{};

    // W[0..3] directly from key_ (bytes 0..3, 4..7, 8..11, 12..15)
    for (int i = 0; i < 4; ++i) {
        W[i][0] = key_[4*i + 0];
        W[i][1] = key_[4*i + 1];
        W[i][2] = key_[4*i + 2];
        W[i][3] = key_[4*i + 3];
    }

    // W[4..43]
    for (int i = 4; i < 44; ++i) {
        std::array<Byte,4> temp = W[i - 1];

        if (i % 4 == 0) {
            temp = rot_word(temp);           // rotate left by 1 byte
            sub_word_inplace(temp);          // S-box each byte
            temp[0] = static_cast<Byte>(temp[0] ^ RCON[(i / 4) - 1]); // XOR first byte with Rcon
        }

        // W[i] = W[i-4] XOR temp
        W[i][0] = static_cast<Byte>(W[i - 4][0] ^ temp[0]);
        W[i][1] = static_cast<Byte>(W[i - 4][1] ^ temp[1]);
        W[i][2] = static_cast<Byte>(W[i - 4][2] ^ temp[2]);
        W[i][3] = static_cast<Byte>(W[i - 4][3] ^ temp[3]);
    }

    // Pack into 11 round keys (4 words per round, 16 bytes), column-major
    std::vector<std::array<Byte,16>> round_keys;
    round_keys.reserve(11);

    for (int r = 0; r < 11; ++r) {
        std::array<Byte,16> rk{};
        int k = 0;
        for (int c = 0; c < 4; ++c) {
            const auto& w = W[4*r + c];
            rk[k++] = w[0];
            rk[k++] = w[1];
            rk[k++] = w[2];
            rk[k++] = w[3];
        }
        round_keys.push_back(rk);
    }
    return round_keys;
}

void AesNaive::addRoundKey(Byte** state, const Byte* round_key) const {
    // state[r][c] ^= round_key[4*c + r]  (column-major)
    for (int c = 0; c < 4; ++c) {
        for (int r = 0; r < 4; ++r) {
            state[r][c] = static_cast<Byte>(state[r][c] ^ round_key[4*c + r]);
        }
    }
}

void AesNaive::addRoundKey(Byte** state, const std::array<Byte,16>& round_key) const {
    addRoundKey(state, round_key.data());
}


AesNaive::~AesNaive() {
    for (std::size_t i = 0; i < 4; ++i) {
        delete[] data_[i];
    }
    delete[] data_;
}
