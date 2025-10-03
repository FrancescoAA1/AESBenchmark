#include <iostream>
#include <vector>
#include <aes_naive.h>
#include <fstream>
#include <array>_tt
#include <cstdint>
#include <cstdio>  
#include <aes_ttable>
using namespace std;

using Byte = std::uint8_t;

int main() {
    std::vector<int> numbers = {1, 2, 3, 4, 5, 6, 9, 10};
    for (const auto& num : numbers) {
        std::cout << num << " ";
    }
    std::cout << std::endl;

    Byte newkey[16] = {
        0x7A, 0x1F, 0x93, 0x04,
        0xC5, 0xE2, 0x9B, 0x16,
        0xA8, 0x3C, 0x5E, 0xF1,
        0x7D, 0x44, 0x11, 0x9E
    };

    AesNaive aes(newkey, 16);

    Byte ** data = aes.createState();

    aes.EncryptFile();
    //Byte ** data = aes.createState(state, 16);
    //aes.displayState(data);


//test optimized AES(AES table)
  std::cout << "\n=== AES-128 T-Table Test ===\n";

    // AES-128 key (FIPS-197 example)
    std::vector<uint8_t> key{
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x97, 0x75,
        0x46, 0x20, 0x63, 0x75
    };

    // Plaintext (FIPS-197 example)
    uint8_t plaintext[16] = {
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2,
        0xe0, 0x37, 0x07, 0x34
    };

    // Expected ciphertext
    uint8_t expected_cipher[16] = {
        0x39, 0x25, 0x84, 0x1d,
        0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97,
        0x19, 0x6a, 0x0b, 0x32
    };

    uint8_t ciphertext[16];
    uint8_t decrypted[16];

    // Create AES with T-tables
    AESTTable aesT(key);
    aes.encryptBlock(plaintext, ciphertext);

// Decrypt
aes.decryptBlock(ciphertext, decrypted);

// Print results
std::cout << "Ciphertext: ";
for (int i = 0; i < 16; i++) std::cout << std::hex << (int)ciphertext[i] << " ";
std::cout << "\nDecrypted : ";
for (int i = 0; i < 16; i++) std::cout << std::hex << (int)decrypted[i] << " ";
std::cout << std::endl;


   return 0;
}