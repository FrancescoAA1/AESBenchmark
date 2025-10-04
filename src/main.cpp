#include <iostream>
#include <vector>

#include <fstream>
#include <array>
#include <cstdint>
#include <cstdio> 

#include <aes_naive.h>
#include <aes_ttable.h>
#include <aes.h>

using namespace std;

using Byte = std::uint8_t;

int main() {

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
    aes.displayState(data);

    //
    //
    //


    array<Byte, BLOCK_SIZE> key = {
        0x7A, 0x1F, 0x93, 0x04,
        0xC5, 0xE2, 0x9B, 0x16,
        0xA8, 0x3C, 0x5E, 0xF1,
        0x7D, 0x44, 0x11, 0x9E
    };

    AES a(key);



    

//test optimized AES(AES table)
//   std::cout << "\n=== AES-128 T-Table Test ===\n";

//     //same key in naive: newkey[16]
//     std::vector<Byte> key = {
//         0x7A, 0x1F, 0x93, 0x04,
//         0xC5, 0xE2, 0x9B, 0x16,
//         0xA8, 0x3C, 0x5E, 0xF1,
//         0x7D, 0x44, 0x11, 0x9E
//     };


// Create AES-TTable object
    // AesTTable aesT(key);

    // // *NEED TO IMPLEMENT THEM IN CODE" 
    // //aesT.EncryptFile();   // reads ..\src\input.jpg → writes ..\src\output_ttable.jpg
    // //aesT.DecryptFile();   // reads ..\src\output_ttable.jpg → writes ..\src\decrypted_ttable.jpg


    // // Plaintext (FIPS-197 example)
    // Byte plaintext[16] = {
    //     0x32, 0x43, 0xf6, 0xa8,
    //     0x88, 0x5a, 0x30, 0x8d,
    //     0x31, 0x31, 0x98, 0xa2,
    //     0xe0, 0x37, 0x07, 0x34
    // };

    // // Expected ciphertext
    // Byte expected_cipher[16] = {
    //     0x39, 0x25, 0x84, 0x1d,
    //     0x02, 0xdc, 0x09, 0xfb,
    //     0xdc, 0x11, 0x85, 0x97,
    //     0x19, 0x6a, 0x0b, 0x32
    // };
    // Byte ciphertext[16] = {0};
    // Byte decrypted[16] = {0};

    // aesT.encryptBlock(plaintext, ciphertext);
    // aesT.decryptBlock(ciphertext, decrypted);

    // std::cout << "Ciphertext: ";
    // for (int i = 0; i < 16; i++)
    //     std::printf("%02X ", ciphertext[i]);

    // std::cout << "\nDecrypted : ";
    // for (int i = 0; i < 16; i++)
    //     std::printf("%02X ", decrypted[i]);

    // std::cout << std::endl;

    return 0;
}