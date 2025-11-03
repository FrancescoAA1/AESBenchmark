/*
#include "../include/aes_constants.h"
#include "../include/aes.h"
#include "../include/aes_naive.h"
#include <iostream>
#include <fstream>
#include <array>
#include "../include/aes_aesni.h"
*/
#include "../include/aes_fileio.h"

// using namespace std;

// AesFileIo::AesFileIo() {}
// AesFileIo::~AesFileIo() {}

// using Byte = std::uint8_t;

 void AesFileIo::encrypt_file() {

    /*AES128U32::Block key = {
        0x04931F7A,
        0x169BE2C5,
        0xF15E3CA8,
        0x9E11447D
    };
    AES128U32 aes(key);

    AES128U32::Block pt{ 0x6bc1bee2u, 0x2e409f96u, 0xe93d7e11u, 0x7393172au };
    AES128U32::Block ct;

    aes.encrypt_block(pt, ct);
    */
}

/*
void AesFileIo::encrypt_file() {

    Key key = {
        0x7A, 0x1F, 0x93, 0x04,
        0xC5, 0xE2, 0x9B, 0x16,
        0xA8, 0x3C, 0x5E, 0xF1,
        0x7D, 0x44, 0x11, 0x9E};
*/
//     AesNaive naive(key);

//     std::array<Byte, 16> buf{};                 // will hold up to 16 bytes
    
//     std::ifstream f("..\\src\\input.jpg", std::ios::binary);
//     std::ofstream out("..\\src\\output.jpg", std::ios::binary); 

//     if (!f || !out) { std::perror("open"); return; }

//     bool end_of_file = false;
//     int nb_blocks = 0;

//     do 
//     {
//         nb_blocks++;
//         f.read(reinterpret_cast<char*>(buf.data()), buf.size());
//         std::streamsize n = f.gcount();             // how many bytes were actually read

//         if (n < 16 || n == 0){
//             end_of_file = true;
//             for (std::streamsize i = n; i < 16; i++){
//                     buf[i] = static_cast<Byte>(16 - n); //PKCS#7 padding
//             }
//         } 
//         // Encrypt the block
//         array<Byte, BLOCK_SIZE> encrypted_block = naive.encrypt_block(buf);
        
//         out.write(reinterpret_cast<const char*>(encrypted_block.data()), encrypted_block.size());

//     } while(!end_of_file);
//     // Implementation for file encryption
//     // Open input file, read contents, encrypt using AesNaive, write to output file
//     f.close();
//     out.close();
// }
// void AesFileIo::decrypt_file() {

//     uint8_t key_ni[16] = {
//         0x7A, 0x1F, 0x93, 0x04,
//         0xC5, 0xE2, 0x9B, 0x16,
//         0xA8, 0x3C, 0x5E, 0xF1,
//         0x7D, 0x44, 0x11, 0x9E};
//     // Implementation for file decryption

//     aesni::AES128KeySchedule ks{};
//     aesni::expand_key(key_ni, ks);

//     aesni::AES128KeySchedule dks{};
//     aesni::expand_key_decrypt(ks, dks);

//     uint8_t decrypted_ni[16];
//     std::array<Byte, 16> buf{};                 // will hold up to 16 bytes

//     std::ifstream f("..\\src\\output.jpg", std::ios::binary);
//     std::ofstream out("..\\src\\decrypted.jpg", std::ios::binary); 
    
//     if (!f || !out) { std::perror("open"); return; }
//     bool end_of_file = false;
//     int nb_blocks = 0;

//     do 
//     {
//         nb_blocks++;
//         f.read(reinterpret_cast<char*>(buf.data()), buf.size());
//         std::streamsize n = f.gcount();             // how many bytes were actually read
//         if (n < 16 || n == 0){
//             end_of_file = true;
//         }
//         // Decrypt the block
//         aesni::decrypt_block(dks, buf.data(), decrypted_ni);

//         if(end_of_file){
//             // Remove PKCS#7 padding
//             Byte padding_length = decrypted_ni[15];
//             out.write(reinterpret_cast<const char*>(decrypted_ni), sizeof(decrypted_ni) - padding_length);
//             break;
//         }else{
//             out.write(reinterpret_cast<const char*>(decrypted_ni), sizeof(decrypted_ni));
//         }

//     } while(!end_of_file);

//     f.close();
//     out.close();
// }

