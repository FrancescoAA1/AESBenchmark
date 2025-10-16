#include <iostream>
#include <vector>

#include <fstream>
#include <array>
#include <cstdint>
#include <cstdio>

#include <chrono>

#include <aes_naive.h>
#include <aes_ttable.h>
#include <aes_aesni.h>

#include "aes_constants.h"

using namespace std;

using Byte = std::uint8_t;

int main()
{

     //---------------- Test AES-128 Naive (aes.h) ---------------
     
    cout << "\n=== AES-128 Naive Test ===\n \n";

    Key key = {
        0x7A, 0x1F, 0x93, 0x04,
        0xC5, 0xE2, 0x9B, 0x16,
        0xA8, 0x3C, 0x5E, 0xF1,
        0x7D, 0x44, 0x11, 0x9E};

    AesNaive naive(key);

    string text = "Hasta la vista, baby!";
    cout << "Message: " + text << endl;
    vector<Byte> message(text.begin(), text.end());

    auto start = std::chrono::high_resolution_clock::now();
    vector<Byte> ciphertext = naive.encrypt_message(message);
    auto end = std::chrono::high_resolution_clock::now();

    string cipher_text_str(ciphertext.begin(), ciphertext.end());
    cout << "Ciphertext: " + cipher_text_str << endl;

    cout << "Encryption took "
         << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count()
         << " microseconds.\n";

    start = std::chrono::high_resolution_clock::now();
    vector<Byte> decrypted = naive.decrypt_message(ciphertext);
    end = std::chrono::high_resolution_clock::now();

    string decrypted_text(decrypted.begin(), decrypted.end());
    cout << "Decrypted message: " + decrypted_text << endl;

    cout << "Decryption took "
         << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count()
         << " microseconds.\n";




    //---------------- Test AES-128 Naive (aes.h) ---------------

    cout << "\n=== AES-128 T-Table Test ===\n \n";

    AesTTable table(key);

    string textT = "Hasta la vista, baby!";
    cout << "Message: " + textT << endl;
    vector<Byte> messageT(textT.begin(), textT.end());

    start = std::chrono::high_resolution_clock::now();
    vector<Byte> ciphertextT = table.encrypt_message(messageT);
    end = std::chrono::high_resolution_clock::now();

    string cipher_text_strT(ciphertextT.begin(), ciphertextT.end());
    cout << "Ciphertext: " + cipher_text_strT << endl;

    cout << "Encryption took "
         << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count()
         << " microseconds.\n";

    start = std::chrono::high_resolution_clock::now();
    vector<Byte> decryptedT = table.decrypt_message(ciphertextT);
    end = std::chrono::high_resolution_clock::now();

    string decrypted_textT(decryptedT.begin(), decryptedT.end());
    cout << "Decrypted message: " + decrypted_textT << endl;

    cout << "Decryption took "
         << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count()
         << " microseconds.\n";



    if (!aesni::cpu_has_aesni()) { std::puts("No AES-NI"); return 1; }

    uint8_t key_ni[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t pt [16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    uint8_t ct [16];

    std::puts("AES-NI test:");
    
    aesni::AES128KeySchedule ks{};
    aesni::expand_key(key_ni, ks);
    aesni::encrypt_block(ks, pt, ct);

     aesni::AES128KeySchedule dks{};
     aesni::expand_key_decrypt(ks, dks);
     uint8_t decrypted_ni[16];
     aesni::decrypt_block(dks, ct, decrypted_ni);

    for (auto b : ct) std::printf("%02x", b);
    cout << "\n"; // Expected: 69c4e0d86a7b0430d8cdb78070b4c55a
    for (auto b : decrypted_ni) std::printf("%02x", b);
    std::puts(""); // Expected: 00112233445566778899aabbccddeeff

    return 0;
}