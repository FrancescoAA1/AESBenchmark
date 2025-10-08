#include <iostream>
#include <vector>

#include <fstream>
#include <array>
#include <cstdint>
#include <cstdio>

#include <chrono>

#include <aes_naive.h>
#include <aes_ttable.h>

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




    return 0;
}