
// Provides reference implementation using established crypto library
#include "../include/aes_botan_wrapper.h"

// Conditional compilation based on Botan availability
#if HAVE_BOTAN

#include <botan/aes.h>


AesBotanWrapper::AesBotanWrapper(const Key& key) {

    // Create AES-128 cipher instance using Botan's factory method
    // Botan automatically selects optimal implementation
    cipher = Botan::BlockCipher::create("AES-128");
    
    // Convert key from std::array to std::vector for Botan interface
    std::vector<uint8_t> key_vec(key.begin(), key.end());
    
    // Initialize cipher with the 128-bit key
    cipher->set_key(key_vec);
}

Block AesBotanWrapper::encrypt_block(const Block &in) {
    Block out;
    cipher->encrypt(in.data(), out.data());
    return out;
}

Block AesBotanWrapper::decrypt_block(const Block &in) {
    Block out;
    cipher->decrypt(in.data(), out.data());
    return out;
}

#else 

// This allows the project to compile without Botan dependency
//since we did not provide an installation shell for Windows

#include <stdexcept>

AesBotanWrapper::AesBotanWrapper(const Key& /*key*/) {
}

Block AesBotanWrapper::encrypt_block(const Block &in) {
    return in;
}

Block AesBotanWrapper::decrypt_block(const Block &in) {
    return in;
}

#endif