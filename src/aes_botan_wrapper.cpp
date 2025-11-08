#include "../include/aes_botan_wrapper.h"
#include <botan/aes.h>

AesBotanWrapper::AesBotanWrapper(const Key& key) {
    cipher = Botan::BlockCipher::create("AES-128");
    std::vector<uint8_t> key_vec(key.begin(), key.end());
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
