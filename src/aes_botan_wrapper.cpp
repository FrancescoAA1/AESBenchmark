#include "../include/aes_botan_wrapper.h"

#if HAVE_BOTAN

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

#else                        // Windows: dummy implementation (no Botan)

#include <stdexcept>

AesBotanWrapper::AesBotanWrapper(const Key& /*key*/) {
    // Either do nothing (if you're sure you won't use this backend),
    // or throw so you notice if it's accidentally used:
    // throw std::runtime_error("Botan backend not available on Windows");
}

Block AesBotanWrapper::encrypt_block(const Block &in) {
    // DANGEROUS: this does no encryption. OK only if you never call it.
    return in;
}

Block AesBotanWrapper::decrypt_block(const Block &in) {
    // Same here: no-op.
    return in;
}

#endif