// #pragma once
// #include <botan/block_cipher.h>
// #include "aes.h"

// class AesBotanWrapper : public IAES {
// public:
//     explicit AesBotanWrapper(const Key& key);

//     Block encrypt_block(const Block &in) override;
//     Block decrypt_block(const Block &in) override;

// private:
//     std::unique_ptr<Botan::BlockCipher> cipher;
// };