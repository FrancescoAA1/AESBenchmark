#pragma once

#include <memory>
#include "aes.h"

//We handle the absence of Botan library at compile time
//This is necessary since we maintained Linux/Windows compatibility 
//but the installation shells only work for Linux.

#if HAVE_BOTAN
  #include <botan/block_cipher.h>
#else


namespace Botan {
    class BlockCipher;
}
#endif

// Wrapper for Botan cryptographic library's AES implementation

class AesBotanWrapper : public IAES {
public:
    explicit AesBotanWrapper(const Key& key);

    Block encrypt_block(const Block &in) override;
    Block decrypt_block(const Block &in) override;

private:

// If HAVE_BOTAN is false, class compiles but cipher operations will fail silently
// This allows the project to build without Botan dependency

#if HAVE_BOTAN
    std::unique_ptr<Botan::BlockCipher> cipher;
#endif
};
