#pragma once

#include <memory>
#include "aes.h"

#if HAVE_BOTAN
  #include <botan/block_cipher.h>
#else

// Forward declaration is enough for a pointer / unique_ptr
namespace Botan {
    class BlockCipher;
}
#endif

class AesBotanWrapper : public IAES {
public:
    explicit AesBotanWrapper(const Key& key);

    Block encrypt_block(const Block &in) override;
    Block decrypt_block(const Block &in) override;

private:
#if HAVE_BOTAN
    std::unique_ptr<Botan::BlockCipher> cipher;
#endif
};
