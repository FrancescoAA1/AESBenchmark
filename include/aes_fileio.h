#ifndef AESFILEIO_H
#define AESFILEIO_H

#include <string>
#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>
#include "aes.h"
#include "aes_constants.h"
#include "sha256.h"

using Byte = std::uint8_t;

class AesFileIo {
public:
    AesFileIo() = default;
    ~AesFileIo() = default;

    void encrypt_file(const std::string &input_filename,
                      const std::string &output_filename,
                      IAES &aes);

    void decrypt_file(const std::string &input_filename,
                      const std::string &output_filename,
                      IAES &aes);
};

#endif
