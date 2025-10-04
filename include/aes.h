//Header guards
#pragma once

#ifndef AES_H
#define AES_H

#include <cstdint>
#include <array>
#include <vector>

//using an alias for clarity
using Byte = std::uint8_t;

//Constants
constexpr int BLOCK_SIZE = 16;

class AES {
    public:
        
    //Constructor
    explicit AES(const std::array<Byte, BLOCK_SIZE>& key);

    //Main methods
    std::vector<Byte> encrypt_message(const std::vector<Byte>& message);
    std::vector<Byte> decrypt_message(const std::vector<Byte>& ciphertext);

    private:

    std::array<Byte, BLOCK_SIZE> key_;

};

#endif