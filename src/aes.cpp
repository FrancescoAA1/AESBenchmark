
#include <vector>
#include <array>
#include <cstdint>


#include "../include/aes.h"

using namespace std;

AES::AES(const array<Byte, BLOCK_SIZE>& key) : key_(key) {
    std::cout << "AES constructor" << std::endl;
}