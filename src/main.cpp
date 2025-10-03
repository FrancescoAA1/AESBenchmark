#include <iostream>
#include <vector>
#include <aes_naive.h>
#include <fstream>
#include <array>
#include <cstdint>
#include <cstdio>   


using namespace std;

int main() {
    std::vector<int> numbers = {1, 2, 3, 4, 5, 6, 9, 10};
    for (const auto& num : numbers) {
        std::cout << num << " ";
    }
    std::cout << std::endl;

    Byte newkey[16] = {
        0x7A, 0x1F, 0x93, 0x04,
        0xC5, 0xE2, 0x9B, 0x16,
        0xA8, 0x3C, 0x5E, 0xF1,
        0x7D, 0x44, 0x11, 0x9E
    };

    AesNaive aes(newkey, 16);

    Byte ** data = aes.createState();

    aes.EncryptFile();
    //Byte ** data = aes.createState(state, 16);
    //aes.displayState(data);
    
    return 0;
}