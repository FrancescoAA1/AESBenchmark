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

    AesNaive aes;

    using Byte = std::uint8_t;

    Byte newkey[16] = {
        0x7A, 0x1F, 0x93, 0x04,
        0xC5, 0xE2, 0x9B, 0x16,
        0xA8, 0x3C, 0x5E, 0xF1,
        0x7D, 0x44, 0x11, 0x9E
    };

    Byte *state = new Byte[16] {};

    std::array<Byte, 16> buf{};                 // will hold up to 16 bytes
    std::array<Byte,16> cipher{};

    std::ifstream f("..\\src\\input.jpg", std::ios::binary);
    std::ofstream out("..\\src\\output.jpg", std::ios::binary); 

    if (!f || !out) { std::perror("open"); return 1; }

    bool end_of_file = false;
    for(;;)
    {
        f.read(reinterpret_cast<char*>(buf.data()), buf.size());
        std::streamsize n = f.gcount();             // how many bytes were actually read
        if (n < 16 || n == 0){
            //Add padding if needed
            end_of_file = true;
        }

        //for (std::streamsize i = 0; i < n; ++i){
        //    std::printf("0X%02X%s", static_cast<unsigned>(buf[i]),
        //        (i + 1 == n) ? "\n" : " ");
        //}

        for (size_t i = 0; i < n; i++)
        {
            state[i] = buf[i];
        }

        cipher = buf;
        out.write(reinterpret_cast<const char*>(cipher.data()), cipher.size());
        
        if (end_of_file) break;
        //encrypt_block
    }
    
    Byte ** data = aes.createState(state, 16);
    aes.displayState(data);
    
    f.close();
    out.close();
    return 0;
}