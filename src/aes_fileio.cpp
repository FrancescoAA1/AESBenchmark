#include "../include/aes_fileio.h"
#include "../include/aes_constants.h"
#include <iostream>
#include <fstream>
#include <array>

using namespace std;

AesFileIo::AesFileIo() {}
AesFileIo::~AesFileIo() {}

using Byte = std::uint8_t;

void AesFileIo::encrypt_file(const std::string &input_filename, const std::string &output_filename) {

    std::array<Byte, 16> buf{};                 // will hold up to 16 bytes
    std::array<Byte,16> cipher{};
    
    std::ifstream f("..\\src\\input.jpg", std::ios::binary);
    std::ofstream out("..\\src\\output.jpg", std::ios::binary); 

    if (!f || !out) { std::perror("open"); return; }

    bool end_of_file = false;

    do 
    {
        f.read(reinterpret_cast<char*>(buf.data()), buf.size());
        std::streamsize n = f.gcount();             // how many bytes were actually read

        if (n < 16 || n == 0){
            end_of_file = true;
            cout << "End of file reached or padding needed." << "n = " << n << endl;
            cout << "Buffer size: " << buf.size() << endl;
            for (std::streamsize i = n; i < 16; i++){
                    buf[i] = static_cast<Byte>(16 - n); //PKCS#7 padding
            }
            for (std::streamsize i = 0; i < 16; i++){
                cout << std::hex << static_cast<int>(buf[i]) << " ";
            }
            cout << endl;

        } 
        cout << "Bytes read: " << n << endl;

    } while(!end_of_file);
    // Implementation for file encryption
    // Open input file, read contents, encrypt using AesNaive, write to output file
}
void AesFileIo::decrypt_file(const std::string &input_filename, const std::string &output_filename) {
    // Implementation for file decryption
    // Open input file, read contents, decrypt using AesNaive, write to output file
}
