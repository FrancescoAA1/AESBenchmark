#ifndef AesFileIo_H
#define AesFileIo_H

#include <string>
#include <vector>


class AesFileIo
{
public:
    // Constructor
    AesFileIo();

    // Main functions used externally
    // We will be timing their execution time in main.cpp
    void encrypt_file();
    void decrypt_file();

    ~AesFileIo();

private:
  
    std::string input_filename_;
    std::string output_filename_;};

#endif