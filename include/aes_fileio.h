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
    void encrypt_file(const std::string &input_filename, const std::string &output_filename);
    void decrypt_file(const std::string &input_filename, const std::string &output_filename);

    ~AesFileIo();

private:
  
    std::string input_filename_;
    std::string output_filename_;};

#endif