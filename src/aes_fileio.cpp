#include "aes_fileio.h"

void AesFileIo::encrypt_file(const std::string &input_filename,
                             const std::string &output_filename,
                             IAES &aes) {

    std::cout << "SHA256 of " << input_filename << ": " << tinysha256::SHA256::file_hash_hex(input_filename.c_str()) << "\n";
    
    std::ifstream in(input_filename, std::ios::binary);
    std::ofstream out(output_filename, std::ios::binary);

    if (!in || !out) {
        std::perror("Error opening files");
        return;
    }

    std::array<Byte, BLOCK_SIZE> buf{};
    while (true) {
        in.read(reinterpret_cast<char*>(buf.data()), BLOCK_SIZE);
        std::streamsize n = in.gcount();

        if (n == 0) break;  // end of file

        if (n < BLOCK_SIZE) {
            Byte pad = BLOCK_SIZE - n;
            for (std::streamsize i = n; i < BLOCK_SIZE; i++) buf[i] = pad;
        }

        auto encrypted_block = aes.encrypt_block(buf);  // must return 16 bytes
        out.write(reinterpret_cast<const char*>(encrypted_block.data()), BLOCK_SIZE);

        if (n < BLOCK_SIZE) break;  // last block
    }

    in.close();
    out.close();
}


void AesFileIo::decrypt_file(const std::string &input_filename,
                             const std::string &output_filename,
                             IAES &aes) {
    std::ifstream in(input_filename, std::ios::binary);
    std::ofstream out(output_filename, std::ios::binary);

    if (!in || !out) {
        std::perror("Error opening files");
        return;
    }

    std::array<Byte, BLOCK_SIZE> buf{};
    std::array<Byte, BLOCK_SIZE> decrypted_block{};

    while (in.read(reinterpret_cast<char*>(buf.data()), BLOCK_SIZE) || in.gcount() > 0) {
        std::streamsize n = in.gcount();
        if (n != BLOCK_SIZE) {
            std::cerr << "Encrypted file corrupted or not a multiple of block size!\n";
            return;
        }

        decrypted_block = aes.decrypt_block(buf);

        if (in.peek() == EOF) {
            Byte pad = decrypted_block[BLOCK_SIZE - 1];
            if (pad < 1 || pad > BLOCK_SIZE) {
                std::cerr << "Invalid padding!\n";
                return;
            }
            out.write(reinterpret_cast<const char*>(decrypted_block.data()), BLOCK_SIZE - pad);
        } else {
            out.write(reinterpret_cast<const char*>(decrypted_block.data()), BLOCK_SIZE);
        }
    }

    in.close();
    out.close();

    std::cout << "SHA256 of " << output_filename << ": " << tinysha256::SHA256::file_hash_hex(output_filename.c_str()) << "\n";
}
