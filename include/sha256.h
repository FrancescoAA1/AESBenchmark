#pragma once
#include <cstddef>
#include <cstdint>
#include <string>

// Small SHA-256 utility for cryptographic hashing

namespace tinysha256 {

class SHA256 {
public:
    SHA256();

    //To initialize the hasher
    void init();

    //Function that feeds bytes into the hash.
    void update(const void* data, std::size_t len);

    // Finalize and write 32-byte digest
    void final(std::uint8_t out[32]);

    //Computes SHA-256 of a whole buffer.
    static std::string hash_hex(const void* data, std::size_t len);

    //Computes SHA-256 of a file
    static std::string file_hash_hex(const char* path);

    // Helper to hex-encode a raw digest
    static std::string to_hex(const std::uint8_t* data, std::size_t len);

private:

    //logical functions for compression + sigma functions
    static inline std::uint32_t rotr(std::uint32_t x, std::uint32_t n) { return (x >> n) | (x << (32u - n)); }
    static inline std::uint32_t ch(std::uint32_t x, std::uint32_t y, std::uint32_t z) { return (x & y) ^ (~x & z); }
    static inline std::uint32_t maj(std::uint32_t x, std::uint32_t y, std::uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    static inline std::uint32_t bsig0(std::uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
    static inline std::uint32_t bsig1(std::uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
    static inline std::uint32_t ssig0(std::uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
    static inline std::uint32_t ssig1(std::uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

    // Big-endian byte order conversion utilities
    static std::uint32_t load_be32(const std::uint8_t* p);
    static void store_be32(std::uint8_t* p, std::uint32_t v);
    static void store_be64(std::uint8_t* p, std::uint64_t v);

    void compress_block(const std::uint8_t block[64]);

private:
    std::uint32_t h_[8];        // Current hash value (A,B,C,D,E,F,G,H)
    std::uint64_t bitlen_ = 0;  // Total number of bits processed so far
    std::uint8_t  buf_[64];     // Input buffer for incomplete blocks
    std::size_t   buflen_ = 0;  // Number of bytes currently in buffer
};

}
