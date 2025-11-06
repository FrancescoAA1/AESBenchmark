#include "sha256.h"

#include <cstdio>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <vector>

namespace tinysha256 {

namespace {
constexpr std::uint32_t K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};
} // namespace

SHA256::SHA256() { init(); }

void SHA256::init() {
    h_[0]=0x6a09e667u; h_[1]=0xbb67ae85u; h_[2]=0x3c6ef372u; h_[3]=0xa54ff53au;
    h_[4]=0x510e527fu; h_[5]=0x9b05688cu; h_[6]=0x1f83d9abu; h_[7]=0x5be0cd19u;
    bitlen_ = 0;
    buflen_ = 0;
}

std::uint32_t SHA256::load_be32(const std::uint8_t* p) {
    return (std::uint32_t(p[0])<<24)|(std::uint32_t(p[1])<<16)|(std::uint32_t(p[2])<<8)|std::uint32_t(p[3]);
}
void SHA256::store_be32(std::uint8_t* p, std::uint32_t v) {
    p[0]=std::uint8_t(v>>24); p[1]=std::uint8_t(v>>16); p[2]=std::uint8_t(v>>8); p[3]=std::uint8_t(v);
}
void SHA256::store_be64(std::uint8_t* p, std::uint64_t v) {
    // big-endian 64-bit store
    for (int i=7;i>=0;--i) p[7-i] = std::uint8_t(v>>(i*8));
}

void SHA256::compress_block(const std::uint8_t block[64]) {
    std::uint32_t w[64];
    for (int i=0;i<16;++i) w[i] = load_be32(block + 4*i);
    for (int i=16;i<64;++i) w[i] = ssig1(w[i-2]) + w[i-7] + ssig0(w[i-15]) + w[i-16];

    std::uint32_t a=h_[0], b=h_[1], c=h_[2], d=h_[3], e=h_[4], f=h_[5], g=h_[6], h=h_[7];

    for (int i=0;i<64;++i) {
        std::uint32_t t1 = h + bsig1(e) + ch(e,f,g) + K[i] + w[i];
        std::uint32_t t2 = bsig0(a) + maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    h_[0]+=a; h_[1]+=b; h_[2]+=c; h_[3]+=d; h_[4]+=e; h_[5]+=f; h_[6]+=g; h_[7]+=h;
}

void SHA256::update(const void* data_v, std::size_t len) {
    auto* data = static_cast<const std::uint8_t*>(data_v);
    bitlen_ += std::uint64_t(len) * 8u;

    // Fill existing partial buffer
    if (buflen_) {
        std::size_t to_copy = (len < (64 - buflen_)) ? len : (64 - buflen_);
        std::memcpy(buf_ + buflen_, data, to_copy);
        buflen_ += to_copy;
        data += to_copy;
        len  -= to_copy;
        if (buflen_ == 64) {
            compress_block(buf_);
            buflen_ = 0;
        }
    }

    // Process full blocks
    while (len >= 64) {
        compress_block(data);
        data += 64;
        len  -= 64;
    }

    // Buffer remainder
    if (len) {
        std::memcpy(buf_, data, len);
        buflen_ = len;
    }
}

void SHA256::final(std::uint8_t out[32]) {
    // Pad: 0x80 then zeros, leaving 8 bytes for length (big-endian)
    std::uint8_t pad[64] = {0x80};
    std::size_t padlen = (buflen_ < 56) ? (56 - buflen_) : (64 + 56 - buflen_);
    update(pad, padlen);

    std::uint8_t lenbe[8];
    store_be64(lenbe, bitlen_);
    update(lenbe, 8);

    for (int i=0;i<8;++i) store_be32(out + 4*i, h_[i]);
}

std::string SHA256::to_hex(const std::uint8_t* data, std::size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (std::size_t i=0;i<len;++i)
        oss << std::setw(2) << static_cast<unsigned>(data[i]);
    return oss.str();
}

std::string SHA256::hash_hex(const void* data, std::size_t len) {
    SHA256 ctx;
    ctx.update(data, len);
    std::uint8_t digest[32];
    ctx.final(digest);
    return to_hex(digest, 32);
}

std::string SHA256::file_hash_hex(const char* path) {
    std::FILE* f = std::fopen(path, "rb");
    if (!f) throw std::runtime_error("fopen failed");

    SHA256 ctx;
    std::vector<std::uint8_t> buf(1u << 16); // 64 KiB

    std::size_t n;
    while ((n = std::fread(buf.data(), 1, buf.size(), f)) != 0) {
        ctx.update(buf.data(), n);
    }
    std::fclose(f);

    std::uint8_t digest[32];
    ctx.final(digest);
    return to_hex(digest, 32);
}

} // namespace tinysha256
