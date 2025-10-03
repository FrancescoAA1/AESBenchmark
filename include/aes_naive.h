#ifndef _LIBRARY_H_
#define _LIBRARY_H_

using Byte = std::uint8_t;

class AesNaive {
public:
    AesNaive(Byte* bytes, unsigned int length);
    Byte ** createState();
    void setstatefromblock(Byte* bytes, unsigned int length);

    void EncryptFile();
    void DecryptFile();

    void displayState(Byte **c);
    void subBytes(Byte **c) const;
    void shiftRows(Byte** state) const;
    void mixColumns(Byte** s) const;
    static Byte xtime(Byte x);

    // returns 11 round keys, each 16 bytes (AES-128)
    std::vector<std::array<Byte,16>> key_expansion() const;

    void addRoundKey(Byte** state, const Byte* round_key) const;
    // optional convenience overload
    void addRoundKey(Byte** state, const std::array<Byte,16>& round_key) const;

    virtual ~AesNaive();

private:
    Byte** data_; 
    Byte* key_;  
};

#endif /* _LIBRARY_H_ */
