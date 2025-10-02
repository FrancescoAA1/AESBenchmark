#ifndef _LIBRARY_H_
#define _LIBRARY_H_

using Byte = std::uint8_t;

class AesNaive {
public:
    AesNaive();
    Byte ** createState(Byte* bytes, unsigned int length);
    void displayState(Byte **c);
    void mutateState(Byte **c);
    virtual ~AesNaive();

private:
    Byte** data_;   
};

#endif /* _LIBRARY_H_ */
