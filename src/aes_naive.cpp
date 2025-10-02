#include <iostream>
#include <iomanip>
#include "..\include\aes_naive.h"

using namespace std;

using Byte = std::uint8_t;

static inline void printByte(Byte b) {
    std::cout << "0X"
              << std::uppercase << std::hex
              << std::setw(2) << std::setfill('0')  
              << static_cast<unsigned>(b); // avoid sign/width issues
    std::cout << std::dec << " "; // restore if you print numbers later
}

AesNaive::AesNaive() {
    //data_ = createState("0123456789abcdef", 16);
    // Initialize the state with the provided chars
    
}
// Task 1(a).  Implement this function
Byte ** AesNaive::createState(Byte* bytes, unsigned int length) {
    // Replace the following with your code
    int n = 4; // AES block size is 4x4
    Byte **state = new Byte*[n];
    for(int i = 0; i < n; i++){
        state[i] = new Byte[n];
    }

    for(int i = 0; i < n; i++){
        for(int j = 0; j < n; j++){
            state[i][j] = bytes[i * n + j];
        }
    }
    return state;
}

// Task 1(b).  Implement this function
void AesNaive::displayState(Byte **c) {
    // Write your code here
    int n = 4; // AES block size is 4x4
    for(int i = 0; i < n; i++){
        for(int j = 0; j < n; j++){
            //cout << c[i][j] << " ";
            //cout << static_cast<int>(c[i][j]) << " ";
            printByte(c[i][j]);
        }
        cout << endl;
    }
}

void AesNaive::mutateState(Byte **c) {
    // Write your code here
    c[3][2] = Byte{0xAC}; // Example mutation: XOR the first byte with 0x01
}

AesNaive::~AesNaive() {
    for (std::size_t i = 0; i < 4; ++i) {
        delete[] data_[i];
    }
    delete[] data_;
}
