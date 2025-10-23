cmake_minimum_required(VERSION 3.15)
project(AES VERSION 0.1.0 LANGUAGES C CXX)


include_directories(include)
enable_testing()


add_executable(AES src/main.cpp src/aes_naive.cpp src/aes_ttable.cpp src/aes_aesni.cpp src/aes_fileio.cpp)

# Compile AES intrinsics only for this file (GCC/Clang need -maes; -mpclmul is for GCM/HASH)
set_source_files_properties(src/aes_aesni.cpp PROPERTIES
    COMPILE_OPTIONS "$<$<CXX_COMPILER_ID:GNU,Clang>:-maes;-mpclmul>"
)

set_property( TARGET AES PROPERTY CMAKE_CXX_STANDARD 17)