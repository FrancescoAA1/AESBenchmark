cmake_minimum_required(VERSION 3.15)
project(AES VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Release)

include_directories(include)
enable_testing()

find_package(PkgConfig)
pkg_check_modules(BOTAN2 REQUIRED botan-2)

include_directories(${BOTAN_INCLUDE_DIRS})
link_directories(${BOTAN_LIBRARY_DIRS})

add_executable(AES src/main.cpp src/aes_naive.cpp src/aes_ttable.cpp src/aes_aesni.cpp src/aes_benchmark.cpp src/aes_fileio.cpp src/aes_naive_int.cpp src/aes_botan_wrapper.cpp src/sha256.cpp)

# Compile AES intrinsics only for this file (GCC/Clang need -maes; -mpclmul is for GCM/HASH)
set_source_files_properties(src/aes_aesni.cpp PROPERTIES
    COMPILE_OPTIONS "$<$<CXX_COMPILER_ID:GNU,Clang>:-maes;-mpclmul>"
)

target_include_directories(AES PRIVATE ${BOTAN2_INCLUDE_DIRS})
target_link_libraries(AES PRIVATE ${BOTAN2_LIBRARIES})
target_compile_options(AES PRIVATE ${BOTAN2_CFLAGS_OTHER})

message(STATUS "Botan include dirs: ${BOTAN2_INCLUDE_DIRS}")
message(STATUS "Botan libraries: ${BOTAN2_LIBRARIES}")
message(STATUS "Botan cflags: ${BOTAN2_CFLAGS_OTHER}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")


# cmake_minimum_required(VERSION 3.15)
# project(AES VERSION 0.1.0 LANGUAGES C CXX)

# set(CMAKE_CXX_STANDARD 17)
# set(CMAKE_CXX_STANDARD_REQUIRED ON)
# set(CMAKE_CXX_EXTENSIONS OFF)

# include_directories(include)
# enable_testing()
# add_executable(AES src/main.cpp src/aes_naive.cpp src/aes_ttable.cpp src/aes_aesni.cpp src/aes_benchmark.cpp src/aes_fileio.cpp src/aes_naive_int.cpp src/sha256.cpp)
# set_source_files_properties(src/aes_aesni.cpp PROPERTIES    
#     COMPILE_OPTIONS "$<$<CXX_COMPILER_ID:GNU,Clang>:-maes;-mpclmul>"
# )
# set_property( TARGET AES PROPERTY CMAKE_CXX_STANDARD 17)

