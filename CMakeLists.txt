cmake_minimum_required(VERSION 3.15)
project(AES VERSION 0.1.0 LANGUAGES C CXX)


include_directories(include)
enable_testing()

add_executable(AES src/main.cpp)

set_property( TARGET AES PROPERTY CMAKE_CXX_STANDARD 17)