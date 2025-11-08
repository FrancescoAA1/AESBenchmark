cmake_minimum_required(VERSION 3.15)
project(AES VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Release)

include_directories(include)
enable_testing()

# --- Option: turn Botan backend on/off (default ON except on Windows) ---
if (WIN32)
    option(USE_BOTAN "Enable Botan backend (requires botan-2)" OFF)
else()
    option(USE_BOTAN "Enable Botan backend (requires botan-2)" ON)
endif()

# --- Try to find Botan via pkg-config when enabled ---
set(BOTAN2_FOUND FALSE)
if (USE_BOTAN)
    find_package(PkgConfig)
    if (PkgConfig_FOUND)
        pkg_check_modules(BOTAN2 botan-2)
        if (BOTAN2_FOUND)
            message(STATUS "Botan2 found:")
            message(STATUS "  include dirs: ${BOTAN2_INCLUDE_DIRS}")
            message(STATUS "  libraries:    ${BOTAN2_LIBRARIES}")
            message(STATUS "  cflags:       ${BOTAN2_CFLAGS_OTHER}")
        else()
            message(WARNING "Botan2 requested (USE_BOTAN=ON) but not found. Disabling Botan backend.")
        endif()
    else()
        message(WARNING "PkgConfig not found; cannot find Botan2. Disabling Botan backend.")
    endif()
endif()

# --- Main executable ---
add_executable(AES
    src/main.cpp
    src/aes_naive.cpp
    src/aes_ttable.cpp
    src/aes_aesni.cpp
    src/aes_benchmark.cpp
    src/aes_fileio.cpp
    src/aes_naive_int.cpp
    src/aes_botan_wrapper.cpp
    src/sha256.cpp
)

# AES-NI flags just for aes_aesni.cpp (GCC/Clang)
set_source_files_properties(src/aes_aesni.cpp PROPERTIES
    COMPILE_OPTIONS "$<$<CXX_COMPILER_ID:GNU,Clang>:-maes;-mpclmul>"
)

# --- Wire Botan into the target only if found ---
if (BOTAN2_FOUND)
    target_include_directories(AES PRIVATE ${BOTAN2_INCLUDE_DIRS})
    target_link_libraries(AES PRIVATE ${BOTAN2_LIBRARIES})
    target_compile_options(AES PRIVATE ${BOTAN2_CFLAGS_OTHER})
    target_compile_definitions(AES PRIVATE HAVE_BOTAN=1)
else()
    target_compile_definitions(AES PRIVATE HAVE_BOTAN=0)
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "USE_BOTAN: ${USE_BOTAN}")
message(STATUS "BOTAN2_FOUND: ${BOTAN2_FOUND}")
