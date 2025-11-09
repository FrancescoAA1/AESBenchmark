# AESBenchmark

# Compilation and Installation

# Prerequisites

Ubuntu 22.04 or Windows 10/11

CMake 3.15+

C++17 compatible compiler

Python 3.8+ with pandas and matplotlib

Botan 2.x


# Installation on Ubuntu

Unzip the File

Execute the two scripts that help with the installation.

A. Get python enviroment running (with all the prerequites necessary),
	
	source pyenv_setup.sh --activate

B. Get the c++ cmake working
	
	./cpp_build.sh --install-deps --install-cmake-latest --source-dir .

C. Navigate to ./build folder (with cd build) and run AES 
	
	./AES

	This command executes:

	- Correctness tests
	- Performance benchmarks and micro-benchmarks on all AES implementations
	- File encryption/decryption
	- Statistical analysis and performance comparison charts

# Running the Test Cases

In main.cpp we perform a correctness test using the Design of Rijnadeal test vectors (present in the \test_vectors folder).
We then perform both a benchmark of all implementations, and a micro-benchmark of single AES steps.
Output files are generated respectively in the \benchmark and \file folders.

# Main Tasks Division
Andersen Tim: AesNI, AesNaiveInt, AESFileIO, main
Fantin Francesco: AesNaive, AesBenchmark, Aes Interface, main
Mahdi Karrar Adam: AesTTable, BotanWrapper, main

We all contributed to the realization of the report.






   