# AESBenchmark

# Compilation and Installation

# Prerequisites

Ubuntu 22.04 or Windows 10/11

CMake 3.15+

C++17 compatible compiler

Python 3.8+ with pandas and matplotlib

Library Dependencies
Botan 2.x

# INSTALLATION ON UBUNTU:

Clone the repository

Execute the two scripts that help with the installation.

A. Get python enviroment running,
	
	source pyenv_setup.sh --activate
	
	(if allready installed)
	source ./venv/bin/activate

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

In main.cpp we perform a correctness test using the Design of Rijnadeal test vectors.
We then perform both a benchmark of all implementations, and a micro-benchmark of single AES steps.
Output Files Generated respectively in the \benchmark and \file folders.







   