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
- File encryption/decryption - Tests with real file I/O
- Performance benchmarks and micro-benchmarks
- Statistical analysis and performance comparison charts

# Running the Test Cases

Interpreting Results
Output Files Generated





   