# AESBenchmark
Project with three versions of AES and their respective performance profiles.

How to Setup the Environment (for Windows)

1) Install a compiler (either GCC or Visual Studio C++ Tools from the Visual Studio Installer), and CMake from CMake.org https://cmake.org/download/
2) Make sure you have installed a compiler by typing "gcc -version" or "cl -version" on your powershell
3) If not working, Win+S, search for Environmental Variables -> System Variables -> PATH -> Modify -> Add the path to cl.exe or gcc.exe. Then, repeat step 2.
4) Install the extensions C/C++ and CMakeTools on VSCode
5) Go to File -> Preferences -> Settings -> type "cmake path" and make sure it is equal to C:\Program Files\CMake\bin\cmake.exe
5) From the project folder type the following commands:
	5.1) mkdir build #create folder
	
	5.2) cd build #enter build folder

	5.2.1) if CMakeCache.txt is missing then run this command:
	cmake -S . -B build -G "Visual Studio 17 2022" -A x64
	
	5.3) cmake --build . #build project
	
	5.4) .\Debug\AES.exe #execute
# Compile for running Ubuntu 24.04.2 LTS.
Instrcutions for download and install Ubuntu 24.04 to test code:

How to set enviroment for Windows:

1): wsl --install -d Ubuntu-24.04  #Copy the command in terminal for installing  :  .
Then setup WSL as default. or first time open, It will ask to create linux username + password

2): Open Ubuntu(wsl) terminal and run :  wsl
 yourname@DESKTOP-XXXX:~$

3): In abuntu, User windows file should be in directory:  /mnt/c/<folderPath>

4): In Ubuntu terminal make ensure CMake and g++ installed run: 
   sudo apt update
   sudo apt install  build-essential -y

5): mkdir build-linux  # Create a separate folder just for ubuntu builds

6): cmake .  # build project, then 
    make
7): ./AES    # run code


----
Setup Python on Windows

navigate to root folder "aesbenchmark"
python -m venv .venv
.\.venv\Scripts\activate
python.exe -m pip install --upgrade pip
pip install matplotlib pandas

----
Setup Python on Ubuntu

sudo apt install python3.12-venv
Y
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install matplotlib pandas
sudo apt install python3-tk
sudo apt install libbotan-3-dev
sudo apt install pkg-config
   