# AESBenchmark
Project with three versions of AES and their respective performance profiles.

How to Setup the Environment (for Windows)

1) Install a compiler (either GCC or Visual Studio C++ Tools from the Visual Studio Installer)
2) Make sure you have installed a compiler by typing "gcc -version" or "cl -version" on your powershell
3) If not working, Win+S, search for Environmental Variables -> System Variables -> PATH -> Modify -> Add the path to cl.exe or gcc.exe. Then, repeat step 2.
4) Install the extensions C/C++ and CMakeTools on VSCode
5) Go to File -> Preferences -> Settings -> type "cmake path" and make sure it is equal to C:\Program Files\CMake\bin\cmake.exe
5) From the project folder type the following commands:
	mkdir build #create folder
	cd build #enter build folder
	cmake --build . #build project
	.\Debug\AES.exe #execute
