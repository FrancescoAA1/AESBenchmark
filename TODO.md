1) generalize the class AES / AESNi / AESTTABLE so that they have a wrapper (unpad / pad / message handling are duplicate code)
//Remove pad message (takes in a std::array of byte and returns a block) and unpad (takes in a block and return std::array)


2) make sure aes_ni can encode and decode multiple blocks

3) create class for benchmarking (or better: doing everything on main??)

4) benchmark with (high-res timers, measure latency and throughput for a block, use a single CPU core, repeat benchmark 10–30 times to be reliable)

5) find increasingly large data sets

6) compute spatial and temporal complexity of each algo

7) verify the program works on Ubuntu

8) write README section for Ubuntu

9) setup Docker

10) write paper