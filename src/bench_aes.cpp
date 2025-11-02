// // bench_aes.cpp
// #include <chrono>
// #include <cmath>
// #include <cstdint>
// #include <functional>
// #include <iostream>
// #include <numeric>
// #include <random>
// #include <string>
// #include <vector>

// #include "../include/aes_naive.h"
// #include "../include/aes_constants.h"
// #include "../include/aes.h"
// #include "../include/aes_naive_int.h"

// using namespace std;
// using Clock = chrono::high_resolution_clock;
// using ns = chrono::nanoseconds;

// // Prevent optimizer removing results
// volatile uint32_t blackhole = 0;

// struct Stats {
//     double total_ns = 0;
//     double avg_ns = 0;
//     double min_ns = 0;
//     double max_ns = 0;
//     double stddev_ns = 0;
//     size_t runs = 0;
// };

// static Stats compute_stats(const vector<double>& samples_ns) {
//     Stats s;
//     s.runs = samples_ns.size();
//     if (s.runs == 0) return s;
//     double sum = 0;
//     s.min_ns = samples_ns[0];
//     s.max_ns = samples_ns[0];
//     for (double v : samples_ns) {
//         sum += v;
//         if (v < s.min_ns) s.min_ns = v;
//         if (v > s.max_ns) s.max_ns = v;
//     }
//     s.total_ns = sum;
//     s.avg_ns = sum / s.runs;
//     double var = 0;
//     for (double v : samples_ns) {
//         double d = v - s.avg_ns;
//         var += d * d;
//     }
//     s.stddev_ns = (s.runs > 1) ? sqrt(var / (s.runs - 1)) : 0.0;
//     return s;
// }

// // Generic benchmark for a function that mutates a State (member or free)
// // Fn signature: void(AesNaive&, AesNaive::State&)
// Stats benchmark_state_mutator(
//     AesNaive &aes,
//     const function<void(AesNaive&, State&)> &fn,
//     const State &input_state,
//     size_t iterations,
//     size_t warmup = 16
// ) {
//     // Warmup
//     State st = input_state;
//     for (size_t i = 0; i < warmup; ++i) {
//         st = input_state;
//         fn(aes, st);
//     }

//     vector<double> samples_ns;
//     samples_ns.reserve(iterations);

//     for (size_t i = 0; i < iterations; ++i) {
//         st = input_state;                     // fresh copy
//         auto t0 = Clock::now();
//         fn(aes, st);
//         auto t1 = Clock::now();
//         ns d = chrono::duration_cast<ns>(t1 - t0);
//         samples_ns.push_back(static_cast<double>(d.count()));

//         // make a simple checksum to prevent optimizer from removing call
//         uint32_t sum = 0;
//         for (int r = 0; r < 4; ++r)
//             for (int c = 0; c < 4; ++c)
//                 sum += st[r][c];
//         blackhole ^= sum;
//     }

//     return compute_stats(samples_ns);
// }

// Stats benchmark_state_mutator_int(
//     AES128Words &aes,
//     const function<void(AES128Words&, AES128Words::Block4x32&)> &fn,
//     const AES128Words::Block4x32 &input_state,
//     size_t iterations,
//     size_t warmup = 16
// ) {
//     // Warmup
//     AES128Words::Block4x32 st = input_state;
//     for (size_t i = 0; i < warmup; ++i) {
//         st = input_state;
//         fn(aes, st);
//     }

//     vector<double> samples_ns;
//     samples_ns.reserve(iterations);

//     for (size_t i = 0; i < iterations; ++i) {
//         st = input_state;                     // fresh copy
//         auto t0 = Clock::now();
//         fn(aes, st);
//         auto t1 = Clock::now();
//         ns d = chrono::duration_cast<ns>(t1 - t0);
//         samples_ns.push_back(static_cast<double>(d.count()));

//         // make a simple checksum to prevent optimizer from removing call
//         uint32_t sum = 0;
//         for (int r = 0; r < 4; ++r)
//             sum += st[r];
//         blackhole ^= sum;
//     }

//     return compute_stats(samples_ns);
// }

// int run_aes_bench() {
//     // Example key (16 bytes)
//     Key key{};
//     for (size_t i = 0; i < key.size(); ++i) key[i] = static_cast<uint8_t>(i);

//     AesNaive aes(key);
//     AES128Words aes_int(key.data());

//     // Prepare a random block/state for tests
//     std::mt19937_64 rng(12345);
//     std::uniform_int_distribution<int> d(0, 255);
//     Block blk{};
//     for (int i = 0; i < (int)blk.size(); ++i) blk[i] = static_cast<uint8_t>(d(rng));
//     State st = aes.bytes_to_state(blk);

//     AES128Words::Block4x32 st_int = aes_int.bytes_to_words_be(blk.data());

//     size_t iterations = 200000; // tune this based on speed of your machine
//     cout << "Running " << iterations << " iterations per test\n\n";

//     // Helper to wrap member functions (State& mutators)
//     auto wrap_member = [](auto memfn) {
//         return function<void(AesNaive&, State&)>(
//             [memfn](AesNaive &a, State &s) { (a.*memfn)(s); }
//         );
//     };

//     // Keep your existing wrap_member(...) for AesNaive.
//     // New: wrapper for static/free functions operating on Block4x32
//     auto wrap_free_int = [](auto fn) {
//         return function<void(AES128Words&, AES128Words::Block4x32&)>(
//             [fn](AES128Words&, AES128Words::Block4x32& s) { fn(s); }
//         );
//     };


//     // List of tests: name + function
//     vector<pair<string, function<void(AesNaive&, State&)>>> tests = {
//         {"sub_bytes",  wrap_member(&AesNaive::sub_bytes)},
//         {"inv_sub_bytes",  wrap_member(&AesNaive::inv_sub_bytes)},
//         {"shift_rows", wrap_member(&AesNaive::shift_rows)},
//         {"inv_shift_rows", wrap_member(&AesNaive::inv_shift_rows)},
//         {"mix_columns", wrap_member(&AesNaive::mix_columns)},
//         {"mix_columns_fast", wrap_member(&AesNaive::mix_columns_fast)},
//         {"inv_mix_columns", wrap_member(&AesNaive::inv_mix_columns)}
//     };

//     vector<pair<string, function<void(AES128Words&, AES128Words::Block4x32&)>>> tests_int = {
//         {"sub_bytes",  wrap_free_int(&AES128Words::sub_bytes)},
//         {"inv_sub_bytes",  wrap_free_int(&AES128Words::inv_sub_bytes)},
//         {"shift_rows", wrap_free_int(&AES128Words::shift_rows)},
//         {"inv_shift_rows", wrap_free_int(&AES128Words::inv_shift_rows)},
//         {"mix_columns", wrap_free_int(&AES128Words::mix_columns)},
//         {"inv_mix_columns", wrap_free_int(&AES128Words::inv_mix_columns)}
//     };

//     // Optionally verify outputs of two implementations are equal once
//     {
//         auto st1 = st;
//         auto st2 = st;
//         aes.mix_columns(st1);
//         aes.mix_columns_fast(st2);
//         if (st1 == st2) cout << "mix_columns == mix_columns_fast (single test)\n";
//         else cout << "WARNING: mix_columns != mix_columns_fast (they differ)\n";
//     }
//     cout << "\n";

//     // Run each test
//     for (auto &t : tests) {
//         cout << "Test: " << t.first << " ...\n";
//         Stats s = benchmark_state_mutator(aes, t.second, st, iterations);
//         cout << "  runs: " << s.runs << "\n";
//         cout << "  total: " << s.total_ns/1e6 << " ms\n";
//         cout << "  avg:   " << s.avg_ns << " ns\n";
//         cout << "  min:   " << s.min_ns << " ns\n";
//         cout << "  max:   " << s.max_ns << " ns\n";
//         cout << "  stddev:" << s.stddev_ns << " ns\n\n";
//     }

//     for (auto &t : tests_int) {
//         cout << "Test 4xINT: " << t.first << " ...\n";
//         Stats s = benchmark_state_mutator_int(aes_int, t.second, st_int, iterations);
//         //                                 ^^^^^^^^             ^^^^^^
//         cout << "  runs: "   << s.runs << "\n";
//         cout << "  total: "  << s.total_ns/1e6 << " ms\n";
//         cout << "  avg:   "  << s.avg_ns << " ns\n";
//         cout << "  min:   "  << s.min_ns << " ns\n";
//         cout << "  max:   "  << s.max_ns << " ns\n";
//         cout << "  stddev:"  << s.stddev_ns << " ns\n\n";
//     }

//     // Use blackhole so optimizer can't ignore (volatile used)
//     if (blackhole == 0xFFFFFFFF) cerr << "interesting\n";

//     return 0;
// }
