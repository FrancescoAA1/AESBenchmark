#pragma once

constexpr int BLOCK_SIZE = 16;
constexpr int N_ROWS = 4;
constexpr int N_COLS = 4;
constexpr int NUM_ROUNDS = 10;
constexpr int KEY_WORDS = 4;
constexpr int EXPANDED_KEY_WORDS = (NUM_ROUNDS + 1)*KEY_WORDS;
constexpr int S_BOX_SIZE = 256;
constexpr int T_TABLE_SIZE = 256;