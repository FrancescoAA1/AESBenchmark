import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# ---------- Load Data ----------
df_steps = pd.read_csv("..\\benchmark\\benchmark_results.csv")
df_all = pd.read_csv("..\\benchmark\\benchmark_AES.csv")

# AES-Naive steps
aes_naive = df_steps[df_steps['Implementation'] == 'AES-Naive']
steps = ['SubBytes', 'ShiftRows', 'MixColumns', 'MixColumnsFast', 'AddRoundKey', 'InvSubBytes']
aes_naive_steps = aes_naive[aes_naive['Operation'].isin(steps)]

# All implementations
implementations = ['AES-Naive', 'AES-TTable', 'AES-NI']
operations = ['Encryption', 'Decryption']
bar_width = 0.2

# ---------- Create figure with 2 subplots (vertical layout) ----------
fig, axes = plt.subplots(2, 1, figsize=(12,12))

# Increase vertical spacing
plt.subplots_adjust(hspace=0.4)

# ---------- Color Palette ----------
colors = plt.get_cmap('Set2').colors  # nice pastel palette

# --- Top subplot: AES-Naive steps ---
axes[0].bar(aes_naive_steps['Operation'], aes_naive_steps['Avg_ns'], color=colors[0])
axes[0].set_ylabel("Avg Time (ns)")
axes[0].set_title("AES-Naive Step Benchmark")
axes[0].set_xticklabels(aes_naive_steps['Operation'], rotation=45)
axes[0].grid(axis='y', linestyle='--', alpha=0.7)

# --- Bottom subplot: Min/Avg/Max for Encrypt/Decrypt across implementations ---
x_labels = []
min_vals, avg_vals, max_vals = [], [], []

# Build data for plotting
for impl in implementations:
    for op in operations:
        subset = df_all[(df_all['Implementation'] == impl) & (df_all['Operation'] == op)]
        min_vals.append(subset['Min_ns'].values[0])
        avg_vals.append(subset['Avg_ns'].values[0])
        max_vals.append(subset['Max_ns'].values[0])
        x_labels.append(f"{impl}\n{op}")

index = np.arange(len(x_labels))

axes[1].bar(index - bar_width, min_vals, bar_width, label='Min', color=colors[1])
axes[1].bar(index, avg_vals, bar_width, label='Avg', color=colors[2])
axes[1].bar(index + bar_width, max_vals, bar_width, label='Max', color=colors[3])

axes[1].set_xticks(index)
axes[1].set_xticklabels(x_labels, rotation=45)
axes[1].set_ylabel("Time (ns)")
axes[1].set_title("AES Encryption/Decryption Benchmark Across Implementations")
axes[1].legend()
axes[1].grid(axis='y', linestyle='--', alpha=0.7)

# Save and show
plt.tight_layout()
plt.savefig("..\\benchmark\\aes_combined_vertical_colored.png")
plt.show()
