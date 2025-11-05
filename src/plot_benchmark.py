# import pandas as pd

# import matplotlib
# matplotlib.use('TkAgg')
# import matplotlib.pyplot as plt
# import numpy as np

# from pathlib import Path

# # ---------- Load Data ----------

# steps_file = Path("..") / "benchmark" / "benchmark_results.csv"
# aes_file   = Path("..") / "benchmark" / "benchmark_AES.csv"

# df_steps = pd.read_csv(steps_file)
# df_all   = pd.read_csv(aes_file)

# # AES-Naive steps
# aes_naive = df_steps[df_steps['Implementation'] == 'AES-Naive']
# steps = ['AddRoundKey','SubBytes', 'ShiftRows', 'MixColumns', 'MixColumnsFast', 'InvMixColumns', 'InvSubBytes', 'InvShiftRows']
# aes_naive_steps = aes_naive[aes_naive['Operation'].isin(steps)]

# # All implementations
# implementations = ['AES-Naive', 'AES-TTable', 'AES-NI']
# operations = ['Encryption', 'Decryption']
# bar_width = 0.2

# # ---------- Create figure with 2 subplots (vertical layout) ----------
# fig, axes = plt.subplots(2, 1, figsize=(12,12))

# # Increase vertical spacing
# plt.subplots_adjust(hspace=0.4)

# # ---------- Color Palette ----------
# colors = plt.get_cmap('Set2').colors  # nice pastel palette

# # --- Top subplot: AES-Naive steps ---
# axes[0].bar(aes_naive_steps['Operation'], aes_naive_steps['Avg_ns'], color=colors[0])
# axes[0].set_ylabel("Avg Time (ns)")
# axes[0].set_title("AES-Naive Step Benchmark")
# axes[0].set_xticks(range(len(aes_naive_steps['Operation'])))
# axes[0].set_xticklabels(aes_naive_steps['Operation'], rotation=0)
# axes[0].grid(axis='y', linestyle='--', alpha=0.7)

# # --- Bottom subplot: Min/Avg/Max for Encrypt/Decrypt across implementations ---
# x_labels = []
# min_vals, avg_vals, max_vals = [], [], []

# # Build data for plotting
# for impl in implementations:
#     for op in operations:
#         subset = df_all[(df_all['Implementation'] == impl) & (df_all['Operation'] == op)]
#         min_vals.append(subset['Min_ns'].values[0])
#         avg_vals.append(subset['Avg_ns'].values[0])
#         max_vals.append(subset['Max_ns'].values[0])
#         x_labels.append(f"{impl}\n{op}")

# index = np.arange(len(x_labels))

# axes[1].bar(index - bar_width, min_vals, bar_width, label='Min', color=colors[1])
# axes[1].bar(index, avg_vals, bar_width, label='Avg', color=colors[2])
# axes[1].bar(index + bar_width, max_vals, bar_width, label='Max', color=colors[3])

# axes[1].set_xticks(index)
# axes[1].set_xticklabels(x_labels, rotation=0)
# axes[1].set_ylabel("Time (ns)")
# axes[1].set_title("AES Encryption/Decryption Benchmark Across Implementations")
# axes[1].legend()
# axes[1].grid(axis='y', linestyle='--', alpha=0.7)

# # Save and show
# plt.tight_layout()
# fig_path = Path("..") / "benchmark" / "aes_combined_vertical_colored.png"
# plt.savefig(fig_path)
# plt.show()



# ---------------- 4. AES-NI vs AES-Botan ----------------
# for i, op in enumerate(['Encryption','Decryption']):
#     ni = df_all[(df_all['Implementation'] == 'AES-NI') & (df_all['Operation'] == op)]
#     botan = df_all[(df_all['Implementation'] == 'AES-Botan') & (df_all['Operation'] == op)]
#     idx = np.arange(2)
#     axes[3].bar(idx[0], ni['Avg_ns'].values[0], color=colors[2], label='AES-NI' if i==0 else "")
#     axes[3].bar(idx[1], botan['Avg_ns'].values[0], color=colors[3], label='AES-Botan' if i==0 else "")
# axes[3].set_xticks([0,1])
# axes[3].set_xticklabels(['AES-NI', 'AES-Botan'])
# axes[3].set_ylabel("Avg Time (ns)")
# axes[3].set_title("AES-NI vs AES-Botan")
# axes[3].grid(axis='y', linestyle='--', alpha=0.7)
# axes[3].legend()

import pandas as pd
import matplotlib
matplotlib.use('TkAgg')  # interactive backend
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

# ---------- Load Data ----------
steps_file = Path("..") / "benchmark" / "benchmark_results.csv"
aes_file   = Path("..") / "benchmark" / "benchmark_AES.csv"

df_steps = pd.read_csv(steps_file)
df_all   = pd.read_csv(aes_file)

colors = plt.get_cmap('Set2').colors

# ---------- 1. AES-Naive Steps ----------
aes_naive = df_steps[df_steps['Implementation'] == 'AES-Naive']
steps_order = ['AddRoundKey','SubBytes', 'ShiftRows', 'MixColumns', 'MixColumnsFast', 
               'InvMixColumns', 'InvSubBytes', 'InvShiftRows']
aes_naive_steps = aes_naive[aes_naive['Operation'].isin(steps_order)].set_index('Operation').reindex(steps_order)

fig1, ax1 = plt.subplots(figsize=(12,6))
ax1.bar(aes_naive_steps.index, aes_naive_steps['Avg_ns'], color=colors[:len(steps_order)])
ax1.set_ylabel("Avg Time (ns)")
ax1.set_title("AES-Naive Step Benchmark")
ax1.grid(axis='y', linestyle='--', alpha=0.7)
plt.tight_layout()
fig1.savefig(Path("..") / "benchmark" / "aes_naive_steps.png", dpi=200)

# ---------- 2. AES Implementations Encryption/Decryption ----------
implementations = ['AES-Naive', 'AES-TTable', 'AES-NI']
operations = ['Encryption', 'Decryption']

x_labels = []
min_vals, avg_vals, max_vals = [], [], []

for impl in implementations:
    for op in operations:
        subset = df_all[(df_all['Implementation'] == impl) & (df_all['Operation'] == op)]
        if not subset.empty:
            min_vals.append(subset['Min_ns'].values[0])
            avg_vals.append(subset['Avg_ns'].values[0])
            max_vals.append(subset['Max_ns'].values[0])
        else:
            min_vals.append(np.nan)
            avg_vals.append(np.nan)
            max_vals.append(np.nan)
        x_labels.append(f"{impl}\n{op}")

index = np.arange(len(x_labels))
bar_width = 0.25

fig2, ax2 = plt.subplots(figsize=(14,6))
ax2.bar(index - bar_width, min_vals, bar_width, label='Min', color=colors[1])
ax2.bar(index, avg_vals, bar_width, label='Avg', color=colors[2])
ax2.bar(index + bar_width, max_vals, bar_width, label='Max', color=colors[3])
ax2.set_xticks(index)
ax2.set_xticklabels(x_labels, rotation=45, ha='right')
ax2.set_ylabel("Time (ns)")
ax2.set_title("AES Implementations: Encryption/Decryption Min/Avg/Max")
ax2.legend()
ax2.grid(axis='y', linestyle='--', alpha=0.7)
plt.tight_layout()
fig2.savefig(Path("..") / "benchmark" / "aes_impl_enc_dec.png", dpi=200)

# ---------- 3. AES-Naive vs AES-Naive-Int ----------
aes_naive_int_file = Path("..") / "benchmark" / "benchmark_AES.csv"
df_naive_int = pd.read_csv(aes_naive_int_file) if aes_naive_int_file.exists() else pd.DataFrame()
if not df_all.empty:
    naive_ops = ['Encryption', 'Decryption']
    fig3, ax3 = plt.subplots(figsize=(8,6))
    for i, op in enumerate(naive_ops):
        subset_naive = df_all[(df_all['Implementation'] == 'AES-Naive') & (df_all['Operation'] == op)]
        subset_int   = df_all[(df_all['Implementation'] == 'AES-Naive-Int') & (df_all['Operation'] == op)]
        ax3.bar(i*2, subset_naive['Avg_ns'].values[0], color=colors[0], label='Naive' if i==0 else "")
        ax3.bar(i*2+1, subset_int['Avg_ns'].values[0], color=colors[1], label='Naive-Int' if i==0 else "")
    ax3.set_xticks([0.5, 2.5])
    ax3.set_xticklabels(['Encryption','Decryption'])
    ax3.set_ylabel("Avg Time (ns)")
    ax3.set_title("AES-Naive vs AES-Naive-Int")
    ax3.legend()
    ax3.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    fig3.savefig(Path("..") / "benchmark" / "aes_naive_vs_naive_int.png", dpi=200)


# ---------- 5. Key Expansion ----------
# Use the step-level benchmark CSV (df_steps) instead of df_all
key_expansion_ops = df_steps[df_steps['Operation'].str.contains("KeyExpansion")]

x_labels = key_expansion_ops['Implementation'].unique()
min_vals, avg_vals, max_vals = [], [], []

for impl in x_labels:
    subset = key_expansion_ops[key_expansion_ops['Implementation'] == impl]
    if not subset.empty:
        min_vals.append(subset['Min_ns'].values[0])
        avg_vals.append(subset['Avg_ns'].values[0])
        max_vals.append(subset['Max_ns'].values[0])
    else:
        min_vals.append(np.nan)
        avg_vals.append(np.nan)
        max_vals.append(np.nan)

index = np.arange(len(x_labels))
fig5, ax5 = plt.subplots(figsize=(12,6))
ax5.bar(index - bar_width, min_vals, bar_width, color=colors[1], label='Min')
ax5.bar(index, avg_vals, bar_width, color=colors[2], label='Avg')
ax5.bar(index + bar_width, max_vals, bar_width, color=colors[3], label='Max')
ax5.set_xticks(index)
ax5.set_xticklabels(x_labels)
ax5.set_ylabel("Time (ns)")
ax5.set_title("AES Key Expansion Benchmark (Step-Level Results)")
ax5.legend()
ax5.grid(axis='y', linestyle='--', alpha=0.7)
plt.tight_layout()
fig5.savefig(Path("..") / "benchmark" / "aes_key_expansion_steps.png", dpi=200)


plt.show()
