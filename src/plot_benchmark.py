import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

# ---------------- Load CSVs ----------------
aes_file = Path("..") / "benchmark" / "benchmark_results.csv"
steps_file = Path("..") / "benchmark" / "benchmark_AES.csv"


df_aes = pd.read_csv(aes_file)
df_steps = pd.read_csv(steps_file)

palette = plt.get_cmap('Set3').colors

# ---------------- Helper for error bars ----------------
def get_median_error(row):
    med = row['Median_ns']
    p05 = row['P05_ns']
    p95 = row['P95_ns']
    return med, med - p05, p95 - med

# ---------------- 1. AES Implementations: Encryption/Decryption ----------------
implementations = ['AES-Naive', 'AES-TTable', 'AES-NI', 'AES-Botan']
operations = ['Encryption', 'Decryption']

labels, medians, err_low, err_high = [], [], [], []

for op in operations:
    for impl in implementations:
        row = df_aes[(df_aes['Implementation'] == impl) & (df_aes['Operation'] == op)]
        if not row.empty:
            med, low, high = get_median_error(row.iloc[0])
            labels.append(f"{impl}\n{op}")
            medians.append(med)
            err_low.append(low)
            err_high.append(high)

fig, ax = plt.subplots(figsize=(12,6))
x = np.arange(len(labels))
bars = ax.bar(x, medians, yerr=[err_low, err_high], capsize=5,
              color=[palette[i % len(palette)] for i in range(len(labels))],
              alpha=0.7, edgecolor='black')
for rect, med in zip(bars, medians):
    ax.text(rect.get_x() + rect.get_width()/2, rect.get_height()*1.05, f"{med:.1f}", ha='center', va='bottom', fontsize=9)
ax.set_yscale('log')
ax.set_xticks(x)
ax.set_xticklabels(labels)
ax.set_ylabel("Time (ns, log scale)")
ax.set_title("AES Implementations Benchmark (Median + 5th-95th Percentile)")
ax.grid(axis='y', linestyle='--', alpha=0.5)
plt.tight_layout()
fig.savefig(Path("..") / "benchmark" / "aes_benchmark_barlog.png", dpi=200)


# ---------------- 2. AES-Naive Steps ----------------
aes_naive = df_steps[df_steps['Implementation'] == 'AES-Naive']
steps_order = ['AddRoundKey','SubBytes', 'ShiftRows', 'MixColumns', 'MixColumnsFast', 
               'InvMixColumns', 'InvSubBytes', 'InvShiftRows']

aes_naive_steps = aes_naive[aes_naive['Operation'].isin(steps_order)].set_index('Operation').reindex(steps_order)
medians_steps = aes_naive_steps['Median_ns'].values
p05_steps = aes_naive_steps['P05_ns'].values
p95_steps = aes_naive_steps['P95_ns'].values
err_low_steps = medians_steps - p05_steps
err_high_steps = p95_steps - medians_steps

fig1, ax1 = plt.subplots(figsize=(12,6))
bars_steps = ax1.bar(steps_order, medians_steps, yerr=[err_low_steps, err_high_steps],
                     capsize=5, color=palette[:len(steps_order)], alpha=0.7, edgecolor='black')
for rect, med in zip(bars_steps, medians_steps):
    ax1.text(rect.get_x() + rect.get_width()/2, rect.get_height()*1.05, f"{med:.1f}", ha='center', va='bottom', fontsize=9)
ax1.set_ylabel("Time (ns)")
ax1.set_title("AES-Naive Step Benchmark (Median + 5th-95th Percentile)")
ax1.grid(axis='y', linestyle='--', alpha=0.5)
plt.tight_layout()
fig1.savefig(Path("..") / "benchmark" / "aes_naive_steps_bar.png", dpi=200)


# ---------------- 3. AES-Naive vs AES-Naive-Int ----------------
naive_int_ops = ['Encryption', 'Decryption']
labels2, medians2, err_low2, err_high2 = [], [], [], []

for op in naive_int_ops:
    for impl in ['AES-Naive', 'AES-Naive-Int']:
        row = df_aes[(df_aes['Implementation'] == impl) & (df_aes['Operation'] == op)]
        if not row.empty:
            med, low, high = get_median_error(row.iloc[0])
            labels2.append(f"{impl}\n{op}")
            medians2.append(med)
            err_low2.append(low)
            err_high2.append(high)

fig2, ax2 = plt.subplots(figsize=(8,6))
x2 = np.arange(len(labels2))
bars2 = ax2.bar(x2, medians2, yerr=[err_low2, err_high2], capsize=5,
                color=[palette[i % len(palette)] for i in range(len(labels2))],
                alpha=0.7, edgecolor='black')
for rect, med in zip(bars2, medians2):
    ax2.text(rect.get_x() + rect.get_width()/2, rect.get_height()*1.05, f"{med:.1f}", ha='center', va='bottom', fontsize=9)
ax2.set_yscale('log')
ax2.set_xticks(x2)
ax2.set_xticklabels(labels2)
ax2.set_ylabel("Time (ns, log scale)")
ax2.set_title("AES-Naive vs AES-Naive-Int Benchmark")
ax2.grid(axis='y', linestyle='--', alpha=0.5)
plt.tight_layout()
fig2.savefig(Path("..") / "benchmark" / "aes_naive_vs_naiveint.png", dpi=200)


# ---------------- 4. Key Expansion Across Implementations ----------------
key_exp_ops = ['AES-Naive', 'AES-TTable', 'AES-NI']
labels3, medians3, err_low3, err_high3 = [], [], [], []

for impl in key_exp_ops:
    # Determine the correct KeyExpansion operation name for each implementation
    if impl == 'AES-Naive':
        op_name = 'KeyExpansion'
    elif impl == 'AES-TTable':
        op_name = 'KeyExpansion'
    elif impl == 'AES-NI':
        op_name = 'KeyExpansion'
    row = df_steps[(df_steps['Implementation'] == impl) & (df_steps['Operation'].str.contains(op_name))]
    if not row.empty:
        med, low, high = get_median_error(row.iloc[0])
        labels3.append(impl)
        medians3.append(med)
        err_low3.append(low)
        err_high3.append(high)

fig3, ax3 = plt.subplots(figsize=(8,6))
x3 = np.arange(len(labels3))
bars3 = ax3.bar(x3, medians3, yerr=[err_low3, err_high3], capsize=5,
                color=[palette[i % len(palette)] for i in range(len(labels3))],
                alpha=0.7, edgecolor='black')
for rect, med in zip(bars3, medians3):
    ax3.text(rect.get_x() + rect.get_width()/2, rect.get_height()*1.05, f"{med:.1f}", ha='center', va='bottom', fontsize=9)
ax3.set_ylabel("Time (ns)")
ax3.set_title("AES Key Expansion Benchmark Across Implementations")
ax3.grid(axis='y', linestyle='--', alpha=0.5)
plt.tight_layout()
fig3.savefig(Path("..") / "benchmark" / "aes_keyexp_comparison.png", dpi=200)

plt.show()
