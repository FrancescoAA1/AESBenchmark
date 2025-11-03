import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

df = pd.read_csv("benchmark_results.csv")

for impl in df['Implementation'].unique():
    sub = df[df['Implementation'] == impl]
    plt.bar(sub['Operation'], sub['Avg_ns'], label=impl)

plt.xticks(rotation=45)
plt.ylabel("Avg Time (ns)")
plt.legend()
plt.tight_layout()
plt.savefig("benchmark_plot.png")
plt.show()


csv_file = "benchmark_AES.csv"
df = pd.read_csv(csv_file)

implementations = df['Implementation'].unique()
operations = df['Operation'].unique()

bar_width = 0.2
opacity = 0.8


for op in operations:
    plt.figure(figsize=(10,6))
    subset = df[df['Operation'] == op]
    
    index = np.arange(len(implementations))
    
    avg = [subset[subset['Implementation'] == impl]['Avg_ns'].values[0] for impl in implementations]
    min_time = [subset[subset['Implementation'] == impl]['Min_ns'].values[0] for impl in implementations]
    max_time = [subset[subset['Implementation'] == impl]['Max_ns'].values[0] for impl in implementations]
    
    plt.bar(index - bar_width, min_time, bar_width, label='Min', color='skyblue')
    plt.bar(index, avg, bar_width, label='Avg', color='orange')
    plt.bar(index + bar_width, max_time, bar_width, label='Max', color='green')
    
    plt.xlabel('Implementation')
    plt.ylabel('Time (ns)')
    plt.title(f'AES {op} Benchmark')
    plt.xticks(index, implementations)
    plt.legend()
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Salva il grafico
    plt.tight_layout()
    plt.savefig(f'benchmark_{op}.png')
    plt.show()