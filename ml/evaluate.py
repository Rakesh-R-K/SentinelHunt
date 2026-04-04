"""
⚠️  DEPRECATED — This script is the original simple evaluator.
    It is kept for reference only.

    For production evaluation, use the new benchmark runner:
        python -m experiments.benchmark_runner

    The new runner supports:
        - ROC/PR curves, per-threshold F1
        - Cross-validation (stratified k-fold)
        - Comparison with published academic results
        - CIC-IDS2017 / UNSW-NB15 compatibility
"""
import warnings
warnings.warn(
    "evaluate.py is deprecated. Use 'python -m experiments.benchmark_runner' instead.",
    DeprecationWarning, stacklevel=2,
)

import pandas as pd

# Load results
df = pd.read_csv("models/iforest_results.csv")

print("\n[+] Total flows:", len(df))

# Count anomalies
anomalies = df[df["iforest_label"] == -1]
print("[+] Detected anomalies:", len(anomalies))

# Compare with heuristic suspicion
print("\n[+] Suspicion score statistics:")
print(df["suspicion_score"].describe())

print("\n[+] ML anomaly score statistics:")
print(df["iforest_score"].describe())

# High suspicion but ML-normal
case1 = df[(df["suspicion_score"] >= 3) & (df["iforest_label"] == 1)]
print("\n[+] High suspicion but ML-normal flows:", len(case1))

# ML-anomalous but low suspicion
case2 = df[(df["suspicion_score"] <= 1) & (df["iforest_label"] == -1)]
print("[+] ML-anomalous but low suspicion flows:", len(case2))

print("\n[+] Sample ML-only anomalies:")
print(case2.head(5)[[
    "packet_count",
    "duration",
    "total_bytes",
    "dns_entropy",
    "suspicion_score",
    "iforest_score"
]])
