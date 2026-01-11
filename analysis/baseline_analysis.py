import pandas as pd

# Load flow-level features (NORMAL traffic only)
df = pd.read_csv("feature_engineering/outputs/flow_features.csv")

print("========== BASIC DATASET INFO ==========")
print("Dataset shape:", df.shape)

print("\n========== COLUMN NAMES ==========")
print(df.columns.tolist())

print("\n========== DATA TYPES ==========")
print(df.dtypes)

print("\n========== MISSING VALUES ==========")
print(df.isnull().sum())

print("\n========== SAMPLE ROWS ==========")
print(df.head())

print("\n========== BASELINE STATISTICS ==========")

numeric_cols = [
    "packet_count",
    "duration",
    "total_bytes",
    "bytes_per_second",
    "packets_per_second",
    "dns_query_length",
    "dns_subdomain_depth",
    "dns_entropy"
]

baseline_stats = df[numeric_cols].describe(percentiles=[0.90, 0.95, 0.99])
print(baseline_stats)

print("\n========== APPLYING ANOMALY RULES ==========")

# Thresholds from baseline
PACKET_THRESHOLD = df["packet_count"].quantile(0.99)
DURATION_THRESHOLD = df["duration"].quantile(0.99)
DNS_ENTROPY_THRESHOLD = df["dns_entropy"].quantile(0.95)

df["flag_high_packet"] = df["packet_count"] > PACKET_THRESHOLD
df["flag_long_duration"] = df["duration"] > DURATION_THRESHOLD
df["flag_high_dns_entropy"] = df["dns_entropy"] > DNS_ENTROPY_THRESHOLD
df["flag_deep_dns"] = df["dns_subdomain_depth"] >= 4

# Suspicion score
df["suspicion_score"] = (
    df["flag_high_packet"].astype(int) +
    df["flag_long_duration"].astype(int) +
    df["flag_high_dns_entropy"].astype(int) +
    df["flag_deep_dns"].astype(int)
)

print(df["suspicion_score"].value_counts().sort_index())

output_path = "feature_engineering/outputs/flow_features_enriched.csv"
df.to_csv(output_path, index=False)

print(f"\nEnriched dataset saved to: {output_path}")
