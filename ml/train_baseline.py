import pandas as pd
import joblib

from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

# -----------------------------
# Load dataset
# -----------------------------
df = pd.read_csv("../feature_engineering/outputs/flow_features_enriched.csv")

FEATURES = [
    "packet_count",
    "duration",
    "total_bytes",
    "avg_packet_size",
    "min_iat",
    "max_iat",
    "mean_iat",
    "std_iat",
    "bytes_per_second",
    "packets_per_second",
    "avg_bytes_per_packet",
    "dns_query_length",
    "dns_subdomain_depth",
    "dns_entropy"
]

X = df[FEATURES]

# -----------------------------
# Feature Scaling
# -----------------------------
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

print("[+] Features scaled successfully")

# -----------------------------
# Train Isolation Forest
# -----------------------------
iso_forest = IsolationForest(
    n_estimators=200,
    contamination=0.05,   # assume 5% anomalies
    random_state=42,
    n_jobs=-1
)

iso_forest.fit(X_scaled)

print("[+] Isolation Forest trained")

# -----------------------------
# Generate anomaly scores
# -----------------------------
df["iforest_score"] = iso_forest.decision_function(X_scaled)
df["iforest_label"] = iso_forest.predict(X_scaled)  # -1 anomaly, 1 normal

# Save outputs
df.to_csv("../ml/models/iforest_results.csv", index=False)

joblib.dump(iso_forest, "../ml/models/isolation_forest.pkl")
joblib.dump(scaler, "../ml/models/scaler.pkl")

print("[+] Model, scaler, and results saved")
