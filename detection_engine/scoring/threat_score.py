import pandas as pd
from sklearn.preprocessing import MinMaxScaler

# =========================
# CONFIG
# =========================
FLOW_FEATURES_FILE = "feature_engineering/outputs/flow_features_enriched.csv"
ML_RESULTS_FILE = "ml/models/iforest_results.csv"
OUTPUT_FILE = "feature_engineering/outputs/flow_threat_scores.csv"

# =========================
# LOAD DATA
# =========================
flows_df = pd.read_csv(FLOW_FEATURES_FILE)
ml_df = pd.read_csv(ML_RESULTS_FILE)

print("[+] Flow records:", len(flows_df))
print("[+] ML records:", len(ml_df))

# =========================
# MERGE ML SCORES INTO FLOWS
# =========================
# Assumes same ordering (as in your pipeline so far)
flows_df["ml_anomaly_score"] = ml_df["iforest_score"]

# =========================
# NORMALIZE ML SCORE
# =========================
ml_scaler = MinMaxScaler()
flows_df["ml_score_normalized"] = ml_scaler.fit_transform(
    flows_df[["ml_anomaly_score"]]
)

# =========================
# NORMALIZE RULE-BASED SCORE
# =========================
rule_scaler = MinMaxScaler()
flows_df["rule_score_normalized"] = rule_scaler.fit_transform(
    flows_df[["suspicion_score"]]
)

# =========================
# SANITY CHECK
# =========================
print("\n[+] Normalized score statistics:")
print(
    flows_df[
        ["ml_score_normalized", "rule_score_normalized"]
    ].describe()
)

# =========================
# FINAL THREAT SCORE (WEIGHTED FUSION)
# =========================
RULE_WEIGHT = 0.6
ML_WEIGHT = 0.4

flows_df["final_threat_score"] = (
    RULE_WEIGHT * flows_df["rule_score_normalized"]
    + ML_WEIGHT * flows_df["ml_score_normalized"]
)

# =========================
# FINAL SCORE STATS
# =========================
print("\n[+] Final threat score statistics:")
print(flows_df["final_threat_score"].describe())


# =========================
# SAVE OUTPUT
# =========================
flows_df.to_csv(OUTPUT_FILE, index=False)
print(f"\n[+] Threat-score-ready flows saved to {OUTPUT_FILE}")
