import pandas as pd

# =========================
# CONFIG
# =========================
INPUT_FILE = "feature_engineering/outputs/flow_threat_scores.csv"
OUTPUT_FILE = "feature_engineering/outputs/flow_threat_scores.csv"

LOW_THRESHOLD = 0.30
HIGH_THRESHOLD = 0.60

# =========================
# LOAD DATA
# =========================
df = pd.read_csv(INPUT_FILE)

print("[+] Loaded flows:", len(df))

# =========================
# SEVERITY CLASSIFICATION
# =========================
def classify_severity(score):
    if score >= HIGH_THRESHOLD:
        return "HIGH"
    elif score >= LOW_THRESHOLD:
        return "MEDIUM"
    else:
        return "LOW"

df["severity"] = df["final_threat_score"].apply(classify_severity)

# =========================
# SEVERITY STATS
# =========================
print("\n[+] Severity distribution:")
print(df["severity"].value_counts())

# =========================
# SAVE OUTPUT
# =========================
df.to_csv(OUTPUT_FILE, index=False)
print(f"\n[+] Severity labels added and saved to {OUTPUT_FILE}")
