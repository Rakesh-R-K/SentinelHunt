import pandas as pd
import json
from datetime import datetime

# =========================
# CONFIG
# =========================
INPUT_FILE = "feature_engineering/outputs/flow_threat_scores.csv"
OUTPUT_FILE = "feature_engineering/outputs/alerts.json"

# =========================
# LOAD DATA
# =========================
df = pd.read_csv(INPUT_FILE)

print("[+] Loaded flows:", len(df))

# =========================
# FILTER ALERT-WORTHY FLOWS
# =========================
alerts_df = df[df["severity"].isin(["MEDIUM", "HIGH"])]

print("[+] Alerts to generate:", len(alerts_df))

# =========================
# ALERT GENERATION
# =========================
alerts = []

for _, row in alerts_df.iterrows():
    reasons = []

    if row["suspicion_score"] > 0:
        reasons.append("Rule-based suspicion triggered")

    if row["ml_score_normalized"] > 0.8:
        reasons.append("High ML anomaly score")

    alert = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "src_ip": row["src_ip"],
        "dst_ip": row["dst_ip"],
        "src_port": int(row["src_port"]),
        "dst_port": int(row["dst_port"]),
        "protocol": row["protocol"],
        "final_threat_score": round(row["final_threat_score"], 3),
        "severity": row["severity"],
        "reasons": reasons
    }

    alerts.append(alert)

# =========================
# SAVE ALERTS
# =========================
with open(OUTPUT_FILE, "w") as f:
    json.dump(alerts, f, indent=2)

print(f"\n[+] Alerts saved to {OUTPUT_FILE}")
