import json
import pandas as pd
from datetime import datetime

# =========================
# CONFIG
# =========================
INPUT_FILE = "feature_engineering/outputs/flow_threat_labeled.csv"
OUTPUT_FILE = "feature_engineering/outputs/alerts.json"

# =========================
# SEVERITY MAPPING
# =========================
SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW"
}

# =========================
# ALERT GENERATION
# =========================
def generate_alerts():
    df = pd.read_csv(INPUT_FILE)

    print("[+] Loaded labeled flows:", len(df))

    alerts = []

    for _, row in df.iterrows():
        # Ignore benign traffic
        if row["threat_label"] == "BENIGN":
            continue

        alert = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "src_ip": row.get("src_ip", "unknown"),
            "dst_ip": row.get("dst_ip", "unknown"),
            "protocol": row.get("protocol", "unknown"),
            "threat_label": row["threat_label"],
            "severity": SEVERITY_MAP.get(
                row.get("threat_score_band", "LOW"),
                "LOW"
            ),
            "final_threat_score": round(
                float(row.get("final_threat_score", 0.0)), 3
            ),
            "confidence": round(
                min(float(row.get("final_threat_score", 0.0)) * 1.2, 1.0),
                2
            ),
            "summary": (
                f"{row['threat_label']} detected "
                f"({row.get('threat_score_band', 'LOW')} severity)"
            )
        }

        alerts.append(alert)

    # =========================
    # WRITE ALERTS
    # =========================
    with open(OUTPUT_FILE, "w") as f:
        json.dump(alerts, f, indent=2)

    print(f"[+] Alerts generated: {len(alerts)}")
    print(f"[+] Alerts written to: {OUTPUT_FILE}")


if __name__ == "__main__":
    generate_alerts()
