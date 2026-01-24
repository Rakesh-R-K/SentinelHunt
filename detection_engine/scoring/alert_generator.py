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
# DAY 9 ADD-ONS
# =========================
def determine_reason(threat_label, threat_score):
    if threat_score >= 0.8:
        return f"High confidence detection of {threat_label}"
    elif threat_score >= 0.5:
        return f"Moderate confidence detection of {threat_label}"
    else:
        return f"Low confidence suspicious activity ({threat_label})"


def determine_threat_type(threat_label):
    label = threat_label.lower()
    if "scan" in label:
        return "port_scan"
    elif "beacon" in label:
        return "beaconing"
    elif "dos" in label or "ddos" in label:
        return "denial_of_service"
    elif "malware" in label:
        return "malware_activity"
    else:
        return "anomalous_flow"

# =========================
# ALERT GENERATION
# =========================
def generate_alerts():
    df = pd.read_csv(INPUT_FILE)

    print("[+] Loaded labeled flows:", len(df))

    alerts = []
    alert_id = 1

    for _, row in df.iterrows():
        # Ignore benign traffic
        if row["threat_label"] == "BENIGN":
            continue

        final_score = float(row.get("final_threat_score", 0.0))

        alert = {
            "alert_id": f"ALERT-{alert_id:04d}",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "src_ip": row.get("src_ip", "unknown"),
            "dst_ip": row.get("dst_ip", "unknown"),
            "src_port": int(row.get("src_port", -1)),
            "dst_port": int(row.get("dst_port", -1)),
            "protocol": row.get("protocol", "unknown"),
            "threat_label": row["threat_label"],
            "threat_type": determine_threat_type(row["threat_label"]),
            "severity": SEVERITY_MAP.get(
                row.get("threat_score_band", "LOW"),
                "LOW"
            ),
            "final_threat_score": round(final_score, 3),
            "confidence": round(min(final_score * 1.2, 1.0), 2),
            "reason": determine_reason(
                row["threat_label"],
                final_score
            ),
            "summary": (
                f"{row['threat_label']} detected "
                f"from {row.get('src_ip', 'unknown')} "
                f"to {row.get('dst_ip', 'unknown')} "
                f"({row.get('threat_score_band', 'LOW')} severity)"
            )
        }

        alerts.append(alert)
        alert_id += 1

    # =========================
    # WRITE ALERTS
    # =========================
    with open(OUTPUT_FILE, "w") as f:
        json.dump(alerts, f, indent=2)

    print(f"[+] Alerts generated: {len(alerts)}")
    print(f"[+] Alerts written to: {OUTPUT_FILE}")


if __name__ == "__main__":
    generate_alerts()
