import json
import pandas as pd
from datetime import datetime
from detection_engine.rules import RULES

# =========================
# CONFIG
# =========================
INPUT_FILE = "feature_engineering/outputs/flow_threat_labeled.csv"
OUTPUT_FILE = "feature_engineering/outputs/alerts.json"

# =========================
# SEVERITY MAPPING (SOC-GRADE)
# =========================
SEVERITY_BANDS = [
    (0.0, 0.3, "LOW"),
    (0.3, 0.6, "MEDIUM"),
    (0.6, 0.8, "HIGH"),
    (0.8, 1.01, "CRITICAL"),
]


def map_severity(score: float) -> str:
    for low, high, severity in SEVERITY_BANDS:
        if low <= score < high:
            return severity
    return "UNKNOWN"


# =========================
# EXPLAINABILITY HELPERS
# =========================
def determine_threat_type(threat_label: str) -> str:
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


def extract_indicators(row) -> list:
    """
    Derive human-readable indicators from flow features.
    These are intentionally simple for Phase 1.
    """
    indicators = []

    if row.get("packet_count", 0) > 1000:
        indicators.append("high packet count")

    if row.get("flow_duration", 0) < 1:
        indicators.append("short-lived high-volume flow")

    if row.get("avg_inter_arrival_time", 1) < 0.01:
        indicators.append("low inter-arrival variance")

    if not indicators:
        indicators.append("statistical anomaly in flow behavior")

    return indicators


def build_reason(threat_label: str, indicators: list) -> str:
    return f"{threat_label} detected due to: " + ", ".join(indicators)


def calculate_confidence(score: float, indicator_count: int) -> float:
    base = min(score, 1.0)
    boost = 0.1 * indicator_count
    return round(min(base + boost, 1.0), 2)


def apply_rules(flow_row):
    triggered_rules = []
    score_boost = 0.0
    indicators = []

    flow = flow_row.to_dict()

    for rule in RULES:
        matched, metadata = rule(flow)
        if matched:
            triggered_rules.append(metadata["rule"])
            score_boost += metadata.get("severity_boost", 0.0)
            indicators.append(metadata.get("indicator"))

    return triggered_rules, score_boost, indicators


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
        severity = map_severity(final_score)

        indicators = extract_indicators(row)
        confidence = calculate_confidence(final_score, len(indicators))
        base_score = float(row.get("final_threat_score", 0.0))

        triggered_rules, rule_score_boost, rule_indicators = apply_rules(row)

        final_score = min(base_score + rule_score_boost, 1.0)
        severity = map_severity(final_score)

        feature_indicators = extract_indicators(row)
        all_indicators = list(set(feature_indicators + rule_indicators))

        confidence = calculate_confidence(final_score, len(triggered_rules))


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
            "severity": severity,
            "final_threat_score": round(final_score, 3),
            "confidence": confidence,
            "triggered_rules": triggered_rules,
            "reason": build_reason(row["threat_label"], all_indicators),
            "summary": (
                f"{severity} alert: {row['threat_label']} "
                f"from {row.get('src_ip', 'unknown')}:{row.get('src_port', '-')}"
                f" → {row.get('dst_ip', 'unknown')}:{row.get('dst_port', '-')}"
                f" over {row.get('protocol', 'unknown')}"
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
