import pandas as pd

# =========================
# CONFIG
# =========================
INPUT_FILE = "feature_engineering/outputs/flow_threat_scores.csv"
OUTPUT_FILE = "feature_engineering/outputs/flow_threat_labeled.csv"

# =========================
# THREAT LABEL LOGIC
# =========================
def assign_threat_label(row):
    """
    Assigns semantic threat labels based on behavioral heuristics.
    Rule-based by design for SOC explainability.
    """

    # -------------------------
    # Port Scan Detection
    # -------------------------
    if row.get("dst_port_count", 0) >= 20:
        return "PORT_SCAN"

    # -------------------------
    # Brute Force Detection
    # -------------------------
    if (
        row.get("connection_count", 0) >= 30
        and row.get("avg_duration", 10) < 1
    ):
        return "BRUTE_FORCE"

    # -------------------------
    # Data Exfiltration
    # -------------------------
    if row.get("bytes_sent", 0) >= 5_000_000:
        return "DATA_EXFIL"

    # -------------------------
    # Command & Control Beaconing
    # -------------------------
    if row.get("periodicity_score", 0) >= 0.8:
        return "C2_BEACON"

    # -------------------------
    # DNS Tunneling
    # -------------------------
    if row.get("dns_query_length", 0) >= 50:
        return "DNS_TUNNEL"

    # -------------------------
    # Generic Suspicious Traffic
    # -------------------------
    if row.get("final_threat_score", 0) >= 0.6:
        return "SUSPICIOUS_TRAFFIC"

    return "BENIGN"


# =========================
# MAIN PIPELINE
# =========================
def label_threats():
    df = pd.read_csv(INPUT_FILE)

    print("[+] Loaded flows:", len(df))

    df["threat_label"] = df.apply(assign_threat_label, axis=1)

    print("\n[+] Threat label distribution:")
    print(df["threat_label"].value_counts())

    df.to_csv(OUTPUT_FILE, index=False)
    print(f"\n[+] Threat-labeled flows saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    label_threats()
