import json
from collections import defaultdict
from datetime import datetime

ALERTS_FILE = "feature_engineering/outputs/alerts.json"
OUTPUT_FILE = "feature_engineering/outputs/aggregated_alerts.json"


def parse_time(ts):
    return datetime.fromisoformat(ts.replace("Z", ""))


def aggregate_alerts():
    with open(ALERTS_FILE, "r") as f:
        alerts = json.load(f)

    buckets = defaultdict(list)

    for alert in alerts:
        src_ip = alert.get("src_ip", "unknown")
        rules = alert.get("triggered_rules", [])

        if not rules:
            rules = ["NO_RULE"]

        for rule in rules:
            key = (src_ip, rule)
            buckets[key].append(alert)

    aggregated = []

    for (src_ip, rule), group in buckets.items():
        severities = [a["severity"] for a in group]
        scores = [a["final_threat_score"] for a in group]

        aggregated.append({
            "entity": src_ip,
            "rule": rule,
            "alert_count": len(group),
            "max_severity": max(severities, key=lambda s: ["LOW","MEDIUM","HIGH","CRITICAL"].index(s)),
            "avg_score": round(sum(scores) / len(scores), 3),
            "first_seen": min(group, key=lambda a: parse_time(a["timestamp"]))["timestamp"],
            "last_seen": max(group, key=lambda a: parse_time(a["timestamp"]))["timestamp"],
        })

    with open(OUTPUT_FILE, "w") as f:
        json.dump(aggregated, f, indent=2)

    print(f"[+] Aggregated incidents generated: {len(aggregated)}")
    print(f"[+] Written to: {OUTPUT_FILE}")


if __name__ == "__main__":
    aggregate_alerts()
