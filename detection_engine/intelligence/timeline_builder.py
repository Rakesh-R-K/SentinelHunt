import json
from datetime import datetime
from collections import defaultdict

ALERTS_FILE = "feature_engineering/outputs/alerts.json"
CAMPAIGNS_FILE = "feature_engineering/outputs/campaigns.json"
OUTPUT_FILE = "feature_engineering/outputs/timelines.json"


def parse_time(ts):
    return datetime.fromisoformat(ts.replace("Z", ""))


def build_timelines():
    with open(ALERTS_FILE, "r") as f:
        alerts = json.load(f)

    with open(CAMPAIGNS_FILE, "r") as f:
        campaigns = json.load(f)

    alert_map = defaultdict(list)

    for alert in alerts:
        entity = alert.get("src_ip", "unknown")
        rules = alert.get("triggered_rules", [])

        if not rules:
            rules = ["NO_RULE"]

        for rule in rules:
            alert_map[(entity, rule)].append(alert)

    timelines = []

    for campaign in campaigns:
        key = (campaign["entity"], campaign["rule"])
        related_alerts = sorted(
            alert_map.get(key, []),
            key=lambda a: parse_time(a["timestamp"])
        )

        timeline_events = []
        last_severity = None

        for alert in related_alerts:
            time_str = parse_time(alert["timestamp"]).strftime("%H:%M:%S")
            score = alert["final_threat_score"]
            severity = alert["severity"]

            if last_severity and severity != last_severity:
                timeline_events.append(
                    f"{time_str} — Severity escalated to {severity}"
                )
            else:
                timeline_events.append(
                    f"{time_str} — {campaign['rule']} detected (score: {score})"
                )

            last_severity = severity

        timelines.append({
            "entity": campaign["entity"],
            "rule": campaign["rule"],
            "campaign_type": campaign["campaign_type"],
            "timeline": timeline_events
        })

    with open(OUTPUT_FILE, "w") as f:
        json.dump(timelines, f, indent=2)

    print(f"[+] Timelines generated: {len(timelines)}")
    print(f"[+] Written to: {OUTPUT_FILE}")


if __name__ == "__main__":
    build_timelines()
