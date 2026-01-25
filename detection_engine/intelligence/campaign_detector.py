import json

INPUT_FILE = "feature_engineering/outputs/aggregated_alerts.json"
OUTPUT_FILE = "feature_engineering/outputs/campaigns.json"


def classify_campaign(alert_count):
    if alert_count >= 5:
        return "active_campaign"
    elif alert_count >= 2:
        return "repeated_activity"
    else:
        return "single_event"


def detect_campaigns():
    with open(INPUT_FILE, "r") as f:
        incidents = json.load(f)

    campaigns = []

    for incident in incidents:
        campaigns.append({
            **incident,
            "campaign_type": classify_campaign(incident["alert_count"])
        })

    with open(OUTPUT_FILE, "w") as f:
        json.dump(campaigns, f, indent=2)

    print(f"[+] Campaigns classified: {len(campaigns)}")
    print(f"[+] Written to: {OUTPUT_FILE}")


if __name__ == "__main__":
    detect_campaigns()
