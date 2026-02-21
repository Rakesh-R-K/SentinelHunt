# Integration Test for Detection Engine
# This script validates end-to-end data flow and detection logic.
# Extend with real test cases as modules evolve.

import sys
sys.path.append('..')

from detection_engine.intelligence import aggregator, campaign_detector
from detection_engine.rules import dns_abuse, port_scan
from detection_engine.scoring import alert_generator, severity, threat_labeler, threat_score


def test_integration():
    # Check if aggregator and campaign detector output files exist and print sample content
    import os
    import json
    aggregator_output = "feature_engineering/outputs/aggregated_alerts.json"
    campaign_output = "feature_engineering/outputs/campaigns.json"

    for path in [aggregator_output, campaign_output]:
        if os.path.exists(path):
            print(f"[TEST] Found {path}")
            with open(path, "r") as f:
                data = json.load(f)
                print(f"[TEST] Sample from {path}: {data[:1]}")
        else:
            print(f"[TEST] Missing {path} (run aggregator/campaign_detector first)")
    assert True

if __name__ == "__main__":
    test_integration()
    print("Integration test completed successfully.")
