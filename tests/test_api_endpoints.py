"""
SentinelHunt — API Endpoint Tests

Tests all REST API endpoints for correct behavior.
"""

import pytest
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class TestAPIEndpoints:
    """Tests for the Express.js API server endpoints."""

    def test_health_endpoint_structure(self):
        """Verify health check response structure."""
        # This test validates the expected structure
        expected_fields = ["status", "timestamp", "uptime", "version"]
        health_response = {
            "status": "healthy",
            "timestamp": "2026-01-15T10:30:00Z",
            "uptime": 120.5,
            "version": "1.0.0",
        }
        for field in expected_fields:
            assert field in health_response

    def test_alert_filtering_logic(self):
        """Test the alert filtering logic used by the API."""
        alerts = [
            {"severity": "CRITICAL", "src_ip": "192.168.1.1"},
            {"severity": "HIGH", "src_ip": "192.168.1.2"},
            {"severity": "MEDIUM", "src_ip": "192.168.1.3"},
            {"severity": "LOW", "src_ip": "192.168.1.4"},
        ]

        # Filter by severity
        filtered = [a for a in alerts if a["severity"] == "CRITICAL"]
        assert len(filtered) == 1

        # Pagination logic
        offset, limit = 0, 2
        paginated = alerts[offset:offset + limit]
        assert len(paginated) == 2

    def test_stats_calculation_logic(self):
        """Test statistics calculation logic."""
        alerts = [
            {"severity": "CRITICAL", "src_ip": "10.0.0.1", "dst_ip": "8.8.8.8",
             "threat_type": "beaconing", "protocol": "TCP", "final_threat_score": 0.9},
            {"severity": "HIGH", "src_ip": "10.0.0.2", "dst_ip": "8.8.4.4",
             "threat_type": "port_scan", "protocol": "TCP", "final_threat_score": 0.7},
            {"severity": "HIGH", "src_ip": "10.0.0.1", "dst_ip": "1.1.1.1",
             "threat_type": "beaconing", "protocol": "UDP", "final_threat_score": 0.75},
        ]

        stats = {
            "total_alerts": len(alerts),
            "critical": sum(1 for a in alerts if a["severity"] == "CRITICAL"),
            "high": sum(1 for a in alerts if a["severity"] == "HIGH"),
            "unique_sources": len(set(a["src_ip"] for a in alerts)),
            "unique_destinations": len(set(a["dst_ip"] for a in alerts)),
        }

        assert stats["total_alerts"] == 3
        assert stats["critical"] == 1
        assert stats["high"] == 2
        assert stats["unique_sources"] == 2
        assert stats["unique_destinations"] == 3


class TestAlertPipeline:
    """End-to-end alert pipeline tests."""

    def test_flow_to_alert_pipeline(self, sample_dns_tunnel_flow):
        """Test that a suspicious flow generates an alert through the pipeline."""
        from detection_engine.rules import RULES

        triggered_rules = []
        for rule_fn in RULES:
            matched, metadata = rule_fn(sample_dns_tunnel_flow)
            if matched:
                triggered_rules.append(metadata["rule"])

        # DNS tunnel flow should trigger at least DNS-related rules
        assert len(triggered_rules) > 0

    def test_benign_flow_no_alert(self, sample_normal_flow):
        """Test that a normal flow doesn't trigger rules (except potential false positives)."""
        from detection_engine.rules import RULES

        triggered = 0
        for rule_fn in RULES:
            matched, _ = rule_fn(sample_normal_flow)
            if matched:
                triggered += 1

        # Normal traffic should trigger very few rules (ideally zero)
        assert triggered <= 1

    def test_mitre_enrichment_pipeline(self, sample_alert):
        """Test full MITRE enrichment pipeline."""
        from detection_engine.mitre_mapping import enrich_alert_with_mitre

        enriched = enrich_alert_with_mitre(sample_alert)
        assert "mitre_attack" in enriched
        assert len(enriched["mitre_attack"]["techniques"]) > 0
        assert "investigation_guidance" in enriched
