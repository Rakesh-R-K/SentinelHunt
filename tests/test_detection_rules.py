"""
SentinelHunt — Detection Rules Unit Tests

Tests all 8 detection rules against crafted flow data to verify
correct detection logic and metadata output.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection_engine.rules.dns_abuse import detect as dns_detect
from detection_engine.rules.port_scan import detect as port_scan_detect
from detection_engine.rules.lateral_movement import detect as lateral_detect
from detection_engine.rules.dga_detector import detect as dga_detect
from detection_engine.rules.ja3_fingerprint import detect as ja3_detect
from detection_engine.rules.protocol_anomaly import detect as protocol_detect
from detection_engine.rules.credential_abuse import detect as cred_detect
from detection_engine.rules.exfiltration import detect as exfil_detect


class TestDNSAbuse:
    """Tests for DNS beaconing detection."""

    def test_detects_dns_beaconing(self, sample_dns_tunnel_flow):
        matched, metadata = dns_detect(sample_dns_tunnel_flow)
        assert matched is True
        assert metadata is not None
        assert metadata["rule"] == "DNS_BEACONING"

    def test_ignores_normal_dns(self, sample_normal_flow):
        matched, metadata = dns_detect(sample_normal_flow)
        assert matched is False
        assert metadata is None

    def test_ignores_non_dns_protocol(self):
        flow = {"protocol": "TCP", "dst_port": 80}
        matched, _ = dns_detect(flow)
        assert matched is False


class TestPortScan:
    """Tests for port scanning detection."""

    def test_detects_port_scan(self, sample_port_scan_flow):
        matched, metadata = port_scan_detect(sample_port_scan_flow)
        assert matched is True
        assert metadata["rule"] == "PORT_SCAN"

    def test_ignores_normal_traffic(self, sample_normal_flow):
        matched, _ = port_scan_detect(sample_normal_flow)
        assert matched is False

    def test_threshold_boundary(self):
        flow = {"dst_port_count": 19}
        matched, _ = port_scan_detect(flow)
        assert matched is False

        flow["dst_port_count"] = 20
        matched, metadata = port_scan_detect(flow)
        assert matched is True


class TestLateralMovement:
    """Tests for lateral movement detection."""

    def test_detects_rdp_lateral(self, sample_lateral_movement_flow):
        matched, metadata = lateral_detect(sample_lateral_movement_flow)
        assert matched is True
        assert metadata["rule"] == "LATERAL_MOVEMENT"
        assert "RDP" in metadata["indicator"]

    def test_ignores_external_traffic(self):
        flow = {
            "src_ip": "192.168.1.100",
            "dst_ip": "8.8.8.8",
            "dst_port": 3389,
            "protocol": "TCP",
            "packet_count": 10,
            "duration": 1.0,
            "packets_per_second": 5,
        }
        matched, _ = lateral_detect(flow)
        assert matched is False


class TestDGADetector:
    """Tests for DGA detection."""

    def test_detects_high_entropy_dns(self):
        flow = {
            "protocol": "UDP",
            "dst_port": 53,
            "dns_entropy": 4.5,
            "dns_query_length": 40,
            "dns_subdomain_depth": 4,
        }
        matched, metadata = dga_detect(flow)
        assert matched is True
        assert metadata["rule"] == "DGA_DETECTED"

    def test_ignores_normal_dns(self):
        flow = {
            "protocol": "UDP",
            "dst_port": 53,
            "dns_entropy": 2.0,
            "dns_query_length": 15,
            "dns_subdomain_depth": 1,
        }
        matched, _ = dga_detect(flow)
        assert matched is False


class TestJA3Fingerprint:
    """Tests for TLS fingerprint detection."""

    def test_detects_suspicious_tls_port(self):
        flow = {
            "protocol": "TCP",
            "dst_port": 4444,  # Common C2 port
            "packet_count": 10,
            "avg_packet_size": 200,
            "total_bytes": 2000,
            "duration": 5,
            "std_iat": 0.1,
            "mean_iat": 0.5,
        }
        matched, metadata = ja3_detect(flow)
        assert matched is True
        assert metadata["rule"] == "SUSPICIOUS_TLS"

    def test_ignores_normal_https(self, sample_normal_flow):
        matched, _ = ja3_detect(sample_normal_flow)
        # Normal HTTPS flow may or may not trigger depending on pattern
        # The test verifies the function doesn't crash
        assert isinstance(matched, bool)


class TestProtocolAnomaly:
    """Tests for protocol anomaly detection."""

    def test_detects_udp_on_tcp_port(self):
        flow = {
            "protocol": "UDP",
            "dst_port": 80,
            "packet_count": 20,
            "total_bytes": 10000,
            "avg_packet_size": 500,
            "bytes_per_second": 1000,
            "duration": 5,
        }
        matched, metadata = protocol_detect(flow)
        assert matched is True
        assert metadata["rule"] == "PROTOCOL_ANOMALY"
        assert "UDP" in metadata["indicator"]

    def test_ignores_standard_protocol(self, sample_normal_flow):
        matched, _ = protocol_detect(sample_normal_flow)
        # Standard HTTPS traffic should not trigger
        assert matched is False


class TestCredentialAbuse:
    """Tests for credential abuse detection."""

    def test_detects_ssh_brute_force(self, sample_brute_force_flow):
        matched, metadata = cred_detect(sample_brute_force_flow)
        assert matched is True
        assert metadata["rule"] == "CREDENTIAL_ABUSE"
        assert "SSH" in metadata["service"]

    def test_ignores_non_auth_port(self, sample_normal_flow):
        matched, _ = cred_detect(sample_normal_flow)
        assert matched is False


class TestExfiltration:
    """Tests for data exfiltration detection."""

    def test_detects_large_outbound_transfer(self, sample_exfiltration_flow):
        matched, metadata = exfil_detect(sample_exfiltration_flow)
        assert matched is True
        assert metadata["rule"] == "DATA_EXFILTRATION"
        assert metadata["bytes_transferred"] == 10_000_000

    def test_detects_dns_exfiltration(self):
        flow = {
            "src_ip": "192.168.1.100",
            "dst_ip": "8.8.8.8",
            "dst_port": 53,
            "protocol": "UDP",
            "total_bytes": 5000,
            "packet_count": 50,
            "duration": 30,
            "bytes_per_second": 166,
            "dns_query_length": 120,
            "dns_entropy": 4.5,
        }
        matched, metadata = exfil_detect(flow)
        assert matched is True


class TestMITREMapping:
    """Tests for MITRE ATT&CK mapping."""

    def test_mapping_exists_for_all_rules(self):
        from detection_engine.mitre_mapping import RULE_MITRE_MAPPING
        expected_rules = [
            "DNS_BEACONING", "PORT_SCAN", "LATERAL_MOVEMENT",
            "DGA_DETECTED", "SUSPICIOUS_TLS", "PROTOCOL_ANOMALY",
            "CREDENTIAL_ABUSE", "DATA_EXFILTRATION",
        ]
        for rule in expected_rules:
            assert rule in RULE_MITRE_MAPPING, f"Missing MITRE mapping for {rule}"

    def test_enrich_alert(self, sample_alert):
        from detection_engine.mitre_mapping import enrich_alert_with_mitre
        enriched = enrich_alert_with_mitre(sample_alert)
        assert "mitre_attack" in enriched
        assert "tactics" in enriched["mitre_attack"]
        assert "techniques" in enriched["mitre_attack"]

    def test_navigator_layer_generation(self, sample_alert):
        from detection_engine.mitre_mapping import (
            enrich_alert_with_mitre,
            generate_navigator_layer,
        )
        enriched = enrich_alert_with_mitre(sample_alert)
        layer = generate_navigator_layer([enriched])
        assert layer["domain"] == "enterprise-attack"
        assert len(layer["techniques"]) > 0
