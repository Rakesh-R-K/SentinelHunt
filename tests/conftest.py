"""
SentinelHunt Test Fixtures

Shared pytest fixtures providing sample flows, mock alerts, and test data
for all test modules.
"""

import pytest
import json
import numpy as np
import pandas as pd
from pathlib import Path
import sys

# Ensure project root is in path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture
def sample_normal_flow():
    """A normal, benign network flow."""
    return {
        "src_ip": "192.168.1.100",
        "dst_ip": "8.8.8.8",
        "src_port": 52341,
        "dst_port": 443,
        "protocol": "TCP",
        "packet_count": 25,
        "duration": 5.234,
        "total_bytes": 15000,
        "avg_packet_size": 600.0,
        "min_iat": 0.01,
        "max_iat": 0.5,
        "mean_iat": 0.15,
        "std_iat": 0.08,
        "bytes_per_second": 2866.0,
        "packets_per_second": 4.78,
        "avg_bytes_per_packet": 600.0,
        "dns_query_length": 0,
        "dns_subdomain_depth": 0,
        "dns_entropy": 0.0,
    }


@pytest.fixture
def sample_dns_tunnel_flow():
    """A flow exhibiting DNS tunneling characteristics."""
    return {
        "src_ip": "192.168.1.50",
        "dst_ip": "192.168.1.1",
        "src_port": 54321,
        "dst_port": 53,
        "protocol": "UDP",
        "packet_count": 100,
        "duration": 10.0,
        "total_bytes": 50000,
        "avg_packet_size": 500.0,
        "min_iat": 0.05,
        "max_iat": 0.2,
        "mean_iat": 0.1,
        "std_iat": 0.02,
        "bytes_per_second": 5000.0,
        "packets_per_second": 10.0,
        "avg_bytes_per_packet": 500.0,
        "dns_query_length": 65,
        "dns_subdomain_depth": 5,
        "dns_entropy": 4.2,
    }


@pytest.fixture
def sample_port_scan_flow():
    """A flow exhibiting port scanning behavior."""
    return {
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.100",
        "src_port": 45678,
        "dst_port": 80,
        "protocol": "TCP",
        "packet_count": 5,
        "duration": 0.1,
        "total_bytes": 300,
        "avg_packet_size": 60.0,
        "min_iat": 0.001,
        "max_iat": 0.05,
        "mean_iat": 0.02,
        "std_iat": 0.01,
        "bytes_per_second": 3000.0,
        "packets_per_second": 50.0,
        "avg_bytes_per_packet": 60.0,
        "dns_query_length": 0,
        "dns_subdomain_depth": 0,
        "dns_entropy": 0.0,
        "dst_port_count": 25,
    }


@pytest.fixture
def sample_lateral_movement_flow():
    """A flow exhibiting lateral movement behavior."""
    return {
        "src_ip": "192.168.1.50",
        "dst_ip": "192.168.1.200",
        "src_port": 49999,
        "dst_port": 3389,
        "protocol": "TCP",
        "packet_count": 8,
        "duration": 1.5,
        "total_bytes": 2000,
        "avg_packet_size": 250.0,
        "min_iat": 0.05,
        "max_iat": 0.3,
        "mean_iat": 0.18,
        "std_iat": 0.05,
        "bytes_per_second": 1333.0,
        "packets_per_second": 5.33,
        "avg_bytes_per_packet": 250.0,
        "dns_query_length": 0,
        "dns_subdomain_depth": 0,
        "dns_entropy": 0.0,
    }


@pytest.fixture
def sample_brute_force_flow():
    """A flow exhibiting credential brute force."""
    return {
        "src_ip": "10.10.10.5",
        "dst_ip": "10.10.10.1",
        "src_port": 55555,
        "dst_port": 22,
        "protocol": "TCP",
        "packet_count": 6,
        "duration": 0.5,
        "total_bytes": 400,
        "avg_packet_size": 66.0,
        "min_iat": 0.01,
        "max_iat": 0.1,
        "mean_iat": 0.08,
        "std_iat": 0.02,
        "bytes_per_second": 800.0,
        "packets_per_second": 12.0,
        "avg_bytes_per_packet": 66.0,
        "dns_query_length": 0,
        "dns_subdomain_depth": 0,
        "dns_entropy": 0.0,
    }


@pytest.fixture
def sample_exfiltration_flow():
    """A flow exhibiting data exfiltration."""
    return {
        "src_ip": "192.168.1.100",
        "dst_ip": "45.33.32.156",
        "src_port": 49000,
        "dst_port": 443,
        "protocol": "TCP",
        "packet_count": 5000,
        "duration": 120.0,
        "total_bytes": 10_000_000,
        "avg_packet_size": 2000.0,
        "min_iat": 0.001,
        "max_iat": 0.1,
        "mean_iat": 0.024,
        "std_iat": 0.015,
        "bytes_per_second": 83333.0,
        "packets_per_second": 41.67,
        "avg_bytes_per_packet": 2000.0,
        "dns_query_length": 0,
        "dns_subdomain_depth": 0,
        "dns_entropy": 0.0,
    }


@pytest.fixture
def sample_alert():
    """A sample alert for testing."""
    return {
        "alert_id": "ALERT-0001",
        "timestamp": "2026-01-15T10:30:00Z",
        "src_ip": "192.168.1.100",
        "dst_ip": "8.8.8.8",
        "src_port": 52341,
        "dst_port": 443,
        "protocol": "TCP",
        "severity": "HIGH",
        "final_threat_score": 0.75,
        "confidence": 0.8,
        "triggered_rules": ["DNS_BEACONING"],
        "threat_label": "DNS_BEACONING",
        "reason": "Suspicious DNS patterns detected",
    }


@pytest.fixture
def sample_feature_matrix():
    """Generate a sample feature matrix for ML testing."""
    np.random.seed(42)
    n_samples = 200
    n_features = 14

    # Normal traffic distribution
    X = np.random.randn(n_samples, n_features) * 0.5 + 1.0
    X = np.abs(X)  # All positive values

    return X


@pytest.fixture
def sample_flow_dataframe():
    """Generate a sample DataFrame of flow features."""
    np.random.seed(42)
    n_flows = 100

    df = pd.DataFrame({
        "src_ip": [f"192.168.1.{i % 254 + 1}" for i in range(n_flows)],
        "dst_ip": [f"10.0.0.{i % 254 + 1}" for i in range(n_flows)],
        "src_port": np.random.randint(1024, 65535, n_flows),
        "dst_port": np.random.choice([80, 443, 53, 22, 3389], n_flows),
        "protocol": np.random.choice(["TCP", "UDP"], n_flows),
        "packet_count": np.random.randint(1, 1000, n_flows),
        "duration": np.random.exponential(5.0, n_flows),
        "total_bytes": np.random.randint(100, 100000, n_flows),
        "avg_packet_size": np.random.uniform(60, 1500, n_flows),
        "min_iat": np.random.exponential(0.01, n_flows),
        "max_iat": np.random.exponential(1.0, n_flows),
        "mean_iat": np.random.exponential(0.1, n_flows),
        "std_iat": np.random.exponential(0.05, n_flows),
        "bytes_per_second": np.random.uniform(100, 50000, n_flows),
        "packets_per_second": np.random.uniform(1, 100, n_flows),
        "avg_bytes_per_packet": np.random.uniform(60, 1500, n_flows),
        "dns_query_length": np.random.randint(0, 80, n_flows),
        "dns_subdomain_depth": np.random.randint(0, 6, n_flows),
        "dns_entropy": np.random.uniform(0, 5, n_flows),
    })

    return df
