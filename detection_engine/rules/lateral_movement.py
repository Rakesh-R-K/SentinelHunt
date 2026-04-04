"""
SentinelHunt — Lateral Movement Detection Rule

Detects internal-to-internal network connections that deviate from
established communication baselines. Lateral movement is a key
indicator of post-compromise activity (MITRE ATT&CK: TA0008).

Detection heuristics:
    - New internal-to-internal connections not in baseline
    - Authentication-related traffic (SMB/RDP/SSH/WinRM port patterns)
    - Rapid sequential connections to multiple internal hosts
    - Internal scanning patterns (many internal targets)
"""

import ipaddress
from typing import Dict, Any, Tuple, Optional, Set
from collections import defaultdict
import logging

logger = logging.getLogger("sentinelhunt.rules.lateral_movement")

# Track known internal communication patterns (built during baseline)
_baseline_connections: Set[tuple] = set()
_internal_targets_per_source: Dict[str, set] = defaultdict(set)

# Ports associated with lateral movement techniques
LATERAL_MOVEMENT_PORTS = {
    22: "SSH",
    135: "MSRPC",
    139: "NetBIOS",
    445: "SMB",
    3389: "RDP",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    1433: "MSSQL",
    3306: "MySQL",
    5432: "PostgreSQL",
    5900: "VNC",
    902: "VMware",
}


def _is_internal_ip(ip: str) -> bool:
    """Check if an IP address is in a private/internal network range."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private
    except (ValueError, TypeError):
        return False


def detect(flow: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Detect potential lateral movement activity.

    Criteria:
        1. Both source and destination are internal IPs
        2. Connection to a lateral-movement-associated port
        3. Multiple internal targets from same source (scanning)
    """
    src_ip = flow.get("src_ip", "")
    dst_ip = flow.get("dst_ip", "")
    dst_port = flow.get("dst_port", -1)
    protocol = flow.get("protocol", "").upper()
    packet_count = flow.get("packet_count", 0)
    duration = flow.get("duration", 0)

    # Only care about internal-to-internal traffic
    if not (_is_internal_ip(src_ip) and _is_internal_ip(dst_ip)):
        return False, None

    # Skip if same host
    if src_ip == dst_ip:
        return False, None

    indicators = []
    severity_boost = 0.0

    # Check for lateral movement ports
    if dst_port in LATERAL_MOVEMENT_PORTS:
        service = LATERAL_MOVEMENT_PORTS[dst_port]
        indicators.append(f"Connection to {service} (port {dst_port}) between internal hosts")
        severity_boost += 0.15

        # Short-lived auth attempts (potential credential spraying)
        if duration < 2.0 and packet_count > 3:
            indicators.append(f"Short-lived {service} session ({duration:.2f}s) — possible credential testing")
            severity_boost += 0.15

    # Track internal targets per source
    _internal_targets_per_source[src_ip].add(dst_ip)

    # Multiple internal targets = scanning/spreading
    internal_target_count = len(_internal_targets_per_source.get(src_ip, set()))
    if internal_target_count >= 3:
        indicators.append(
            f"Source {src_ip} contacted {internal_target_count} internal hosts — lateral scanning"
        )
        severity_boost += 0.20

    # High packet rate between internal hosts on auth ports
    packets_per_second = flow.get("packets_per_second", 0)
    if dst_port in LATERAL_MOVEMENT_PORTS and packets_per_second > 10:
        indicators.append(
            f"High packet rate ({packets_per_second:.1f} pps) on {LATERAL_MOVEMENT_PORTS[dst_port]}"
        )
        severity_boost += 0.10

    if not indicators:
        return False, None

    return True, {
        "rule": "LATERAL_MOVEMENT",
        "severity_boost": min(severity_boost, 0.5),
        "indicator": "; ".join(indicators),
        "mitre_tactic": "TA0008",
        "mitre_technique": "T1021",
        "internal_targets": internal_target_count,
    }
