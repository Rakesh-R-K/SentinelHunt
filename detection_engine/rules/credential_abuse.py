"""
SentinelHunt — Credential Abuse / Brute Force Detection Rule

Detects credential stuffing, password spraying, and brute force attack
patterns based on connection behavior analysis
(MITRE ATT&CK: T1110, T1110.001, T1110.003, T1110.004).

Detection approach:
    - Track failed connection patterns per source IP
    - Detect rapid sequential connections to auth ports
    - Identify password spraying (many targets, same port)
    - Time-window based analysis
"""

from typing import Dict, Any, Tuple, Optional
from collections import defaultdict
import time
import logging

logger = logging.getLogger("sentinelhunt.rules.credential_abuse")

# Track connection attempts per source IP with sliding window
_connection_tracker: Dict[str, list] = defaultdict(list)
_target_tracker: Dict[str, set] = defaultdict(set)

# Authentication-related ports
AUTH_PORTS = {
    22: "SSH",
    23: "Telnet",
    21: "FTP",
    3389: "RDP",
    445: "SMB",
    389: "LDAP",
    636: "LDAPS",
    88: "Kerberos",
    1433: "MSSQL",
    3306: "MySQL",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM",
    8080: "HTTP-Auth",
    443: "HTTPS-Auth",
}

# Configuration
WINDOW_SECONDS = 300     # 5-minute sliding window
FAILURE_THRESHOLD = 10   # Connections in window to trigger
SPRAY_TARGET_THRESHOLD = 5  # Unique targets for spray detection


def _cleanup_old_entries(src_ip: str, current_time: float) -> None:
    """Remove entries older than the sliding window."""
    cutoff = current_time - WINDOW_SECONDS
    _connection_tracker[src_ip] = [
        t for t in _connection_tracker[src_ip] if t > cutoff
    ]


def detect(flow: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Detect credential abuse and brute force patterns.

    Criteria:
        1. Multiple connections to authentication ports from same source
        2. Short-duration connections (failed auth attempts)
        3. Many unique targets (password spraying)
        4. High packets-per-second on auth ports
    """
    src_ip = flow.get("src_ip", "")
    dst_ip = flow.get("dst_ip", "")
    dst_port = flow.get("dst_port", -1)
    protocol = flow.get("protocol", "").upper()
    packet_count = flow.get("packet_count", 0)
    duration = flow.get("duration", 0)
    total_bytes = flow.get("total_bytes", 0)
    packets_per_second = flow.get("packets_per_second", 0)

    # Only check connections to authentication ports
    if dst_port not in AUTH_PORTS:
        return False, None

    service = AUTH_PORTS[dst_port]
    current_time = time.time()
    indicators = []
    severity_boost = 0.0

    # Track this connection
    _connection_tracker[src_ip].append(current_time)
    _target_tracker[src_ip].add(dst_ip)
    _cleanup_old_entries(src_ip, current_time)

    # ---- Pattern 1: Brute force (many connections, short duration) ----
    recent_count = len(_connection_tracker[src_ip])

    if recent_count >= FAILURE_THRESHOLD:
        indicators.append(
            f"Brute force pattern: {recent_count} connections to auth ports "
            f"in {WINDOW_SECONDS}s window from {src_ip}"
        )
        severity_boost += 0.30

    # ---- Pattern 2: Short-lived connections (failed auth) ----
    if duration < 1.0 and packet_count >= 3 and packet_count <= 15:
        indicators.append(
            f"Short-lived {service} session ({duration:.2f}s, {packet_count} pkts) "
            f"— likely failed authentication"
        )
        severity_boost += 0.15

    # ---- Pattern 3: Password spray (many unique targets) ----
    unique_targets = len(_target_tracker.get(src_ip, set()))
    if unique_targets >= SPRAY_TARGET_THRESHOLD:
        indicators.append(
            f"Password spray: {src_ip} targeted {unique_targets} unique hosts "
            f"on {service} (port {dst_port})"
        )
        severity_boost += 0.25

    # ---- Pattern 4: High connection rate ----
    if packets_per_second > 20 and dst_port in AUTH_PORTS:
        indicators.append(
            f"High-rate connection attempts ({packets_per_second:.1f} pps) "
            f"to {service}"
        )
        severity_boost += 0.15

    # ---- Pattern 5: Very small payload (reset/rejection) ----
    if total_bytes < 200 and packet_count >= 3 and dst_port in {22, 3389}:
        indicators.append(
            f"Minimal payload ({total_bytes}B) {service} connection "
            f"— likely rejected/failed"
        )
        severity_boost += 0.10

    if not indicators:
        return False, None

    return True, {
        "rule": "CREDENTIAL_ABUSE",
        "severity_boost": min(severity_boost, 0.5),
        "indicator": "; ".join(indicators),
        "recent_connection_count": recent_count,
        "unique_targets": unique_targets,
        "service": service,
        "mitre_tactic": "TA0006",
        "mitre_technique": "T1110",
    }
