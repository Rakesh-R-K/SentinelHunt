"""
SentinelHunt — Protocol Anomaly Detection Rule

Detects protocols running on non-standard ports and protocol violations
that may indicate tunneling, evasion, or malicious activity
(MITRE ATT&CK: T1571, T1572).

Detection approach:
    - Port/protocol mismatch detection
    - Unexpected traffic volume on service ports
    - Unusual packet size distributions for known protocols
"""

from typing import Dict, Any, Tuple, Optional
import logging

logger = logging.getLogger("sentinelhunt.rules.protocol_anomaly")

# Standard port-to-protocol mapping
STANDARD_PORT_PROTOCOLS = {
    20: ("FTP-Data", "TCP"),
    21: ("FTP-Control", "TCP"),
    22: ("SSH", "TCP"),
    23: ("Telnet", "TCP"),
    25: ("SMTP", "TCP"),
    53: ("DNS", "UDP"),
    80: ("HTTP", "TCP"),
    110: ("POP3", "TCP"),
    143: ("IMAP", "TCP"),
    443: ("HTTPS", "TCP"),
    993: ("IMAPS", "TCP"),
    995: ("POP3S", "TCP"),
    3306: ("MySQL", "TCP"),
    3389: ("RDP", "TCP"),
    5432: ("PostgreSQL", "TCP"),
    8080: ("HTTP-Alt", "TCP"),
    8443: ("HTTPS-Alt", "TCP"),
}

# Expected packet size ranges for common protocols
EXPECTED_PACKET_SIZES = {
    "DNS": (40, 512),       # Typical DNS response size
    "SSH": (50, 16384),
    "HTTP": (40, 65535),
    "HTTPS": (40, 16384),
    "SMTP": (40, 2048),
}

# Ports that should not normally carry high-volume traffic
LOW_VOLUME_PORTS = {22, 23, 25, 110, 143}


def detect(flow: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Detect protocol anomalies in network flows.

    Criteria:
        1. Protocol running on non-standard port
        2. Unexpected traffic volume for the protocol/port
        3. Packet size distribution anomalies
        4. UDP traffic on typically TCP-only ports
    """
    protocol = flow.get("protocol", "").upper()
    dst_port = flow.get("dst_port", -1)
    src_port = flow.get("src_port", -1)
    packet_count = flow.get("packet_count", 0)
    total_bytes = flow.get("total_bytes", 0)
    avg_packet_size = flow.get("avg_packet_size", 0)
    duration = flow.get("duration", 0)
    bytes_per_second = flow.get("bytes_per_second", 0)

    indicators = []
    severity_boost = 0.0

    # ---- Anomaly 1: Protocol mismatch ----
    # UDP traffic on typically TCP-only ports
    if protocol == "UDP" and dst_port in STANDARD_PORT_PROTOCOLS:
        expected_name, expected_proto = STANDARD_PORT_PROTOCOLS[dst_port]
        if expected_proto == "TCP":
            indicators.append(
                f"UDP traffic on {expected_name} port {dst_port} "
                f"(expected TCP) — possible tunneling"
            )
            severity_boost += 0.25

    # TCP traffic on DNS port (unusual, possible DNS-over-TCP tunnel)
    if protocol == "TCP" and dst_port == 53:
        if total_bytes > 5000:
            indicators.append(
                f"Large TCP session on DNS port 53 ({total_bytes} bytes) "
                f"— possible DNS tunneling via TCP"
            )
            severity_boost += 0.20

    # ---- Anomaly 2: HTTP on non-standard ports ----
    # High-volume traffic on unusual ports (potential HTTP tunnel)
    non_http_ports = set(range(1024, 65536)) - {8080, 8443, 8888, 3000, 3001}
    if (
        protocol == "TCP"
        and dst_port in non_http_ports
        and total_bytes > 50_000
        and packet_count > 20
    ):
        # HTTP-like traffic pattern on unusual ports
        if 200 < avg_packet_size < 1500:
            indicators.append(
                f"HTTP-like traffic pattern on non-standard port {dst_port} "
                f"({total_bytes} bytes, avg_pkt={avg_packet_size:.0f}B)"
            )
            severity_boost += 0.15

    # ---- Anomaly 3: Excessive volume on low-volume ports ----
    if dst_port in LOW_VOLUME_PORTS:
        if total_bytes > 100_000:
            port_info = STANDARD_PORT_PROTOCOLS.get(
                dst_port, (f"Port {dst_port}", protocol)
            )
            indicators.append(
                f"Excessive data volume ({total_bytes} bytes) on "
                f"{port_info[0]} port — potential data exfiltration via protocol abuse"
            )
            severity_boost += 0.20

    # ---- Anomaly 4: Very large packets on small-packet protocols ----
    if dst_port == 53 and protocol == "UDP":
        if avg_packet_size > 512:
            indicators.append(
                f"Oversized DNS packets (avg {avg_packet_size:.0f} bytes, "
                f"standard max is 512) — potential DNS tunneling"
            )
            severity_boost += 0.20

    # ---- Anomaly 5: Encrypted traffic on typically unencrypted ports ----
    # Small, uniform packets on plaintext ports suggest tunneling
    plaintext_ports = {80, 21, 23, 25, 110, 143}
    if dst_port in plaintext_ports and protocol == "TCP":
        if avg_packet_size > 0 and packet_count > 10:
            # High entropy indicator: many packets, moderate size
            if 100 < avg_packet_size < 600 and duration > 5:
                indicators.append(
                    f"Potentially encrypted traffic on plaintext port {dst_port} "
                    f"(uniform packet pattern)"
                )
                severity_boost += 0.15

    if not indicators:
        return False, None

    return True, {
        "rule": "PROTOCOL_ANOMALY",
        "severity_boost": min(severity_boost, 0.45),
        "indicator": "; ".join(indicators),
        "mitre_tactic": "TA0011",
        "mitre_technique": "T1571",
    }
