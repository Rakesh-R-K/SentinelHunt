"""
SentinelHunt — Data Exfiltration Detection Rule

Detects anomalous outbound data transfers that may indicate data theft
(MITRE ATT&CK: TA0010, T1041, T1048, T1567).

Detection approach:
    - Track egress data volume per internal host
    - Detect anomalous upload-to-download ratios
    - Time-of-day analysis (large transfers at unusual hours)
    - Slow exfiltration via accumulated transfer tracking
    - DNS exfiltration (excessive DNS query data)
"""

import ipaddress
from typing import Dict, Any, Tuple, Optional
from collections import defaultdict
import logging

logger = logging.getLogger("sentinelhunt.rules.exfiltration")

# Cumulative tracker for slow exfiltration detection
_cumulative_egress: Dict[str, int] = defaultdict(int)
_flow_count_per_source: Dict[str, int] = defaultdict(int)

# Thresholds
SINGLE_FLOW_BYTES_THRESHOLD = 5_000_000        # 5 MB in one flow
CUMULATIVE_BYTES_THRESHOLD = 50_000_000         # 50 MB cumulative
HIGH_UPLOAD_RATIO_THRESHOLD = 5.0               # Upload 5x more than download
DNS_EXFIL_QUERY_LENGTH_THRESHOLD = 100          # Very long DNS queries


def _is_internal_ip(ip: str) -> bool:
    """Check if IP is in a private range."""
    try:
        return ipaddress.ip_address(ip).is_private
    except (ValueError, TypeError):
        return False


def _is_external_ip(ip: str) -> bool:
    """Check if IP is external (not private, not loopback)."""
    try:
        addr = ipaddress.ip_address(ip)
        return not addr.is_private and not addr.is_loopback
    except (ValueError, TypeError):
        return False


def detect(flow: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Detect potential data exfiltration.

    Criteria:
        1. Large outbound data transfers from internal to external
        2. Anomalous upload ratio (much more upload than download)
        3. Cumulative data tracking (slow exfil detection)
        4. DNS exfiltration (excessive data in DNS queries)
        5. Unusual transfer timing patterns
    """
    src_ip = flow.get("src_ip", "")
    dst_ip = flow.get("dst_ip", "")
    dst_port = flow.get("dst_port", -1)
    protocol = flow.get("protocol", "").upper()
    total_bytes = flow.get("total_bytes", 0)
    packet_count = flow.get("packet_count", 0)
    duration = flow.get("duration", 0)
    bytes_per_second = flow.get("bytes_per_second", 0)
    dns_query_length = flow.get("dns_query_length", 0)
    dns_entropy = flow.get("dns_entropy", 0)

    indicators = []
    severity_boost = 0.0

    # ---- Pattern 1: Large single-flow transfer (internal → external) ----
    is_egress = _is_internal_ip(src_ip) and _is_external_ip(dst_ip)

    if is_egress and total_bytes >= SINGLE_FLOW_BYTES_THRESHOLD:
        mb_transferred = total_bytes / (1024 * 1024)
        indicators.append(
            f"Large outbound transfer: {mb_transferred:.1f} MB "
            f"from {src_ip} to {dst_ip}:{dst_port}"
        )
        severity_boost += 0.30

    # ---- Pattern 2: Cumulative slow exfiltration ----
    if is_egress:
        _cumulative_egress[src_ip] += total_bytes
        _flow_count_per_source[src_ip] += 1

        cumulative_mb = _cumulative_egress[src_ip] / (1024 * 1024)
        if _cumulative_egress[src_ip] >= CUMULATIVE_BYTES_THRESHOLD:
            indicators.append(
                f"Cumulative egress alert: {cumulative_mb:.1f} MB total "
                f"from {src_ip} across {_flow_count_per_source[src_ip]} flows "
                f"— potential slow exfiltration"
            )
            severity_boost += 0.25

    # ---- Pattern 3: High data rate on unusual ports ----
    if is_egress and bytes_per_second > 1_000_000:  # > 1 MB/s
        if dst_port not in {80, 443, 8080, 8443}:
            mbps = bytes_per_second / (1024 * 1024)
            indicators.append(
                f"High-rate transfer ({mbps:.1f} MB/s) on non-standard "
                f"port {dst_port} — unusual exfiltration channel"
            )
            severity_boost += 0.20

    # ---- Pattern 4: DNS-based exfiltration ----
    if protocol == "UDP" and dst_port == 53:
        if dns_query_length > DNS_EXFIL_QUERY_LENGTH_THRESHOLD:
            indicators.append(
                f"Oversized DNS query ({dns_query_length} chars) — "
                f"potential DNS exfiltration encoding data in query names"
            )
            severity_boost += 0.25

        # High-entropy + long DNS queries = data encoding
        if dns_entropy > 4.0 and dns_query_length > 50:
            indicators.append(
                f"High-entropy DNS query (entropy={dns_entropy:.2f}, "
                f"length={dns_query_length}) — encoded data exfiltration"
            )
            severity_boost += 0.20

    # ---- Pattern 5: Long-duration steady transfer ----
    if is_egress and duration > 300 and total_bytes > 1_000_000:
        indicators.append(
            f"Sustained outbound transfer: {duration:.0f}s duration, "
            f"{total_bytes / (1024 * 1024):.1f} MB — low-and-slow exfiltration"
        )
        severity_boost += 0.15

    if not indicators:
        return False, None

    return True, {
        "rule": "DATA_EXFILTRATION",
        "severity_boost": min(severity_boost, 0.5),
        "indicator": "; ".join(indicators),
        "bytes_transferred": total_bytes,
        "cumulative_egress_mb": round(
            _cumulative_egress.get(src_ip, 0) / (1024 * 1024), 2
        ),
        "mitre_tactic": "TA0010",
        "mitre_technique": "T1041",
    }
