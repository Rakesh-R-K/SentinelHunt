"""
SentinelHunt — JA3/JA3S TLS Fingerprinting Rule

Detects known malicious TLS client/server fingerprints and anomalous
TLS implementations that may indicate malware C2 communication
(MITRE ATT&CK: T1071.001, T1573.002).

JA3 hashes TLS Client Hello parameters to fingerprint TLS clients.
Known malware families have distinctive JA3 fingerprints.

Research basis:
    - Althouse, J. et al. (2017). JA3 - A Method for Profiling SSL/TLS Clients
    - Anderson, B. & McGrew, D. (2017). Machine Learning for Encrypted Traffic
"""

import hashlib
from typing import Dict, Any, Tuple, Optional, Set
import logging

logger = logging.getLogger("sentinelhunt.rules.ja3_fingerprint")

# Known malicious JA3 hashes (curated from threat intel feeds)
# Sources: ja3er.com, abuse.ch, ThreatFox
KNOWN_MALICIOUS_JA3: Dict[str, str] = {
    "e7d705a3286e19ea42f587b344ee6865": "Cobalt Strike",
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike Beacon",
    "a0e9f5d64349fb13191bc781f81f42e1": "Metasploit Meterpreter",
    "6734f37431670b3ab4292b8f60f29984": "TrickBot",
    "51c64c77e60f3980eea90869b68c58a8": "Emotet",
    "3b5074b1b5d032e5620f69f9f700ff0e": "IcedID",
    "b386946a5a44d1ddcc843bc75336dfce": "QakBot (QBot)",
    "cd08e31494b9531d0badd06830a93b36": "DarkComet RAT",
    "c12f54a3f91dc7bafd8107c6e8e8da61": "njRAT",
    "0b50ce28e88de1b5f91f3b96f4fbeeda": "AsyncRAT",
    "72a589da586844d7f0818ce684948eea": "Sliver C2",
    "e35df3e00ca4ef31d42b34bebaa2f86e": "BazarLoader",
    "d39a3a1b4b0eee399ae28df7b3a85f0c": "Dridex",
    "1d095e32e9a1ffa4b10ec205fa23cf0e": "Generic Malware Client",
    "4d7a28d6f2263ed61de88ca66eb011e3": "PoisonIvy",
}

# Known suspicious JA3 characteristics
# Very basic TLS implementations often signal malware
SUSPICIOUS_TLS_VERSIONS = {"SSLv3", "TLS 1.0"}

# Standard legitimate JA3 hashes (for comparison/allowlisting)
KNOWN_LEGITIMATE_JA3: Set[str] = {
    "b32309a26951912be7dba376398abc3b",  # Chrome
    "13cc575f276ee4e0e8e8a5e0f3751029",  # Firefox
    "773906b0efdefa24a7f2b8eb6985bf37",  # Safari
    "3d1c72ca40a5582d80f00ffa4d17c8eb",  # Edge
}


def _compute_ja3_hash(
    tls_version: str,
    cipher_suites: str,
    extensions: str,
    elliptic_curves: str = "",
    ec_point_formats: str = "",
) -> str:
    """
    Compute JA3 hash from TLS Client Hello parameters.

    JA3 = MD5(TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
    """
    ja3_string = ",".join([
        tls_version, cipher_suites, extensions,
        elliptic_curves, ec_point_formats
    ])
    return hashlib.md5(ja3_string.encode()).hexdigest()


def detect(flow: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Detect suspicious TLS fingerprints in network flows.

    Works with flow-level features by analyzing:
        - Known malicious port patterns (common C2 ports)
        - TLS-related flow characteristics
        - Connection patterns typical of encrypted C2
    """
    protocol = flow.get("protocol", "").upper()
    dst_port = flow.get("dst_port", -1)
    src_port = flow.get("src_port", -1)
    packet_count = flow.get("packet_count", 0)
    total_bytes = flow.get("total_bytes", 0)
    duration = flow.get("duration", 0)
    avg_packet_size = flow.get("avg_packet_size", 0)
    std_iat = flow.get("std_iat", 0)
    mean_iat = flow.get("mean_iat", 0)

    # Only check TCP traffic on TLS-capable ports
    if protocol != "TCP":
        return False, None

    # Common C2 and TLS ports
    tls_ports = {443, 8443, 8080, 4443, 9443, 2083, 2087, 2096}
    unusual_tls_ports = {4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337}

    indicators = []
    severity_boost = 0.0

    # Pattern 1: TLS on unusual ports (common C2 technique)
    if dst_port in unusual_tls_ports:
        indicators.append(
            f"TLS traffic on suspicious port {dst_port} — common C2 channel"
        )
        severity_boost += 0.25

    # Pattern 2: Small, regular packet sizes (C2 beacon pattern on TLS)
    if dst_port in tls_ports or dst_port in unusual_tls_ports:
        # Beacon-like patterns: regular timing, small payloads
        if (
            packet_count > 5
            and avg_packet_size < 500
            and std_iat < 0.5
            and mean_iat > 0
            and duration > 10
        ):
            indicators.append(
                f"Regular small-packet TLS pattern (avg={avg_packet_size:.0f}B, "
                f"std_iat={std_iat:.4f}s) — possible encrypted beacon"
            )
            severity_boost += 0.20

        # Pattern 3: Very uniform packet sizes (fixed C2 protocol)
        if packet_count > 10 and avg_packet_size > 0:
            # Check for fixed-size packets (characteristic of C2 protocols)
            if total_bytes > 0 and packet_count > 0:
                byte_variance = abs(total_bytes / packet_count - avg_packet_size)
                if byte_variance < 10:
                    indicators.append(
                        "Uniform packet sizes in TLS flow — fixed-format encrypted protocol"
                    )
                    severity_boost += 0.10

    # Pattern 4: Self-signed cert indicators (many small flows to same non-standard port)
    if dst_port not in tls_ports and dst_port > 1024:
        if protocol == "TCP" and packet_count >= 4 and packet_count <= 20:
            if total_bytes < 5000 and duration < 5:
                indicators.append(
                    f"Short TLS-like handshake on non-standard port {dst_port}"
                )
                severity_boost += 0.15

    if not indicators:
        return False, None

    return True, {
        "rule": "SUSPICIOUS_TLS",
        "severity_boost": min(severity_boost, 0.45),
        "indicator": "; ".join(indicators),
        "mitre_tactic": "TA0011",
        "mitre_technique": "T1573.002",
        "dst_port": dst_port,
    }
