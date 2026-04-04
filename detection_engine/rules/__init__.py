"""
SentinelHunt Detection Rules Registry

All detection rules are registered here. Each rule implements a
`detect(flow)` function that returns (matched: bool, metadata: dict).
"""

from .port_scan import detect as port_scan_detect
from .dns_abuse import detect as dns_beaconing_detect
from .lateral_movement import detect as lateral_movement_detect
from .dga_detector import detect as dga_detect
from .ja3_fingerprint import detect as ja3_detect
from .protocol_anomaly import detect as protocol_anomaly_detect
from .credential_abuse import detect as credential_abuse_detect
from .exfiltration import detect as exfiltration_detect

# Master list of all detection rules
# Each rule is a callable: (flow_dict) -> (bool, Optional[dict])
RULES = [
    port_scan_detect,
    dns_beaconing_detect,
    lateral_movement_detect,
    dga_detect,
    ja3_detect,
    protocol_anomaly_detect,
    credential_abuse_detect,
    exfiltration_detect,
]

# Rule name → callable mapping for selective execution
RULE_REGISTRY = {
    "PORT_SCAN": port_scan_detect,
    "DNS_BEACONING": dns_beaconing_detect,
    "LATERAL_MOVEMENT": lateral_movement_detect,
    "DGA_DETECTED": dga_detect,
    "SUSPICIOUS_TLS": ja3_detect,
    "PROTOCOL_ANOMALY": protocol_anomaly_detect,
    "CREDENTIAL_ABUSE": credential_abuse_detect,
    "DATA_EXFILTRATION": exfiltration_detect,
}
