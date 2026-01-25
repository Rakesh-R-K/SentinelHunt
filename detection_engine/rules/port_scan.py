"""
Port Scan Detection Rule
"""

def detect(flow):
    """
    Detect potential port scanning behavior.

    Criteria:
    - High destination port diversity
    """
    dst_port_count = flow.get("dst_port_count", 0)

    if dst_port_count >= 20:
        return True, {
            "rule": "PORT_SCAN",
            "severity_boost": 0.25,
            "indicator": "high destination port diversity"
        }

    return False, None
