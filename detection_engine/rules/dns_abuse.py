"""
DNS Abuse / DNS Beaconing Detection Rule
Feature-aligned with SentinelHunt Phase 1 dataset
"""

def detect(flow):
    protocol = flow.get("protocol", "").upper()
    dst_port = flow.get("dst_port", -1)

    packets_per_second = flow.get("packets_per_second", 0)
    dns_entropy = flow.get("dns_entropy", 0)
    dns_depth = flow.get("dns_subdomain_depth", 0)

    flag_entropy = flow.get("flag_high_dns_entropy", 0)
    flag_depth = flow.get("flag_deep_dns", 0)

    if protocol == "UDP" and dst_port == 53:
        # SOC-grade DNS beaconing heuristic
        if (
            packets_per_second > 5
            and (dns_entropy > 3.5 or flag_entropy == 1)
            and (dns_depth >= 3 or flag_depth == 1)
        ):
            return True, {
                "rule": "DNS_BEACONING",
                "severity_boost": 0.2,
                "indicator": "suspicious high-entropy, repetitive DNS queries"
            }

    return False, None
