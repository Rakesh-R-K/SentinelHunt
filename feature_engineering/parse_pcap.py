"""
SentinelHunt - Feature Engineering Module

Purpose:
- Parse PCAP files
- Extract network flows (5-tuple)
- Generate SOC-grade flow-level behavioral features

Days:
- Day 3: Basic flow features
- Day 4: Temporal, rate, and DNS intelligence features
"""

from scapy.all import rdpcap, IP, TCP, UDP
from scapy.layers.dns import DNS
from collections import defaultdict, Counter
import pandas as pd
import numpy as np
import math
import sys

# -------------------------------
# Load PCAP
# -------------------------------
def load_pcap(pcap_path):
    packets = rdpcap(pcap_path)
    print(f"[+] Loaded {len(packets)} packets from {pcap_path}")
    return packets


# -------------------------------
# Extract flows (5-tuple)
# -------------------------------
def extract_flows(packets):
    """
    Flow key:
    (src_ip, dst_ip, src_port, dst_port, protocol)
    """
    flows = defaultdict(list)

    for pkt in packets:
        if IP not in pkt:
            continue

        ip = pkt[IP]
        proto = None
        sport = None
        dport = None

        if TCP in pkt:
            proto = "TCP"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            proto = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        else:
            continue

        flow_key = (ip.src, ip.dst, sport, dport, proto)
        flows[flow_key].append(pkt)

    return flows


# -------------------------------
# Entropy helper
# -------------------------------
def shannon_entropy(s):
    if not s:
        return 0
    probs = [c / len(s) for c in Counter(s).values()]
    return -sum(p * math.log2(p) for p in probs)


# -------------------------------
# Feature extraction per flow
# -------------------------------
def extract_flow_features(flow_packets):
    """
    Extract SOC-grade behavioral features from a single network flow.
    """

    # -------------------------------
    # Basic packet data
    # -------------------------------
    times = [float(pkt.time) for pkt in flow_packets]
    sizes = [len(pkt) for pkt in flow_packets]

    packet_count = len(flow_packets)
    total_bytes = sum(sizes)

    duration = max(times) - min(times) if packet_count > 1 else 0
    avg_packet_size = total_bytes / packet_count if packet_count > 0 else 0

    # -------------------------------
    # Temporal Features (IAT)
    # -------------------------------
    if packet_count > 1:
        iats = np.diff(sorted(times))
        min_iat = float(np.min(iats))
        max_iat = float(np.max(iats))
        mean_iat = float(np.mean(iats))
        std_iat = float(np.std(iats))
    else:
        min_iat = max_iat = mean_iat = std_iat = 0.0

    # -------------------------------
    # Rate & Volume Features
    # -------------------------------
    bytes_per_second = total_bytes / duration if duration > 0 else 0
    packets_per_second = packet_count / duration if duration > 0 else 0
    avg_bytes_per_packet = total_bytes / packet_count if packet_count > 0 else 0

    # -------------------------------
    # DNS Intelligence Features
    # -------------------------------
    dns_query = None

    for pkt in flow_packets:
        if DNS in pkt and pkt[DNS].qd:
            try:
                dns_query = pkt[DNS].qd.qname.decode().rstrip(".")
                break
            except Exception:
                pass

    if dns_query:
        dns_query_length = len(dns_query)
        dns_subdomain_depth = dns_query.count(".")
        dns_entropy = shannon_entropy(dns_query)
    else:
        dns_query_length = 0
        dns_subdomain_depth = 0
        dns_entropy = 0.0

    # -------------------------------
    # Return final feature set
    # -------------------------------
    return {
        # Basic
        "packet_count": packet_count,
        "duration": round(duration, 6),
        "total_bytes": total_bytes,
        "avg_packet_size": round(avg_packet_size, 2),

        # Temporal
        "min_iat": round(min_iat, 6),
        "max_iat": round(max_iat, 6),
        "mean_iat": round(mean_iat, 6),
        "std_iat": round(std_iat, 6),

        # Rate
        "bytes_per_second": round(bytes_per_second, 2),
        "packets_per_second": round(packets_per_second, 2),
        "avg_bytes_per_packet": round(avg_bytes_per_packet, 2),

        # DNS
        "dns_query_length": dns_query_length,
        "dns_subdomain_depth": dns_subdomain_depth,
        "dns_entropy": round(dns_entropy, 3)
    }


# -------------------------------
# Main pipeline
# -------------------------------
def main(pcap_path):
    packets = load_pcap(pcap_path)
    flows = extract_flows(packets)

    print(f"[+] Total flows extracted: {len(flows)}")

    rows = []

    for flow_key, pkts in flows.items():
        features = extract_flow_features(pkts)

        row = {
            "src_ip": flow_key[0],
            "dst_ip": flow_key[1],
            "src_port": flow_key[2],
            "dst_port": flow_key[3],
            "protocol": flow_key[4],
            **features
        }

        rows.append(row)

    df = pd.DataFrame(rows)

    output_path = "outputs/flow_features.csv"
    df.to_csv(output_path, index=False)

    print(f"[+] Saved flow-level features to {output_path}")
    print("[+] Sample output:")
    print(df.head())


# -------------------------------
# Entry point
# -------------------------------
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 parse_pcap.py <pcap_file>")
        sys.exit(1)

    main(sys.argv[1])

