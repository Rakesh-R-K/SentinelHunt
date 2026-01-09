from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict
import pandas as pd
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
# Feature extraction per flow
# -------------------------------
def extract_flow_features(flow_packets):
    times = [pkt.time for pkt in flow_packets]
    sizes = [len(pkt) for pkt in flow_packets]

    packet_count = len(flow_packets)
    duration = max(times) - min(times) if packet_count > 1 else 0
    avg_packet_size = sum(sizes) / packet_count

    return {
        "packet_count": packet_count,
        "duration": round(duration, 6),
        "avg_packet_size": round(avg_packet_size, 2)
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
