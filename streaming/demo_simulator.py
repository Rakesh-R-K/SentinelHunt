"""
SentinelHunt — Demo Traffic Simulator

Generates realistic synthetic network flows and publishes them
to Redis Streams for live demonstration purposes.

Simulates a mix of:
    - Normal web browsing (HTTP/HTTPS)
    - DNS lookups
    - Background services
    - 🚨 Port scanning attacks
    - 🚨 DNS tunneling / DGA beaconing
    - 🚨 Lateral movement (RDP/SMB)
    - 🚨 Data exfiltration
    - 🚨 Credential brute force (SSH)

Usage:
    python -m streaming.demo_simulator
    python -m streaming.demo_simulator --rate 10 --duration 120
"""

import json
import time
import random
import string
import math
import logging
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

logger = logging.getLogger("sentinelhunt.demo")


# =============================================
# Flow Generators
# =============================================

def _random_internal_ip():
    return f"192.168.1.{random.randint(10, 254)}"

def _random_external_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def _random_domain():
    tlds = ["com", "org", "net", "io", "dev"]
    words = ["cloud", "api", "data", "service", "auth", "edge", "cdn", "app", "web", "mail"]
    return f"{random.choice(words)}{random.randint(1,99)}.{random.choice(tlds)}"


def generate_normal_https() -> Dict[str, Any]:
    """Normal HTTPS web browsing."""
    duration = random.uniform(0.5, 30.0)
    packets = random.randint(10, 500)
    total_bytes = random.randint(5000, 500000)
    return {
        "src_ip": _random_internal_ip(),
        "dst_ip": _random_external_ip(),
        "src_port": random.randint(49152, 65535),
        "dst_port": 443,
        "protocol": "TCP",
        "packet_count": packets,
        "duration": round(duration, 3),
        "total_bytes": total_bytes,
        "avg_packet_size": round(total_bytes / packets, 2),
        "min_iat": round(random.uniform(0.001, 0.05), 6),
        "max_iat": round(random.uniform(0.5, 5.0), 6),
        "mean_iat": round(duration / packets, 6),
        "std_iat": round(random.uniform(0.01, 0.3), 6),
        "bytes_per_second": round(total_bytes / max(duration, 0.01), 2),
        "packets_per_second": round(packets / max(duration, 0.01), 2),
        "avg_bytes_per_packet": round(total_bytes / packets, 2),
        "dns_query_length": 0,
        "dns_subdomain_depth": 0,
        "dns_entropy": 0.0,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


def generate_normal_dns() -> Dict[str, Any]:
    """Normal DNS lookup."""
    domain = _random_domain()
    return {
        "src_ip": _random_internal_ip(),
        "dst_ip": "8.8.8.8",
        "src_port": random.randint(49152, 65535),
        "dst_port": 53,
        "protocol": "UDP",
        "packet_count": 2,
        "duration": round(random.uniform(0.01, 0.2), 3),
        "total_bytes": random.randint(80, 200),
        "avg_packet_size": random.uniform(60, 100),
        "min_iat": round(random.uniform(0.01, 0.05), 6),
        "max_iat": round(random.uniform(0.05, 0.2), 6),
        "mean_iat": round(random.uniform(0.02, 0.1), 6),
        "std_iat": round(random.uniform(0.005, 0.02), 6),
        "bytes_per_second": round(random.uniform(400, 2000), 2),
        "packets_per_second": round(random.uniform(5, 20), 2),
        "avg_bytes_per_packet": round(random.uniform(60, 100), 2),
        "dns_query_length": len(domain),
        "dns_subdomain_depth": domain.count("."),
        "dns_entropy": round(random.uniform(2.0, 3.5), 4),
        "dns_query": domain,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


def generate_port_scan() -> Dict[str, Any]:
    """🚨 Port scanning attack."""
    target = _random_internal_ip()
    return {
        "src_ip": _random_internal_ip(),
        "dst_ip": target,
        "src_port": random.randint(40000, 65535),
        "dst_port": random.choice([22, 80, 443, 3389, 8080, 445]),
        "protocol": "TCP",
        "packet_count": random.randint(1, 5),
        "duration": round(random.uniform(0.01, 0.5), 3),
        "total_bytes": random.randint(40, 300),
        "avg_packet_size": round(random.uniform(40, 80), 2),
        "min_iat": round(random.uniform(0.001, 0.01), 6),
        "max_iat": round(random.uniform(0.01, 0.1), 6),
        "mean_iat": round(random.uniform(0.005, 0.05), 6),
        "std_iat": round(random.uniform(0.001, 0.01), 6),
        "bytes_per_second": round(random.uniform(100, 3000), 2),
        "packets_per_second": round(random.uniform(10, 100), 2),
        "avg_bytes_per_packet": round(random.uniform(40, 80), 2),
        "dns_query_length": 0,
        "dns_subdomain_depth": 0,
        "dns_entropy": 0.0,
        "dst_port_count": random.randint(20, 100),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


def generate_dns_tunnel() -> Dict[str, Any]:
    """🚨 DNS tunneling / DGA beaconing."""
    # Generate random high-entropy subdomain (looks like encoded data)
    random_sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(30, 60)))
    domain = f"{random_sub}.{random.choice(['c2-server', 'data-drop', 'beacon-relay'])}.evil.com"

    entropy = round(random.uniform(3.8, 4.8), 4)
    packets = random.randint(50, 200)
    duration = round(random.uniform(5, 30), 3)

    return {
        "src_ip": _random_internal_ip(),
        "dst_ip": _random_internal_ip(),
        "src_port": random.randint(49152, 65535),
        "dst_port": 53,
        "protocol": "UDP",
        "packet_count": packets,
        "duration": duration,
        "total_bytes": random.randint(10000, 80000),
        "avg_packet_size": round(random.uniform(200, 500), 2),
        "min_iat": round(random.uniform(0.05, 0.2), 6),
        "max_iat": round(random.uniform(0.2, 0.5), 6),
        "mean_iat": round(duration / packets, 6),
        "std_iat": round(random.uniform(0.01, 0.05), 6),
        "bytes_per_second": round(random.uniform(1000, 5000), 2),
        "packets_per_second": round(packets / max(duration, 0.01), 2),
        "avg_bytes_per_packet": round(random.uniform(200, 500), 2),
        "dns_query_length": len(domain),
        "dns_subdomain_depth": domain.count("."),
        "dns_entropy": entropy,
        "dns_query": domain,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


def generate_lateral_movement() -> Dict[str, Any]:
    """🚨 Lateral movement (RDP / SMB)."""
    port = random.choice([3389, 445, 5985, 135])
    service_map = {3389: "RDP", 445: "SMB", 5985: "WinRM", 135: "DCOM"}

    return {
        "src_ip": _random_internal_ip(),
        "dst_ip": _random_internal_ip(),
        "src_port": random.randint(49152, 65535),
        "dst_port": port,
        "protocol": "TCP",
        "packet_count": random.randint(5, 30),
        "duration": round(random.uniform(0.5, 10.0), 3),
        "total_bytes": random.randint(1000, 50000),
        "avg_packet_size": round(random.uniform(100, 500), 2),
        "min_iat": round(random.uniform(0.01, 0.1), 6),
        "max_iat": round(random.uniform(0.2, 1.0), 6),
        "mean_iat": round(random.uniform(0.05, 0.3), 6),
        "std_iat": round(random.uniform(0.02, 0.1), 6),
        "bytes_per_second": round(random.uniform(500, 5000), 2),
        "packets_per_second": round(random.uniform(2, 30), 2),
        "avg_bytes_per_packet": round(random.uniform(100, 500), 2),
        "dns_query_length": 0,
        "dns_subdomain_depth": 0,
        "dns_entropy": 0.0,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


def generate_exfiltration() -> Dict[str, Any]:
    """🚨 Data exfiltration (large outbound transfer)."""
    total_bytes = random.randint(5_000_000, 50_000_000)
    duration = round(random.uniform(30, 300), 3)
    packets = random.randint(3000, 30000)

    return {
        "src_ip": _random_internal_ip(),
        "dst_ip": _random_external_ip(),
        "src_port": random.randint(49152, 65535),
        "dst_port": random.choice([443, 8443, 9090]),
        "protocol": "TCP",
        "packet_count": packets,
        "duration": duration,
        "total_bytes": total_bytes,
        "avg_packet_size": round(total_bytes / packets, 2),
        "min_iat": round(random.uniform(0.001, 0.01), 6),
        "max_iat": round(random.uniform(0.1, 0.5), 6),
        "mean_iat": round(duration / packets, 6),
        "std_iat": round(random.uniform(0.005, 0.05), 6),
        "bytes_per_second": round(total_bytes / max(duration, 0.01), 2),
        "packets_per_second": round(packets / max(duration, 0.01), 2),
        "avg_bytes_per_packet": round(total_bytes / packets, 2),
        "dns_query_length": 0,
        "dns_subdomain_depth": 0,
        "dns_entropy": 0.0,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


def generate_brute_force() -> Dict[str, Any]:
    """🚨 SSH brute force attack."""
    return {
        "src_ip": _random_external_ip(),
        "dst_ip": _random_internal_ip(),
        "src_port": random.randint(49152, 65535),
        "dst_port": 22,
        "protocol": "TCP",
        "packet_count": random.randint(3, 8),
        "duration": round(random.uniform(0.2, 2.0), 3),
        "total_bytes": random.randint(200, 600),
        "avg_packet_size": round(random.uniform(50, 100), 2),
        "min_iat": round(random.uniform(0.01, 0.05), 6),
        "max_iat": round(random.uniform(0.1, 0.5), 6),
        "mean_iat": round(random.uniform(0.05, 0.2), 6),
        "std_iat": round(random.uniform(0.01, 0.05), 6),
        "bytes_per_second": round(random.uniform(200, 1000), 2),
        "packets_per_second": round(random.uniform(5, 30), 2),
        "avg_bytes_per_packet": round(random.uniform(50, 100), 2),
        "dns_query_length": 0,
        "dns_subdomain_depth": 0,
        "dns_entropy": 0.0,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


# =============================================
# Traffic Mix
# =============================================

# Weighted traffic distribution (realistic: 85% benign, 15% malicious)
TRAFFIC_MIX = [
    (generate_normal_https,     40, "HTTPS"),
    (generate_normal_dns,       30, "DNS"),
    (generate_normal_https,     15, "HTTP"),
    (generate_port_scan,         4, "🚨 Port Scan"),
    (generate_dns_tunnel,        3, "🚨 DNS Tunnel"),
    (generate_lateral_movement,  3, "🚨 Lateral Movement"),
    (generate_exfiltration,      2, "🚨 Exfiltration"),
    (generate_brute_force,       3, "🚨 Brute Force"),
]


def pick_flow() -> tuple:
    """Pick a random flow generator based on weighted distribution."""
    total = sum(w for _, w, _ in TRAFFIC_MIX)
    r = random.randint(1, total)
    cumulative = 0
    for gen_fn, weight, label in TRAFFIC_MIX:
        cumulative += weight
        if r <= cumulative:
            return gen_fn(), label
    return TRAFFIC_MIX[0][0](), TRAFFIC_MIX[0][2]


# =============================================
# Main Simulator
# =============================================

def run_simulator(
    rate: float = 5.0,
    duration: int = 0,
    redis_host: str = "localhost",
    redis_port: int = 6379,
):
    """
    Run the traffic simulator.

    Args:
        rate: Flows per second to generate
        duration: Duration in seconds (0 = infinite)
        redis_host: Redis host
        redis_port: Redis port
    """
    from streaming.redis_broker import RedisBroker

    print("═══════════════════════════════════════════════")
    print("  SentinelHunt Demo Traffic Simulator")
    print("═══════════════════════════════════════════════")
    print(f"  Rate: {rate} flows/sec")
    print(f"  Duration: {'∞' if duration == 0 else f'{duration}s'}")
    print(f"  Redis: {redis_host}:{redis_port}")
    print("─────────────────────────────────────────────")

    broker = RedisBroker(host=redis_host, port=redis_port)

    if not broker.is_connected:
        print("\n  ❌ Redis not available!")
        print("  Start Redis: docker run -d -p 6379:6379 redis:7-alpine")
        print("  Or: redis-server")
        return

    print("  ✅ Redis connected — publishing to sentinelhunt:flows")
    print("═══════════════════════════════════════════════")
    print()

    interval = 1.0 / rate
    total_flows = 0
    attack_flows = 0
    start_time = time.time()

    try:
        while True:
            flow, label = pick_flow()
            entry_id = broker.publish_flow(flow)

            total_flows += 1
            is_attack = "🚨" in label

            if is_attack:
                attack_flows += 1
                print(f"  [{total_flows:05d}] {label}: "
                      f"{flow['src_ip']}:{flow['src_port']} → "
                      f"{flow['dst_ip']}:{flow['dst_port']} "
                      f"({flow['protocol']}) — {entry_id}")
            elif total_flows % 20 == 0:
                elapsed = time.time() - start_time
                print(f"  [{total_flows:05d}] {total_flows} flows generated "
                      f"({attack_flows} attacks, {elapsed:.0f}s elapsed)")

            # Check duration
            if duration > 0 and (time.time() - start_time) >= duration:
                break

            time.sleep(interval)

    except KeyboardInterrupt:
        pass

    elapsed = time.time() - start_time
    print(f"\n{'═' * 50}")
    print(f"  Simulation Complete")
    print(f"  Total flows: {total_flows}")
    print(f"  Attack flows: {attack_flows} ({attack_flows/max(total_flows,1)*100:.1f}%)")
    print(f"  Duration: {elapsed:.1f}s")
    print(f"  Effective rate: {total_flows/max(elapsed,0.01):.1f} flows/sec")
    print(f"{'═' * 50}")

    broker.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SentinelHunt Demo Traffic Simulator")
    parser.add_argument("--rate", type=float, default=5.0, help="Flows per second (default: 5)")
    parser.add_argument("--duration", type=int, default=0, help="Duration in seconds (0=infinite)")
    parser.add_argument("--redis-host", default="localhost", help="Redis host")
    parser.add_argument("--redis-port", type=int, default=6379, help="Redis port")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    run_simulator(
        rate=args.rate,
        duration=args.duration,
        redis_host=args.redis_host,
        redis_port=args.redis_port,
    )
