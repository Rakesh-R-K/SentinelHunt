#!/usr/bin/env python3
"""
C2 Beaconing Simulation

Purpose:
- Simulate command-and-control (C2) beaconing traffic
- Regular, periodic connections with low variability
- Characteristic of malware heartbeats

Detection features:
- Regular inter-arrival times (low std_iat)
- Periodic connections to same destination
- Small packet sizes
- Long-lived persistent connection

Run from: WSL or Kali Linux
"""

import socket
import time
import random
from datetime import datetime
import subprocess

# ========================================
# CONFIGURATION
# ========================================
C2_SERVER = "example.com"  # Fake C2 server (will fail, but generates traffic)
C2_PORT = 443  # HTTPS port (common for C2)
BEACON_INTERVAL = 5  # Seconds between beacons
BEACON_COUNT = 30  # Number of beacons to send
JITTER = 0.5  # Small timing jitter (seconds)
PCAP_OUTPUT = f"beaconing_attack_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"

print("=" * 60)
print("  SENTINELHUNT C2 BEACONING SIMULATION")
print("=" * 60)
print(f"[+] C2 Server: {C2_SERVER}:{C2_PORT}")
print(f"[+] Beacon Interval: {BEACON_INTERVAL}s (±{JITTER}s)")
print(f"[+] Beacon Count: {BEACON_COUNT}")
print(f"[+] PCAP Output: {PCAP_OUTPUT}")
print("")

# ========================================
# START PACKET CAPTURE
# ========================================
print("[+] Starting packet capture...")
try:
    tcpdump_process = subprocess.Popen(
        ['sudo', 'tcpdump', '-i', 'any', '-w', PCAP_OUTPUT, f'host {C2_SERVER}'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(2)
    print("[+] Packet capture started")
except Exception as e:
    print(f"[!] Failed to start tcpdump: {e}")
    tcpdump_process = None

# ========================================
# SIMULATE BEACONING
# ========================================
print("\n[+] Starting C2 beaconing...\n")

beacon_timestamps = []
success_count = 0
fail_count = 0

try:
    for i in range(BEACON_COUNT):
        timestamp = datetime.now()
        beacon_timestamps.append(timestamp)
        
        # Add jitter to make it more realistic
        jitter = random.uniform(-JITTER, JITTER)
        
        print(f"[{timestamp.strftime('%H:%M:%S')}] Beacon #{i+1}/{BEACON_COUNT}...", end=' ')
        
        try:
            # Simulate beacon (TCP connection attempt)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            
            # Try to connect (will likely fail, but generates traffic)
            try:
                sock.connect((C2_SERVER, C2_PORT))
                
                # If connection succeeds, send small beacon
                beacon_data = b"BEACON\x00" + str(i).encode()
                sock.send(beacon_data)
                
                print("✓ Sent")
                success_count += 1
                
            except (socket.timeout, socket.error):
                print("✗ Failed (expected)")
                fail_count += 1
            
            sock.close()
            
        except Exception as e:
            print(f"✗ Error: {e}")
            fail_count += 1
        
        # Wait for next beacon interval (with jitter)
        if i < BEACON_COUNT - 1:
            time.sleep(BEACON_INTERVAL + jitter)

except KeyboardInterrupt:
    print("\n\n[!] Beaconing interrupted by user")

# ========================================
# STOP PACKET CAPTURE
# ========================================
print("\n[+] Stopping beaconing...")
time.sleep(2)

if tcpdump_process:
    print("[+] Stopping packet capture...")
    tcpdump_process.terminate()
    tcpdump_process.wait()

# ========================================
# CALCULATE TIMING STATISTICS
# ========================================
if len(beacon_timestamps) > 1:
    intervals = []
    for i in range(1, len(beacon_timestamps)):
        interval = (beacon_timestamps[i] - beacon_timestamps[i-1]).total_seconds()
        intervals.append(interval)
    
    import statistics
    mean_interval = statistics.mean(intervals)
    std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0

# ========================================
# ATTACK SUMMARY
# ========================================
print("\n" + "=" * 60)
print("  BEACONING COMPLETE")
print("=" * 60)
print(f"[+] Total beacons: {len(beacon_timestamps)}")
print(f"[+] Successful: {success_count}")
print(f"[+] Failed: {fail_count}")

if len(beacon_timestamps) > 1:
    print(f"[+] Mean interval: {mean_interval:.3f}s")
    print(f"[+] Std interval: {std_interval:.3f}s (LOW = regular pattern)")

print(f"[+] PCAP file: {PCAP_OUTPUT}")
print("")
print("Expected detections:")
print("  ✓ Regular timing pattern (LOW std_iat)")
print("  ✓ Repeated connections to same destination")
print("  ✓ Persistent long-duration flow")
print("  ✓ Beaconing behavior signature")
print("")
print("Behavioral characteristics:")
print("  - Periodic heartbeats (malware check-in)")
print("  - Small data transfers")
print("  - Consistent timing (automated)")
print("")
print("Next steps:")
print("  1. Transfer PCAP to SentinelHunt")
print("  2. Run feature extraction")
print("  3. Verify low std_iat detection")
print("=" * 60)
