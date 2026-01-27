#!/bin/bash
#
# Port Scan Attack Simulation
# Purpose: Generate network traffic that should trigger port scan detection rules
# Run from: Kali Linux VM
#

echo "================================================"
echo "  SENTINELHUNT PORT SCAN SIMULATION"
echo "================================================"

# Configuration
TARGET_IP="192.168.1.100"  # Change to your target WSL IP
OUTPUT_FILE="port_scan_attack_$(date +%Y%m%d_%H%M%S).pcap"

echo "[+] Target: $TARGET_IP"
echo "[+] Output: $OUTPUT_FILE"
echo ""

# Start packet capture in background
echo "[+] Starting packet capture..."
sudo tcpdump -i eth0 -w "$OUTPUT_FILE" host $TARGET_IP &
TCPDUMP_PID=$!
sleep 2

echo "[+] Running nmap scans..."
echo ""

# 1. SYN Stealth Scan (stealthy, half-open connections)
echo "[1/4] SYN Stealth Scan..."
sudo nmap -sS -p 1-1000 --max-rate 100 $TARGET_IP

# 2. TCP Connect Scan (full connections)
echo "[2/4] TCP Connect Scan..."
sudo nmap -sT -p 20-80 $TARGET_IP

# 3. UDP Scan (DNS, DHCP, SNMP ports)
echo "[3/4] UDP Scan..."
sudo nmap -sU -p 53,67,161 $TARGET_IP

# 4. Comprehensive Scan (service detection)
echo "[4/4] Service Detection Scan..."
sudo nmap -sV -p 22,80,443,3389 $TARGET_IP

echo ""
echo "[+] Scans complete. Waiting 5 seconds for packet capture..."
sleep 5

# Stop packet capture
sudo kill $TCPDUMP_PID 2>/dev/null
sleep 1

echo ""
echo "================================================"
echo "  SCAN COMPLETE"
echo "================================================"
echo "[+] PCAP file: $OUTPUT_FILE"
echo "[+] Transfer this file to WSL for analysis"
echo ""
echo "Next steps:"
echo "  1. scp $OUTPUT_FILE user@wsl-ip:/path/to/SentinelHunt/datasets/raw/attack/"
echo "  2. Run feature extraction: parse_pcap.py"
echo "  3. Run detection engine"
echo ""
echo "Expected detections:"
echo "  - High packet count"
echo "  - Multiple destination ports"
echo "  - Short flow durations"
echo "  - Port scan signatures"
echo "================================================"
