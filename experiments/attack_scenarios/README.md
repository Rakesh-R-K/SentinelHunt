# Attack Simulation Scripts

Realistic attack scenarios for validating SentinelHunt detection capabilities.

## Available Scenarios

### 1. Port Scanning (`port_scan.sh`)
**Attack Type**: Reconnaissance  
**Technique**: Network port enumeration using nmap  
**Expected Detections**:
- High packet count
- Multiple destination ports
- Short-lived connections
- Port scan signatures

**Usage**:
```bash
chmod +x port_scan.sh
sudo ./port_scan.sh
```

### 2. DNS Tunneling (`dns_tunnel.py`)
**Attack Type**: Command & Control / Data Exfiltration  
**Technique**: Encoding data in DNS queries  
**Expected Detections**:
- High DNS entropy (>3.5)
- Deep subdomain structure (3+ levels)
- High query frequency
- DNS_BEACONING rule trigger

**Usage**:
```bash
python3 dns_tunnel.py
```

### 3. C2 Beaconing (`beaconing.py`)
**Attack Type**: Command & Control  
**Technique**: Periodic malware check-ins  
**Expected Detections**:
- Regular timing pattern (low std_iat)
- Repeated connections to same destination
- Small data transfers
- Persistent connections

**Usage**:
```bash
python3 beaconing.py
```

### 4. Data Exfiltration (`exfiltration.py`)
**Attack Type**: Data Theft  
**Technique**: Large-scale data upload  
**Expected Detections**:
- High bytes_per_second
- Large total_bytes
- Sustained high-volume traffic
- Anomalous transfer patterns

**Usage**:
```bash
python3 exfiltration.py
```

## Workflow

### Step 1: Run Attack Simulation
```bash
cd experiments/attack_scenarios/
python3 dns_tunnel.py
# Generates: dns_tunnel_attack_20260127_143022.pcap
```

### Step 2: Transfer PCAP to Dataset
```bash
mv *.pcap ../../datasets/raw/attack/
```

### Step 3: Extract Features
```bash
cd ../../feature_engineering/
python3 parse_pcap.py --pcap ../datasets/raw/attack/dns_tunnel_attack_20260127_143022.pcap
```

### Step 4: Run Detection
```bash
cd ../detection_engine/
python3 detect_all.py
```

### Step 5: Analyze Results
```bash
cd ../feature_engineering/outputs/
cat alerts.json | grep "DNS_BEACONING"
```

## Attack Matrix

| Scenario | Detection Features | Expected Alert Severity |
|----------|-------------------|------------------------|
| Port Scan | packet_count, duration | HIGH |
| DNS Tunnel | dns_entropy, dns_subdomain_depth | CRITICAL |
| Beaconing | std_iat, duration | HIGH |
| Exfiltration | bytes_per_second, total_bytes | CRITICAL |

## Ground Truth Labels

Create ground truth for evaluation:

```python
# ground_truth.json
{
  "dns_tunnel_attack_20260127_143022.pcap": "DNS_TUNNELING",
  "port_scan_attack_20260127_143100.pcap": "PORT_SCAN",
  "beaconing_attack_20260127_143200.pcap": "C2_BEACONING",
  "exfiltration_attack_20260127_143300.pcap": "DATA_EXFILTRATION"
}
```

## Prerequisites

### Kali Linux
```bash
sudo apt update
sudo apt install nmap tcpdump python3 python3-pip
```

### WSL
```bash
sudo apt install tcpdump python3 python3-pip
pip3 install requests
```

## Safety Notes

⚠️ **Run these scripts in isolated lab environments only**
- Use VMs or containers
- Don't target production systems
- Obey responsible disclosure

## Validation Metrics

After running all simulations, calculate:
- **True Positive Rate**: Attacks correctly detected
- **False Positive Rate**: Benign traffic misclassified
- **Precision**: Accuracy of detections
- **Recall**: Coverage of attack types

## Advanced Scenarios (Future)

- [ ] SQL injection scanning
- [ ] SSH brute force
- [ ] Lateral movement simulation
- [ ] Multi-stage APT campaign
- [ ] Zero-day exploitation patterns

## Integration with Evaluation

```bash
cd ../experiments/
python3 evaluation.py --ground-truth ground_truth.json --alerts ../feature_engineering/outputs/alerts.json
```

## Capstone Value

✅ Demonstrates real attack validation  
✅ Provides empirical detection rates  
✅ Shows understanding of attack techniques  
✅ Enables metrics calculation (precision, recall, F1)  
✅ Proves system works against actual threats

## License

Part of SentinelHunt - AI-Assisted Threat Hunting Platform
