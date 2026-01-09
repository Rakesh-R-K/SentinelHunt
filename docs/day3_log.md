# Day 3 Log — PCAP Parsing & Flow-Level Feature Extraction

## Objective
Convert raw PCAP network captures into structured, flow-level data suitable for behavioral analysis and machine learning.

---

## Work Completed

### 1. PCAP Parsing
- Successfully loaded PCAP files using Scapy.
- Verified packet integrity and timestamps.
- Parsed ~20,000 packets from baseline normal traffic capture.

### 2. Flow Extraction
- Defined a network flow using the standard 5-tuple:
  (src_ip, dst_ip, src_port, dst_port, protocol)
- Grouped packets into flows using TCP and UDP headers.
- Extracted approximately 2,400 unique flows from the dataset.

### 3. Feature Engineering (Initial Set)
For each flow, the following features were extracted:
- Packet count
- Flow duration (seconds)
- Average packet size (bytes)
- Protocol type (TCP/UDP)

These features represent basic but critical behavioral characteristics of network communication.

### 4. Structured Output
- Exported flow-level features to CSV format.
- Output file: `feature_engineering/outputs/flow_features.csv`
- Dataset is now ready for further feature enrichment and ML-based anomaly detection.

---

## Observations
- DNS traffic (UDP port 53) generates a large number of short-duration flows.
- HTTPS traffic (TCP port 443) shows longer-lived flows with higher packet counts.
- Baseline traffic appears consistent and suitable for training unsupervised models.

---

## Next Steps
- Add advanced temporal features (inter-arrival time, variance).
- Introduce DNS-specific features (query length, entropy).
- Begin identifying beaconing-like periodic behavior.

---

## Status
✅ Day 3 objectives successfully completed.
