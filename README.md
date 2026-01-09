## Status

🟢 **Phase 1: Data Collection & Feature Engineering (In Progress)**

### ✔ Completed
- Baseline benign network traffic captured using `tcpdump`
- Multiple clean PCAP files collected (web browsing, idle traffic, Git activity)
- Dataset metadata documented (PCAPs intentionally excluded from repository)
- PCAP parsing pipeline implemented using Scapy
- Network flows extracted using standard 5-tuple definition
- Initial flow-level behavioral features generated:
  - Packet count
  - Flow duration
  - Average packet size
- Flow features exported to structured CSV format for downstream analysis

### 🔄 In Progress
- Advanced behavioral feature engineering (timing, DNS entropy, beaconing patterns)

### ⏭ Next
- Temporal and DNS-specific feature enrichment
- Unsupervised anomaly detection model development
- Explainable AI layer for alert interpretation
