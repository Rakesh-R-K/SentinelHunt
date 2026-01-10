## Status

🟢 **Phase 1: Data Collection & Feature Engineering (Completed)**

### ✅ Completed
- Baseline benign network traffic captured using `tcpdump`
- Multiple clean PCAP files collected:
  - Web browsing traffic
  - Idle/background traffic
  - Git activity traffic
- Dataset metadata documented  
  *(PCAP files intentionally excluded from repository)*
- PCAP parsing pipeline implemented using **Scapy**
- Network flows extracted using standard **5-tuple definition**
- Flow features exported to structured **CSV format** for downstream analysis

### ✅ Flow-Level Feature Engineering (SOC-Grade)
- **Basic Features**
  - Packet count
  - Flow duration
  - Average packet size
- **Temporal Features**
  - Inter-arrival time statistics (min, max, mean, std)
- **Rate & Volume Features**
  - Total bytes
  - Bytes per second
  - Packets per second
  - Average bytes per packet
- **DNS Intelligence Features**
  - DNS query length
  - Subdomain depth
  - Shannon entropy of DNS queries

These features enable detection of behavioral patterns such as:
- Beaconing malware
- DNS tunneling
- Low-and-slow command-and-control traffic

No machine learning is used at this stage — detection is possible through
behavioral reasoning alone.

---

🔵 **Phase 2: Detection Logic & Anomaly Modeling (Next)**

### 🔜 Planned
- Rule-based detection logic using engineered features
- Flow suspicion scoring and prioritization
- Labeling of flows (normal vs suspicious)
- Unsupervised anomaly detection (e.g., Isolation Forest, LOF)
- Preparation of ML-ready datasets
- Explainability layer for alert interpretation (SOC-focused)

---

📌 **Current Focus**
Building analyst-grade detection logic on top of behavior-aware flow features.
