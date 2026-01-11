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

---

🟡 **Phase 2: Baseline Analysis & Rule-Based Detection (In Progress)**

### ✅ Completed (Day 5)
- Statistical baseline established from **2415 benign network flows**
- Percentile-based profiling (90th / 95th / 99th) used to define normal behavior
- Key observations:
  - Most flows are short-lived and bursty
  - Long-duration or high-volume flows are rare
  - High DNS entropy and deep subdomains are uncommon in benign traffic
- Explainable **rule-based anomaly detection** implemented using:
  - High packet volume thresholds
  - Long-lived connection thresholds
  - DNS entropy thresholds
  - DNS subdomain depth analysis
- Flow-level **suspicion scoring system** introduced
- Dataset enriched with anomaly flags and suspicion scores for downstream use

This phase demonstrates that meaningful anomaly detection is possible  
**without machine learning**, using interpretable and defensible heuristics.

---

🔵 **Phase 3: ML-Based Anomaly Detection & Threat Scoring (Next)**

### 🔜 Planned
- Unsupervised anomaly detection (Isolation Forest, LOF)
- Feature selection and normalization
- Comparison of ML alerts vs rule-based alerts
- Threat score aggregation and prioritization
- Detection engine integration
- Explainability layer for analyst-facing alerts

---

📌 **Current Focus**  
Transitioning from rule-based detection to machine learning–assisted  
anomaly detection while preserving interpretability and analyst trust.
