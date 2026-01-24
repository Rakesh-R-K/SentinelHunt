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

🟡 **Phase 2: Baseline Analysis & Rule-Based Detection (Completed)**

### ✅ Completed
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
- Dataset enriched with anomaly flags and suspicion scores

This phase demonstrates that meaningful anomaly detection is possible  
**without machine learning**, using interpretable and defensible heuristics.

---

🔵 **Phase 3: Machine Learning–Based Detection (Completed)**

### ✅ Completed (Day 6)
- ML-safe feature selection from enriched flow dataset
- Feature normalization and preprocessing
- Unsupervised anomaly detection using **Isolation Forest**
- Generation of ML anomaly scores
- Hybrid analysis of heuristic vs ML-based detection
- Model and scaler persistence for future inference

---

🟣 **Phase 4: Threat Scoring & SOC Alerting (Completed)**

### ✅ Completed (Day 8)
- Normalized ML anomaly scores and rule-based suspicion scores
- Implemented **weighted threat score fusion**
- Classified flows into **LOW / MEDIUM / HIGH / CRITICAL** severity bands
- Introduced explainable **threat labeling layer**
- Conservatively labeled suspicious traffic without overclassification
- Generated **SOC-style JSON alerts** with:
  - Timestamp
  - Source and destination context
  - Threat label
  - Severity
  - Confidence score

---

🔴 **Phase 5: Alert Triage & Analyst Contextualization (Completed)**

### ✅ Completed (Day 9)
- Enhanced alerts with **analyst-readable explanations**
- Introduced unique **alert identifiers (ALERT-XXXX)** for tracking
- Added **human-readable reason field** explaining why each alert was raised
- Added **threat categorization layer** (e.g., anomalous flow, scan, beaconing)
- Enriched alerts with full **flow context**:
  - Source IP / Destination IP
  - Source port / Destination port
  - Protocol
- Implemented **confidence scoring** to indicate detection reliability
- Generated **SOC-ready alert output** suitable for triage and investigation

This phase transforms raw detections into **actionable security intelligence**,  
bridging the gap between detection logic and real-world SOC workflows.

---

## ✅ Current Pipeline State

**PCAP → Flow Extraction → Feature Engineering → Baseline Modeling →  
Rule-Based Detection → ML Detection → Threat Scoring → Alert Triage**

SentinelHunt now functions as a **complete end-to-end threat hunting pipeline**.
