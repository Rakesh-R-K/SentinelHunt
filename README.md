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
- Enriched alerts with full **flow context**
- Implemented **confidence scoring** to indicate detection reliability

This phase transforms raw detections into **actionable SOC alerts**.

---

🟠 **Phase 6: Alert Intelligence & Campaign Analysis (Completed)**

### ✅ Completed (Day 11)
- Implemented **alert aggregation** to correlate related alerts
- Reduced alert noise by grouping alerts by:
  - Source entity
  - Detection rule
- Introduced **campaign classification**:
  - Single event
  - Repeated activity
  - Active campaign
- Successfully detected and classified an **active DNS beaconing campaign**
- Built **attack timeline reconstruction** to visualize:
  - Repeated detections
  - Threat score evolution
  - Severity escalation over time
- Enabled analyst-style investigation and incident prioritization

This phase elevates SentinelHunt from alerting to **true security intelligence**.

---

## ✅ Current Pipeline State

**PCAP → Flow Extraction → Feature Engineering → Baseline Modeling →  
Rule-Based Detection → ML Detection → Threat Scoring → Alert Triage →  
Alert Aggregation → Campaign Detection → Timeline Reconstruction**

SentinelHunt now functions as a **full end-to-end SOC-grade threat hunting platform**.

---

## Detection Engine

SentinelHunt uses a hybrid detection approach combining:
- Statistical anomaly scoring
- Deterministic rule-based detection
- Machine learning–based anomaly detection

### Alert Lifecycle
1. Network flows are extracted from PCAP files
2. Flow-level features are engineered (rate, entropy, timing)
3. Rule-based and ML-based scores are fused
4. Alerts are generated with severity and confidence
5. Alerts are aggregated into incidents
6. Campaigns are identified and timelines reconstructed

### Rule-Based Detection (Current)
Implemented rules include:
- **DNS Beaconing Detection**
  - High DNS entropy
  - Deep subdomain usage
  - Elevated packet rates

These rules enhance explainability and improve confidence in high-risk alerts.
