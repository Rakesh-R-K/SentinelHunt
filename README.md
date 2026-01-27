# 🛡️ SentinelHunt

**AI-Assisted Network Threat Hunting Platform**

> Behavioral anomaly detection meets explainable AI to hunt unknown network threats without signatures

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9+-green.svg)](https://www.python.org/)
[![Go](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)

---

## 🎯 Project Overview

SentinelHunt is a **capstone-level threat hunting platform** that detects zero-day and unknown network threats using behavioral anomaly detection and explainable AI. Unlike signature-based systems (Snort, Suricata), SentinelHunt analyzes traffic behavior patterns to identify suspicious activity that has never been seen before.

### Why SentinelHunt?

| Traditional IDS | SentinelHunt |
|-----------------|--------------|
| ❌ Signature-based (misses zero-days) | ✅ Behavior-based (catches unknowns) |
| ❌ Black-box ML models | ✅ Explainable AI (SHAP) |
| ❌ Single language | ✅ Multi-language (Go, Python, JavaScript, TypeScript) |
| ❌ Batch processing | ✅ Real-time + batch modes |
| ❌ Alert spam | ✅ Campaign intelligence & timeline reconstruction |
| ❌ No payload inspection (encrypted traffic) | ✅ Works with encryption (metadata only) |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    SENTINELHUNT                         │
└─────────────────────────────────────────────────────────┘

[Packet Capture] ──> [Feature Engineering] ──> [Detection]
     (Go)                  (Python)              (Python)
                                                     │
                                                     v
                                            [Explainability]
                                                 (SHAP)
                                                     │
                                                     v
                                            [API + Dashboard]
                                          (Node.js + React/TS)
```

### Components

1. **📡 Packet Collector (Go)** - High-performance live capture & flow aggregation
2. **🔧 Feature Engineering (Python)** - Extract 14 behavioral features from flows
3. **🤖 Detection Engine (Python)** - Hybrid rule-based + ML anomaly detection
4. **🧠 Explainability (Python + SHAP)** - Transparent threat explanations
5. **🎨 Dashboard (React + TypeScript)** - Interactive SOC analyst interface
6. **🌐 API Backend (Node.js)** - RESTful services for threat data
7. **⚔️ Attack Simulation (Python + Bash)** - Validation & testing suite
8. **📊 Evaluation (Python)** - Metrics, confusion matrix, performance analysis

---

## ✨ Key Features

### 🔍 Detection Capabilities

- **Zero-Day Detection** - Catches attacks with no prior signatures
- **DNS Tunneling** - High entropy, deep subdomains, suspicious patterns
- **Port Scanning** - Multiple destination ports, high packet rates
- **C2 Beaconing** - Regular timing patterns (low IAT variability)
- **Data Exfiltration** - High throughput, large byte transfers
- **Encrypted Traffic Support** - Works without payload inspection

### 🧠 Explainable AI

- **SHAP Explanations** - Why each alert was triggered
- **Feature Importance** - Global and per-alert attribution
- **Human Narratives** - Analyst-friendly threat descriptions
- **Visualizations** - Publication-quality plots for presentations

### 📈 SOC Intelligence

- **Alert Aggregation** - Group related alerts by entity/rule
- **Campaign Detection** - Identify sustained attack patterns
- **Timeline Reconstruction** - Chronological attack progression
- **Severity Classification** - CRITICAL / HIGH / MEDIUM / LOW bands

---

## 🚀 Quick Start

### Prerequisites

```bash
# WSL/Ubuntu
sudo apt update
sudo apt install python3 python3-pip tcpdump golang nodejs npm

# Python dependencies
pip3 install pandas numpy scikit-learn scapy shap matplotlib seaborn

# Node.js dependencies (for dashboard)
cd dashboard/backend && npm install
cd ../frontend && npm install

# Go dependencies (for collector)
cd collector && go mod download
```

### Running the Platform

#### 1. Start API Backend
```bash
cd dashboard/backend
npm start
# API running on http://localhost:5000
```

#### 2. Start Dashboard
```bash
cd dashboard/frontend
npm start
# Dashboard at http://localhost:3000
```

#### 3. Run Detection Pipeline (Existing Data)
```bash
cd feature_engineering
python3 parse_pcap.py  # Extract features

cd ../ml
python3 train_baseline.py  # Train model

cd ../detection_engine/scoring
python3 threat_score.py  # Score flows
python3 threat_labeler.py  # Generate alerts

cd ../intelligence
python3 aggregator.py  # Aggregate incidents
python3 campaign_detector.py  # Detect campaigns
python3 timeline_builder.py  # Build timelines
```

#### 4. Generate Explanations
```bash
cd explainability
python3 explain_ml.py  # SHAP analysis
python3 alert_explainer.py  # Human narratives
```

#### 5. Evaluate Performance
```bash
cd experiments
python3 evaluation.py  # Calculate metrics
```

---

## 📊 Current Status

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

🟢 **Phase 7: Real-Time Collection & Dashboard (Completed)**

### ✅ Completed (Day 12)
- **Go Packet Collector**: High-performance live capture
- **Node.js API Backend**: RESTful services
- **React + TypeScript Dashboard**: Interactive UI
- **SHAP Explainability**: ML interpretability
- **Attack Simulations**: Port scan, DNS tunnel, beaconing, exfiltration
- **Evaluation Framework**: Metrics, confusion matrix

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
