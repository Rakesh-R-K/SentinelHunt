# 🛡️ SentinelHunt

**AI-Powered Real-Time Network Threat Hunting Platform**

> Ensemble ML anomaly detection, MITRE ATT&CK mapping, and real-time streaming to hunt unknown network threats without signatures

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9+-green.svg)](https://www.python.org/)
[![Go](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)
[![Redis](https://img.shields.io/badge/Redis-7+-red.svg)](https://redis.io/)
[![Docker](https://img.shields.io/badge/Docker-Compose-blue.svg)](https://docs.docker.com/compose/)

---

## 🎯 What is SentinelHunt?

SentinelHunt is a **capstone-grade threat hunting platform** that combines ensemble machine learning, MITRE ATT&CK mapping, and real-time Redis streaming to detect zero-day and advanced persistent threats in network traffic — without relying on signatures.

### How It Compares

| Capability | Traditional IDS | SentinelHunt |
|-----------|----------------|--------------|
| Detection | ❌ Signature-based (misses zero-days) | ✅ Behavioral ML ensemble (catches unknowns) |
| ML Models | ❌ None or single model | ✅ 5-model ensemble (Autoencoder, LSTM, IForest, LOF, OCSVM) |
| Detection Rules | ❌ Regex patterns | ✅ 8 behavioral rules (DGA, lateral movement, exfil, JA3...) |
| Threat Intel | ❌ Static feeds | ✅ VirusTotal + AbuseIPDB + Shodan + 5 OSINT feeds |
| Framework Mapping | ❌ None | ✅ Automated MITRE ATT&CK (7 tactics, 20+ techniques) |
| Architecture | ❌ Batch files | ✅ Redis Streams real-time pipeline |
| Explainability | ❌ Black box | ✅ SHAP + human-readable narratives |
| Dashboard | ❌ Static reports | ✅ WebSocket real-time SOC interface |

---

## 🏗️ Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                     SentinelHunt v2.0                         │
└───────────────────────────────────────────────────────────────┘

┌──────────┐    ┌──────────────┐    ┌─────────────────────┐
│ Go       │    │ Redis        │    │ Real-Time Scorer     │
│ Collector│───▶│ Streams      │───▶│ (ML + Rules + MITRE)│
│ (pcap)   │    │              │    │                     │
└──────────┘    └──────────────┘    └─────────┬───────────┘
                                              │
                                              ▼
┌──────────┐    ┌──────────────┐    ┌─────────────────────┐
│ React    │◀───│ Socket.io    │◀───│ Alert Stream        │
│ Dashboard│    │ WebSocket    │    │ (sentinelhunt:alerts)│
└──────────┘    └──────────────┘    └─────────────────────┘
                                              │
                                    ┌─────────┴───────────┐
                                    │  Threat Intel        │
                                    │  (VT/AbuseIPDB/      │
                                    │   Shodan/OSINT)      │
                                    └─────────────────────┘
```

### Components

| Component | Language | Description |
|-----------|----------|-------------|
| **Packet Collector** | Go | High-performance pcap capture → Redis Streams |
| **Real-Time Scorer** | Python | Ensemble ML + 8 detection rules + MITRE mapping |
| **ML Engine** | Python/PyTorch | Autoencoder, LSTM, IForest, LOF, OneClassSVM |
| **Detection Rules** | Python | DGA, lateral movement, exfil, credential abuse, JA3, protocol anomaly |
| **MITRE Mapper** | Python | Auto ATT&CK enrichment + Navigator layer export |
| **Threat Intel** | Python | VirusTotal, AbuseIPDB, Shodan, IOC DB (STIX 2.1) |
| **API Server** | Node.js | REST + WebSocket (Socket.io), JWT auth, rate limiting |
| **Dashboard** | React/TS | Real-time SOC interface with investigation workflows |
| **Explainability** | Python | SHAP feature attribution + human-readable narratives |

---

## ✨ Key Features

### 🤖 ML Ensemble (5 Models)
- **Autoencoder** — Deep reconstruction error for anomaly detection (PyTorch)
- **LSTM** — Temporal sequence modeling for beaconing patterns
- **Isolation Forest** — Tree-based unsupervised outlier detection
- **Local Outlier Factor** — Density-based local anomaly scoring
- **One-Class SVM** — Boundary-based novelty detection

### 🔍 8 Detection Rules
- Port scanning · DNS tunneling/DGA · JA3 TLS fingerprinting · Lateral movement (RDP/SMB)
- Protocol anomaly · Credential brute force · Data exfiltration · C2 beaconing

### ⬡ MITRE ATT&CK Integration
- Automated technique mapping (20+ techniques across 7 tactics)
- ATT&CK Navigator layer export
- Per-alert investigation guidance

### 🌐 Threat Intelligence
- **APIs:** VirusTotal, AbuseIPDB, Shodan
- **OSINT Feeds:** alienvault, abuse.ch, emerging threats, etc.
- **IOC Database:** SQLite-backed with STIX 2.1 import/export

### 🧠 Explainable AI
- SHAP-based feature attribution (global + per-alert)
- Human-readable threat narratives for SOC analysts
- Feature importance visualizations

---

## 🚀 Quick Start

### Option 1: Docker (Recommended)

```bash
# Clone and start all services
git clone https://github.com/your-org/SentinelHunt.git
cd SentinelHunt

# Copy environment config
cp .env.example .env
# Edit .env with your API keys (optional)

# Launch platform (5 services)
docker-compose up -d

# Dashboard: http://localhost:3000
# API:       http://localhost:5000
# Redis:     localhost:6379
```

### Option 2: Manual Setup

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Install Node.js dependencies
cd dashboard/backend && npm install && cd ../..
cd dashboard/frontend && npm install && cd ../..

# 3. Install Go dependencies
cd collector && go mod download && cd ..

# 4. Start Redis
docker run -d -p 6379:6379 redis:7-alpine

# 5. Start API backend
cd dashboard/backend && npm start &

# 6. Start dashboard
cd dashboard/frontend && npm start &

# 7. Train ML models
python -m ml.training_pipeline --ensemble

# 8. Start real-time scorer
python -m streaming.realtime_scorer &

# 9. (Optional) Run demo traffic simulator
python -m streaming.demo_simulator --rate 10
```

### Demo Mode (No Real Traffic Needed)

```bash
# Start Redis + API + Dashboard, then:
python -m streaming.demo_simulator --rate 5 --duration 120

# Generates realistic benign + attack flows (85/15 mix):
# Port scans, DNS tunnels, lateral movement, exfiltration, brute force
```

### Default Credentials

| Username | Password | Role |
|----------|----------|------|
| `analyst` | `sentinelhunt2026` | SOC Analyst |
| `admin` | `sentineladmin` | Administrator |

---

## 📊 Detection Capabilities

### Attack Types Detected

| Attack | Detection Method | MITRE Technique |
|--------|-----------------|-----------------|
| Port Scanning | Destination port count heuristic + ML | T1046 |
| DNS Tunneling | Entropy + subdomain depth + query length | T1071.004 |
| DGA Beaconing | Bigram entropy analysis + ML | T1568.002 |
| Lateral Movement | Internal-to-internal on admin ports | T1021 |
| Data Exfiltration | Volume + rate threshold + ML | T1041, T1048 |
| Credential Brute Force | Connection frequency + failure patterns | T1110 |
| Protocol Anomaly | Port-service mismatch detection | T1571 |
| C2 Communication | Timing regularity + encrypted traffic | T1573.002 |

### ML Model Ensemble

```
                    IsolationForest (25%)
                           │
Input → Feature    →   Autoencoder (30%)   → Weighted  → Final
        Engineering      │                    Voting      Score
                      LOF (20%)              │
                           │            ─────┘
                    OneClassSVM (25%)
```

Each model scores flows independently. The ensemble combines scores using
calibrated weights to minimize false positives while maximizing detection.

---

## 🧪 Testing

```bash
# Run full test suite
pytest tests/ -v --tb=short

# Run with coverage
pytest tests/ --cov=detection_engine --cov=ml --cov=streaming -v

# Run specific test module
pytest tests/test_detection_rules.py -v
pytest tests/test_ml_models.py -v
pytest tests/test_api_endpoints.py -v
```

### Benchmarking

```bash
# Run against standard IDS datasets (CIC-IDS2017)
python -m experiments.benchmark_runner

# Adversarial robustness testing
python -c "
from ml.adversarial_robustness import AdversarialTester
# See experiments/ for full usage
"
```

---

## 📁 Project Structure

```
SentinelHunt/
├── collector/                  # Go packet collector
│   ├── main.go                 # Entry point + packet processing
│   ├── flow_tracker.go         # Flow aggregation + feature extraction
│   ├── redis_publisher.go      # Redis Streams integration
│   └── config.yaml             # Collector configuration
├── ml/                         # Machine learning engine
│   ├── models/
│   │   ├── autoencoder.py      # Deep autoencoder (PyTorch)
│   │   ├── lstm_detector.py    # LSTM sequence detector
│   │   └── ensemble.py         # 4-model ensemble system
│   ├── training_pipeline.py    # Production training pipeline
│   └── adversarial_robustness.py  # Adversarial attack testing
├── detection_engine/           # Detection logic
│   ├── rules/                  # 8 behavioral detection rules
│   ├── scoring/                # Threat scoring + severity
│   ├── intelligence/           # Campaign detection + timelines
│   └── mitre_mapping.py        # ATT&CK technique mapper
├── streaming/                  # Real-time pipeline
│   ├── redis_broker.py         # Redis Streams pub/sub
│   ├── realtime_scorer.py      # Live flow scoring engine
│   ├── demo_simulator.py       # Demo traffic generator
│   └── config.py               # Centralized configuration
├── threat_intel/               # Threat intelligence
│   ├── enrichment.py           # VT/AbuseIPDB/Shodan client
│   ├── ioc_manager.py          # IOC database (STIX 2.1)
│   └── feed_ingester.py        # OSINT feed pipeline
├── dashboard/
│   ├── backend/                # Express + Socket.io API
│   └── frontend/               # React + TypeScript SOC UI
├── explainability/             # SHAP + narratives
├── experiments/                # Benchmarking + evaluation
├── tests/                      # pytest test suite
├── docker-compose.yml          # 5-service deployment
├── config.yaml                 # Platform-wide configuration
├── .env.example                # Environment variable template
└── requirements.txt            # Python dependencies
```

---

## 🔧 Configuration

All settings are controlled via `config.yaml` and environment variables:

```yaml
# config.yaml — key settings
ml:
  ensemble_threshold: 0.5       # Anomaly threshold
  iforest_n_estimators: 200     # IForest trees
detection:
  port_scan_threshold: 20       # Min ports for scan detection
  dns_entropy_threshold: 3.5    # DGA entropy cutoff
redis:
  host: localhost
  flow_stream: sentinelhunt:flows
  alert_stream: sentinelhunt:alerts
```

See `.env.example` for API keys and secrets.

---

## 🐳 Docker Deployment

```bash
docker-compose up -d

# Services:
#   redis        — Message broker (port 6379)
#   ml-engine    — Python ML scorer
#   api-server   — Node.js REST + WebSocket (port 5000)
#   dashboard    — React frontend (port 3000)
#   collector    — Go packet capture
```

---

## 📚 References

- CIC-IDS2017 Dataset — Canadian Institute for Cybersecurity
- MITRE ATT&CK Framework — https://attack.mitre.org
- SHAP (SHapley Additive exPlanations) — Lundberg & Lee, 2017
- Isolation Forest — Liu, Ting & Zhou, 2008

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
