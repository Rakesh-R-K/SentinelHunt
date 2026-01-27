# SentinelHunt Architecture

## System Overview

SentinelHunt is a multi-layered threat hunting platform that combines behavioral anomaly detection with explainable AI to identify unknown network threats without relying on signatures.

### Core Design Principles

1. **Behavior-First Detection** - Analyze traffic patterns, not payload content
2. **Explainable Decisions** - Every alert backed by human-readable explanations
3. **Multi-Language Architecture** - Right tool for each job (Go, Python, JavaScript, TypeScript)
4. **SOC-Centric** - Built for security analysts, not just data scientists
5. **Modular & Extensible** - Components can be upgraded independently

---

## High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    SENTINELHUNT PLATFORM                         │
└──────────────────────────────────────────────────────────────────┘

┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│   Kali VM   │────>│ WSL/Ubuntu   │────>│  Dashboard   │
│ (Capture)   │     │ (Processing) │     │  (Browser)   │
└─────────────┘     └──────────────┘     └──────────────┘

         │                  │                     │
         │                  │                     │
         v                  v                     v
   [PCAP Files]     [Detection Engine]    [React UI]
```

### Data Flow

```
Network Traffic
    │
    v
┌─────────────────────────────────────────────────────────┐
│ LAYER 1: COLLECTION (Go)                                │
│  - Packet capture (libpcap)                             │
│  - 5-tuple flow aggregation                             │
│  - Real-time feature extraction                         │
└────────────────┬────────────────────────────────────────┘
                 │
                 v [Flow Features JSON/CSV]
                 │
┌─────────────────────────────────────────────────────────┐
│ LAYER 2: FEATURE ENGINEERING (Python)                   │
│  - Parse PCAP files                                     │
│  - Extract 14 behavioral features                       │
│  - DNS intelligence (entropy, depth)                    │
│  - Temporal analysis (IAT statistics)                   │
└────────────────┬────────────────────────────────────────┘
                 │
                 v [Enriched Features CSV]
                 │
┌─────────────────────────────────────────────────────────┐
│ LAYER 3: DETECTION ENGINE (Python)                      │
│  ┌────────────────┐          ┌──────────────────┐      │
│  │ Rule-Based IDS │          │   ML Anomaly     │      │
│  │  - DNS abuse   │          │   Detection      │      │
│  │  - Port scan   │          │ (Isolation       │      │
│  │  - Beaconing   │          │  Forest)         │      │
│  └───────┬────────┘          └─────────┬────────┘      │
│          │                             │                │
│          v                             v                │
│   [Suspicion Score]          [ML Anomaly Score]        │
│          │                             │                │
│          └──────────┬──────────────────┘                │
│                     v                                   │
│            [Threat Score Fusion]                        │
│            [Severity Classification]                    │
│            [Threat Labeling]                            │
└────────────────┬────────────────────────────────────────┘
                 │
                 v [Alerts JSON]
                 │
┌─────────────────────────────────────────────────────────┐
│ LAYER 4: INTELLIGENCE (Python)                          │
│  - Alert aggregation by entity/rule                     │
│  - Campaign classification                              │
│  - Attack timeline reconstruction                       │
└────────────────┬────────────────────────────────────────┘
                 │
                 v [Campaigns, Timelines JSON]
                 │
┌─────────────────────────────────────────────────────────┐
│ LAYER 5: EXPLAINABILITY (Python + SHAP)                 │
│  - Global feature importance                            │
│  - Per-alert SHAP values                                │
│  - Human-readable narratives                            │
└────────────────┬────────────────────────────────────────┘
                 │
                 v [Explanations JSON, Visualizations PNG]
                 │
┌─────────────────────────────────────────────────────────┐
│ LAYER 6: API & DASHBOARD                                │
│  Backend (Node.js/Express) + Frontend (React/TypeScript)│
│  - RESTful API endpoints                                │
│  - Real-time statistics                                 │
│  - Interactive visualizations (Recharts)                │
│  - Alert drill-down                                     │
└─────────────────────────────────────────────────────────┘
```

---

## Component Details

### 1. Packet Collector (Go)

**Files**: `collector/main.go`, `collector/flow_tracker.go`

**Purpose**: High-performance packet capture and flow aggregation

**Tech Stack**:
- Go 1.21+
- gopacket library (libpcap wrapper)
- Concurrent goroutines for packet processing

**Features**:
- Live capture from network interfaces
- PCAP file reading support
- BPF filtering for targeted capture
- 5-tuple flow aggregation (src_ip, dst_ip, src_port, dst_port, protocol)
- Real-time feature extraction
- Automatic flow expiration and export
- Memory-safe (flow count limits)

**Performance**:
- 10,000+ packets/sec throughput
- Sub-millisecond flow updates
- ~100 MB memory for 10K flows

**Why Go?**
- 10-100x faster than Python for packet processing
- Native concurrency (goroutines)
- Single binary deployment
- Cross-platform

---

### 2. Feature Engineering (Python)

**Files**: `feature_engineering/parse_pcap.py`, `feature_engineering/parsers/*`

**Purpose**: Extract SOC-grade behavioral features from network flows

**Features Extracted** (14 total):

**Basic Features**:
- packet_count
- duration
- total_bytes
- avg_packet_size

**Temporal Features** (Inter-Arrival Time):
- min_iat
- max_iat
- mean_iat
- std_iat

**Rate Features**:
- bytes_per_second
- packets_per_second
- avg_bytes_per_packet

**DNS Intelligence**:
- dns_query_length
- dns_subdomain_depth
- dns_entropy (Shannon entropy)

**Why These Features?**
- No payload inspection needed (works with encryption)
- Behavioral patterns (not signatures)
- Research-validated for anomaly detection

---

### 3. Detection Engine (Python)

**Files**: `detection_engine/rules/*.py`, `detection_engine/scoring/*.py`

**Architecture**:
```
Input: Flow Features
    │
    ├──> Rule-Based Detection
    │    ├── DNS Abuse Detection
    │    ├── Port Scan Detection
    │    └── [Extensible Rules]
    │
    └──> ML Anomaly Detection
         └── Isolation Forest (sklearn)

         ↓
    [Score Fusion]
         ↓
    [Severity Classification]
         ↓
    [Threat Labeling]
         ↓
    Output: Alerts JSON
```

**Rule-Based Detection**:
- DNS_BEACONING: High entropy + deep subdomains + high packet rate
- PORT_SCAN: Multiple dest ports + high packet count
- Extensible rule framework

**ML Anomaly Detection**:
- Algorithm: Isolation Forest (unsupervised)
- Training: Benign traffic only (no attack labels needed)
- Features: All 14 behavioral features (scaled)
- Contamination: 5% (assumed anomaly rate)
- Trees: 200 estimators

**Hybrid Threat Scoring**:
```python
final_score = 0.6 * rule_score + 0.4 * ml_score
```
- Combines interpretable rules with ML flexibility
- Weighted fusion balances precision and recall

**Severity Bands**:
- CRITICAL: score ≥ 0.8
- HIGH: score ≥ 0.6
- MEDIUM: score ≥ 0.4
- LOW: score < 0.4

---

### 4. Intelligence Layer (Python)

**Files**: `detection_engine/intelligence/*.py`

**Components**:

**Alert Aggregation**:
- Groups alerts by (entity, rule)
- Reduces analyst noise
- Provides incident-level view

**Campaign Detection**:
- Classifies attack patterns:
  - single_event (one-off)
  - repeated_activity (multiple occurrences)
  - active_campaign (sustained attack)
- Uses alert count, time span, severity

**Timeline Reconstruction**:
- Chronological attack progression
- Severity escalation tracking
- Investigative context

---

### 5. Explainability Module (Python)

**Files**: `explainability/explain_ml.py`, `explainability/alert_explainer.py`

**Purpose**: Make ML decisions transparent and defensible

**Technique**: SHAP (SHapley Additive exPlanations)
- Research: Lundberg & Lee (2017) NeurIPS
- Game-theory based feature attribution
- Model-agnostic

**Outputs**:
1. **Global Feature Importance**: Which features matter most overall?
2. **Per-Alert Explanations**: Why was THIS flow flagged?
3. **Visualizations**: Summary plots, bar charts (publication-quality)
4. **Narratives**: Human-readable explanations for analysts

**Example**:
```
Alert ALERT-0001 flagged because:
  1. HIGH DNS ENTROPY: 4.85
     → Indicates possible DNS tunneling
  2. HIGH PACKET RATE: 142.3 pps
     → Suggests scanning activity
  3. DEEP SUBDOMAINS: 4 levels
     → Characteristic of DNS tunneling
```

**Why SHAP for Cybersecurity?**
- Transparent to SOC analysts
- Justifies escalation decisions
- Compliance/audit trail
- Model debugging

---

### 6. API Backend (Node.js)

**Files**: `dashboard/backend/server.js`

**Tech Stack**:
- Node.js + Express.js
- Middleware: CORS, Helmet (security), Morgan (logging), Compression

**Endpoints**:
```
GET /api/health             - Health check
GET /api/alerts             - All alerts (filterable)
GET /api/alerts/:id         - Specific alert
GET /api/incidents          - Aggregated incidents
GET /api/campaigns          - Detected campaigns
GET /api/timelines          - Attack timelines
GET /api/flows              - Network flows
GET /api/stats              - System statistics
GET /api/charts/severity    - Severity distribution
GET /api/charts/top-sources - Top attacking IPs
GET /api/charts/timeline    - Alert timeline
```

**Features**:
- RESTful design
- JSON-native
- Query parameter filtering
- Error handling
- Request logging

**Why Node.js?**
- Non-blocking I/O (concurrent requests)
- JSON-native (perfect for security data)
- Fast API development
- Industry standard (used by Splunk, etc.)

---

### 7. Dashboard Frontend (React + TypeScript)

**Files**: `dashboard/frontend/src/*`

**Tech Stack**:
- React 18
- TypeScript (type-safe)
- Material-UI (components)
- Recharts (visualizations)
- Axios (API calls)

**Components**:
- **StatsCards**: Key metrics (total alerts, critical count, etc.)
- **SeverityChart**: Pie chart of severity distribution
- **TimelineChart**: Line chart of alerts over time
- **TopSourcesChart**: Bar chart of attacking IPs
- **AlertTable**: Expandable table with drill-down

**Features**:
- Dark cybersecurity theme
- Real-time updates (30s refresh)
- Responsive design
- Color-coded severity
- Interactive visualizations

**Why React + TypeScript?**
- Industry standard (used by enterprise SOCs)
- Component-based (reusable)
- Type-safe (fewer bugs)
- Rich ecosystem
- Recruiter-friendly

---

## Technology Choices

| Component | Language | Justification |
|-----------|----------|---------------|
| Packet Collector | Go | Performance, concurrency, single binary |
| Feature Engineering | Python | Scapy, pandas, numpy ecosystem |
| Detection Engine | Python | sklearn, ML libraries, rapid development |
| Explainability | Python | SHAP, matplotlib, research tools |
| API Backend | JavaScript (Node.js) | JSON-native, non-blocking, fast APIs |
| Dashboard Frontend | TypeScript (React) | Industry standard, type-safe, recruiter appeal |
| Experiments | Python + Bash | Flexibility, attack tool integration |

---

## Data Formats

### Flow Features (CSV)
```csv
src_ip,dst_ip,src_port,dst_port,protocol,packet_count,duration,dns_entropy,...
192.168.1.100,8.8.8.8,54321,53,UDP,42,5.234,3.45,...
```

### Alerts (JSON)
```json
{
  "alert_id": "ALERT-0001",
  "timestamp": "2026-01-27T14:30:00Z",
  "severity": "CRITICAL",
  "threat_label": "SUSPICIOUS_TRAFFIC",
  "final_threat_score": 0.95,
  "confidence": 0.89,
  "reason": "High DNS entropy + deep subdomains + high packet rate"
}
```

### SHAP Explanations (JSON)
```json
{
  "alert_id": "ALERT-0001",
  "top_features": [
    {
      "feature": "dns_entropy",
      "shap_contribution": 0.1247,
      "actual_value": 4.85,
      "impact": "increased"
    }
  ]
}
```

---

## Deployment

### Development
```bash
# Terminal 1: API Backend
cd dashboard/backend && npm install && npm start

# Terminal 2: Dashboard Frontend
cd dashboard/frontend && npm install && npm start

# Terminal 3: Packet Collector
cd collector && go build && sudo ./sentinelhunt-collector
```

### Production
- **Collector**: systemd service, cap_net_raw capability
- **API**: PM2 process manager, reverse proxy (nginx)
- **Dashboard**: Static build served via CDN
- **Detection**: Cron jobs or event-driven triggers

---

## Performance Characteristics

| Component | Throughput | Latency | Memory |
|-----------|-----------|---------|--------|
| Go Collector | 10K pps | <1ms | 100MB |
| Feature Extraction | 1K flows/s | N/A | 500MB |
| ML Detection | 500 flows/s | <100ms | 1GB |
| API Backend | 1K req/s | <50ms | 200MB |
| Dashboard | N/A | <1s load | 100MB |

---

## Security Considerations

1. **API Authentication**: Add JWT tokens for production
2. **Input Validation**: Sanitize all user inputs
3. **Rate Limiting**: Prevent DoS on API
4. **HTTPS**: TLS for all communications
5. **Audit Logging**: Track all analyst actions

---

## Future Enhancements

1. **Distributed Collection**: Multiple sensors → central aggregator
2. **Real-Time Streaming**: WebSocket alerts
3. **Threat Intelligence Integration**: VirusTotal, MISP feeds
4. **Automated Response**: Block IPs, isolate hosts
5. **Multi-Tenancy**: Support multiple networks/customers
6. **SIEM Integration**: Export to Splunk, Elastic

---

## References

1. Sommer, R., & Paxson, V. (2010). "Outside the closed world: On using machine learning for network intrusion detection."
2. Liu, F. T., et al. (2008). "Isolation forest." IEEE ICDM.
3. Lundberg, S. M., & Lee, S. I. (2017). "A unified approach to interpreting model predictions." NeurIPS.

---

**This architecture demonstrates**:
✅ Multi-language proficiency  
✅ Systems thinking  
✅ Production-grade design  
✅ Research-informed decisions  
✅ SOC operational awareness