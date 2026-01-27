# ❓ SentinelHunt FAQ

Frequently Asked Questions for users, contributors, and interviewers.

---

## 🎓 General Questions

### Q1: What is SentinelHunt?
**A:** SentinelHunt is an AI-assisted network threat hunting platform that detects zero-day attacks using behavioral anomaly detection and explainable AI. Unlike traditional signature-based IDS (Snort, Suricata), SentinelHunt analyzes traffic patterns to identify unknown threats.

---

### Q2: Who is this for?
**A:** 
- **SOC Analysts**: Real-time threat detection and investigation
- **Security Researchers**: Novel anomaly detection framework
- **Students**: Educational tool for IDS concepts
- **SMBs**: Affordable alternative to enterprise IDS
- **Capstone Projects**: Demonstrates full-stack + ML + security skills

---

### Q3: How is this different from Snort/Suricata/Zeek?
**A:**

| Feature | Snort/Suricata | Zeek | SentinelHunt |
|---------|---------------|------|--------------|
| **Detection** | Signature-based | Script-based + Optional ML | Hybrid (Rules + ML) |
| **Zero-Days** | ❌ Misses unknowns | ✅ Catches some | ✅ Designed for unknowns |
| **Explainability** | ✅ High (rules) | 🟡 Medium (scripts) | ✅ High (SHAP) |
| **Campaign Intelligence** | ❌ No | ❌ No | ✅ Yes |
| **Multi-Language** | C | C++ | Go + Python + JS + TS |
| **Encrypted Traffic** | ❌ Requires DPI | ✅ Metadata | ✅ Metadata |

**SentinelHunt complements (not replaces) these tools.** It can ingest Zeek logs as input.

---

### Q4: Is this production-ready?
**A:** **Partially.** Current version (1.0.0) is suitable for:
- ✅ Research and educational environments
- ✅ Lab testing and validation
- ✅ Proof-of-concept deployments
- ✅ Capstone/thesis projects

For production, you need:
- ⚠️ Authentication & authorization (JWT/OAuth2)
- ⚠️ HTTPS/TLS encryption
- ⚠️ Database backend (PostgreSQL)
- ⚠️ Comprehensive logging and monitoring
- ⚠️ Rate limiting and DDoS protection
- ⚠️ Security audit and penetration testing

See [DEVELOPMENT.md](DEVELOPMENT.md#security) for hardening checklist.

---

## 🔬 Technical Questions

### Q5: Why Isolation Forest instead of deep learning?
**A:**
1. **Unsupervised**: No need for labeled attack data
2. **Efficient**: Fast training/inference on commodity hardware
3. **Interpretable**: Works well with SHAP for explainability
4. **Proven**: Widely used for anomaly detection (Liu et al., 2008)

Deep learning (LSTM, Transformers) requires:
- Large labeled datasets (thousands of attacks)
- GPU hardware
- Complex hyperparameter tuning
- Harder to explain (even with SHAP)

**For future work**, we plan to add LSTM for temporal pattern detection.

---

### Q6: How does it handle encrypted traffic?
**A:** SentinelHunt analyzes **metadata**, not payloads:
- Packet sizes and counts
- Inter-arrival times (timing patterns)
- DNS queries (visible before encryption)
- Flow duration and volume

**This works with TLS 1.3** where payloads are fully encrypted. We don't need to decrypt traffic.

**Example**: C2 beaconing can be detected by regular timing patterns, regardless of payload encryption.

---

### Q7: What is the false positive rate?
**A:** In lab environment: **3.2%**

This means:
- Out of 2,415 benign flows, 77 were falsely flagged (mostly MEDIUM/LOW severity)
- Acceptable for SOC environments (analysts can quickly dismiss low-severity alerts)
- Can be reduced by:
  - Tuning detection thresholds
  - Active learning from analyst feedback
  - Adding more features

**Production environments** typically have higher FPR due to diverse legitimate traffic patterns.

---

### Q8: Why 60/40 weight for rule-based vs ML?
**A:** 
- **60% rules**: Prioritizes interpretability and known attack patterns
- **40% ML**: Allows ML to contribute to unknown patterns

This ratio was chosen based on:
1. SOC analyst preference for explainable alerts
2. Empirical testing during development
3. Balance between false positives (too much ML) and false negatives (too much rules)

**Can be tuned** in `detection_engine/scoring/threat_score.py`

---

### Q9: How fast is it?
**A:**

| Component | Performance |
|-----------|-------------|
| **Go Collector** | 10,000+ packets/second |
| **Feature Engineering** | 2,500 flows in ~5 seconds |
| **ML Inference** | < 100ms for 1000 flows |
| **API Response Time** | ~15ms average |
| **Dashboard Load** | < 2 seconds |

**Bottleneck**: PCAP parsing with Scapy (Python). Go collector is 10X faster.

---

### Q10: Can it scale to enterprise networks?
**A:** Not in current form. For enterprise scale, you need:

**Distributed Architecture**:
- Multiple collectors (one per network segment)
- Message queue (Kafka) for flow aggregation
- Centralized ML inference server
- Database backend (TimescaleDB for time-series)
- Load-balanced API servers

**Estimated Scaling**:
- Single-node: ~10K pps, suitable for small networks (<500 hosts)
- Distributed: 100K+ pps, suitable for enterprise (5000+ hosts)

See [CHANGELOG.md](CHANGELOG.md) Roadmap for v2.0.0 scalability features.

---

## 🛠️ Usage Questions

### Q11: What network interfaces are supported?
**A:** Any interface visible to `tcpdump`:
- Ethernet (eth0, enp0s3)
- Wireless (wlan0)
- Virtual (docker0, vboxnet0)
- Loopback (lo)

**Check interfaces**: `ip link show` or `ifconfig`

**Configure in**: `collector/config.yaml`

---

### Q12: Can I use existing PCAP files?
**A:** **Yes!** SentinelHunt works with pre-captured PCAP files:

```bash
cd feature_engineering
python3 parse_pcap.py --input /path/to/your.pcap --output outputs/flow_features.csv
# Continue with detection pipeline...
```

**Supported formats**: .pcap, .pcapng

---

### Q13: How do I add custom detection rules?
**A:**

1. Create new rule file: `detection_engine/rules/my_rule.py`

```python
class MyRuleDetector:
    def __init__(self, threshold):
        self.threshold = threshold
    
    def check(self, flow):
        if flow['some_feature'] > self.threshold:
            return {
                'triggered': True,
                'score': 0.85,
                'reason': 'Explanation here'
            }
        return {'triggered': False}
```

2. Import in `detection_engine/rules/__init__.py`
3. Add to scoring pipeline in `threat_score.py`

See [DEVELOPMENT.md](DEVELOPMENT.md#contributing) for detailed guide.

---

### Q14: Can I retrain the ML model on my data?
**A:** **Yes!**

```bash
cd ml
python3 train_baseline.py --input ../feature_engineering/outputs/my_benign_data.csv
```

**Important**: Training data should be **benign only** (normal traffic). Isolation Forest learns what "normal" looks like.

**Contamination parameter**: Set to expected anomaly rate (default 0.01 = 1%)

---

### Q15: How do I export results?
**A:** Results are already in JSON/CSV format:

**Alerts**: `feature_engineering/outputs/alerts.json`
```json
[
    {
        "alert_id": "ALERT-0001",
        "timestamp": "2024-01-15T10:30:00",
        "source_ip": "192.168.1.100",
        "threat_label": "Port Scan",
        "severity": "HIGH"
    }
]
```

**Campaigns**: `feature_engineering/outputs/campaigns.json`

**SHAP Explanations**: `explainability/outputs/alert_explanations.json`

**For reports**: Load JSON into Python and generate PDF/HTML using libraries like `reportlab` or `jinja2`.

---

## 🔐 Security Questions

### Q16: Is it safe to run the collector as root?
**A:** **Minimally risky, but not ideal.** Packet capture requires root for raw socket access.

**Best practices**:
1. Use Linux capabilities instead of root:
   ```bash
   sudo setcap cap_net_raw,cap_net_admin=eip collector/collector
   ./collector  # No sudo needed
   ```

2. Run in isolated container (Docker)
3. Use dedicated user with minimal permissions
4. Enable SELinux/AppArmor

See [DEVELOPMENT.md](DEVELOPMENT.md#security) for hardening guide.

---

### Q17: Does it store sensitive data?
**A:** **By default, no.** SentinelHunt extracts metadata (not payloads) and stores:
- IP addresses (can be anonymized)
- Port numbers
- Packet counts/sizes
- DNS queries (not responses)

**PCAP files** are not committed to Git (see `.gitignore`).

**For GDPR compliance**:
- Anonymize IPs before storage: `192.168.1.100` → `192.168.xxx.xxx`
- Set data retention policies
- Encrypt outputs at rest
- Document what data is collected

---

### Q18: Can it be exploited by adversaries?
**A:** **Potential attack vectors**:

1. **Adversarial ML**: Attackers craft flows to evade detection
   - **Mitigation**: Adversarial training (planned v1.2.0)

2. **Training Data Poisoning**: Attacker pollutes training data
   - **Mitigation**: Anomaly detection on training data, curated datasets

3. **API Exploitation**: Unauthorized access to threat intelligence
   - **Mitigation**: Authentication (planned v1.1.0), HTTPS, rate limiting

4. **Denial of Service**: Flood with packets to overwhelm collector
   - **Mitigation**: Rate limiting, BPF filtering, resource limits

See [DEVELOPMENT.md](DEVELOPMENT.md#security) for full threat model.

---

## 🎨 Customization Questions

### Q19: Can I change the dashboard theme?
**A:** **Yes!** Edit `dashboard/frontend/src/App.tsx`:

```typescript
const theme = createTheme({
    palette: {
        mode: 'dark',  // Change to 'light'
        primary: { main: '#00bcd4' },  // Change colors
        background: { default: '#0a1929' }  // Change background
    }
});
```

**Material-UI themes**: See [Material-UI documentation](https://mui.com/material-ui/customization/theming/)

---

### Q20: Can I add more charts?
**A:** **Yes!** Create new component in `dashboard/frontend/src/components/`:

**Example**: `TopSourcesChart.tsx`
```typescript
import { BarChart, Bar, XAxis, YAxis } from 'recharts';

export default function TopSourcesChart({ data }) {
    return (
        <BarChart data={data}>
            <XAxis dataKey="source_ip" />
            <YAxis />
            <Bar dataKey="count" fill="#00bcd4" />
        </BarChart>
    );
}
```

Import in `App.tsx` and fetch data from API.

**Recharts documentation**: [recharts.org](https://recharts.org/)

---

## 🎓 Capstone/Academic Questions

### Q21: Is this suitable for a thesis/capstone?
**A:** **Absolutely!** SentinelHunt demonstrates:

✅ **Software Engineering**: Multi-tier architecture, API design, full-stack development  
✅ **Machine Learning**: Feature engineering, model training, evaluation  
✅ **Cybersecurity**: Threat detection, attack simulation, SOC workflows  
✅ **Research**: Literature review, novel contributions, evaluation methodology  
✅ **Documentation**: Comprehensive guides, academic writing  

**Thesis angles**:
- "Explainable AI for Network Intrusion Detection"
- "Hybrid Detection Systems: Rules vs Machine Learning"
- "Campaign Intelligence in Threat Hunting"
- "Behavioral Anomaly Detection for Zero-Day Attacks"

---

### Q22: What are the novel contributions?
**A:** See [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md) Section: Novel Contributions

**Summary**:
1. Systematic hybrid detection fusion (60/40 weighted)
2. Campaign intelligence layer (alert → narrative)
3. SHAP for network anomaly detection (underexplored)
4. Multi-language performance optimization
5. Encrypted traffic capability (metadata-based)

---

### Q23: Where can I find related work?
**A:** See [docs/research_background.md](docs/research_background.md)

**Key papers**:
- Liu et al. (2008): Isolation Forest
- Lundberg & Lee (2017): SHAP
- Sommer & Paxson (2010): ML for IDS challenges
- Denning (1987): Intrusion detection model

**Research gaps addressed**:
- Most IDS lack explainability → We added SHAP
- Most systems are signature or ML only → We use hybrid
- Few systems correlate alerts → We have campaign intelligence

---

### Q24: How do I cite this project?
**A:**

**BibTeX**:
```bibtex
@software{sentinelhunt2024,
    title={SentinelHunt: AI-Assisted Network Threat Hunting Platform},
    author={[Your Name]},
    year={2024},
    url={https://github.com/[your-username]/SentinelHunt},
    note={Version 1.0.0}
}
```

**APA**:
```
[Your Name]. (2024). SentinelHunt: AI-Assisted Network Threat Hunting Platform (Version 1.0.0) [Computer software]. https://github.com/[your-username]/SentinelHunt
```

---

## 💼 Recruiter/Interview Questions

### Q25: What did you learn from this project?
**A:** 

**Technical Skills**:
- Multi-language proficiency (Go, Python, JavaScript, TypeScript)
- Full-stack development (backend API, frontend dashboard)
- Machine learning (unsupervised anomaly detection, SHAP)
- Cybersecurity (threat modeling, attack simulation)

**Soft Skills**:
- Project planning and time management (13-day development)
- Technical documentation and communication
- Problem-solving (debugging performance bottlenecks)
- Research and literature review

**Key Insight**: "Perfect is the enemy of good" → Ship MVP, iterate based on feedback.

---

### Q26: What was the biggest challenge?
**A:** **Performance optimization in Python PCAP parsing.**

**Problem**: Scapy processed ~1,000 packets/second, too slow for real-time capture.

**Solution**: Rewrote collector in Go using `gopacket` library → 10X speedup (10,000+ pps).

**Lesson**: Choose the right tool for the job. Python excels at ML/data science, but Go is better for high-performance network I/O.

---

### Q27: How would you improve this?
**A:** See [CHANGELOG.md](CHANGELOG.md) Roadmap

**Short-term (3 months)**:
- Add authentication (JWT)
- Database backend (PostgreSQL)
- Active learning from analyst feedback

**Long-term (6-12 months)**:
- Deep learning models (LSTM)
- SIEM integration (Splunk, ELK)
- Distributed deployment (Kubernetes)
- Graph-based attack modeling

**Research directions**:
- Adversarial ML robustness
- Zero-shot learning for novel attacks
- Causal inference for attribution

---

### Q28: Can you walk me through the architecture?
**A:** Use [docs/ARCHITECTURE_DIAGRAMS.md](docs/ARCHITECTURE_DIAGRAMS.md)

**High-level**:
1. **Collection (Go)**: Capture packets → Extract flows → Export JSON
2. **Feature Engineering (Python)**: Parse flows → Calculate 14 features → CSV
3. **Detection (Python)**: Rules (60%) + ML (40%) → Fused threat score
4. **Intelligence (Python)**: Aggregate → Detect campaigns → Build timelines
5. **API (Node.js)**: Serve JSON via REST endpoints
6. **Dashboard (React)**: Visualize alerts, campaigns, charts

**Key design principles**:
- Separation of concerns (each layer is independent)
- Performance optimization (Go for speed, Python for ML)
- Modularity (easy to swap components)

---

### Q29: What makes this capstone-level?
**A:**

**Breadth**: Multiple domains (software engineering, ML, cybersecurity)  
**Depth**: Novel contributions (hybrid detection, SHAP integration, campaign intelligence)  
**Complexity**: 9 major subsystems, 5 programming languages  
**Research**: 12+ papers cited, theoretical foundations  
**Engineering**: Production-grade tools (React, Express, Material-UI)  
**Documentation**: 8 comprehensive guides (3,000+ lines)  
**Validation**: Attack simulations, ground truth evaluation (89.8% F1)  

**Not just a "student project"** → Demonstrates industry-ready skills.

---

### Q30: Where can I see the code?
**A:**

**GitHub Repository**: [Link to your repo]

**Key files to review**:
- [README.md](README.md) - Project overview
- [collector/main.go](collector/main.go) - Go packet capture
- [dashboard/frontend/src/App.tsx](dashboard/frontend/src/App.tsx) - React dashboard
- [detection_engine/scoring/threat_score.py](detection_engine/scoring/threat_score.py) - Hybrid fusion
- [explainability/explain_ml.py](explainability/explain_ml.py) - SHAP integration

**Live Demo**: [URL if deployed]

**Demo Video**: [YouTube link if available]

---

## 🤝 Contributing Questions

### Q31: How can I contribute?
**A:** See [DEVELOPMENT.md](DEVELOPMENT.md#contributing)

**Ways to contribute**:
- Report bugs or feature requests (GitHub Issues)
- Submit code fixes or new features (Pull Requests)
- Improve documentation
- Add detection rules for new attack types
- Create attack simulations for validation
- Optimize performance

**Good first issues**:
- Add unit tests for existing code
- Create new dashboard charts
- Implement additional detection rules
- Improve documentation

---

### Q32: What's the development workflow?
**A:**

1. Fork repository
2. Create feature branch: `git checkout -b feature/my-feature`
3. Make changes (follow code style guidelines)
4. Add tests
5. Update documentation
6. Commit: `git commit -m "feat: Add my feature"`
7. Push: `git push origin feature/my-feature`
8. Open Pull Request

**Code review**: Maintainer reviews within 5 business days.

---

## 📞 Support Questions

### Q33: I'm getting an error. Where can I get help?
**A:**

1. **Check documentation**: [DEVELOPMENT.md](DEVELOPMENT.md)
2. **Troubleshooting section**: Common issues and solutions
3. **Search closed issues**: Someone may have encountered the same problem
4. **Open new issue**: Provide error message, system info, reproduction steps
5. **Email**: [Your contact email]

**Response time**: 2-3 business days for issues, 1-2 days for critical bugs.

---

### Q34: Is there a community?
**A:** Currently building! Join:

- **GitHub Discussions**: Ask questions, share ideas
- **Discord/Slack**: Real-time chat (if set up)
- **Email List**: Monthly updates on releases
- **LinkedIn**: [Your LinkedIn profile]

**Future plans**: Monthly community calls, workshops, CTF challenges.

---

### Q35: What's the license?
**A:** **MIT License** (see [LICENSE](LICENSE))

**You are free to**:
- ✅ Use commercially
- ✅ Modify and distribute
- ✅ Use privately
- ✅ Sublicense

**Conditions**:
- Include license and copyright notice
- No warranty provided

**Why MIT?**: Permissive license encourages adoption and contribution.

---

**Don't see your question? Open an issue or email!** 📧
