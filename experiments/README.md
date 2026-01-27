# SentinelHunt Experiments & Evaluation

Rigorous testing, attack simulation, and performance measurement.

## Overview

This module provides:
1. **Attack Simulation** - Realistic threat scenarios
2. **Ground Truth Labeling** - Known attack/benign classification
3. **Performance Evaluation** - Detection rate metrics
4. **Comparative Analysis** - Rule-based vs ML detection

## Directory Structure

```
experiments/
├── attack_scenarios/       # Attack simulation scripts
│   ├── port_scan.sh
│   ├── dns_tunnel.py
│   ├── beaconing.py
│   └── exfiltration.py
├── evaluation.py           # Metrics calculation
├── ground_truth.json       # Attack labels
└── results/                # Evaluation outputs
    ├── evaluation_metrics.json
    ├── confusion_matrix.png
    └── metrics_bar_chart.png
```

## Quick Start

### 1. Run Attack Simulations

```bash
cd attack_scenarios/

# Port scan
sudo ./port_scan.sh

# DNS tunneling
python3 dns_tunnel.py

# C2 beaconing
python3 beaconing.py

# Data exfiltration
python3 exfiltration.py
```

### 2. Process Attack PCAPs

```bash
cd ../feature_engineering/
python3 parse_pcap.py --pcap ../datasets/raw/attack/dns_tunnel_attack.pcap
```

### 3. Run Detection

```bash
# Existing detection pipeline
cd ../detection_engine/
python3 detect_all.py
```

### 4. Evaluate Performance

```bash
cd ../experiments/
python3 evaluation.py
```

## Evaluation Metrics

### Confusion Matrix

|                | Predicted Benign | Predicted Malicious |
|----------------|------------------|---------------------|
| **Actual Benign**    | TN (True Negative)  | FP (False Positive) |
| **Actual Malicious** | FN (False Negative) | TP (True Positive)  |

### Key Metrics

- **Accuracy** = (TP + TN) / Total
- **Precision** = TP / (TP + FP) - "When we flag, how often correct?"
- **Recall (TPR)** = TP / (TP + FN) - "How many attacks do we catch?"
- **F1 Score** = 2 × (Precision × Recall) / (Precision + Recall)
- **False Positive Rate** = FP / (FP + TN) - "How often do we cry wolf?"
- **Specificity (TNR)** = TN / (TN + FP) - "How good at recognizing benign?"

## Expected Results

Based on benign + attack mix:

| Metric | Target | Actual (Your System) |
|--------|--------|----------------------|
| Recall (Detection Rate) | >85% | ? |
| Precision | >80% | ? |
| F1 Score | >80% | ? |
| False Positive Rate | <10% | ? |
| Accuracy | >90% | ? |

## Outputs

### 1. evaluation_metrics.json
```json
{
  "confusion_matrix": {
    "true_negatives": 2345,
    "false_positives": 45,
    "false_negatives": 12,
    "true_positives": 98
  },
  "performance_metrics": {
    "accuracy": 0.9772,
    "precision": 0.6853,
    "recall": 0.8909,
    "f1_score": 0.7750,
    "fpr": 0.0188
  }
}
```

### 2. Visualizations
- **confusion_matrix.png** - Heatmap of detection accuracy
- **metrics_bar_chart.png** - Performance metrics comparison
- **score_distributions.png** - Threat score histograms

## Research-Grade Evaluation

### Baseline Comparison

Compare SentinelHunt against:
1. **Pure rule-based IDS** (Snort/Suricata)
2. **Pure ML anomaly detection** (Isolation Forest only)
3. **Hybrid approach** (SentinelHunt)

### Statistical Significance

For capstone rigor, report:
- **95% confidence intervals** on metrics
- **Cross-validation** results (if multiple attack samples)
- **ROC curves** for different thresholds
- **Precision-Recall curves**

## Validation Workflow

```
┌─────────────────┐
│ Capture Normal  │
│ Traffic (Days)  │
└────────┬────────┘
         │
         v
┌─────────────────┐     ┌──────────────────┐
│ Train Baseline  │────>│ Establish Normal │
│ (Benign Only)   │     │ Behavior Profile │
└─────────────────┘     └──────────────────┘
                                 │
         ┌───────────────────────┘
         v
┌─────────────────┐     ┌──────────────────┐
│ Run Attack      │────>│ Capture Attack   │
│ Simulations     │     │ PCAPs            │
└─────────────────┘     └────────┬─────────┘
                                 │
                                 v
                        ┌──────────────────┐
                        │ Run Detection    │
                        │ Pipeline         │
                        └────────┬─────────┘
                                 │
                                 v
                        ┌──────────────────┐
                        │ Compare Against  │
                        │ Ground Truth     │
                        └────────┬─────────┘
                                 │
                                 v
                        ┌──────────────────┐
                        │ Calculate        │
                        │ Metrics          │
                        └──────────────────┘
```

## Advanced Experiments

### 1. Threshold Tuning
```python
for threshold in [0.4, 0.5, 0.6, 0.7, 0.8]:
    metrics = evaluate_at_threshold(threshold)
    plot_precision_recall_curve()
```

### 2. Feature Ablation
Test impact of removing individual features:
```python
for feature in FEATURE_COLUMNS:
    metrics = evaluate_without_feature(feature)
    print(f"{feature}: {metrics['recall']:.3f}")
```

### 3. Time-Series Analysis
Measure detection latency:
- Time from attack start to first alert
- Alert aggregation effectiveness

## Capstone Value

✅ Demonstrates scientific rigor  
✅ Provides quantitative results  
✅ Shows understanding of ML evaluation  
✅ Enables comparison with related work  
✅ Publication-ready visualizations  
✅ Defensible methodology

## Common Pitfalls

❌ **Overfitting**: Training and testing on same data  
✓ Solution: Separate capture periods for train/test

❌ **Label Leakage**: Using attack info during training  
✓ Solution: Only benign data for baseline, attacks for testing

❌ **Imbalanced Classes**: 99% benign, 1% malicious  
✓ Solution: Use F1 score, not just accuracy

## Next Steps

After evaluation:
1. Analyze false positives - What benign traffic triggered alerts?
2. Analyze false negatives - Which attacks were missed? Why?
3. Feature importance - Which features matter most?
4. Tune threshold - Balance precision vs recall
5. Compare with literature - How do your results stack up?

## References

1. Tavallaee, M., et al. (2009). "A detailed analysis of the KDD CUP 99 data set."
2. Ring, M., et al. (2019). "A survey of network-based intrusion detection data sets."
3. Sommer, R., & Paxson, V. (2010). "Outside the closed world: On using machine learning for network intrusion detection."

## License

Part of SentinelHunt - AI-Assisted Threat Hunting Platform
