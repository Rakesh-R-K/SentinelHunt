# SentinelHunt Explainability Module

Making machine learning decisions transparent and defensible for SOC analysts.

## Overview

This module implements **SHAP (SHapley Additive exPlanations)** to explain:
- Why the Isolation Forest model flagged specific flows as anomalous
- Which features contributed most to the anomaly score
- How feature values differ from normal behavior

## Research Basis

**SHAP**: Lundberg & Lee (2017) - "A Unified Approach to Interpreting Model Predictions"

SHAP provides:
- **Model-agnostic explanations** based on game theory
- **Consistent feature attribution** across predictions
- **Visualizations** that are intuitive for non-ML experts

## Installation

```bash
pip install shap matplotlib
```

## Usage

### 1. Generate Global Feature Importance

```bash
cd explainability/
python3 explain_ml.py
```

**Outputs:**
- `outputs/feature_importance.csv` - Ranked feature importance
- `outputs/shap_summary_plot.png` - Beeswarm plot
- `outputs/shap_bar_plot.png` - Feature importance bars
- `outputs/alert_explanations.json` - Per-alert SHAP values

### 2. Generate Human-Readable Narratives

```bash
python3 alert_explainer.py
```

**Output:**
- `outputs/alert_narratives.json` - Analyst-friendly explanations

## Example Output

### Feature Importance

```
Top Features (Mean |SHAP|):
  dns_entropy               0.042156
  bytes_per_second          0.038742
  packet_count              0.031845
  dns_subdomain_depth       0.028934
  packets_per_second        0.025123
```

### Per-Alert Explanation

```
🚨 Alert: ALERT-0001 (CRITICAL)
   Threat: SUSPICIOUS_TRAFFIC
   Source: 192.168.118.134 → 192.168.118.2
   ML Threat Score: 1.000

📊 Why This Flow Was Flagged (Top Contributing Factors):

   1. HIGH DNS QUERY RANDOMNESS (ENTROPY): 4.85
      → This feature INCREASED the anomaly score by 0.1247
      💡 High DNS entropy indicates possible DNS tunneling or DGA malware

   2. HIGH PACKET TRANSMISSION RATE: 142.30
      → This feature INCREASED the anomaly score by 0.0923
      💡 Unusually high packet count suggests potential scanning activity

   3. HIGH DATA TRANSFER RATE: 8456.21
      → This feature INCREASED the anomaly score by 0.0712
      💡 High data transfer rate could indicate bulk data exfiltration
```

## Visualizations

### SHAP Summary Plot (Beeswarm)
- Shows feature importance and value distributions
- Red = high feature value, Blue = low feature value
- Horizontal spread = impact on model output

### SHAP Bar Plot
- Global feature importance ranking
- Use in capstone presentation

## Integration with Dashboard

```javascript
// Fetch SHAP explanation for alert
fetch(`/api/alerts/${alertId}/explanation`)
  .then(res => res.json())
  .then(data => displayExplanation(data));
```

## Why SHAP for Cybersecurity?

| Challenge | SHAP Solution |
|-----------|---------------|
| SOC analysts distrust black-box ML | Transparent feature-level explanations |
| Need justification for escalation | Cite specific anomalous behaviors |
| Compliance & audit requirements | Defensible, reproducible explanations |
| Model debugging | Identify which features drive false positives |

## Key Metrics

- **Computation Time**: ~5 seconds for 500 flows
- **Explanation Depth**: Top 5 contributing features per alert
- **Visualization**: PNG exports for reports/presentations

## Capstone Value

✅ Demonstrates understanding of **Explainable AI (XAI)**  
✅ Bridges ML and operational security (SOC workflows)  
✅ Shows research depth (SHAP paper citation)  
✅ Provides publication-quality visualizations  
✅ Differentiates from black-box anomaly detection

## Future Enhancements

- [ ] Interactive SHAP force plots
- [ ] Real-time explanations via API
- [ ] Counterfactual explanations ("What would make this flow benign?")
- [ ] LIME comparison for model-agnostic validation

## References

1. Lundberg, S. M., & Lee, S. I. (2017). A unified approach to interpreting model predictions. *NeurIPS*.
2. Ribeiro, M. T., Singh, S., & Guestrin, C. (2016). "Why Should I Trust You?": Explaining the Predictions of Any Classifier. *KDD*.
3. Molnar, C. (2020). *Interpretable Machine Learning*. https://christophm.github.io/interpretable-ml-book/

## License

Part of SentinelHunt - AI-Assisted Threat Hunting Platform
