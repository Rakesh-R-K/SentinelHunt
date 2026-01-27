"""
SentinelHunt Explainability Module

Purpose:
- Add SHAP (SHapley Additive exPlanations) for ML interpretability
- Explain why specific flows were flagged as anomalous
- Provide feature importance for the Isolation Forest model
- Generate analyst-friendly explanations

Research Basis:
- Lundberg & Lee (2017) - "A Unified Approach to Interpreting Model Predictions"
- Explainable AI for cybersecurity decision-making
"""

import pandas as pd
import numpy as np
import joblib
import shap
import json
import matplotlib.pyplot as plt
from pathlib import Path

# ========================================
# CONFIGURATION
# ========================================
MODEL_FILE = "../ml/models/iforest_model.pkl"
SCALER_FILE = "../ml/models/scaler.pkl"
FLOWS_FILE = "../feature_engineering/outputs/flow_features_enriched.csv"
ALERTS_FILE = "../feature_engineering/outputs/alerts.json"
OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)

FEATURE_COLUMNS = [
    "packet_count",
    "duration",
    "total_bytes",
    "avg_packet_size",
    "min_iat",
    "max_iat",
    "mean_iat",
    "std_iat",
    "bytes_per_second",
    "packets_per_second",
    "avg_bytes_per_packet",
    "dns_query_length",
    "dns_subdomain_depth",
    "dns_entropy"
]

# ========================================
# LOAD DATA & MODELS
# ========================================
print("[+] Loading models and data...")

# Load trained models
iforest_model = joblib.load(MODEL_FILE)
scaler = joblib.load(SCALER_FILE)

# Load flow data
flows_df = pd.read_csv(FLOWS_FILE)
X = flows_df[FEATURE_COLUMNS]
X_scaled = scaler.transform(X)

# Load alerts for context
with open(ALERTS_FILE, 'r') as f:
    alerts = json.load(f)

print(f"[+] Loaded {len(flows_df)} flows")
print(f"[+] Loaded {len(alerts)} alerts")

# ========================================
# GLOBAL FEATURE IMPORTANCE
# ========================================
print("\n[+] Calculating global feature importance with SHAP...")

# Create SHAP explainer for Isolation Forest
# Note: For Isolation Forest, we use TreeExplainer
explainer = shap.TreeExplainer(iforest_model)

# Calculate SHAP values for all flows (sample for speed)
sample_size = min(500, len(X_scaled))
sample_indices = np.random.choice(len(X_scaled), sample_size, replace=False)
X_sample = X_scaled[sample_indices]

shap_values = explainer.shap_values(X_sample)

# ========================================
# FEATURE IMPORTANCE SUMMARY
# ========================================
print("\n[+] Global Feature Importance (Mean |SHAP|):")
print("=" * 60)

mean_abs_shap = np.abs(shap_values).mean(axis=0)
feature_importance = pd.DataFrame({
    'feature': FEATURE_COLUMNS,
    'importance': mean_abs_shap
}).sort_values('importance', ascending=False)

for idx, row in feature_importance.iterrows():
    print(f"  {row['feature']:<25} {row['importance']:.6f}")

# Save feature importance
feature_importance.to_csv(OUTPUT_DIR / "feature_importance.csv", index=False)
print(f"\n[+] Feature importance saved to {OUTPUT_DIR / 'feature_importance.csv'}")

# ========================================
# VISUALIZATIONS
# ========================================
print("\n[+] Generating SHAP visualizations...")

# Summary plot (beeswarm)
plt.figure(figsize=(10, 8))
shap.summary_plot(
    shap_values, 
    pd.DataFrame(X_sample, columns=FEATURE_COLUMNS),
    show=False
)
plt.tight_layout()
plt.savefig(OUTPUT_DIR / "shap_summary_plot.png", dpi=150, bbox_inches='tight')
plt.close()
print(f"[+] Summary plot saved to {OUTPUT_DIR / 'shap_summary_plot.png'}")

# Feature importance bar plot
plt.figure(figsize=(10, 6))
shap.summary_plot(
    shap_values,
    pd.DataFrame(X_sample, columns=FEATURE_COLUMNS),
    plot_type="bar",
    show=False
)
plt.tight_layout()
plt.savefig(OUTPUT_DIR / "shap_bar_plot.png", dpi=150, bbox_inches='tight')
plt.close()
print(f"[+] Bar plot saved to {OUTPUT_DIR / 'shap_bar_plot.png'}")

# ========================================
# PER-ALERT EXPLANATIONS
# ========================================
print("\n[+] Generating per-alert explanations...")

alert_explanations = []

# Get top 10 critical alerts
critical_alerts = [a for a in alerts if a['severity'] == 'CRITICAL'][:10]

for alert in critical_alerts:
    # Find matching flow in dataset
    src_ip = alert['src_ip']
    dst_ip = alert['dst_ip']
    
    # Find flow (simple matching - in production, use alert_id mapping)
    matching_flows = flows_df[
        (flows_df['src_ip'] == src_ip) & 
        (flows_df['dst_ip'] == dst_ip)
    ]
    
    if matching_flows.empty:
        continue
    
    flow_idx = matching_flows.index[0]
    flow_features = X_scaled[flow_idx:flow_idx+1]
    
    # Calculate SHAP values for this specific flow
    shap_values_single = explainer.shap_values(flow_features)[0]
    
    # Get top 5 contributing features
    feature_contributions = pd.DataFrame({
        'feature': FEATURE_COLUMNS,
        'shap_value': shap_values_single,
        'actual_value': X.iloc[flow_idx].values
    }).sort_values('shap_value', key=abs, ascending=False).head(5)
    
    # Build human-readable explanation
    explanation = {
        'alert_id': alert['alert_id'],
        'severity': alert['severity'],
        'threat_label': alert['threat_label'],
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'ml_score': alert['final_threat_score'],
        'top_features': []
    }
    
    for _, row in feature_contributions.iterrows():
        explanation['top_features'].append({
            'feature': row['feature'],
            'shap_contribution': float(row['shap_value']),
            'actual_value': float(row['actual_value']),
            'impact': 'increased' if row['shap_value'] > 0 else 'decreased'
        })
    
    alert_explanations.append(explanation)

# Save per-alert explanations
with open(OUTPUT_DIR / "alert_explanations.json", 'w') as f:
    json.dump(alert_explanations, f, indent=2)

print(f"[+] Alert explanations saved to {OUTPUT_DIR / 'alert_explanations.json'}")
print(f"[+] Generated explanations for {len(alert_explanations)} critical alerts")

# ========================================
# EXPLANATION SUMMARY
# ========================================
print("\n" + "=" * 60)
print("  EXPLAINABILITY ANALYSIS COMPLETE")
print("=" * 60)
print(f"\nTop 3 Most Important Features:")
for idx, row in feature_importance.head(3).iterrows():
    print(f"  {idx+1}. {row['feature']:<25} (importance: {row['importance']:.6f})")

print(f"\nOutputs generated:")
print(f"  - {OUTPUT_DIR / 'feature_importance.csv'}")
print(f"  - {OUTPUT_DIR / 'shap_summary_plot.png'}")
print(f"  - {OUTPUT_DIR / 'shap_bar_plot.png'}")
print(f"  - {OUTPUT_DIR / 'alert_explanations.json'}")

print("\n[+] Use these visualizations in your capstone presentation!")
print("[+] SHAP values provide transparent, defensible explanations for SOC analysts")
