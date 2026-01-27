"""
Alert Explainer - Human-Readable Threat Explanations

Purpose:
- Convert technical SHAP values into analyst-friendly language
- Provide context-aware explanations based on feature values
- Support SOC analyst investigation workflows
"""

import json
from pathlib import Path
from typing import Dict, List

# ========================================
# EXPLANATION TEMPLATES
# ========================================

FEATURE_DESCRIPTIONS = {
    'packet_count': 'number of packets in the flow',
    'duration': 'flow duration in seconds',
    'total_bytes': 'total bytes transferred',
    'avg_packet_size': 'average packet size',
    'min_iat': 'minimum inter-arrival time',
    'max_iat': 'maximum inter-arrival time',
    'mean_iat': 'average inter-arrival time',
    'std_iat': 'inter-arrival time variability',
    'bytes_per_second': 'data transfer rate',
    'packets_per_second': 'packet transmission rate',
    'avg_bytes_per_packet': 'average bytes per packet',
    'dns_query_length': 'DNS query string length',
    'dns_subdomain_depth': 'DNS subdomain nesting level',
    'dns_entropy': 'DNS query randomness (entropy)'
}

THREAT_PATTERNS = {
    'high_packet_count': 'Unusually high packet count suggests potential scanning or flooding activity',
    'high_dns_entropy': 'High DNS entropy indicates possible DNS tunneling or DGA (Domain Generation Algorithm) malware',
    'long_duration': 'Long-lived connection may indicate persistent backdoor or data exfiltration',
    'high_bytes_per_second': 'High data transfer rate could indicate bulk data exfiltration',
    'deep_dns': 'Deep subdomain structure is characteristic of DNS tunneling attacks',
    'regular_timing': 'Regular timing patterns (low IAT variability) suggest beaconing malware',
    'burst_traffic': 'Bursty traffic pattern (high IAT variability) may indicate automated scanning'
}

# ========================================
# EXPLAINER CLASS
# ========================================

class AlertExplainer:
    def __init__(self, alert_explanations_file: str):
        with open(alert_explanations_file, 'r') as f:
            self.explanations = json.load(f)
    
    def generate_narrative(self, alert_id: str) -> str:
        """Generate human-readable narrative for an alert"""
        
        # Find alert explanation
        alert = next((a for a in self.explanations if a['alert_id'] == alert_id), None)
        if not alert:
            return f"No explanation found for {alert_id}"
        
        narrative = []
        narrative.append(f"🚨 Alert: {alert['alert_id']} ({alert['severity']})")
        narrative.append(f"   Threat: {alert['threat_label']}")
        narrative.append(f"   Source: {alert['src_ip']} → {alert['dst_ip']}")
        narrative.append(f"   ML Threat Score: {alert['ml_score']:.3f}\n")
        
        narrative.append("📊 Why This Flow Was Flagged (Top Contributing Factors):\n")
        
        for idx, feature in enumerate(alert['top_features'], 1):
            feat_name = feature['feature']
            shap_val = feature['shap_contribution']
            actual = feature['actual_value']
            impact = feature['impact']
            
            desc = FEATURE_DESCRIPTIONS.get(feat_name, feat_name)
            
            # Build explanation
            if impact == 'increased':
                explanation = f"   {idx}. HIGH {desc.upper()}: {actual:.2f}"
                explanation += f"\n      → This feature INCREASED the anomaly score by {abs(shap_val):.4f}"
            else:
                explanation = f"   {idx}. LOW {desc.upper()}: {actual:.2f}"
                explanation += f"\n      → This feature decreased the anomaly score by {abs(shap_val):.4f}"
            
            # Add context
            context = self._get_context(feat_name, actual)
            if context:
                explanation += f"\n      💡 {context}"
            
            narrative.append(explanation)
        
        return "\n".join(narrative)
    
    def _get_context(self, feature: str, value: float) -> str:
        """Provide context based on feature and value"""
        
        if feature == 'dns_entropy' and value > 3.5:
            return THREAT_PATTERNS['high_dns_entropy']
        elif feature == 'dns_subdomain_depth' and value >= 4:
            return THREAT_PATTERNS['deep_dns']
        elif feature == 'packet_count' and value > 100:
            return THREAT_PATTERNS['high_packet_count']
        elif feature == 'duration' and value > 60:
            return THREAT_PATTERNS['long_duration']
        elif feature == 'bytes_per_second' and value > 10000:
            return THREAT_PATTERNS['high_bytes_per_second']
        elif feature == 'std_iat' and value < 0.01:
            return THREAT_PATTERNS['regular_timing']
        elif feature == 'std_iat' and value > 1.0:
            return THREAT_PATTERNS['burst_traffic']
        
        return ""
    
    def generate_all_narratives(self, output_file: str):
        """Generate narratives for all alerts"""
        narratives = []
        
        for alert in self.explanations:
            narrative = self.generate_narrative(alert['alert_id'])
            narratives.append({
                'alert_id': alert['alert_id'],
                'narrative': narrative
            })
        
        with open(output_file, 'w') as f:
            json.dump(narratives, f, indent=2)
        
        print(f"[+] Generated {len(narratives)} alert narratives → {output_file}")

# ========================================
# MAIN EXECUTION
# ========================================

if __name__ == "__main__":
    print("=" * 60)
    print("  SENTINELHUNT ALERT EXPLAINER")
    print("=" * 60)
    
    explainer = AlertExplainer("outputs/alert_explanations.json")
    
    # Generate narratives for all alerts
    explainer.generate_all_narratives("outputs/alert_narratives.json")
    
    # Display sample explanation
    if explainer.explanations:
        print("\n📝 Sample Alert Explanation:\n")
        sample_alert = explainer.explanations[0]
        narrative = explainer.generate_narrative(sample_alert['alert_id'])
        print(narrative)
    
    print("\n" + "=" * 60)
    print("  EXPLANATION GENERATION COMPLETE")
    print("=" * 60)
    print("\n💡 These explanations make ML decisions transparent to SOC analysts")
    print("💡 Use in capstone presentation to demonstrate Explainable AI")
