# Day 8 — Threat Scoring & Alerting

## Objectives
- Fuse ML-based anomaly detection with rule-based heuristics
- Assign human-readable severity levels
- Generate SOC-style alerts with explainable context

## Work Completed
- Normalized Isolation Forest anomaly scores
- Normalized rule-based suspicion scores
- Implemented weighted threat score fusion
- Classified flows into severity bands:
  - LOW
  - MEDIUM
  - HIGH
  - CRITICAL
- Designed conservative, explainable threat labeling logic
- Avoided overfitting and false attribution of attack types
- Generated structured JSON alerts for analyst consumption

## Results
- Total flows analyzed: 2415
- Alerts generated: 69
- Majority of traffic correctly classified as BENIGN
- System flagged only genuinely suspicious flows
- No forced or hallucinated threat categories

## Key Takeaway
This milestone marks the transition from anomaly detection  
to a **true threat-hunting and alerting system** suitable for SOC workflows.
