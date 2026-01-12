# Day 6 Log — Baseline Anomaly Detection Modeling

## Objective
Validate engineered flow-level features using unsupervised machine learning and compare ML-based anomaly detection with heuristic rules.

## Work Completed
- Selected ML-safe numeric and behavioral flow features
- Applied feature normalization using StandardScaler
- Trained Isolation Forest for unsupervised anomaly detection
- Generated ML anomaly scores and anomaly labels for all flows
- Persisted trained model, scaler, and inference outputs
- Performed comparative analysis between heuristic suspicion scores and ML anomaly scores

## Observations
- Isolation Forest detected ~5% anomalous flows, consistent with contamination setting
- Heuristic rules were conservative with zero high-suspicion false positives
- Majority of anomalies were detected exclusively by ML, indicating subtle behavioral deviations
- Strong alignment observed between rule-based flags and statistical learning

## Outcome
- Confirmed effectiveness of engineered flow features
- Established a hybrid IDS foundation combining explainable heuristics and ML-based detection
- Prepared the pipeline for attack traffic validation in subsequent phases
