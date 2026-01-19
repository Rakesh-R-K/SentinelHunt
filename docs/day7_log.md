# Day 7 Log — Threat Scoring & Alert Generation

## Objective
Transform anomaly detection outputs into actionable, explainable security alerts.

## Work Completed
- Normalized ML anomaly scores and rule-based suspicion scores
- Implemented weighted threat score fusion (rules + ML)
- Classified flows into LOW, MEDIUM, and HIGH severity levels
- Generated SOC-style JSON alerts for MEDIUM and HIGH severity flows
- Added explainability via rule and ML-based reasons

## Results
- Total flows processed: 2415
- LOW severity: 421
- MEDIUM severity: 1925
- HIGH severity: 69
- Alerts generated: 1994

## Outcome
SentinelHunt now functions as a complete flow-based IDS with explainable alerting.
