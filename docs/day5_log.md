# Day 5 Log — Baseline Traffic Analysis & Rule-Based Anomaly Detection

## Objective
Establish a statistical baseline of normal network traffic and identify anomalous flows using explainable, rule-based heuristics.

## Dataset
- Source: Normal traffic PCAPs
- Total flows analyzed: 2415
- Features per flow: 19

## Baseline Observations
- Median packet count per flow: 10
- 95% of flows have fewer than 85 packets
- 99% of flows last less than 225 seconds
- High DNS entropy (>3.8) is rare and appears in less than 5% of flows
- DNS subdomain depth ≥4 is extremely uncommon

## Detection Logic
Flows were flagged as suspicious if they exceeded:
- 99th percentile packet count
- 99th percentile duration
- 95th percentile DNS entropy
- DNS subdomain depth ≥4

A cumulative suspicion score was assigned based on triggered conditions.

## Results
- Normal flows (score 0): 2256
- Mildly suspicious flows (score 1): 138
- Highly suspicious flows (score ≥2): 21

## Key Takeaways
- Normal traffic is highly bursty and short-lived
- A small fraction of flows exhibit extreme behavior
- Rule-based detection provides interpretable and realistic anomaly signals
- These results form a strong foundation for ML-based anomaly detection

## Next Steps
- Train Isolation Forest on baseline features
- Test anomaly detection against attack PCAPs
- Integrate scoring logic into detection engine
