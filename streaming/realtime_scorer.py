"""
SentinelHunt — Real-Time Flow Scorer

Consumes flows from Redis Stream, applies ML models and detection rules
in real-time, and publishes scored alerts back to Redis.

This is the core real-time detection pipeline connecting:
    Collector → Redis → [Scorer] → Alert Stream → Dashboard
"""

import json
import time
import signal
import logging
import sys
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from streaming.config import get_config, setup_logging, ML_MODEL_DIR
from streaming.redis_broker import RedisBroker
from detection_engine.rules import RULES
from detection_engine.mitre_mapping import enrich_alert_with_mitre

logger = logging.getLogger("sentinelhunt.streaming.scorer")


class RealtimeScorer:
    """
    Real-time flow scoring engine.

    Continuously consumes flows from Redis, applies detection rules
    and ML models, then publishes scored alerts.
    """

    def __init__(self, config=None):
        self.config = config or get_config()
        self.broker: Optional[RedisBroker] = None
        self.ml_model = None
        self.scaler = None
        self._running = False
        self._alert_counter = 0

        # Feature list for ML scoring
        self.features = self.config.ml.feature_columns

    def initialize(self) -> None:
        """Initialize connections and load models."""
        logger.info("Initializing real-time scorer...")

        # Connect to Redis
        redis_cfg = self.config.redis
        self.broker = RedisBroker(
            host=redis_cfg.host,
            port=redis_cfg.port,
            db=redis_cfg.db,
            password=redis_cfg.password,
            flow_stream=redis_cfg.flow_stream,
            alert_stream=redis_cfg.alert_stream,
            consumer_group=redis_cfg.consumer_group,
        )

        # Load ML models
        self._load_models()

        logger.info("Real-time scorer initialized")

    def _load_models(self) -> None:
        """Load pre-trained ML models for scoring."""
        import joblib

        # Try to load ensemble first, then fall back to IForest
        ensemble_path = ML_MODEL_DIR / "ensemble"
        iforest_path = ML_MODEL_DIR / "isolation_forest.pkl"
        scaler_path = ML_MODEL_DIR / "scaler.pkl"

        try:
            if ensemble_path.exists():
                from ml.models.ensemble import EnsembleDetector
                self.ml_model = EnsembleDetector()
                self.ml_model.load(str(ensemble_path))
                logger.info("Loaded ensemble model from %s", ensemble_path)
            elif iforest_path.exists():
                self.ml_model = joblib.load(iforest_path)
                logger.info("Loaded IsolationForest from %s", iforest_path)
            else:
                logger.warning("No ML model found — rules-only detection mode")

            if scaler_path.exists():
                self.scaler = joblib.load(scaler_path)
                logger.info("Loaded scaler from %s", scaler_path)
        except Exception as e:
            logger.error("Failed to load ML models: %s", e)

    def score_flow(self, flow: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Score a single flow using rules + ML.

        Returns an alert dict if the flow is suspicious, or None.
        """
        # Apply detection rules
        triggered_rules = []
        total_severity_boost = 0.0
        rule_indicators = []

        for rule_fn in RULES:
            try:
                matched, metadata = rule_fn(flow)
                if matched and metadata:
                    triggered_rules.append(metadata.get("rule", "UNKNOWN"))
                    total_severity_boost += metadata.get("severity_boost", 0.0)
                    if metadata.get("indicator"):
                        rule_indicators.append(metadata["indicator"])
            except Exception as e:
                logger.debug("Rule execution error: %s", e)

        # Apply ML model scoring
        ml_score = 0.0
        ml_label = 0

        if self.ml_model is not None:
            try:
                feature_values = np.array([
                    [float(flow.get(f, 0)) for f in self.features]
                ])

                if self.scaler is not None:
                    feature_values = self.scaler.transform(feature_values)

                if hasattr(self.ml_model, "score_samples"):
                    ml_score = float(self.ml_model.score_samples(
                        feature_values if self.scaler is None
                        else self.scaler.inverse_transform(feature_values)
                    )[0])
                elif hasattr(self.ml_model, "decision_function"):
                    raw_score = self.ml_model.decision_function(feature_values)[0]
                    ml_score = max(0, -raw_score)  # Invert: more negative = more anomalous

                if hasattr(self.ml_model, "predict"):
                    pred = self.ml_model.predict(feature_values)[0]
                    ml_label = 1 if pred == -1 else int(pred)
            except Exception as e:
                logger.debug("ML scoring error: %s", e)

        # Fuse scores
        rule_score = min(total_severity_boost, 1.0)
        det_cfg = self.config.detection
        final_score = (
            det_cfg.rule_weight * rule_score
            + det_cfg.ml_weight * ml_score
        )
        final_score = min(final_score, 1.0)

        # Determine severity
        if final_score >= det_cfg.severity_high:
            severity = "CRITICAL"
        elif final_score >= det_cfg.severity_medium:
            severity = "HIGH"
        elif final_score >= det_cfg.severity_low:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Only generate alerts for suspicious traffic
        if not triggered_rules and ml_label == 0 and final_score < det_cfg.severity_low:
            return None

        self._alert_counter += 1

        alert = {
            "alert_id": f"RT-{self._alert_counter:06d}",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "src_ip": flow.get("src_ip", "unknown"),
            "dst_ip": flow.get("dst_ip", "unknown"),
            "src_port": flow.get("src_port", -1),
            "dst_port": flow.get("dst_port", -1),
            "protocol": flow.get("protocol", "unknown"),
            "severity": severity,
            "final_threat_score": round(final_score, 4),
            "ml_score": round(ml_score, 4),
            "rule_score": round(rule_score, 4),
            "triggered_rules": triggered_rules,
            "indicators": rule_indicators,
            "confidence": round(min(final_score + 0.1 * len(triggered_rules), 1.0), 2),
            "threat_label": triggered_rules[0] if triggered_rules else (
                "ML_ANOMALY" if ml_label == 1 else "SUSPICIOUS_TRAFFIC"
            ),
            "flow_metadata": {
                "packet_count": flow.get("packet_count", 0),
                "total_bytes": flow.get("total_bytes", 0),
                "duration": flow.get("duration", 0),
            },
        }

        # Enrich with MITRE ATT&CK context
        alert = enrich_alert_with_mitre(alert)

        return alert

    def run(self, consumer_name: str = "scorer-1") -> None:
        """
        Main event loop: consume flows, score, publish alerts.
        """
        if not self.broker or not self.broker.is_connected:
            logger.error("Redis not connected. Cannot run real-time scorer.")
            logger.info("Falling back to batch mode...")
            return

        self._running = True
        logger.info("Real-time scorer started (consumer: %s)", consumer_name)

        # Handle graceful shutdown
        def signal_handler(sig, frame):
            logger.info("Shutdown signal received")
            self._running = False

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        alerts_generated = 0
        flows_processed = 0

        while self._running:
            try:
                # Consume batch of flows
                flows = self.broker.consume_flows(
                    consumer_name, batch_size=10, block_ms=1000
                )

                for flow in flows:
                    flows_processed += 1

                    # Score the flow
                    alert = self.score_flow(flow)

                    if alert:
                        # Publish alert to Redis
                        self.broker.publish_alert(alert)
                        alerts_generated += 1

                        if alert["severity"] in ("CRITICAL", "HIGH"):
                            logger.info(
                                "🚨 %s alert: %s from %s → %s (score: %.3f)",
                                alert["severity"],
                                alert["threat_label"],
                                alert["src_ip"],
                                alert["dst_ip"],
                                alert["final_threat_score"],
                            )

                    # Acknowledge processed flow
                    stream_id = flow.get("_stream_id")
                    if stream_id:
                        self.broker.acknowledge(
                            self.config.redis.flow_stream, stream_id
                        )

                # Periodic stats
                if flows_processed > 0 and flows_processed % 100 == 0:
                    logger.info(
                        "Stats — flows: %d, alerts: %d (%.1f%% alert rate)",
                        flows_processed,
                        alerts_generated,
                        (alerts_generated / flows_processed * 100) if flows_processed > 0 else 0,
                    )

            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error("Scorer loop error: %s", e)
                time.sleep(1)

        logger.info(
            "Real-time scorer stopped. Processed %d flows, generated %d alerts.",
            flows_processed, alerts_generated,
        )

    def stop(self) -> None:
        """Stop the scorer."""
        self._running = False
        if self.broker:
            self.broker.close()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SentinelHunt Real-Time Scorer")
    parser.add_argument("--consumer", default="scorer-1", help="Consumer name")
    parser.add_argument("--config", default=None, help="Config file path")
    args = parser.parse_args()

    if args.config:
        from streaming.config import load_config
        config = load_config(args.config)
    else:
        config = get_config()

    setup_logging(config)

    scorer = RealtimeScorer(config)
    scorer.initialize()
    scorer.run(consumer_name=args.consumer)
