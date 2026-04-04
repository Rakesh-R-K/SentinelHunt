"""
SentinelHunt — Adversarial Robustness Testing

Tests ML models against adversarial traffic modifications to assess
their resilience against evasion techniques.

Attack types:
    1. Feature perturbation — small changes to flow features
    2. Mimicry attacks — make malicious traffic look benign
    3. Time shifting — alter timing features to evade beaconing detection
    4. Volume scaling — adjust data volumes to avoid exfil detection
"""

import logging
import json
import numpy as np
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger("sentinelhunt.ml.adversarial")


class AdversarialTester:
    """
    Test ML model robustness against adversarial attacks.
    """

    def __init__(self, model, scaler=None, feature_names: Optional[List[str]] = None):
        self.model = model
        self.scaler = scaler
        self.feature_names = feature_names or []
        self.results: List[Dict] = []

    def feature_perturbation_attack(
        self,
        X: np.ndarray,
        epsilon: float = 0.1,
        n_iterations: int = 5,
    ) -> Dict[str, Any]:
        """
        Add small random perturbations to features and measure detection stability.

        A robust model should maintain detection accuracy under small noise.
        """
        logger.info("Running feature perturbation attack (epsilon=%.2f)", epsilon)

        original_scores = self._get_scores(X)
        original_predictions = (original_scores > 0.5).astype(int)
        original_anomaly_rate = original_predictions.mean()

        perturbation_results = []

        for iteration in range(n_iterations):
            noise = np.random.normal(0, epsilon, X.shape)
            X_perturbed = X + noise
            X_perturbed = np.clip(X_perturbed, 0, None)  # Non-negative features

            perturbed_scores = self._get_scores(X_perturbed)
            perturbed_predictions = (perturbed_scores > 0.5).astype(int)

            # Measure impact
            score_difference = np.abs(original_scores - perturbed_scores).mean()
            prediction_flip_rate = (original_predictions != perturbed_predictions).mean()

            perturbation_results.append({
                "iteration": iteration + 1,
                "mean_score_change": round(float(score_difference), 4),
                "prediction_flip_rate": round(float(prediction_flip_rate), 4),
                "new_anomaly_rate": round(float(perturbed_predictions.mean()), 4),
            })

        result = {
            "attack_type": "feature_perturbation",
            "epsilon": epsilon,
            "n_iterations": n_iterations,
            "original_anomaly_rate": round(float(original_anomaly_rate), 4),
            "avg_score_change": round(
                float(np.mean([r["mean_score_change"] for r in perturbation_results])), 4
            ),
            "avg_flip_rate": round(
                float(np.mean([r["prediction_flip_rate"] for r in perturbation_results])), 4
            ),
            "per_iteration": perturbation_results,
            "robustness_score": round(
                1.0 - float(np.mean([r["prediction_flip_rate"] for r in perturbation_results])), 4
            ),
        }

        self.results.append(result)
        logger.info(
            "Perturbation attack: avg_flip_rate=%.4f, robustness=%.4f",
            result["avg_flip_rate"], result["robustness_score"],
        )
        return result

    def mimicry_attack(
        self,
        X_malicious: np.ndarray,
        X_benign: np.ndarray,
        blend_ratios: Optional[List[float]] = None,
    ) -> Dict[str, Any]:
        """
        Blend malicious traffic features with benign traffic features
        to test if the model can still detect subtle attacks.
        """
        logger.info("Running mimicry attack")

        if blend_ratios is None:
            blend_ratios = [0.1, 0.2, 0.3, 0.5, 0.7, 0.9]

        original_scores = self._get_scores(X_malicious)
        original_detection_rate = (original_scores > 0.5).mean()

        # Get benign centroid
        benign_mean = X_benign.mean(axis=0)
        benign_std = X_benign.std(axis=0) + 1e-8

        blend_results = []

        for ratio in blend_ratios:
            # Blend: move malicious samples toward benign distribution
            X_blended = (1 - ratio) * X_malicious + ratio * benign_mean
            # Add small random noise from benign distribution
            noise = np.random.normal(0, benign_std * ratio * 0.1, X_blended.shape)
            X_blended = X_blended + noise
            X_blended = np.clip(X_blended, 0, None)

            blended_scores = self._get_scores(X_blended)
            detection_rate = (blended_scores > 0.5).mean()

            blend_results.append({
                "blend_ratio": ratio,
                "detection_rate": round(float(detection_rate), 4),
                "evasion_rate": round(float(1.0 - detection_rate), 4),
                "avg_score": round(float(blended_scores.mean()), 4),
            })

        # At what blend ratio does detection drop below 50%?
        evasion_threshold = None
        for br in blend_results:
            if br["detection_rate"] < 0.5:
                evasion_threshold = br["blend_ratio"]
                break

        result = {
            "attack_type": "mimicry",
            "original_detection_rate": round(float(original_detection_rate), 4),
            "blend_results": blend_results,
            "evasion_threshold": evasion_threshold,
            "robustness_score": round(
                float(evasion_threshold or 1.0), 4
            ),
        }

        self.results.append(result)
        logger.info(
            "Mimicry attack: evasion_threshold=%.2f",
            evasion_threshold or 1.0,
        )
        return result

    def timing_evasion_attack(
        self,
        X: np.ndarray,
        timing_feature_indices: Optional[List[int]] = None,
    ) -> Dict[str, Any]:
        """
        Modify timing features (IAT, duration) to evade beaconing detection
        while keeping volume features unchanged.
        """
        logger.info("Running timing evasion attack")

        if timing_feature_indices is None:
            # Default: min_iat(4), max_iat(5), mean_iat(6), std_iat(7)
            timing_feature_indices = [4, 5, 6, 7]

        original_scores = self._get_scores(X)
        original_detection_rate = (original_scores > 0.5).mean()

        jitter_levels = [0.05, 0.1, 0.2, 0.5, 1.0]
        jitter_results = []

        for jitter in jitter_levels:
            X_modified = X.copy()
            for idx in timing_feature_indices:
                if idx < X.shape[1]:
                    noise = np.random.normal(0, jitter, X.shape[0])
                    X_modified[:, idx] = X[:, idx] * (1 + noise)
                    X_modified[:, idx] = np.clip(X_modified[:, idx], 0, None)

            modified_scores = self._get_scores(X_modified)
            detection_rate = (modified_scores > 0.5).mean()

            jitter_results.append({
                "jitter_level": jitter,
                "detection_rate": round(float(detection_rate), 4),
                "avg_score_change": round(
                    float(np.abs(original_scores - modified_scores).mean()), 4
                ),
            })

        result = {
            "attack_type": "timing_evasion",
            "original_detection_rate": round(float(original_detection_rate), 4),
            "jitter_results": jitter_results,
            "robustness_score": round(
                float(np.mean([r["detection_rate"] for r in jitter_results])), 4
            ),
        }

        self.results.append(result)
        return result

    def _get_scores(self, X: np.ndarray) -> np.ndarray:
        """Get anomaly scores from the model."""
        if self.scaler is not None:
            X_scaled = self.scaler.transform(X)
        else:
            X_scaled = X

        if hasattr(self.model, "score_samples"):
            return self.model.score_samples(X if self.scaler is None else self.scaler.inverse_transform(X_scaled))
        elif hasattr(self.model, "decision_function"):
            raw = self.model.decision_function(X_scaled)
            # Normalize to [0, 1]
            return np.clip(-raw / (np.abs(raw).max() + 1e-8) * 0.5 + 0.5, 0, 1)
        else:
            return np.zeros(len(X))

    def generate_report(self) -> Dict[str, Any]:
        """Generate a comprehensive robustness report."""
        overall_robustness = np.mean([
            r.get("robustness_score", 0.5) for r in self.results
        ]) if self.results else 0.0

        report = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "total_attacks_tested": len(self.results),
            "overall_robustness_score": round(float(overall_robustness), 4),
            "robustness_grade": (
                "A" if overall_robustness >= 0.9 else
                "B" if overall_robustness >= 0.7 else
                "C" if overall_robustness >= 0.5 else
                "D" if overall_robustness >= 0.3 else "F"
            ),
            "attack_results": self.results,
            "recommendations": [],
        }

        for result in self.results:
            score = result.get("robustness_score", 1.0)
            attack_type = result.get("attack_type", "unknown")
            if score < 0.7:
                report["recommendations"].append(
                    f"Model vulnerable to {attack_type} attacks (score: {score:.2f}). "
                    f"Consider adversarial training or feature engineering improvements."
                )

        return report

    def save_report(self, path: str) -> None:
        """Save robustness report to file."""
        report = self.generate_report()
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
        logger.info("Robustness report saved to %s", output_path)
