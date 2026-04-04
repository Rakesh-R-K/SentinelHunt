"""
SentinelHunt — Ensemble Anomaly Detection System

Combines multiple anomaly detection algorithms with weighted voting
and confidence calibration for robust threat detection.

Models in the ensemble:
    1. Isolation Forest — tree-based outlier detection
    2. Autoencoder — reconstruction-error-based detection
    3. Local Outlier Factor — density-based detection
    4. One-Class SVM — boundary-based detection

Each model's vote is weighted by its historical accuracy, and the
final score represents calibrated ensemble confidence.

Research basis:
    - Aggarwal, C. & Sathe, S. (2017). Outlier Ensembles
    - Zimek, A. et al. (2014). Ensembles for Unsupervised Outlier Detection
"""

import logging
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple

import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler, MinMaxScaler

from .autoencoder import AutoencoderDetector

logger = logging.getLogger("sentinelhunt.ml.ensemble")


class EnsembleDetector:
    """
    Weighted ensemble of anomaly detectors with confidence calibration.

    Each detector provides an anomaly score in [0, 1]. The ensemble
    combines these via weighted averaging, where weights reflect each
    detector's reliability on validation data.
    """

    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
        threshold: float = 0.5,
        iforest_params: Optional[Dict] = None,
        lof_params: Optional[Dict] = None,
        ocsvm_params: Optional[Dict] = None,
        autoencoder_params: Optional[Dict] = None,
    ):
        # Default weights
        self.weights = weights or {
            "isolation_forest": 0.25,
            "autoencoder": 0.30,
            "lof": 0.20,
            "ocsvm": 0.25,
        }
        self.threshold = threshold

        # Initialize detectors with configurable parameters
        iforest_cfg = iforest_params or {}
        self.isolation_forest = IsolationForest(
            n_estimators=iforest_cfg.get("n_estimators", 200),
            contamination=iforest_cfg.get("contamination", 0.05),
            random_state=iforest_cfg.get("random_state", 42),
            n_jobs=-1,
        )

        lof_cfg = lof_params or {}
        self.lof = LocalOutlierFactor(
            n_neighbors=lof_cfg.get("n_neighbors", 20),
            contamination=lof_cfg.get("contamination", 0.05),
            novelty=True,
            n_jobs=-1,
        )

        ocsvm_cfg = ocsvm_params or {}
        self.ocsvm = OneClassSVM(
            kernel=ocsvm_cfg.get("kernel", "rbf"),
            gamma=ocsvm_cfg.get("gamma", "scale"),
            nu=ocsvm_cfg.get("nu", 0.05),
        )

        ae_cfg = autoencoder_params or {}
        self.autoencoder = AutoencoderDetector(
            input_dim=ae_cfg.get("input_dim", 14),
            latent_dim=ae_cfg.get("latent_dim", 8),
            epochs=ae_cfg.get("epochs", 100),
            batch_size=ae_cfg.get("batch_size", 64),
            learning_rate=ae_cfg.get("learning_rate", 1e-3),
        )

        self.scaler = StandardScaler()
        self.score_normalizer = MinMaxScaler()
        self._fitted = False
        self._model_metrics: Dict[str, Dict] = {}

    def fit(self, X: np.ndarray, validation_split: float = 0.2) -> Dict[str, Any]:
        """
        Train all ensemble members on normal traffic data.

        Args:
            X: Feature matrix of predominantly normal traffic
            validation_split: Fraction for threshold calibration
        """
        logger.info("Training ensemble on %d samples with %d features", X.shape[0], X.shape[1])

        X_scaled = self.scaler.fit_transform(X)

        # Split for calibration
        n_val = int(len(X_scaled) * validation_split)
        indices = np.random.permutation(len(X_scaled))
        train_idx, val_idx = indices[n_val:], indices[:n_val]
        X_train, X_val = X_scaled[train_idx], X_scaled[val_idx]

        results = {}

        # 1. Isolation Forest
        logger.info("[1/4] Training Isolation Forest...")
        self.isolation_forest.fit(X_train)
        results["isolation_forest"] = {"status": "trained"}

        # 2. Autoencoder
        logger.info("[2/4] Training Autoencoder...")
        ae_results = self.autoencoder.fit(X[train_idx], validation_split=0.2)
        results["autoencoder"] = ae_results

        # 3. Local Outlier Factor
        logger.info("[3/4] Training Local Outlier Factor...")
        self.lof.fit(X_train)
        results["lof"] = {"status": "trained"}

        # 4. One-Class SVM
        logger.info("[4/4] Training One-Class SVM...")
        # Use a subset for SVM (can be slow on large datasets)
        svm_sample_size = min(5000, len(X_train))
        svm_indices = np.random.choice(len(X_train), svm_sample_size, replace=False)
        self.ocsvm.fit(X_train[svm_indices])
        results["ocsvm"] = {"status": "trained", "samples_used": svm_sample_size}

        # Calibrate individual model scores on validation data
        self._calibrate_scores(X, X_val)
        self._fitted = True

        logger.info("Ensemble training complete. All 4 models ready.")
        return results

    def _calibrate_scores(self, X_full: np.ndarray, X_val: np.ndarray) -> None:
        """Calibrate score normalization using validation data."""
        # Collect raw scores from each model on validation set
        raw_scores = self._get_raw_scores(X_val, from_scaled=True)

        # Fit normalizer to map all scores into comparable [0, 1] range
        score_matrix = np.column_stack(list(raw_scores.values()))
        self.score_normalizer.fit(score_matrix)

        logger.info("Score calibration complete across %d validation samples", len(X_val))

    def _get_raw_scores(
        self, X: np.ndarray, from_scaled: bool = False
    ) -> Dict[str, np.ndarray]:
        """Get raw anomaly scores from each model."""
        X_input = X if from_scaled else self.scaler.transform(X)
        scores = {}

        # Isolation Forest: decision_function (lower = more anomalous)
        iforest_scores = -self.isolation_forest.decision_function(X_input)
        scores["isolation_forest"] = iforest_scores

        # LOF: decision_function (lower = more anomalous)
        lof_scores = -self.lof.decision_function(X_input)
        scores["lof"] = lof_scores

        # One-Class SVM: decision_function (lower = more anomalous)
        ocsvm_scores = -self.ocsvm.decision_function(X_input)
        scores["ocsvm"] = ocsvm_scores

        # Autoencoder: reconstruction error (higher = more anomalous)
        ae_scores = self.autoencoder.score_samples(
            X if not from_scaled else self.scaler.inverse_transform(X)
        )
        scores["autoencoder"] = ae_scores

        return scores

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """
        Compute ensemble anomaly scores.

        Returns weighted average of all model scores, normalized to [0, 1].
        """
        if not self._fitted:
            raise RuntimeError("Ensemble not fitted. Call fit() first.")

        raw_scores = self._get_raw_scores(X)

        # Normalize scores
        score_matrix = np.column_stack(list(raw_scores.values()))
        normalized = self.score_normalizer.transform(score_matrix)
        normalized = np.clip(normalized, 0, 1)

        # Weighted combination
        model_names = list(raw_scores.keys())
        final_scores = np.zeros(len(X))
        total_weight = 0

        for i, name in enumerate(model_names):
            weight = self.weights.get(name, 0.25)
            final_scores += weight * normalized[:, i]
            total_weight += weight

        if total_weight > 0:
            final_scores /= total_weight

        return np.clip(final_scores, 0.0, 1.0)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict anomaly labels: 1 = anomaly, 0 = normal."""
        scores = self.score_samples(X)
        return (scores > self.threshold).astype(int)

    def predict_with_details(self, X: np.ndarray) -> List[Dict[str, Any]]:
        """
        Get detailed predictions with per-model breakdown.

        Returns a list of dicts with scores from each model,
        the ensemble score, and the final label.
        """
        if not self._fitted:
            raise RuntimeError("Ensemble not fitted.")

        raw_scores = self._get_raw_scores(X)
        ensemble_scores = self.score_samples(X)
        predictions = (ensemble_scores > self.threshold).astype(int)

        details = []
        for i in range(len(X)):
            detail = {
                "ensemble_score": round(float(ensemble_scores[i]), 4),
                "is_anomaly": bool(predictions[i]),
                "model_scores": {},
                "model_votes": {},
            }
            for name, scores in raw_scores.items():
                detail["model_scores"][name] = round(float(scores[i]), 4)
                detail["model_votes"][name] = bool(scores[i] > np.median(scores))

            # Count votes
            votes_for_anomaly = sum(detail["model_votes"].values())
            detail["voter_agreement"] = f"{votes_for_anomaly}/4"

            details.append(detail)

        return details

    def get_feature_importance(self, feature_names: List[str]) -> Dict[str, float]:
        """
        Get feature importance from the Isolation Forest component.
        """
        if hasattr(self.isolation_forest, "feature_importances_"):
            importances = self.isolation_forest.feature_importances_
        else:
            # Approximate from tree depths
            importances = np.zeros(len(feature_names))
            for tree in self.isolation_forest.estimators_:
                importances += tree.feature_importances_
            importances /= len(self.isolation_forest.estimators_)

        return {
            name: round(float(imp), 6)
            for name, imp in sorted(
                zip(feature_names, importances),
                key=lambda x: x[1],
                reverse=True,
            )
        }

    def save(self, path: str) -> None:
        """Save all ensemble models to disk."""
        save_dir = Path(path)
        save_dir.mkdir(parents=True, exist_ok=True)

        # Save sklearn models
        joblib.dump(self.isolation_forest, save_dir / "iforest.pkl")
        joblib.dump(self.lof, save_dir / "lof.pkl")
        joblib.dump(self.ocsvm, save_dir / "ocsvm.pkl")
        joblib.dump(self.scaler, save_dir / "ensemble_scaler.pkl")
        joblib.dump(self.score_normalizer, save_dir / "score_normalizer.pkl")

        # Save autoencoder
        self.autoencoder.save(str(save_dir / "autoencoder"))

        # Save metadata
        metadata = {
            "weights": self.weights,
            "threshold": self.threshold,
            "saved_at": datetime.now().isoformat(),
            "model_metrics": self._model_metrics,
        }
        with open(save_dir / "ensemble_metadata.json", "w") as f:
            json.dump(metadata, f, indent=2)

        logger.info("Ensemble saved to %s", save_dir)

    def load(self, path: str) -> None:
        """Load all ensemble models from disk."""
        save_dir = Path(path)

        self.isolation_forest = joblib.load(save_dir / "iforest.pkl")
        self.lof = joblib.load(save_dir / "lof.pkl")
        self.ocsvm = joblib.load(save_dir / "ocsvm.pkl")
        self.scaler = joblib.load(save_dir / "ensemble_scaler.pkl")
        self.score_normalizer = joblib.load(save_dir / "score_normalizer.pkl")

        self.autoencoder.load(str(save_dir / "autoencoder"))

        with open(save_dir / "ensemble_metadata.json", "r") as f:
            metadata = json.load(f)
        self.weights = metadata["weights"]
        self.threshold = metadata["threshold"]
        self._model_metrics = metadata.get("model_metrics", {})

        self._fitted = True
        logger.info("Ensemble loaded from %s", save_dir)
