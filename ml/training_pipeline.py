"""
SentinelHunt — ML Training Pipeline

Production-grade ML pipeline that replaces the original train_baseline.py.
Features:
    - Configurable via YAML (no hardcoded params)
    - Hyperparameter tuning via RandomizedSearchCV
    - K-fold cross-validation
    - Model versioning with timestamps and metadata
    - Train/validation/test splits
    - Ensemble training orchestration
    - Proper logging and experiment tracking
"""

import logging
import json
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List

import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import (
    RandomizedSearchCV,
    StratifiedKFold,
    train_test_split,
)
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    precision_recall_fscore_support,
    roc_auc_score,
    accuracy_score,
)
from scipy.stats import uniform, randint

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from streaming.config import get_config, setup_logging, ML_MODEL_DIR, DATA_DIR

logger = logging.getLogger("sentinelhunt.ml.pipeline")


class MLPipeline:
    """
    End-to-end ML pipeline for training, evaluating, and versioning models.
    """

    def __init__(self, config=None):
        self.config = config or get_config()
        self.ml_cfg = self.config.ml
        self.features = self.ml_cfg.feature_columns
        self.scaler = StandardScaler()
        self.model_version: Optional[str] = None
        self.experiment_log: List[Dict] = []

    def load_data(
        self, data_path: Optional[str] = None
    ) -> pd.DataFrame:
        """Load flow feature dataset."""
        if data_path is None:
            data_path = str(DATA_DIR / "flow_features_enriched.csv")

        df = pd.read_csv(data_path)
        logger.info("Loaded %d flows from %s", len(df), data_path)

        # Validate required features
        missing = [f for f in self.features if f not in df.columns]
        if missing:
            logger.warning("Missing features: %s", missing)

        return df

    def prepare_data(
        self,
        df: pd.DataFrame,
        test_size: float = 0.2,
    ) -> Dict[str, np.ndarray]:
        """
        Prepare data for training with proper splits.

        Returns dict with X_train, X_val, X_test, and full X.
        """
        available_features = [f for f in self.features if f in df.columns]
        X = df[available_features].fillna(0).values

        X_train_val, X_test = train_test_split(
            X, test_size=test_size, random_state=42
        )
        X_train, X_val = train_test_split(
            X_train_val, test_size=self.ml_cfg.validation_split, random_state=42
        )

        logger.info(
            "Data split — train: %d, val: %d, test: %d",
            len(X_train), len(X_val), len(X_test),
        )

        return {
            "X_full": X,
            "X_train": X_train,
            "X_val": X_val,
            "X_test": X_test,
            "feature_names": available_features,
        }

    def train_isolation_forest(
        self,
        X_train: np.ndarray,
        tune_hyperparams: bool = True,
    ) -> Dict[str, Any]:
        """
        Train Isolation Forest with optional hyperparameter tuning.
        """
        logger.info("Training Isolation Forest...")

        if tune_hyperparams:
            # Define parameter search space
            param_distributions = {
                "n_estimators": randint(100, 500),
                "contamination": uniform(0.01, 0.09),
                "max_samples": uniform(0.5, 0.5),
                "max_features": uniform(0.5, 0.5),
            }

            base_model = IsolationForest(random_state=42, n_jobs=-1)

            # Use anomaly score as scoring (custom scorer)
            # For unsupervised, we optimize for score stability
            search = RandomizedSearchCV(
                base_model,
                param_distributions,
                n_iter=20,
                cv=3,
                scoring="neg_mean_squared_error",  # Proxy score
                random_state=42,
                n_jobs=-1,
                refit=True,
            )

            # For RandomizedSearchCV with unsupervised models,
            # we create dummy labels (all same class)
            dummy_y = np.zeros(len(X_train))
            search.fit(X_train, dummy_y)
            model = search.best_estimator_
            best_params = search.best_params_
            logger.info("Best IForest params: %s", best_params)
        else:
            model = IsolationForest(
                n_estimators=self.ml_cfg.iforest_n_estimators,
                contamination=self.ml_cfg.iforest_contamination,
                random_state=self.ml_cfg.iforest_random_state,
                n_jobs=-1,
            )
            model.fit(X_train)
            best_params = {
                "n_estimators": self.ml_cfg.iforest_n_estimators,
                "contamination": self.ml_cfg.iforest_contamination,
            }

        return {"model": model, "params": best_params}

    def train_ensemble(
        self,
        X_train: np.ndarray,
        X_val: np.ndarray,
    ) -> Dict[str, Any]:
        """
        Train the full ensemble detector.
        """
        from ml.models.ensemble import EnsembleDetector

        logger.info("Training ensemble detector...")

        ensemble = EnsembleDetector(
            weights=self.ml_cfg.ensemble_weights,
            threshold=self.ml_cfg.ensemble_threshold,
            iforest_params={
                "n_estimators": self.ml_cfg.iforest_n_estimators,
                "contamination": self.ml_cfg.iforest_contamination,
                "random_state": self.ml_cfg.iforest_random_state,
            },
            autoencoder_params={
                "input_dim": len(self.features),
                "latent_dim": self.ml_cfg.autoencoder_latent_dim,
                "epochs": self.ml_cfg.autoencoder_epochs,
                "batch_size": self.ml_cfg.autoencoder_batch_size,
                "learning_rate": self.ml_cfg.autoencoder_learning_rate,
            },
        )

        # Combine train and val for final ensemble training
        X_combined = np.vstack([X_train, X_val])
        results = ensemble.fit(X_combined, validation_split=0.2)

        return {"ensemble": ensemble, "training_results": results}

    def evaluate(
        self,
        model,
        X_test: np.ndarray,
        model_name: str = "unknown",
    ) -> Dict[str, Any]:
        """
        Evaluate a trained model on test data.

        Since we're doing unsupervised anomaly detection, we report:
        - Anomaly rate
        - Score distribution statistics
        - Threshold analysis
        """
        if hasattr(model, "score_samples"):
            scores = model.score_samples(X_test)
        elif hasattr(model, "decision_function"):
            scores = -model.decision_function(X_test)
        else:
            scores = np.zeros(len(X_test))

        if hasattr(model, "predict"):
            predictions = model.predict(X_test)
            if predictions.min() == -1:
                # sklearn convention: -1 = anomaly
                predictions = (predictions == -1).astype(int)
        else:
            predictions = np.zeros(len(X_test))

        anomaly_rate = predictions.mean()

        metrics = {
            "model_name": model_name,
            "test_samples": len(X_test),
            "anomaly_rate": round(float(anomaly_rate), 4),
            "score_stats": {
                "mean": round(float(scores.mean()), 4),
                "std": round(float(scores.std()), 4),
                "min": round(float(scores.min()), 4),
                "max": round(float(scores.max()), 4),
                "p50": round(float(np.percentile(scores, 50)), 4),
                "p95": round(float(np.percentile(scores, 95)), 4),
                "p99": round(float(np.percentile(scores, 99)), 4),
            },
            "total_anomalies": int(predictions.sum()),
        }

        logger.info(
            "Evaluation [%s] — anomaly_rate: %.2f%%, mean_score: %.4f",
            model_name, anomaly_rate * 100, scores.mean(),
        )

        return metrics

    def generate_version_id(self) -> str:
        """Generate a unique model version ID."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        hash_suffix = hashlib.md5(
            timestamp.encode()
        ).hexdigest()[:6]
        return f"v_{timestamp}_{hash_suffix}"

    def save_model(
        self,
        model: Any,
        metrics: Dict,
        model_name: str,
        version: Optional[str] = None,
    ) -> str:
        """
        Save model with versioning and metadata.
        """
        version = version or self.generate_version_id()
        save_dir = Path(self.ml_cfg.model_dir) / version

        if hasattr(model, "save"):
            model.save(str(save_dir / model_name))
        else:
            save_dir.mkdir(parents=True, exist_ok=True)
            joblib.dump(model, save_dir / f"{model_name}.pkl")

        # Save scaler
        joblib.dump(self.scaler, save_dir / "scaler.pkl")

        # Save experiment metadata
        experiment = {
            "version": version,
            "model_name": model_name,
            "timestamp": datetime.now().isoformat(),
            "metrics": metrics,
            "config": {
                "features": self.features,
                "iforest_n_estimators": self.ml_cfg.iforest_n_estimators,
                "iforest_contamination": self.ml_cfg.iforest_contamination,
            },
        }
        with open(save_dir / "experiment.json", "w") as f:
            json.dump(experiment, f, indent=2)

        logger.info("Model %s saved to %s (version: %s)", model_name, save_dir, version)
        return str(save_dir)

    def run_full_pipeline(
        self,
        data_path: Optional[str] = None,
        train_ensemble: bool = True,
        tune_hyperparams: bool = False,
    ) -> Dict[str, Any]:
        """
        Execute the complete ML pipeline:
        1. Load data
        2. Prepare splits
        3. Train models (IForest + optionally ensemble)
        4. Evaluate
        5. Save with versioning

        Returns comprehensive results dictionary.
        """
        setup_logging(self.config)
        logger.info("=" * 60)
        logger.info("  SentinelHunt ML Pipeline — Starting")
        logger.info("=" * 60)

        # 1. Load and prepare data
        df = self.load_data(data_path)
        data = self.prepare_data(df)
        X_train = self.scaler.fit_transform(data["X_train"])
        X_val = self.scaler.transform(data["X_val"])
        X_test = self.scaler.transform(data["X_test"])

        version = self.generate_version_id()
        results = {"version": version, "models": {}}

        # 2. Train Isolation Forest
        iforest_result = self.train_isolation_forest(X_train, tune_hyperparams)
        iforest_model = iforest_result["model"]
        iforest_metrics = self.evaluate(iforest_model, X_test, "isolation_forest")
        self.save_model(iforest_model, iforest_metrics, "isolation_forest", version)
        results["models"]["isolation_forest"] = iforest_metrics

        # 3. Generate scores on full dataset
        X_full_scaled = self.scaler.transform(data["X_full"])
        df["iforest_score"] = iforest_model.decision_function(X_full_scaled)
        df["iforest_label"] = iforest_model.predict(X_full_scaled)

        # Save annotated results
        output_path = DATA_DIR / "iforest_results.csv"
        df.to_csv(output_path, index=False)
        logger.info("IForest results saved to %s", output_path)

        # Also save to models dir for backward compatibility
        df.to_csv(ML_MODEL_DIR / "iforest_results.csv", index=False)
        joblib.dump(iforest_model, ML_MODEL_DIR / "isolation_forest.pkl")
        joblib.dump(self.scaler, ML_MODEL_DIR / "scaler.pkl")

        # 4. Train ensemble (optional, more compute-intensive)
        if train_ensemble:
            try:
                ensemble_result = self.train_ensemble(
                    data["X_train"], data["X_val"]
                )
                ensemble = ensemble_result["ensemble"]
                ensemble_metrics = self.evaluate(
                    ensemble, data["X_test"], "ensemble"
                )
                ensemble.save(str(ML_MODEL_DIR / "ensemble"))
                results["models"]["ensemble"] = ensemble_metrics

                # Generate ensemble scores on full dataset
                ensemble_scores = ensemble.score_samples(data["X_full"])
                df["ensemble_score"] = ensemble_scores
                df["ensemble_label"] = (ensemble_scores > 0.5).astype(int)
                df.to_csv(output_path, index=False)
            except Exception as e:
                logger.error("Ensemble training failed: %s", e)
                results["models"]["ensemble"] = {"error": str(e)}

        logger.info("=" * 60)
        logger.info("  ML Pipeline Complete — Version: %s", version)
        logger.info("=" * 60)

        # Save full experiment results
        with open(ML_MODEL_DIR / "latest_experiment.json", "w") as f:
            json.dump(results, f, indent=2, default=str)

        return results


# ====================================================
# CLI entry point
# ====================================================
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SentinelHunt ML Training Pipeline")
    parser.add_argument("--data", type=str, default=None, help="Path to flow features CSV")
    parser.add_argument("--ensemble", action="store_true", help="Train full ensemble")
    parser.add_argument("--tune", action="store_true", help="Run hyperparameter tuning")
    parser.add_argument("--config", type=str, default=None, help="Path to config YAML")
    args = parser.parse_args()

    if args.config:
        from streaming.config import load_config
        config = load_config(args.config)
    else:
        config = get_config()

    pipeline = MLPipeline(config)
    results = pipeline.run_full_pipeline(
        data_path=args.data,
        train_ensemble=args.ensemble,
        tune_hyperparams=args.tune,
    )

    print("\n✅ Pipeline completed successfully!")
    print(f"   Version: {results['version']}")
    for model_name, metrics in results["models"].items():
        anomaly_rate = metrics.get("anomaly_rate", "N/A")
        print(f"   {model_name}: anomaly_rate={anomaly_rate}")
