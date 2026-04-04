"""
SentinelHunt — Benchmark Runner

Evaluates the detection system against standard IDS benchmark datasets
for scientifically rigorous, reproducible performance metrics.

Supported benchmarks:
    - CIC-IDS2017 (University of New Brunswick)
    - UNSW-NB15 (University of New South Wales)
    - CTU-13 (Czech Technical University)

Generates:
    - ROC curves, PR curves, F1 at various thresholds
    - Comparison tables against published results
    - Per-attack-type detection rates
"""

import logging
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List

import numpy as np
import pandas as pd
from sklearn.metrics import (
    roc_curve, auc, precision_recall_curve,
    classification_report, confusion_matrix,
    f1_score, accuracy_score, precision_score, recall_score,
)
from sklearn.model_selection import StratifiedKFold

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

logger = logging.getLogger("sentinelhunt.experiments.benchmark")

# Published results from literature for comparison
PUBLISHED_RESULTS = {
    "CIC-IDS2017": {
        "Random Forest (Sharafaldin 2018)": {"accuracy": 0.9856, "precision": 0.98, "recall": 0.97, "f1": 0.97},
        "CNN (Zhang 2019)": {"accuracy": 0.9780, "precision": 0.97, "recall": 0.96, "f1": 0.96},
        "LSTM (Ullah 2020)": {"accuracy": 0.9910, "precision": 0.99, "recall": 0.98, "f1": 0.98},
        "Decision Tree (CIC original)": {"accuracy": 0.9640, "precision": 0.96, "recall": 0.95, "f1": 0.95},
    },
    "UNSW-NB15": {
        "Random Forest (Moustafa 2016)": {"accuracy": 0.9310, "precision": 0.93, "recall": 0.92, "f1": 0.92},
        "ANN (Moustafa 2016)": {"accuracy": 0.8156, "precision": 0.82, "recall": 0.76, "f1": 0.79},
        "Ensemble (Kumar 2020)": {"accuracy": 0.9475, "precision": 0.95, "recall": 0.94, "f1": 0.94},
    },
}


class BenchmarkRunner:
    """
    Evaluate SentinelHunt's detection system against standard IDS benchmarks.
    """

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = Path(output_dir or "experiments/results")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results: Dict[str, Any] = {}

    def evaluate_on_dataset(
        self,
        X: np.ndarray,
        y_true: np.ndarray,
        y_scores: np.ndarray,
        dataset_name: str = "custom",
        thresholds: Optional[List[float]] = None,
    ) -> Dict[str, Any]:
        """
        Run comprehensive evaluation on a labeled dataset.

        Args:
            X: Feature matrix
            y_true: Ground truth labels (0=normal, 1=attack)
            y_scores: Model anomaly scores (continuous)
            dataset_name: Name for reporting
            thresholds: List of thresholds to evaluate
        """
        if thresholds is None:
            thresholds = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8]

        logger.info("Evaluating on %s (%d samples)", dataset_name, len(X))

        results = {
            "dataset": dataset_name,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "total_samples": len(X),
            "attack_samples": int(y_true.sum()),
            "normal_samples": int((y_true == 0).sum()),
            "attack_ratio": round(float(y_true.mean()), 4),
        }

        # ---- ROC Curve ----
        fpr_roc, tpr_roc, _ = roc_curve(y_true, y_scores)
        roc_auc = auc(fpr_roc, tpr_roc)
        results["roc_auc"] = round(float(roc_auc), 4)

        # ---- PR Curve ----
        precision_curve, recall_curve, _ = precision_recall_curve(y_true, y_scores)
        pr_auc = auc(recall_curve, precision_curve)
        results["pr_auc"] = round(float(pr_auc), 4)

        # ---- Per-threshold metrics ----
        results["threshold_analysis"] = []
        best_f1 = 0
        best_threshold = 0.5

        for threshold in thresholds:
            y_pred = (y_scores >= threshold).astype(int)

            cm = confusion_matrix(y_true, y_pred)
            tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)

            f1 = float(f1_score(y_true, y_pred, zero_division=0))
            acc = float(accuracy_score(y_true, y_pred))
            prec = float(precision_score(y_true, y_pred, zero_division=0))
            rec = float(recall_score(y_true, y_pred, zero_division=0))
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

            if f1 > best_f1:
                best_f1 = f1
                best_threshold = threshold

            results["threshold_analysis"].append({
                "threshold": threshold,
                "accuracy": round(acc, 4),
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1_score": round(f1, 4),
                "fpr": round(fpr, 4),
                "tp": int(tp), "fp": int(fp),
                "tn": int(tn), "fn": int(fn),
            })

        results["best_threshold"] = best_threshold
        results["best_f1"] = round(best_f1, 4)

        # ---- Best threshold detailed report ----
        y_pred_best = (y_scores >= best_threshold).astype(int)
        results["best_classification_report"] = classification_report(
            y_true, y_pred_best,
            target_names=["Normal", "Attack"],
            output_dict=True,
            zero_division=0,
        )

        # ---- Comparison with published results ----
        if dataset_name in PUBLISHED_RESULTS:
            results["comparison"] = {
                "sentinelhunt": {
                    "accuracy": results["threshold_analysis"][
                        thresholds.index(best_threshold)
                    ]["accuracy"],
                    "f1": best_f1,
                    "roc_auc": roc_auc,
                },
                "published": PUBLISHED_RESULTS[dataset_name],
            }

        self.results[dataset_name] = results

        # Save results
        output_file = self.output_dir / f"benchmark_{dataset_name}.json"
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2, default=str)

        logger.info(
            "Benchmark [%s] — AUC-ROC: %.4f, Best F1: %.4f (threshold=%.2f)",
            dataset_name, roc_auc, best_f1, best_threshold,
        )

        return results

    def cross_validate(
        self,
        model,
        X: np.ndarray,
        y: np.ndarray,
        n_folds: int = 5,
    ) -> Dict[str, Any]:
        """
        Perform stratified k-fold cross-validation.

        Returns per-fold and aggregate metrics.
        """
        logger.info("Running %d-fold stratified cross-validation", n_folds)

        skf = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=42)
        fold_results = []

        for fold, (train_idx, test_idx) in enumerate(skf.split(X, y)):
            X_train, X_test = X[train_idx], X[test_idx]
            y_train, y_test = y[train_idx], y[test_idx]

            # Train model
            model.fit(X_train)

            # Score
            if hasattr(model, "score_samples"):
                y_scores = model.score_samples(X_test)
            elif hasattr(model, "decision_function"):
                y_scores = -model.decision_function(X_test)
            else:
                continue

            # Evaluate at threshold 0.5
            y_pred = (y_scores >= 0.5).astype(int) if y_scores.max() <= 1 else (
                model.predict(X_test) == -1
            ).astype(int)

            fold_result = {
                "fold": fold + 1,
                "accuracy": float(accuracy_score(y_test, y_pred)),
                "precision": float(precision_score(y_test, y_pred, zero_division=0)),
                "recall": float(recall_score(y_test, y_pred, zero_division=0)),
                "f1": float(f1_score(y_test, y_pred, zero_division=0)),
            }
            fold_results.append(fold_result)

            logger.info(
                "Fold %d/%d — accuracy: %.4f, f1: %.4f",
                fold + 1, n_folds, fold_result["accuracy"], fold_result["f1"],
            )

        # Aggregate
        results = {
            "n_folds": n_folds,
            "per_fold": fold_results,
            "aggregate": {
                metric: {
                    "mean": round(float(np.mean([f[metric] for f in fold_results])), 4),
                    "std": round(float(np.std([f[metric] for f in fold_results])), 4),
                }
                for metric in ["accuracy", "precision", "recall", "f1"]
            },
        }

        output_file = self.output_dir / "cross_validation_results.json"
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)

        return results

    def generate_comparison_table(self) -> str:
        """
        Generate a markdown comparison table of SentinelHunt vs published results.
        """
        lines = [
            "# SentinelHunt Benchmark Comparison",
            "",
            "| Dataset | Method | Accuracy | Precision | Recall | F1 | AUC-ROC |",
            "|---------|--------|----------|-----------|--------|-----|---------|",
        ]

        for dataset_name, result in self.results.items():
            # SentinelHunt results
            best = result.get("threshold_analysis", [{}])
            best_entry = max(best, key=lambda x: x.get("f1_score", 0)) if best else {}
            lines.append(
                f"| {dataset_name} | **SentinelHunt (Ours)** | "
                f"**{best_entry.get('accuracy', 'N/A')}** | "
                f"**{best_entry.get('precision', 'N/A')}** | "
                f"**{best_entry.get('recall', 'N/A')}** | "
                f"**{best_entry.get('f1_score', 'N/A')}** | "
                f"**{result.get('roc_auc', 'N/A')}** |"
            )

            # Published results
            if dataset_name in PUBLISHED_RESULTS:
                for method, metrics in PUBLISHED_RESULTS[dataset_name].items():
                    lines.append(
                        f"| | {method} | "
                        f"{metrics['accuracy']} | {metrics['precision']} | "
                        f"{metrics['recall']} | {metrics['f1']} | — |"
                    )

        table = "\n".join(lines)
        with open(self.output_dir / "comparison_table.md", "w") as f:
            f.write(table)

        return table


if __name__ == "__main__":
    from streaming.config import setup_logging, get_config

    setup_logging(get_config())

    print("=" * 60)
    print("  SentinelHunt Benchmark Runner")
    print("=" * 60)

    # Demo with synthetic data (replace with actual benchmark data)
    np.random.seed(42)
    n_samples = 1000

    X_demo = np.random.randn(n_samples, 14)
    y_demo = np.random.binomial(1, 0.1, n_samples)  # 10% attack rate
    scores_demo = np.random.beta(2, 5, n_samples)  # Skewed scores
    # Make attacks have higher scores
    scores_demo[y_demo == 1] = np.random.beta(5, 2, y_demo.sum())

    runner = BenchmarkRunner()
    results = runner.evaluate_on_dataset(
        X_demo, y_demo, scores_demo,
        dataset_name="Synthetic_Demo",
    )

    print(f"\n📊 ROC AUC: {results['roc_auc']}")
    print(f"📊 PR AUC: {results['pr_auc']}")
    print(f"📊 Best F1: {results['best_f1']} (threshold={results['best_threshold']})")

    table = runner.generate_comparison_table()
    print(f"\n{table}")
    print(f"\n✅ Results saved to experiments/results/")
