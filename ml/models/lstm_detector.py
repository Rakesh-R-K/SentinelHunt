"""
SentinelHunt — LSTM-Based Temporal Anomaly Detector

Models sequences of network flows from the same source IP to detect
behavioral shifts over time (e.g., normal → compromised → exfiltration).

Architecture:
    Sliding window of flow sequences → LSTM(2 layers, 64 hidden) → Dense → Anomaly Score

Research basis:
    - Bontemps, L. et al. (2016). Collective Anomaly Detection based on LSTM-RNNs
    - Kim, T. et al. (2020). An LSTM-based anomaly detection model for network traffic
"""

import logging
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger("sentinelhunt.ml.lstm")

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    logger.warning("PyTorch not installed — LSTM detector will use statistical fallback")


# ====================================================
# LSTM Network
# ====================================================
if TORCH_AVAILABLE:
    class _LSTMNet(nn.Module):
        """LSTM network for sequence anomaly detection."""

        def __init__(
            self,
            input_dim: int,
            hidden_dim: int = 64,
            num_layers: int = 2,
            dropout: float = 0.2,
        ):
            super().__init__()
            self.hidden_dim = hidden_dim
            self.num_layers = num_layers

            self.lstm = nn.LSTM(
                input_size=input_dim,
                hidden_size=hidden_dim,
                num_layers=num_layers,
                batch_first=True,
                dropout=dropout if num_layers > 1 else 0,
            )

            self.decoder = nn.Sequential(
                nn.Linear(hidden_dim, 32),
                nn.LeakyReLU(0.2),
                nn.Dropout(0.1),
                nn.Linear(32, input_dim),
            )

        def forward(self, x):
            # x shape: (batch, seq_len, features)
            lstm_out, _ = self.lstm(x)
            # Use the last timestep output to predict next step
            last_hidden = lstm_out[:, -1, :]
            prediction = self.decoder(last_hidden)
            return prediction


# ====================================================
# Statistical Fallback
# ====================================================
class _StatisticalSequenceDetector:
    """Fallback: detect anomalous sequences using rolling statistics."""

    def __init__(self, window_size: int = 10):
        self.window_size = window_size
        self.baseline_means: Optional[np.ndarray] = None
        self.baseline_stds: Optional[np.ndarray] = None
        self.threshold: float = 3.0  # z-score threshold

    def fit(self, X_sequences: np.ndarray) -> None:
        # X_sequences: (n_sequences, seq_len, features)
        sequence_means = X_sequences.mean(axis=1)
        self.baseline_means = sequence_means.mean(axis=0)
        self.baseline_stds = sequence_means.std(axis=0) + 1e-8

    def score(self, X_sequences: np.ndarray) -> np.ndarray:
        sequence_means = X_sequences.mean(axis=1)
        z_scores = np.abs(
            (sequence_means - self.baseline_means) / self.baseline_stds
        )
        return z_scores.mean(axis=1) / self.threshold


# ====================================================
# LSTM Anomaly Detector (public API)
# ====================================================
class LSTMDetector:
    """
    LSTM-based temporal sequence anomaly detector.

    Groups flows by source IP, creates sliding windows of sequential
    flows, and learns normal temporal patterns. Deviations from learned
    patterns indicate potential compromise or behavioral shifts.
    """

    def __init__(
        self,
        input_dim: int = 14,
        hidden_dim: int = 64,
        num_layers: int = 2,
        sequence_length: int = 10,
        epochs: int = 50,
        batch_size: int = 32,
        learning_rate: float = 1e-3,
        threshold_percentile: float = 95.0,
        device: Optional[str] = None,
    ):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.sequence_length = sequence_length
        self.epochs = epochs
        self.batch_size = batch_size
        self.learning_rate = learning_rate
        self.threshold_percentile = threshold_percentile
        self.threshold_: Optional[float] = None
        self.training_history: list = []
        self.scaler = StandardScaler()

        if TORCH_AVAILABLE:
            self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
            self.model = _LSTMNet(input_dim, hidden_dim, num_layers).to(self.device)
            self._use_torch = True
        else:
            self._use_torch = False
            self._fallback = _StatisticalSequenceDetector(window_size=sequence_length)

        self._fitted = False

    @staticmethod
    def create_sequences(
        X: np.ndarray,
        groups: Optional[np.ndarray] = None,
        seq_length: int = 10,
    ) -> tuple:
        """
        Create sliding window sequences for LSTM input.

        If groups (e.g., source IPs) are provided, sequences are created
        within each group to avoid mixing flows from different sources.

        Returns:
            sequences: (n_sequences, seq_length, n_features)
            targets: (n_sequences, n_features) — next step prediction targets
        """
        sequences = []
        targets = []

        if groups is not None:
            unique_groups = np.unique(groups)
            for grp in unique_groups:
                mask = groups == grp
                X_group = X[mask]
                if len(X_group) > seq_length:
                    for i in range(len(X_group) - seq_length):
                        sequences.append(X_group[i:i + seq_length])
                        targets.append(X_group[i + seq_length])
        else:
            for i in range(len(X) - seq_length):
                sequences.append(X[i:i + seq_length])
                targets.append(X[i + seq_length])

        if not sequences:
            return np.array([]).reshape(0, seq_length, X.shape[1]), np.array([])

        return np.array(sequences), np.array(targets)

    def fit(
        self,
        X: np.ndarray,
        groups: Optional[np.ndarray] = None,
        validation_split: float = 0.2,
    ) -> Dict[str, Any]:
        """
        Train the LSTM on normal traffic sequences.

        Args:
            X: Feature matrix (n_samples, n_features)
            groups: Group labels (e.g., source IPs) for sequence creation
            validation_split: Fraction of data for validation
        """
        logger.info(
            "Training LSTM: %d samples, %d features, seq_length=%d",
            X.shape[0], X.shape[1], self.sequence_length,
        )

        X_scaled = self.scaler.fit_transform(X)
        sequences, targets = self.create_sequences(
            X_scaled, groups, self.sequence_length
        )

        if len(sequences) == 0:
            logger.warning("No sequences generated — not enough data for seq_length=%d", self.sequence_length)
            self._fitted = True
            self.threshold_ = 1.0
            return {"error": "insufficient_data"}

        logger.info("Created %d sequences for training", len(sequences))

        if self._use_torch:
            return self._fit_torch(sequences, targets, validation_split)
        else:
            return self._fit_fallback(sequences)

    def _fit_torch(
        self, sequences: np.ndarray, targets: np.ndarray, val_split: float
    ) -> Dict[str, Any]:
        """Train using PyTorch."""
        n_val = max(1, int(len(sequences) * val_split))
        indices = np.random.permutation(len(sequences))
        train_idx, val_idx = indices[n_val:], indices[:n_val]

        X_train_seq = torch.FloatTensor(sequences[train_idx]).to(self.device)
        y_train = torch.FloatTensor(targets[train_idx]).to(self.device)
        X_val_seq = torch.FloatTensor(sequences[val_idx]).to(self.device)
        y_val = torch.FloatTensor(targets[val_idx]).to(self.device)

        train_loader = DataLoader(
            TensorDataset(X_train_seq, y_train),
            batch_size=self.batch_size,
            shuffle=True,
        )

        criterion = nn.MSELoss()
        optimizer = optim.Adam(
            self.model.parameters(), lr=self.learning_rate, weight_decay=1e-5
        )
        scheduler = optim.lr_scheduler.ReduceLROnPlateau(
            optimizer, patience=8, factor=0.5
        )

        best_val_loss = float("inf")
        patience_counter = 0
        best_state = None
        self.training_history = []

        for epoch in range(self.epochs):
            self.model.train()
            train_loss = 0.0
            for batch_x, batch_y in train_loader:
                optimizer.zero_grad()
                prediction = self.model(batch_x)
                loss = criterion(prediction, batch_y)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                optimizer.step()
                train_loss += loss.item() * len(batch_x)
            train_loss /= len(X_train_seq)

            self.model.eval()
            with torch.no_grad():
                val_pred = self.model(X_val_seq)
                val_loss = criterion(val_pred, y_val).item()

            scheduler.step(val_loss)
            self.training_history.append({
                "epoch": epoch + 1,
                "train_loss": round(train_loss, 6),
                "val_loss": round(val_loss, 6),
            })

            if (epoch + 1) % 10 == 0:
                logger.info(
                    "Epoch %d/%d — train: %.6f, val: %.6f",
                    epoch + 1, self.epochs, train_loss, val_loss,
                )

            if val_loss < best_val_loss:
                best_val_loss = val_loss
                patience_counter = 0
                best_state = {k: v.cpu().clone() for k, v in self.model.state_dict().items()}
            else:
                patience_counter += 1
                if patience_counter >= 15:
                    logger.info("Early stopping at epoch %d", epoch + 1)
                    break

        if best_state:
            self.model.load_state_dict(best_state)
            self.model.to(self.device)

        # Set threshold from training prediction errors
        errors = self._compute_errors_torch(sequences, targets)
        self.threshold_ = float(np.percentile(errors, self.threshold_percentile))
        self._fitted = True

        logger.info("LSTM trained. Threshold: %.6f", self.threshold_)
        return {
            "epochs_trained": len(self.training_history),
            "best_val_loss": best_val_loss,
            "threshold": self.threshold_,
        }

    def _fit_fallback(self, sequences: np.ndarray) -> Dict[str, Any]:
        """Train using statistical fallback."""
        self._fallback.fit(sequences)
        scores = self._fallback.score(sequences)
        self.threshold_ = float(np.percentile(scores, self.threshold_percentile))
        self._fitted = True
        return {"threshold": self.threshold_, "method": "statistical_fallback"}

    def _compute_errors_torch(
        self, sequences: np.ndarray, targets: np.ndarray
    ) -> np.ndarray:
        """Compute prediction errors for sequences."""
        self.model.eval()
        seq_tensor = torch.FloatTensor(sequences).to(self.device)
        with torch.no_grad():
            predictions = self.model(seq_tensor).cpu().numpy()
        return np.mean((targets - predictions) ** 2, axis=1)

    def score_samples(
        self,
        X: np.ndarray,
        groups: Optional[np.ndarray] = None,
    ) -> np.ndarray:
        """
        Score individual samples by creating sequences and computing errors.

        Returns per-sample anomaly scores in [0, 1].
        For samples without enough history, returns 0.0 (uncertain).
        """
        if not self._fitted:
            raise RuntimeError("LSTM not fitted. Call fit() first.")

        X_scaled = self.scaler.transform(X)
        scores = np.zeros(len(X))

        if self._use_torch:
            sequences, targets = self.create_sequences(
                X_scaled, groups, self.sequence_length
            )
            if len(sequences) > 0:
                errors = self._compute_errors_torch(sequences, targets)
                normalized = errors / (2 * self.threshold_) if self.threshold_ > 0 else errors
                normalized = np.clip(normalized, 0.0, 1.0)
                # Map scores back to original sample indices
                offset = self.sequence_length
                for i, score in enumerate(normalized):
                    if offset + i < len(scores):
                        scores[offset + i] = score
        else:
            sequences, _ = self.create_sequences(
                X_scaled, groups, self.sequence_length
            )
            if len(sequences) > 0:
                raw_scores = self._fallback.score(sequences)
                normalized = np.clip(raw_scores, 0.0, 1.0)
                offset = self.sequence_length
                for i, score in enumerate(normalized):
                    if offset + i < len(scores):
                        scores[offset + i] = score

        return scores

    def predict(self, X: np.ndarray, groups: Optional[np.ndarray] = None) -> np.ndarray:
        """Predict anomaly labels: 1 = anomaly, 0 = normal."""
        scores = self.score_samples(X, groups)
        return (scores > 0.5).astype(int)

    def save(self, path: str) -> None:
        """Save model to disk."""
        save_dir = Path(path)
        save_dir.mkdir(parents=True, exist_ok=True)

        import joblib
        joblib.dump(self.scaler, save_dir / "lstm_scaler.pkl")

        metadata = {
            "input_dim": self.input_dim,
            "hidden_dim": self.hidden_dim,
            "num_layers": self.num_layers,
            "sequence_length": self.sequence_length,
            "threshold": self.threshold_,
            "use_torch": self._use_torch,
            "trained_at": datetime.now().isoformat(),
        }
        with open(save_dir / "lstm_metadata.json", "w") as f:
            json.dump(metadata, f, indent=2)

        if self._use_torch:
            torch.save(self.model.state_dict(), save_dir / "lstm_model.pt")
        else:
            joblib.dump(self._fallback, save_dir / "lstm_fallback.pkl")

        logger.info("LSTM saved to %s", save_dir)

    def load(self, path: str) -> None:
        """Load model from disk."""
        save_dir = Path(path)
        import joblib

        self.scaler = joblib.load(save_dir / "lstm_scaler.pkl")
        with open(save_dir / "lstm_metadata.json", "r") as f:
            metadata = json.load(f)

        self.threshold_ = metadata["threshold"]
        self.sequence_length = metadata["sequence_length"]

        if metadata.get("use_torch") and self._use_torch:
            self.model.load_state_dict(
                torch.load(save_dir / "lstm_model.pt", map_location=self.device)
            )
            self.model.eval()
        elif (save_dir / "lstm_fallback.pkl").exists():
            self._fallback = joblib.load(save_dir / "lstm_fallback.pkl")
            self._use_torch = False

        self._fitted = True
        logger.info("LSTM loaded from %s", save_dir)
