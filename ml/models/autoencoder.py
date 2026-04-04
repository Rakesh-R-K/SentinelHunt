"""
SentinelHunt — Deep Autoencoder Anomaly Detector

Uses reconstruction error as an anomaly score: normal traffic is
reconstructed accurately; anomalous traffic produces high error.

Architecture:
    Input(14) → 64 → 32 → 16 (bottleneck) → 32 → 64 → Output(14)

Research basis:
    - An, J. & Cho, S. (2015). Variational Autoencoder based Anomaly Detection
    - Chalapathy, R. & Chawla, S. (2019). Deep Learning for Anomaly Detection
"""

import logging
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, Tuple, Dict, Any

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger("sentinelhunt.ml.autoencoder")

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    logger.warning("PyTorch not installed — autoencoder will use sklearn fallback")


# ====================================================
# PyTorch Autoencoder Network
# ====================================================
if TORCH_AVAILABLE:
    class _AutoencoderNet(nn.Module):
        """Symmetric bottleneck autoencoder."""

        def __init__(self, input_dim: int, latent_dim: int = 8):
            super().__init__()

            self.encoder = nn.Sequential(
                nn.Linear(input_dim, 64),
                nn.BatchNorm1d(64),
                nn.LeakyReLU(0.2),
                nn.Dropout(0.2),

                nn.Linear(64, 32),
                nn.BatchNorm1d(32),
                nn.LeakyReLU(0.2),
                nn.Dropout(0.1),

                nn.Linear(32, latent_dim),
                nn.BatchNorm1d(latent_dim),
                nn.LeakyReLU(0.2),
            )

            self.decoder = nn.Sequential(
                nn.Linear(latent_dim, 32),
                nn.BatchNorm1d(32),
                nn.LeakyReLU(0.2),
                nn.Dropout(0.1),

                nn.Linear(32, 64),
                nn.BatchNorm1d(64),
                nn.LeakyReLU(0.2),
                nn.Dropout(0.2),

                nn.Linear(64, input_dim),
            )

        def forward(self, x):
            z = self.encoder(x)
            reconstruction = self.decoder(z)
            return reconstruction

        def encode(self, x):
            return self.encoder(x)


# ====================================================
# Sklearn Fallback Autoencoder (when PyTorch unavailable)
# ====================================================
class _SklearnAutoencoder:
    """Simple PCA-based reconstruction error as fallback."""

    def __init__(self, n_components: int = 8):
        from sklearn.decomposition import PCA
        self.pca = PCA(n_components=n_components)
        self.fitted = False

    def fit(self, X: np.ndarray) -> None:
        self.pca.fit(X)
        self.fitted = True

    def reconstruction_error(self, X: np.ndarray) -> np.ndarray:
        Z = self.pca.transform(X)
        X_hat = self.pca.inverse_transform(Z)
        return np.mean((X - X_hat) ** 2, axis=1)


# ====================================================
# Autoencoder Anomaly Detector (public API)
# ====================================================
class AutoencoderDetector:
    """
    Deep autoencoder for network anomaly detection.

    Train on normal traffic only. At inference time, flows with
    reconstruction error above a learned threshold are flagged
    as anomalous.
    """

    def __init__(
        self,
        input_dim: int = 14,
        latent_dim: int = 8,
        epochs: int = 100,
        batch_size: int = 64,
        learning_rate: float = 1e-3,
        threshold_percentile: float = 95.0,
        device: Optional[str] = None,
    ):
        self.input_dim = input_dim
        self.latent_dim = latent_dim
        self.epochs = epochs
        self.batch_size = batch_size
        self.learning_rate = learning_rate
        self.threshold_percentile = threshold_percentile
        self.threshold_: Optional[float] = None
        self.training_history: list = []
        self.scaler = StandardScaler()

        if TORCH_AVAILABLE:
            self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
            self.model = _AutoencoderNet(input_dim, latent_dim).to(self.device)
            self._use_torch = True
        else:
            self._use_torch = False
            self._fallback = _SklearnAutoencoder(n_components=latent_dim)

        self._fitted = False

    def fit(self, X: np.ndarray, validation_split: float = 0.2) -> Dict[str, Any]:
        """
        Train the autoencoder on normal traffic data.

        Returns training metadata including loss history.
        """
        logger.info(
            "Training autoencoder: %d samples, %d features, %d epochs",
            X.shape[0], X.shape[1], self.epochs,
        )

        X_scaled = self.scaler.fit_transform(X)

        if self._use_torch:
            return self._fit_torch(X_scaled, validation_split)
        else:
            return self._fit_fallback(X_scaled)

    def _fit_torch(self, X: np.ndarray, val_split: float) -> Dict[str, Any]:
        """Train using PyTorch with early stopping."""
        # Split data
        n_val = int(len(X) * val_split)
        indices = np.random.permutation(len(X))
        train_idx, val_idx = indices[n_val:], indices[:n_val]

        X_train = torch.FloatTensor(X[train_idx]).to(self.device)
        X_val = torch.FloatTensor(X[val_idx]).to(self.device)

        train_loader = DataLoader(
            TensorDataset(X_train, X_train),
            batch_size=self.batch_size,
            shuffle=True,
        )

        criterion = nn.MSELoss()
        optimizer = optim.Adam(self.model.parameters(), lr=self.learning_rate,
                               weight_decay=1e-5)
        scheduler = optim.lr_scheduler.ReduceLROnPlateau(
            optimizer, patience=10, factor=0.5, min_lr=1e-6
        )

        best_val_loss = float("inf")
        patience_counter = 0
        best_state = None

        self.training_history = []

        for epoch in range(self.epochs):
            # Training
            self.model.train()
            train_loss = 0.0
            for batch_x, _ in train_loader:
                optimizer.zero_grad()
                reconstruction = self.model(batch_x)
                loss = criterion(reconstruction, batch_x)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                optimizer.step()
                train_loss += loss.item() * len(batch_x)
            train_loss /= len(X_train)

            # Validation
            self.model.eval()
            with torch.no_grad():
                val_reconstruction = self.model(X_val)
                val_loss = criterion(val_reconstruction, X_val).item()

            scheduler.step(val_loss)

            self.training_history.append({
                "epoch": epoch + 1,
                "train_loss": round(train_loss, 6),
                "val_loss": round(val_loss, 6),
            })

            if (epoch + 1) % 20 == 0:
                logger.info(
                    "Epoch %d/%d — train_loss: %.6f, val_loss: %.6f",
                    epoch + 1, self.epochs, train_loss, val_loss,
                )

            # Early stopping
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                patience_counter = 0
                best_state = {k: v.cpu().clone() for k, v in self.model.state_dict().items()}
            else:
                patience_counter += 1
                if patience_counter >= 20:
                    logger.info("Early stopping at epoch %d", epoch + 1)
                    break

        # Restore best model
        if best_state:
            self.model.load_state_dict(best_state)
            self.model.to(self.device)

        # Set anomaly threshold from training data reconstruction errors
        errors = self._compute_errors_torch(X)
        self.threshold_ = float(np.percentile(errors, self.threshold_percentile))
        self._fitted = True

        logger.info(
            "Autoencoder trained. Threshold (p%.1f): %.6f",
            self.threshold_percentile, self.threshold_,
        )

        return {
            "epochs_trained": len(self.training_history),
            "best_val_loss": best_val_loss,
            "threshold": self.threshold_,
            "history": self.training_history,
        }

    def _fit_fallback(self, X: np.ndarray) -> Dict[str, Any]:
        """Train using sklearn PCA fallback."""
        self._fallback.fit(X)
        errors = self._fallback.reconstruction_error(X)
        self.threshold_ = float(np.percentile(errors, self.threshold_percentile))
        self._fitted = True
        logger.info("Autoencoder (PCA fallback) trained. Threshold: %.6f", self.threshold_)
        return {"threshold": self.threshold_, "method": "pca_fallback"}

    def _compute_errors_torch(self, X: np.ndarray) -> np.ndarray:
        """Compute per-sample reconstruction errors."""
        self.model.eval()
        X_tensor = torch.FloatTensor(X).to(self.device)
        with torch.no_grad():
            reconstruction = self.model(X_tensor).cpu().numpy()
        return np.mean((X - reconstruction) ** 2, axis=1)

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """
        Score samples by reconstruction error (higher = more anomalous).

        Returns normalized anomaly scores in [0, 1].
        """
        if not self._fitted:
            raise RuntimeError("Autoencoder not fitted. Call fit() first.")

        X_scaled = self.scaler.transform(X)

        if self._use_torch:
            errors = self._compute_errors_torch(X_scaled)
        else:
            errors = self._fallback.reconstruction_error(X_scaled)

        # Normalize: map [0, 2*threshold] → [0, 1], clip outliers
        scores = errors / (2 * self.threshold_) if self.threshold_ > 0 else errors
        return np.clip(scores, 0.0, 1.0)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict anomaly labels: 1 = anomaly, 0 = normal.
        """
        scores = self.score_samples(X)
        threshold_normalized = 0.5  # Maps to self.threshold_ in original space
        return (scores > threshold_normalized).astype(int)

    def save(self, path: str) -> None:
        """Save model to disk."""
        save_dir = Path(path)
        save_dir.mkdir(parents=True, exist_ok=True)

        # Save scaler and metadata
        import joblib
        joblib.dump(self.scaler, save_dir / "ae_scaler.pkl")

        metadata = {
            "input_dim": self.input_dim,
            "latent_dim": self.latent_dim,
            "threshold": self.threshold_,
            "threshold_percentile": self.threshold_percentile,
            "use_torch": self._use_torch,
            "trained_at": datetime.now().isoformat(),
            "training_history": self.training_history,
        }
        with open(save_dir / "ae_metadata.json", "w") as f:
            json.dump(metadata, f, indent=2)

        if self._use_torch:
            torch.save(self.model.state_dict(), save_dir / "autoencoder.pt")
        else:
            joblib.dump(self._fallback, save_dir / "autoencoder_fallback.pkl")

        logger.info("Autoencoder saved to %s", save_dir)

    def load(self, path: str) -> None:
        """Load model from disk."""
        save_dir = Path(path)
        import joblib

        self.scaler = joblib.load(save_dir / "ae_scaler.pkl")

        with open(save_dir / "ae_metadata.json", "r") as f:
            metadata = json.load(f)

        self.threshold_ = metadata["threshold"]
        self.threshold_percentile = metadata["threshold_percentile"]
        self.training_history = metadata.get("training_history", [])

        if metadata.get("use_torch") and self._use_torch:
            self.model.load_state_dict(
                torch.load(save_dir / "autoencoder.pt", map_location=self.device)
            )
            self.model.eval()
        elif (save_dir / "autoencoder_fallback.pkl").exists():
            self._fallback = joblib.load(save_dir / "autoencoder_fallback.pkl")
            self._use_torch = False

        self._fitted = True
        logger.info("Autoencoder loaded from %s", save_dir)
