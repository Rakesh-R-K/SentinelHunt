"""
SentinelHunt — ML Model Unit Tests

Tests model initialization, fitting, prediction shape, and score ranges.
"""

import pytest
import numpy as np
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class TestAutoencoderDetector:
    """Tests for the autoencoder anomaly detector."""

    def test_initialization(self):
        from ml.models.autoencoder import AutoencoderDetector
        detector = AutoencoderDetector(input_dim=14, latent_dim=8, epochs=5)
        assert detector.input_dim == 14
        assert detector._fitted is False

    def test_fit_and_predict(self, sample_feature_matrix):
        from ml.models.autoencoder import AutoencoderDetector
        detector = AutoencoderDetector(input_dim=14, latent_dim=8, epochs=5, batch_size=32)
        result = detector.fit(sample_feature_matrix, validation_split=0.2)
        assert "threshold" in result or "error" not in result

        scores = detector.score_samples(sample_feature_matrix)
        assert len(scores) == len(sample_feature_matrix)
        assert all(0 <= s <= 1 for s in scores)

        predictions = detector.predict(sample_feature_matrix)
        assert len(predictions) == len(sample_feature_matrix)
        assert set(predictions).issubset({0, 1})

    def test_save_and_load(self, sample_feature_matrix, tmp_path):
        from ml.models.autoencoder import AutoencoderDetector
        detector = AutoencoderDetector(input_dim=14, epochs=3)
        detector.fit(sample_feature_matrix)

        save_path = str(tmp_path / "ae_model")
        detector.save(save_path)

        loaded = AutoencoderDetector(input_dim=14)
        loaded.load(save_path)

        original_scores = detector.score_samples(sample_feature_matrix[:10])
        loaded_scores = loaded.score_samples(sample_feature_matrix[:10])
        np.testing.assert_array_almost_equal(original_scores, loaded_scores, decimal=3)


class TestEnsembleDetector:
    """Tests for the ensemble anomaly detector."""

    def test_initialization(self):
        from ml.models.ensemble import EnsembleDetector
        ensemble = EnsembleDetector()
        assert not ensemble._fitted

    def test_fit_and_predict(self, sample_feature_matrix):
        from ml.models.ensemble import EnsembleDetector
        ensemble = EnsembleDetector(
            autoencoder_params={"epochs": 3, "input_dim": 14},
        )
        results = ensemble.fit(sample_feature_matrix, validation_split=0.2)
        assert isinstance(results, dict)

        scores = ensemble.score_samples(sample_feature_matrix)
        assert len(scores) == len(sample_feature_matrix)
        assert all(0 <= s <= 1 for s in scores)

    def test_predict_with_details(self, sample_feature_matrix):
        from ml.models.ensemble import EnsembleDetector
        ensemble = EnsembleDetector(
            autoencoder_params={"epochs": 3, "input_dim": 14},
        )
        ensemble.fit(sample_feature_matrix)

        details = ensemble.predict_with_details(sample_feature_matrix[:5])
        assert len(details) == 5
        for detail in details:
            assert "ensemble_score" in detail
            assert "model_scores" in detail
            assert "voter_agreement" in detail


class TestLSTMDetector:
    """Tests for the LSTM temporal detector."""

    def test_initialization(self):
        from ml.models.lstm_detector import LSTMDetector
        detector = LSTMDetector(input_dim=14, sequence_length=5, epochs=3)
        assert detector.sequence_length == 5

    def test_create_sequences(self, sample_feature_matrix):
        from ml.models.lstm_detector import LSTMDetector
        sequences, targets = LSTMDetector.create_sequences(
            sample_feature_matrix, seq_length=5
        )
        assert sequences.shape[1] == 5
        assert sequences.shape[2] == sample_feature_matrix.shape[1]
        assert len(targets) == len(sequences)

    def test_fit_and_score(self, sample_feature_matrix):
        from ml.models.lstm_detector import LSTMDetector
        detector = LSTMDetector(
            input_dim=14, sequence_length=5, epochs=3, batch_size=16
        )
        result = detector.fit(sample_feature_matrix)
        assert isinstance(result, dict)

        scores = detector.score_samples(sample_feature_matrix)
        assert len(scores) == len(sample_feature_matrix)
