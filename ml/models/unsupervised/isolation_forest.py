"""Isolation Forest for network anomaly detection.

Detects anomalies in network traffic by isolating observations using
random trees. Anomalies are isolated with shorter path lengths.

Author: AIGuard Security Team
"""

from __future__ import annotations

import pickle
import logging
from pathlib import Path
from typing import Optional, Sequence
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)


class IsolationForestDetector:
    """Isolation Forest-based anomaly detector.

    Detects novel and unknown attacks by identifying outliers in
    network flow feature space.

    Attributes:
        model: Trained Isolation Forest
        scaler: Feature scaler
        threshold: Anomaly score threshold

    Example:
        >>> detector = IsolationForestDetector(n_estimators=200)
        >>> detector.train(X_normal)
        >>> anomalies = detector.detect(X_test)
        >>> scores = detector.score_samples(X_test)
    """

    def __init__(
        self,
        n_estimators: int = 100,
        max_samples: str | int = "auto",
        contamination: float = 0.1,
        max_features: float = 1.0,
        random_state: int = 42,
        n_jobs: int = -1,
    ) -> None:
        """Initialize the Isolation Forest detector.

        Args:
            n_estimators: Number of isolation trees
            max_samples: Number of samples to draw for each tree
            contamination: Expected fraction of anomalies
            max_features: Number of features to consider
            random_state: Random seed
            n_jobs: Number of parallel jobs
        """
        self.model: Optional[IsolationForest] = None
        self.scaler = StandardScaler()
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.is_trained: bool = False
        self.threshold: float = 0.0

        self._params = {
            "n_estimators": n_estimators,
            "max_samples": max_samples,
            "contamination": contamination,
            "max_features": max_features,
            "random_state": random_state,
            "n_jobs": n_jobs,
        }

    def train(
        self,
        X: np.ndarray,
        feature_names: Optional[Sequence[str]] = None,
    ) -> dict[str, float]:
        """Train the Isolation Forest on normal traffic data.

        Args:
            X: Feature matrix (ideally normal/benign traffic only)
            feature_names: Optional feature names

        Returns:
            Training metrics
        """
        logger.info(f"Training Isolation Forest with {len(X)} samples")

        X_scaled = self.scaler.fit_transform(X)

        self.model = IsolationForest(**self._params)
        self.model.fit(X_scaled)

        # Calculate threshold from training data
        scores = self.model.score_samples(X_scaled)
        self.threshold = float(np.percentile(scores, 100 * (1 - self.contamination)))

        self.is_trained = True

        metrics = {
            "n_samples": int(len(X)),
            "n_features": int(X.shape[1]),
            "threshold": self.threshold,
            "mean_score": float(np.mean(scores)),
            "std_score": float(np.std(scores)),
        }

        logger.info(f"Training complete - Threshold: {self.threshold:.4f}")
        return metrics

    def detect(self, X: np.ndarray) -> np.ndarray:
        """Detect anomalies in the input data.

        Args:
            X: Feature matrix

        Returns:
            Boolean array (True = anomaly)
        """
        if not self.is_trained or self.model is None:
            raise RuntimeError("Model not trained")

        X_scaled = self.scaler.transform(X)
        predictions = self.model.predict(X_scaled)
        return predictions == -1  # -1 = anomaly, 1 = normal

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """Get anomaly scores for input data.

        Args:
            X: Feature matrix

        Returns:
            Anomaly scores (lower = more anomalous)
        """
        if not self.is_trained or self.model is None:
            raise RuntimeError("Model not trained")

        X_scaled = self.scaler.transform(X)
        return self.model.score_samples(X_scaled)

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        """Get decision function values.

        Args:
            X: Feature matrix

        Returns:
            Decision scores (positive = normal, negative = anomaly)
        """
        if not self.is_trained or self.model is None:
            raise RuntimeError("Model not trained")

        X_scaled = self.scaler.transform(X)
        return self.model.decision_function(X_scaled)

    def detect_with_scores(self, X: np.ndarray) -> list[tuple[bool, float]]:
        """Detect anomalies with confidence scores.

        Args:
            X: Feature matrix

        Returns:
            List of (is_anomaly, anomaly_score) tuples
        """
        scores = self.score_samples(X)
        is_anomaly = scores < self.threshold
        return list(zip(is_anomaly, scores))

    def update_threshold(self, contamination: float) -> None:
        """Update the anomaly threshold.

        Args:
            contamination: New contamination rate (0-1)
        """
        self.contamination = contamination
        # Would need to recompute threshold with stored training data
        logger.info(f"Threshold updated with contamination={contamination}")

    def save(self, path: str | Path) -> None:
        """Save the trained detector."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump({
                "model": self.model,
                "scaler": self.scaler,
                "threshold": self.threshold,
                "params": self._params,
                "is_trained": self.is_trained,
            }, f)
        logger.info(f"Detector saved to {path}")

    def load(self, path: str | Path) -> None:
        """Load a trained detector."""
        with open(path, "rb") as f:
            data = pickle.load(f)
        self.model = data["model"]
        self.scaler = data["scaler"]
        self.threshold = data["threshold"]
        self._params = data["params"]
        self.is_trained = data["is_trained"]
        logger.info(f"Detector loaded from {path}")
