"""Model ensemble voting system for ML-based intrusion detection.

Combines predictions from multiple models (Random Forest, XGBoost, LSTM, CNN)
using weighted voting to improve detection accuracy and reduce false positives.

Author: AIGuard Security Team
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional, Sequence
import numpy as np

logger = logging.getLogger(__name__)


class EnsembleVoter:
    """Weighted ensemble voting system for combining model predictions.

    Supports multiple voting strategies:
        - Majority voting
        - Weighted voting (model weights)
        - Stacking (meta-learner over base model predictions)
        - Soft voting (probability averaging)

    Attributes:
        models: List of (model_name, model, weight) tuples
        strategy: Voting strategy ('majority', 'weighted', 'soft', 'stacking')

    Example:
        >>> ensemble = EnsembleVoter(strategy="weighted")
        >>> ensemble.add_model("rf", rf_model, weight=0.4)
        >>> ensemble.add_model("xgb", xgb_model, weight=0.35)
        >>> ensemble.add_model("lstm", lstm_model, weight=0.25)
        >>> predictions = ensemble.predict(X)
    """

    def __init__(
        self,
        strategy: str = "weighted",
        threshold: float = 0.5,
    ) -> None:
        """Initialize the ensemble voter.

        Args:
            strategy: Voting strategy ('majority', 'weighted', 'soft', 'stacking')
            threshold: Decision threshold for binary predictions
        """
        self.strategy = strategy
        self.threshold = threshold
        self.models: list[dict[str, object]] = []
        self.is_fitted = False
        self.meta_learner = None

        logger.info(f"Ensemble voter initialized with strategy: {strategy}")

    def add_model(
        self,
        name: str,
        model: object,
        weight: float = 1.0,
        is_anomaly_detector: bool = False,
    ) -> None:
        """Add a model to the ensemble.

        Args:
            name: Model name
            model: Model object (must have predict/predict_proba methods)
            weight: Model weight for weighted voting
            is_anomaly_detector: Whether model is an anomaly detector
        """
        self.models.append({
            "name": name,
            "model": model,
            "weight": weight,
            "is_anomaly_detector": is_anomaly_detector,
        })
        logger.info(f"Added model '{name}' with weight {weight}")

    def set_weights(self, weights: dict[str, float]) -> None:
        """Update model weights.

        Args:
            weights: Dictionary of model_name -> weight
        """
        for entry in self.models:
            if entry["name"] in weights:
                entry["weight"] = weights[entry["name"]]
        logger.info(f"Updated weights: {weights}")

    def normalize_weights(self) -> None:
        """Normalize weights to sum to 1."""
        total = sum(entry["weight"] for entry in self.models)
        if total > 0:
            for entry in self.models:
                entry["weight"] = entry["weight"] / total

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Get ensemble predictions.

        Args:
            X: Feature matrix

        Returns:
            Predicted labels
        """
        if self.strategy == "majority":
            return self._majority_vote(X)
        elif self.strategy == "weighted":
            return self._weighted_vote(X)
        elif self.strategy == "soft":
            return self._soft_vote(X)
        elif self.strategy == "stacking":
            return self._stacking_predict(X)
        else:
            raise ValueError(f"Unknown strategy: {self.strategy}")

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Get ensemble probability predictions.

        Args:
            X: Feature matrix

        Returns:
            Probability matrix
        """
        if self.strategy == "soft":
            return self._soft_proba(X)
        elif self.strategy == "weighted":
            return self._weighted_proba(X)
        else:
            # For other strategies, return binary probabilities
            predictions = self.predict(X)
            n_classes = 2
            proba = np.zeros((len(predictions), n_classes))
            for i, pred in enumerate(predictions):
                proba[i, int(pred)] = 1.0
            return proba

    def _majority_vote(self, X: np.ndarray) -> np.ndarray:
        """Majority voting prediction."""
        predictions = []
        for entry in self.models:
            model = entry["model"]
            if entry["is_anomaly_detector"]:
                pred = model.detect(X) if hasattr(model, "detect") else model.predict(X)
            else:
                pred = model.predict(X) if hasattr(model, "predict") else model(X)
            predictions.append(np.asarray(pred).ravel())

        predictions = np.array(predictions)
        # Majority vote
        from scipy.stats import mode
        result, _ = mode(predictions, axis=0, keepdims=False)
        return result

    def _weighted_vote(self, X: np.ndarray) -> np.ndarray:
        """Weighted voting prediction."""
        self.normalize_weights()

        all_predictions = []
        all_weights = []

        for entry in self.models:
            model = entry["model"]
            weight = entry["weight"]

            if entry["is_anomaly_detector"]:
                pred = model.detect(X) if hasattr(model, "detect") else model.predict(X)
            else:
                pred = model.predict(X) if hasattr(model, "predict") else model(X)

            all_predictions.append(np.asarray(pred).ravel())
            all_weights.append(weight)

        # Weighted vote
        predictions = np.array(all_predictions)
        weights = np.array(all_weights)

        # For each sample, compute weighted vote
        unique_labels = np.unique(predictions)
        result = np.zeros(predictions.shape[1])

        for i in range(predictions.shape[1]):
            scores = {}
            for j, label in enumerate(predictions[:, i]):
                scores[label] = scores.get(label, 0) + weights[j]
            result[i] = max(scores, key=scores.get)

        return result

    def _soft_vote(self, X: np.ndarray) -> np.ndarray:
        """Soft voting (probability averaging)."""
        self.normalize_weights()

        all_proba = []
        all_weights = []

        for entry in self.models:
            model = entry["model"]
            weight = entry["weight"]

            if hasattr(model, "predict_proba"):
                proba = model.predict_proba(X)
            elif hasattr(model, "decision_function"):
                scores = model.decision_function(X)
                proba = np.column_stack([1 - scores, scores])
            else:
                pred = model.predict(X) if hasattr(model, "predict") else model(X)
                proba = np.zeros((len(pred), 2))
                for i, p in enumerate(pred):
                    proba[i, int(p)] = 1.0

            all_proba.append(np.asarray(proba))
            all_weights.append(weight)

        # Weighted average of probabilities
        weights = np.array(all_weights)
        weights = weights / weights.sum()

        avg_proba = np.zeros_like(all_proba[0])
        for proba, w in zip(all_proba, weights):
            avg_proba += proba * w

        return np.argmax(avg_proba, axis=1)

    def _soft_proba(self, X: np.ndarray) -> np.ndarray:
        """Get soft voting probabilities."""
        self.normalize_weights()

        all_proba = []
        all_weights = []

        for entry in self.models:
            model = entry["model"]
            weight = entry["weight"]

            if hasattr(model, "predict_proba"):
                proba = model.predict_proba(X)
            elif hasattr(model, "decision_function"):
                scores = model.decision_function(X)
                proba = np.column_stack([1 - scores, scores])
            else:
                pred = model.predict(X)
                proba = np.zeros((len(pred), 2))
                for i, p in enumerate(pred):
                    proba[i, int(p)] = 1.0

            all_proba.append(np.asarray(proba))
            all_weights.append(weight)

        weights = np.array(all_weights)
        weights = weights / weights.sum()

        avg_proba = np.zeros_like(all_proba[0])
        for proba, w in zip(all_proba, weights):
            avg_proba += proba * w

        return avg_proba

    def _weighted_proba(self, X: np.ndarray) -> np.ndarray:
        """Get weighted voting probabilities."""
        return self._soft_proba(X)

    def _stacking_predict(self, X: np.ndarray) -> np.ndarray:
        """Stacking prediction using meta-learner."""
        if not self.is_fitted or self.meta_learner is None:
            raise RuntimeError("Stacking ensemble not fitted. Call fit() first.")

        meta_features = self._get_meta_features(X)
        return self.meta_learner.predict(meta_features)

    def _get_meta_features(self, X: np.ndarray) -> np.ndarray:
        """Get meta-features from base models."""
        meta_features = []

        for entry in self.models:
            model = entry["model"]
            if hasattr(model, "predict_proba"):
                proba = model.predict_proba(X)
                meta_features.append(proba)
            elif hasattr(model, "decision_function"):
                scores = model.decision_function(X)
                meta_features.append(scores.reshape(-1, 1))
            else:
                pred = model.predict(X)
                meta_features.append(pred.reshape(-1, 1))

        return np.hstack(meta_features)

    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        meta_learner: Optional[object] = None,
    ) -> "EnsembleVoter":
        """Fit the ensemble (for stacking strategy).

        Args:
            X: Feature matrix
            y: Labels
            meta_learner: Meta-learner model (default: LogisticRegression)

        Returns:
            Self
        """
        if self.strategy != "stacking":
            logger.info("Fit only needed for stacking strategy")
            return self

        if meta_learner is None:
            from sklearn.linear_model import LogisticRegression
            meta_learner = LogisticRegression(max_iter=1000)

        self.meta_learner = meta_learner
        meta_features = self._get_meta_features(X)
        self.meta_learner.fit(meta_features, y)
        self.is_fitted = True

        logger.info("Stacking ensemble fitted")
        return self

    def evaluate(
        self,
        X: np.ndarray,
        y: np.ndarray,
    ) -> dict[str, object]:
        """Evaluate ensemble performance.

        Args:
            X: Feature matrix
            y: True labels

        Returns:
            Evaluation metrics
        """
        from sklearn.metrics import (
            accuracy_score, precision_score, recall_score, f1_score,
            classification_report,
        )

        predictions = self.predict(X)

        metrics = {
            "accuracy": float(accuracy_score(y, predictions)),
            "precision": float(precision_score(y, predictions, average="weighted", zero_division=0)),
            "recall": float(recall_score(y, predictions, average="weighted", zero_division=0)),
            "f1": float(f1_score(y, predictions, average="weighted", zero_division=0)),
            "n_samples": int(len(y)),
            "n_models": int(len(self.models)),
            "strategy": self.strategy,
        }

        logger.info(f"Ensemble evaluation - Accuracy: {metrics['accuracy']:.4f}, F1: {metrics['f1']:.4f}")
        return metrics

    def get_model_summary(self) -> list[dict[str, object]]:
        """Get summary of all models in the ensemble."""
        return [
            {
                "name": entry["name"],
                "weight": float(entry["weight"]),
                "type": type(entry["model"]).__name__,
                "is_anomaly_detector": entry["is_anomaly_detector"],
            }
            for entry in self.models
        ]
