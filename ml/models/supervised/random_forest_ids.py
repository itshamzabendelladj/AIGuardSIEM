"""Random Forest-based Intrusion Detection System.

Trains a Random Forest classifier on network flow features for detecting
known attack types. Supports CICIDS2017, CSE-CIC-IDS2018, and NSL-KDD datasets.

Author: AIGuard Security Team
"""

from __future__ import annotations

import pickle
import logging
from pathlib import Path
from typing import Optional, Sequence
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.utils.class_weight import compute_class_weight

logger = logging.getLogger(__name__)

# Attack type labels
ATTACK_TYPES: dict[str, int] = {
    "BENIGN": 0,
    "DoS Hulk": 1,
    "DoS GoldenEye": 2,
    "DoS slowloris": 3,
    "DoS Slowhttptest": 4,
    "PortScan": 5,
    "DDoS": 6,
    "FTP-Patator": 7,
    "SSH-Patator": 8,
    "Bot": 9,
    "Web Attack - Brute Force": 10,
    "Web Attack - XSS": 11,
    "Web Attack - Sql Injection": 12,
    "Infiltration": 13,
    "Heartbleed": 14,
}


class RandomForestIDS:
    """Random Forest-based Intrusion Detection System.

    Attributes:
        model: Trained Random Forest classifier
        scaler: Feature scaler for normalization
        label_encoder: Encoder for attack type labels
        feature_names: Names of input features
        n_estimators: Number of trees in the forest
        max_depth: Maximum tree depth

    Example:
        >>> ids = RandomForestIDS(n_estimators=100)
        >>> ids.train(X_train, y_train)
        >>> predictions = ids.predict(X_test)
        >>> ids.export_onnx("rf_ids.onnx")
    """

    def __init__(
        self,
        n_estimators: int = 100,
        max_depth: Optional[int] = None,
        max_features: str = "sqrt",
        min_samples_split: int = 2,
        min_samples_leaf: int = 1,
        class_weight: str = "balanced",
        random_state: int = 42,
        n_jobs: int = -1,
    ) -> None:
        """Initialize the Random Forest IDS.

        Args:
            n_estimators: Number of trees in the forest
            max_depth: Maximum depth of each tree
            max_features: Number of features to consider at each split
            min_samples_split: Minimum samples required to split a node
            min_samples_leaf: Minimum samples at a leaf node
            class_weight: Class weighting strategy ('balanced' or None)
            random_state: Random seed for reproducibility
            n_jobs: Number of parallel jobs (-1 for all cores)
        """
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.model: Optional[RandomForestClassifier] = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_names: list[str] = []
        self.is_trained: bool = False

        self._model_params = {
            "n_estimators": n_estimators,
            "max_depth": max_depth,
            "max_features": max_features,
            "min_samples_split": min_samples_split,
            "min_samples_leaf": min_samples_leaf,
            "class_weight": class_weight,
            "random_state": random_state,
            "n_jobs": n_jobs,
            "oob_score": True,
            "verbose": 0,
        }

    def train(
        self,
        X: np.ndarray,
        y: np.ndarray,
        feature_names: Optional[Sequence[str]] = None,
        validation_split: float = 0.2,
    ) -> dict[str, float]:
        """Train the Random Forest model.

        Args:
            X: Feature matrix of shape (n_samples, n_features)
            y: Label vector of shape (n_samples,)
            feature_names: Optional list of feature names
            validation_split: Fraction of data to use for validation

        Returns:
            Dictionary of training metrics
        """
        logger.info(f"Training Random Forest IDS with {len(X)} samples, {X.shape[1]} features")

        # Store feature names
        if feature_names:
            self.feature_names = list(feature_names)

        # Encode labels
        y_encoded = self.label_encoder.fit_transform(y)

        # Split data
        X_train, X_val, y_train, y_val = train_test_split(
            X, y_encoded, test_size=validation_split,
            random_state=42, stratify=y_encoded
        )

        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_val_scaled = self.scaler.transform(X_val)

        # Create and train model
        self.model = RandomForestClassifier(**self._model_params)
        self.model.fit(X_train_scaled, y_train)

        # Evaluate
        y_pred = self.model.predict(X_val_scaled)
        accuracy = accuracy_score(y_val, y_pred)

        # Cross-validation
        cv_scores = cross_val_score(
            self.model, X_train_scaled, y_train, cv=5, scoring="f1_weighted"
        )

        # OOB score
        oob_score = self.model.oob_score_ if hasattr(self.model, "oob_score_") else 0.0

        metrics = {
            "accuracy": float(accuracy),
            "cv_f1_mean": float(cv_scores.mean()),
            "cv_f1_std": float(cv_scores.std()),
            "oob_score": float(oob_score),
            "n_samples": int(len(X)),
            "n_features": int(X.shape[1]),
            "n_classes": int(len(self.label_encoder.classes_)),
        }

        self.is_trained = True
        logger.info(f"Training complete - Accuracy: {accuracy:.4f}, CV F1: {cv_scores.mean():.4f}")

        # Log classification report
        class_names = [str(c) for c in self.label_encoder.classes_]
        logger.info("\n" + classification_report(y_val, y_pred, target_names=class_names))

        return metrics

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict attack types for given features.

        Args:
            X: Feature matrix of shape (n_samples, n_features)

        Returns:
            Predicted labels as strings
        """
        if not self.is_trained or self.model is None:
            raise RuntimeError("Model not trained. Call train() first.")

        X_scaled = self.scaler.transform(X)
        y_pred = self.model.predict(X_scaled)
        return self.label_encoder.inverse_transform(y_pred)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Get prediction probabilities.

        Args:
            X: Feature matrix

        Returns:
            Probability matrix of shape (n_samples, n_classes)
        """
        if not self.is_trained or self.model is None:
            raise RuntimeError("Model not trained. Call train() first.")

        X_scaled = self.scaler.transform(X)
        return self.model.predict_proba(X_scaled)

    def predict_with_confidence(self, X: np.ndarray) -> list[tuple[str, float]]:
        """Predict with confidence scores.

        Args:
            X: Feature matrix

        Returns:
            List of (predicted_label, confidence) tuples
        """
        probabilities = self.predict_proba(X)
        predictions = self.predict(X)
        confidences = np.max(probabilities, axis=1)
        return list(zip(predictions, confidences))

    def feature_importance(self) -> dict[str, float]:
        """Get feature importance scores.

        Returns:
            Dictionary mapping feature names to importance scores
        """
        if not self.is_trained or self.model is None:
            raise RuntimeError("Model not trained")

        importances = self.model.feature_importances_
        names = self.feature_names or [f"feature_{i}" for i in range(len(importances))]
        return dict(zip(names, importances))

    def evaluate(self, X: np.ndarray, y: np.ndarray) -> dict[str, object]:
        """Evaluate model performance.

        Args:
            X: Feature matrix
            y: True labels

        Returns:
            Dictionary with evaluation metrics
        """
        y_pred = self.predict(X)
        y_encoded = self.label_encoder.transform(y)

        report = classification_report(
            self.label_encoder.transform(y),
            self.label_encoder.transform(y_pred),
            output_dict=True,
            zero_division=0,
        )

        cm = confusion_matrix(y, y_pred)

        return {
            "accuracy": float(accuracy_score(y, y_pred)),
            "classification_report": report,
            "confusion_matrix": cm.tolist(),
            "n_samples": int(len(y)),
        }

    def save(self, path: str | Path) -> None:
        """Save the trained model to disk.

        Args:
            path: Path to save the model
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "wb") as f:
            pickle.dump({
                "model": self.model,
                "scaler": self.scaler,
                "label_encoder": self.label_encoder,
                "feature_names": self.feature_names,
                "model_params": self._model_params,
                "is_trained": self.is_trained,
            }, f)

        logger.info(f"Model saved to {path}")

    def load(self, path: str | Path) -> None:
        """Load a trained model from disk.

        Args:
            path: Path to the saved model
        """
        path = Path(path)
        with open(path, "rb") as f:
            data = pickle.load(f)

        self.model = data["model"]
        self.scaler = data["scaler"]
        self.label_encoder = data["label_encoder"]
        self.feature_names = data["feature_names"]
        self._model_params = data["model_params"]
        self.is_trained = data["is_trained"]

        logger.info(f"Model loaded from {path}")

    def export_onnx(self, path: str | Path) -> None:
        """Export model to ONNX format for C++ inference.

        Args:
            path: Output ONNX file path
        """
        try:
            from skl2onnx import convert_sklearn
            from skl2onnx.common.data_types import FloatTensorType
        except ImportError:
            logger.warning("skl2onnx not installed. Install with: pip install skl2onnx")
            return

        if not self.is_trained or self.model is None:
            raise RuntimeError("Model not trained")

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        # Combine scaler and model into a pipeline
        from sklearn.pipeline import Pipeline
        pipeline = Pipeline([("scaler", self.scaler), ("model", self.model)])

        n_features = len(self.feature_names) if self.feature_names else 84
        initial_type = [("input", FloatTensorType([None, n_features]))]

        onnx_model = convert_sklearn(
            pipeline, initial_types=initial_type, target_opset=15
        )

        with open(path, "wb") as f:
            f.write(onnx_model.SerializeToString())

        logger.info(f"ONNX model exported to {path}")
