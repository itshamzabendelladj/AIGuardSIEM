"""End-to-end ML training pipeline for intrusion detection models.

Orchestrates the complete ML workflow: data loading, preprocessing,
model training, evaluation, and ONNX export.

Author: AIGuard Security Team
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Optional, Sequence
import numpy as np
import pandas as pd
from dataclasses import dataclass, field

from ml.models.supervised.random_forest_ids import RandomForestIDS
from ml.models.unsupervised.isolation_forest import IsolationForestDetector
from ml.inference.ensemble import EnsembleVoter

logger = logging.getLogger(__name__)


@dataclass
class TrainingConfig:
    """Configuration for the training pipeline."""
    # Data paths
    train_data_path: str = ""
    test_data_path: str = ""
    validation_split: float = 0.2

    # Feature columns
    feature_columns: list[str] = field(default_factory=list)
    label_column: str = "label"

    # Model configurations
    rf_n_estimators: int = 100
    rf_max_depth: Optional[int] = None
    if_n_estimators: int = 200
    if_contamination: float = 0.1

    # Ensemble
    ensemble_strategy: str = "weighted"
    rf_weight: float = 0.4
    if_weight: float = 0.3
    xgb_weight: float = 0.3

    # Output
    model_output_dir: str = "models"
    export_onnx: bool = True

    # Training
    random_state: int = 42
    n_jobs: int = -1


class TrainingPipeline:
    """End-to-end ML training pipeline.

    Orchestrates:
        1. Data loading and preprocessing
        2. Feature engineering
        3. Model training (supervised + unsupervised)
        4. Model evaluation
        5. Ensemble creation
        6. ONNX export
        7. Model artifact persistence

    Example:
        >>> config = TrainingConfig(train_data_path="data/cicids2017.csv")
        >>> pipeline = TrainingPipeline(config)
        >>> results = pipeline.run()
    """

    def __init__(self, config: TrainingConfig) -> None:
        """Initialize the training pipeline.

        Args:
            config: Training configuration
        """
        self.config = config
        self.models: dict[str, object] = {}
        self.metrics: dict[str, dict] = {}
        self.ensemble: Optional[EnsembleVoter] = None

        # Create output directory
        Path(config.model_output_dir).mkdir(parents=True, exist_ok=True)

    def load_data(self, path: str) -> tuple[np.ndarray, np.ndarray, list[str]]:
        """Load and preprocess training data.

        Args:
            path: Path to CSV data file

        Returns:
            Tuple of (features, labels, feature_names)
        """
        logger.info(f"Loading data from {path}")

        df = pd.read_csv(path, low_memory=False)

        # Clean column names
        df.columns = df.columns.str.strip()

        # Determine feature columns
        if self.config.feature_columns:
            feature_cols = self.config.feature_columns
        else:
            # Exclude label and non-numeric columns
            feature_cols = [
                col for col in df.columns
                if col != self.config.label_column and df[col].dtype in
                [np.float64, np.int64, np.float32, np.int32]
            ]

        # Extract features and labels
        X = df[feature_cols].values.astype(np.float32)
        y = df[self.config.label_column].values

        # Handle NaN and infinity
        X = np.nan_to_num(X, nan=0.0, posinf=1e10, neginf=-1e10)

        logger.info(f"Loaded {len(X)} samples with {X.shape[1]} features")
        logger.info(f"Labels: {np.unique(y, return_counts=True)}")

        return X, y, feature_cols

    def preprocess(
        self,
        X: np.ndarray,
        y: np.ndarray,
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Preprocess data: split, normalize, balance.

        Args:
            X: Features
            y: Labels

        Returns:
            Tuple of (X_train, X_test, y_train, y_test, X_val, y_val)
        """
        from sklearn.model_selection import train_test_split

        # Split into train+val and test
        X_trainval, X_test, y_trainval, y_test = train_test_split(
            X, y, test_size=0.2, random_state=self.config.random_state, stratify=y
        )

        # Split train into train and validation
        X_train, X_val, y_train, y_val = train_test_split(
            X_trainval, y_trainval, test_size=self.config.validation_split,
            random_state=self.config.random_state, stratify=y_trainval
        )

        logger.info(f"Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")

        return X_train, X_test, y_train, y_test, X_val, y_val

    def train_random_forest(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        feature_names: list[str],
    ) -> RandomForestIDS:
        """Train Random Forest IDS model."""
        logger.info("Training Random Forest IDS")
        start_time = time.time()

        model = RandomForestIDS(
            n_estimators=self.config.rf_n_estimators,
            max_depth=self.config.rf_max_depth,
            random_state=self.config.random_state,
            n_jobs=self.config.n_jobs,
        )
        metrics = model.train(X_train, y_train, feature_names=feature_names)
        metrics["training_time_s"] = time.time() - start_time

        self.models["random_forest"] = model
        self.metrics["random_forest"] = metrics

        # Save model
        model_path = Path(self.config.model_output_dir) / "random_forest_ids.pkl"
        model.save(model_path)

        if self.config.export_onnx:
            onnx_path = Path(self.config.model_output_dir) / "random_forest_ids.onnx"
            model.export_onnx(onnx_path)

        logger.info(f"Random Forest trained in {metrics['training_time_s']:.1f}s")
        return model

    def train_isolation_forest(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
    ) -> IsolationForestDetector:
        """Train Isolation Forest anomaly detector."""
        logger.info("Training Isolation Forest detector")
        start_time = time.time()

        # Train on benign traffic only
        benign_mask = y_train == "BENIGN" if isinstance(y_train[0], str) else y_train == 0
        X_benign = X_train[benign_mask]

        if len(X_benign) == 0:
            logger.warning("No benign samples found, training on all data")
            X_benign = X_train

        model = IsolationForestDetector(
            n_estimators=self.config.if_n_estimators,
            contamination=self.config.if_contamination,
            random_state=self.config.random_state,
            n_jobs=self.config.n_jobs,
        )
        metrics = model.train(X_benign)
        metrics["training_time_s"] = time.time() - start_time

        self.models["isolation_forest"] = model
        self.metrics["isolation_forest"] = metrics

        # Save model
        model_path = Path(self.config.model_output_dir) / "isolation_forest.pkl"
        model.save(model_path)

        logger.info(f"Isolation Forest trained in {metrics['training_time_s']:.1f}s")
        return model

    def train_xgboost(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
    ) -> Optional[object]:
        """Train XGBoost model."""
        try:
            import xgboost as xgb
            from sklearn.preprocessing import LabelEncoder
        except ImportError:
            logger.warning("XGBoost not installed, skipping")
            return None

        logger.info("Training XGBoost model")
        start_time = time.time()

        le = LabelEncoder()
        y_encoded = le.fit_transform(y_train)

        model = xgb.XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=self.config.random_state,
            n_jobs=self.config.n_jobs,
            use_label_encoder=False,
            eval_metric="mlogloss",
        )
        model.fit(X_train, y_encoded)

        metrics = {
            "training_time_s": time.time() - start_time,
            "n_classes": len(le.classes_),
        }

        self.models["xgboost"] = model
        self.models["xgboost_label_encoder"] = le
        self.metrics["xgboost"] = metrics

        # Save model
        import pickle
        model_path = Path(self.config.model_output_dir) / "xgboost_ids.pkl"
        with open(model_path, "wb") as f:
            pickle.dump({"model": model, "label_encoder": le}, f)

        logger.info(f"XGBoost trained in {metrics['training_time_s']:.1f}s")
        return model

    def create_ensemble(self) -> EnsembleVoter:
        """Create ensemble from trained models."""
        logger.info("Creating model ensemble")

        ensemble = EnsembleVoter(strategy=self.config.ensemble_strategy)

        if "random_forest" in self.models:
            ensemble.add_model("random_forest", self.models["random_forest"],
                             weight=self.config.rf_weight)

        if "isolation_forest" in self.models:
            ensemble.add_model("isolation_forest", self.models["isolation_forest"],
                             weight=self.config.if_weight, is_anomaly_detector=True)

        if "xgboost" in self.models:
            ensemble.add_model("xgboost", self.models["xgboost"],
                             weight=self.config.xgb_weight)

        self.ensemble = ensemble
        logger.info(f"Ensemble created with {len(self.models)} models")
        return ensemble

    def evaluate_all(self, X_test: np.ndarray, y_test: np.ndarray) -> dict[str, dict]:
        """Evaluate all trained models."""
        results = {}

        for name, model in self.models.items():
            if name == "xgboost_label_encoder":
                continue

            logger.info(f"Evaluating {name}")
            try:
                if name == "random_forest":
                    metrics = model.evaluate(X_test, y_test)
                elif name == "isolation_forest":
                    from sklearn.metrics import classification_report
                    predictions = model.detect(X_test)
                    y_binary = np.where(y_test == "BENIGN" if isinstance(y_test[0], str)
                                       else y_test == 0, 0, 1)
                    report = classification_report(
                        y_binary, predictions.astype(int), output_dict=True, zero_division=0
                    )
                    metrics = {"classification_report": report}
                elif name == "xgboost":
                    from sklearn.metrics import classification_report, accuracy_score
                    le = self.models["xgboost_label_encoder"]
                    y_encoded = le.transform(y_test)
                    predictions = model.predict(X_test)
                    metrics = {
                        "accuracy": float(accuracy_score(y_encoded, predictions)),
                        "classification_report": classification_report(
                            y_encoded, predictions, output_dict=True, zero_division=0
                        ),
                    }
                else:
                    continue

                results[name] = metrics
            except Exception as e:
                logger.error(f"Failed to evaluate {name}: {e}")
                results[name] = {"error": str(e)}

        # Evaluate ensemble
        if self.ensemble:
            try:
                ensemble_metrics = self.ensemble.evaluate(X_test, y_test)
                results["ensemble"] = ensemble_metrics
            except Exception as e:
                logger.error(f"Failed to evaluate ensemble: {e}")
                results["ensemble"] = {"error": str(e)}

        return results

    def run(self) -> dict[str, object]:
        """Run the complete training pipeline.

        Returns:
            Dictionary with all results and metrics
        """
        logger.info("Starting ML training pipeline")
        pipeline_start = time.time()

        # Load data
        X, y, feature_names = self.load_data(self.config.train_data_path)

        # Preprocess
        X_train, X_test, y_train, y_test, X_val, y_val = self.preprocess(X, y)

        # Train models
        self.train_random_forest(X_train, y_train, feature_names)
        self.train_isolation_forest(X_train, y_train)
        self.train_xgboost(X_train, y_train)

        # Create ensemble
        self.create_ensemble()

        # Evaluate
        evaluation = self.evaluate_all(X_test, y_test)

        pipeline_time = time.time() - pipeline_start
        logger.info(f"Training pipeline complete in {pipeline_time:.1f}s")

        return {
            "models": list(self.models.keys()),
            "metrics": self.metrics,
            "evaluation": evaluation,
            "pipeline_time_s": pipeline_time,
            "n_samples": len(X),
            "n_features": X.shape[1],
        }


# Convenience function for quick training
def train_models(
    data_path: str,
    output_dir: str = "models",
    export_onnx: bool = True,
) -> dict[str, object]:
    """Quick-start training function.

    Args:
        data_path: Path to training data CSV
        output_dir: Output directory for models
        export_onnx: Whether to export ONNX models

    Returns:
        Training results
    """
    config = TrainingConfig(
        train_data_path=data_path,
        model_output_dir=output_dir,
        export_onnx=export_onnx,
    )
    pipeline = TrainingPipeline(config)
    return pipeline.run()
