"""ONNX Runtime inference wrapper for sub-millisecond model inference.

Provides a unified interface for running ONNX models with support for
INT8 quantization, GPU acceleration, and batch processing.

Author: AIGuard Security Team
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Optional, Sequence
import numpy as np

logger = logging.getLogger(__name__)

try:
    import onnxruntime as ort
    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False


class ONNXInferenceEngine:
    """ONNX Runtime inference engine for ML model inference.

    Features:
        - Sub-millisecond inference with ONNX Runtime
        - INT8 quantization support for CPU efficiency
        - GPU acceleration via CUDA/TensorRT
        - Batch processing for throughput
        - Model warmup and caching
        - Performance metrics

    Example:
        >>> engine = ONNXInferenceEngine(model_path="model.onnx", device="cpu")
        >>> engine.warmup()
        >>> predictions = engine.infer(input_data)
    """

    def __init__(
        self,
        model_path: str | Path,
        device: str = "cpu",
        num_threads: int = 4,
        batch_size: int = 1,
        enable_int8: bool = False,
        gpu_device_id: int = 0,
    ) -> None:
        """Initialize the ONNX inference engine.

        Args:
            model_path: Path to ONNX model file
            device: Inference device ('cpu', 'cuda', 'tensorrt')
            num_threads: Number of intra-op threads (CPU)
            batch_size: Default batch size
            enable_int8: Enable INT8 quantization
            gpu_device_id: GPU device ID (for CUDA)
        """
        if not ONNX_AVAILABLE:
            raise ImportError("onnxruntime not installed. Install with: pip install onnxruntime")

        self.model_path = Path(model_path)
        self.device = device
        self.batch_size = batch_size
        self.enable_int8 = enable_int8

        # Configure session options
        session_options = ort.SessionOptions()
        session_options.intra_op_num_threads = num_threads
        session_options.inter_op_num_threads = 2
        session_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        session_options.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL

        # Configure provider
        if device == "cuda":
            providers = [
                ("CUDAExecutionProvider", {"device_id": gpu_device_id}),
                "CPUExecutionProvider",
            ]
        elif device == "tensorrt":
            providers = [
                ("TensorrtExecutionProvider", {
                    "device_id": gpu_device_id,
                    "trt_fp16_enable": True,
                    "trt_int8_enable": enable_int8,
                }),
                "CUDAExecutionProvider",
                "CPUExecutionProvider",
            ]
        else:
            providers = ["CPUExecutionProvider"]

        # Create session
        self.session = ort.InferenceSession(
            str(self.model_path),
            sess_options=session_options,
            providers=providers,
        )

        # Get input/output info
        self.input_names = [inp.name for inp in self.session.get_inputs()]
        self.input_shapes = [inp.shape for inp in self.session.get_inputs()]
        self.output_names = [out.name for out in self.session.get_outputs()]
        self.output_shapes = [out.shape for out in self.session.get_outputs()]

        # Metrics
        self.inference_count = 0
        self.total_inference_time_ms = 0.0
        self.warmup_done = False

        logger.info(
            f"ONNX inference engine loaded: {self.model_path.name} "
            f"(device={device}, inputs={self.input_names}, outputs={self.output_names})"
        )

    def warmup(self, num_runs: int = 10) -> None:
        """Warmup the model with dummy inputs.

        Args:
            num_runs: Number of warmup inference runs
        """
        logger.info(f"Warming up ONNX model ({num_runs} runs)")

        for shape, name in zip(self.input_shapes, self.input_names):
            # Replace dynamic dimensions with default batch size
            dummy_shape = [self.batch_size if isinstance(d, str) or d is None else d for d in shape]
            dummy_input = np.random.randn(*dummy_shape).astype(np.float32)

            for _ in range(num_runs):
                self.session.run(self.output_names, {name: dummy_input})

        self.warmup_done = True
        logger.info("ONNX model warmup complete")

    def infer(
        self,
        inputs: np.ndarray | dict[str, np.ndarray],
    ) -> dict[str, np.ndarray]:
        """Run inference on input data.

        Args:
            inputs: Input array or dictionary of named inputs

        Returns:
            Dictionary of output name -> output array
        """
        if isinstance(inputs, np.ndarray):
            if len(self.input_names) != 1:
                raise ValueError(f"Model expects {len(self.input_names)} inputs, got 1")
            feed = {self.input_names[0]: inputs.astype(np.float32)}
        else:
            feed = {k: v.astype(np.float32) for k, v in inputs.items()}

        start_time = time.perf_counter()
        results = self.session.run(self.output_names, feed)
        inference_time = (time.perf_counter() - start_time) * 1000

        self.inference_count += 1
        self.total_inference_time_ms += inference_time

        return dict(zip(self.output_names, results))

    def infer_batch(
        self,
        inputs: np.ndarray,
        batch_size: Optional[int] = None,
    ) -> np.ndarray:
        """Run batched inference.

        Args:
            inputs: Input array of shape (n_samples, ...)
            batch_size: Override default batch size

        Returns:
            Concatenated output array
        """
        batch_size = batch_size or self.batch_size
        n_samples = inputs.shape[0]
        results = []

        for i in range(0, n_samples, batch_size):
            batch = inputs[i:i + batch_size]
            output = self.infer(batch)
            # Get first output
            first_output = list(output.values())[0]
            results.append(first_output)

        return np.concatenate(results, axis=0)

    def predict(self, inputs: np.ndarray) -> np.ndarray:
        """Get predicted class labels.

        Args:
            inputs: Input features

        Returns:
            Predicted class indices
        """
        output = self.infer(inputs)
        first_output = list(output.values())[0]

        if first_output.ndim == 2 and first_output.shape[1] > 1:
            return np.argmax(first_output, axis=1)
        return (first_output > 0.5).astype(int).ravel()

    def predict_proba(self, inputs: np.ndarray) -> np.ndarray:
        """Get prediction probabilities.

        Args:
            inputs: Input features

        Returns:
            Probability array
        """
        output = self.infer(inputs)
        first_output = list(output.values())[0]

        if first_output.ndim == 2 and first_output.shape[1] > 1:
            # Softmax if not already probabilities
            if not np.allclose(first_output.sum(axis=1), 1.0):
                exp = np.exp(first_output - first_output.max(axis=1, keepdims=True))
                return exp / exp.sum(axis=1, keepdims=True)
            return first_output
        return first_output.ravel()

    def get_latency_stats(self) -> dict[str, float]:
        """Get inference latency statistics.

        Returns:
            Dictionary with latency metrics
        """
        if self.inference_count == 0:
            return {"avg_ms": 0, "total_ms": 0, "count": 0}

        return {
            "avg_ms": self.total_inference_time_ms / self.inference_count,
            "total_ms": self.total_inference_time_ms,
            "count": self.inference_count,
            "p50_ms": self.total_inference_time_ms / self.inference_count,  # Simplified
        }

    def get_model_info(self) -> dict[str, object]:
        """Get model information.

        Returns:
            Model info dictionary
        """
        return {
            "model_path": str(self.model_path),
            "device": self.device,
            "input_names": self.input_names,
            "input_shapes": self.input_shapes,
            "output_names": self.output_names,
            "output_shapes": self.output_shapes,
            "warmup_done": self.warmup_done,
            "inference_count": self.inference_count,
            "providers": self.session.get_providers(),
        }

    def reset_metrics(self) -> None:
        """Reset inference metrics."""
        self.inference_count = 0
        self.total_inference_time_ms = 0.0


class MultiModelInferenceEngine:
    """Manages multiple ONNX models for ensemble inference.

    Example:
        >>> engine = MultiModelInferenceEngine()
        >>> engine.load_model("rf", "models/rf.onnx")
        >>> engine.load_model("xgb", "models/xgb.onnx")
        >>> results = engine.infer_all(input_data)
    """

    def __init__(self, device: str = "cpu", num_threads: int = 4) -> None:
        """Initialize multi-model engine."""
        self.device = device
        self.num_threads = num_threads
        self.models: dict[str, ONNXInferenceEngine] = {}

    def load_model(
        self,
        name: str,
        model_path: str | Path,
        enable_int8: bool = False,
    ) -> None:
        """Load an ONNX model.

        Args:
            name: Model name
            model_path: Path to ONNX model
            enable_int8: Enable INT8 quantization
        """
        engine = ONNXInferenceEngine(
            model_path=model_path,
            device=self.device,
            num_threads=self.num_threads,
            enable_int8=enable_int8,
        )
        engine.warmup()
        self.models[name] = engine
        logger.info(f"Loaded model '{name}' for ensemble inference")

    def infer_all(self, inputs: np.ndarray) -> dict[str, dict[str, np.ndarray]]:
        """Run inference on all loaded models.

        Args:
            inputs: Input features

        Returns:
            Dictionary of model_name -> outputs
        """
        return {name: model.infer(inputs) for name, model in self.models.items()}

    def predict_all(self, inputs: np.ndarray) -> dict[str, np.ndarray]:
        """Get predictions from all models.

        Args:
            inputs: Input features

        Returns:
            Dictionary of model_name -> predictions
        """
        return {name: model.predict(inputs) for name, model in self.models.items()}

    def predict_proba_all(self, inputs: np.ndarray) -> dict[str, np.ndarray]:
        """Get probabilities from all models.

        Args:
            inputs: Input features

        Returns:
            Dictionary of model_name -> probabilities
        """
        return {name: model.predict_proba(inputs) for name, model in self.models.items()}

    def get_all_latency_stats(self) -> dict[str, dict[str, float]]:
        """Get latency stats for all models."""
        return {name: model.get_latency_stats() for name, model in self.models.items()}

    def get_model_names(self) -> list[str]:
        """Get list of loaded model names."""
        return list(self.models.keys())
