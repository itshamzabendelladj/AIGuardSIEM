"""LSTM-based sequence anomaly detection for network traffic.

Uses Long Short-Term Memory networks to detect temporal anomalies
in network flow sequences. Captures temporal dependencies that
traditional ML models miss.

Author: AIGuard Security Team
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional, Sequence
import numpy as np

try:
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, TensorDataset
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

logger = logging.getLogger(__name__)


if TORCH_AVAILABLE:

    class LSTMAnomalyDetector(nn.Module):
        """LSTM-based anomaly detection model.

        Uses an autoencoder architecture with LSTM encoder and decoder
        to reconstruct input sequences. High reconstruction error
        indicates anomaly.

        Args:
            input_size: Number of input features
            hidden_size: LSTM hidden state size
            num_layers: Number of LSTM layers
            dropout: Dropout rate
            sequence_length: Input sequence length

        Example:
            >>> detector = LSTMAnomalyDetector(input_size=84, hidden_size=128)
            >>> detector.train(X_sequences, epochs=50)
            >>> anomalies = detector.detect(X_test_sequences)
        """

        def __init__(
            self,
            input_size: int = 84,
            hidden_size: int = 128,
            num_layers: int = 2,
            dropout: float = 0.2,
            sequence_length: int = 10,
            device: str = "cpu",
        ) -> None:
            super().__init__()

            self.input_size = input_size
            self.hidden_size = hidden_size
            self.num_layers = num_layers
            self.sequence_length = sequence_length
            self.device = torch.device(device if torch.cuda.is_available() else "cpu")

            # Encoder
            self.encoder = nn.LSTM(
                input_size=input_size,
                hidden_size=hidden_size,
                num_layers=num_layers,
                batch_first=True,
                dropout=dropout if num_layers > 1 else 0,
            )

            # Bottleneck
            self.bottleneck = nn.Linear(hidden_size, hidden_size // 2)
            self.bottleneck_activation = nn.ReLU()

            # Decoder
            self.decoder = nn.LSTM(
                input_size=hidden_size // 2,
                hidden_size=hidden_size,
                num_layers=num_layers,
                batch_first=True,
                dropout=dropout if num_layers > 1 else 0,
            )

            # Output layer
            self.output_layer = nn.Linear(hidden_size, input_size)

            # Reconstruction threshold
            self.threshold: float = 0.0

            self.to(self.device)

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            """Forward pass through the autoencoder.

            Args:
                x: Input tensor of shape (batch, seq_len, input_size)

            Returns:
                Reconstructed tensor of same shape
            """
            # Encode
            encoded, (hidden, cell) = self.encoder(x)

            # Bottleneck
            bottlenecked = self.bottleneck_activation(self.bottleneck(encoded))

            # Decode
            decoded, _ = self.decoder(bottlenecked)

            # Output
            output = self.output_layer(decoded)
            return output

        def train_model(
            self,
            X: np.ndarray,
            epochs: int = 50,
            batch_size: int = 64,
            learning_rate: float = 0.001,
            validation_split: float = 0.1,
        ) -> dict[str, list[float]]:
            """Train the LSTM anomaly detector.

            Args:
                X: Training sequences of shape (n_samples, seq_len, n_features)
                epochs: Number of training epochs
                batch_size: Training batch size
                learning_rate: Learning rate
                validation_split: Fraction of data for validation

            Returns:
                Dictionary with training and validation loss history
            """
            logger.info(f"Training LSTM anomaly detector with {len(X)} sequences")

            # Convert to tensor
            X_tensor = torch.FloatTensor(X).to(self.device)

            # Split data
            n_val = int(len(X) * validation_split)
            n_train = len(X) - n_val

            train_dataset = TensorDataset(X_tensor[:n_train], X_tensor[:n_train])
            val_dataset = TensorDataset(X_tensor[n_train:], X_tensor[n_train:])

            train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
            val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)

            # Loss and optimizer
            criterion = nn.MSELoss()
            optimizer = torch.optim.Adam(self.parameters(), lr=learning_rate)
            scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
                optimizer, mode="min", factor=0.5, patience=5
            )

            train_losses: list[float] = []
            val_losses: list[float] = []

            best_val_loss = float("inf")

            for epoch in range(epochs):
                # Training
                self.train()
                epoch_train_loss = 0.0
                for batch_x, _ in train_loader:
                    optimizer.zero_grad()
                    reconstructed = self(batch_x)
                    loss = criterion(reconstructed, batch_x)
                    loss.backward()
                    optimizer.step()
                    epoch_train_loss += loss.item()

                epoch_train_loss /= len(train_loader)
                train_losses.append(epoch_train_loss)

                # Validation
                self.eval()
                epoch_val_loss = 0.0
                with torch.no_grad():
                    for batch_x, _ in val_loader:
                        reconstructed = self(batch_x)
                        loss = criterion(reconstructed, batch_x)
                        epoch_val_loss += loss.item()

                epoch_val_loss /= len(val_loader) if len(val_loader) > 0 else 1
                val_losses.append(epoch_val_loss)

                scheduler.step(epoch_val_loss)

                if epoch_val_loss < best_val_loss:
                    best_val_loss = epoch_val_loss

                if (epoch + 1) % 10 == 0:
                    logger.info(
                        f"Epoch {epoch+1}/{epochs} - "
                        f"Train Loss: {epoch_train_loss:.6f}, "
                        f"Val Loss: {epoch_val_loss:.6f}"
                    )

            # Set threshold from validation reconstruction errors
            self.eval()
            with torch.no_grad():
                val_reconstruction_errors: list[float] = []
                for batch_x, _ in val_loader:
                    reconstructed = self(batch_x)
                    errors = torch.mean((reconstructed - batch_x) ** 2, dim=(1, 2))
                    val_reconstruction_errors.extend(errors.cpu().numpy())

            self.threshold = float(
                np.percentile(val_reconstruction_errors, 95)
            )

            logger.info(f"Training complete. Threshold: {self.threshold:.6f}")

            return {"train_losses": train_losses, "val_losses": val_losses}

        def detect(self, X: np.ndarray) -> np.ndarray:
            """Detect anomalies in sequences.

            Args:
                X: Input sequences of shape (n_samples, seq_len, n_features)

            Returns:
                Boolean array (True = anomaly)
            """
            self.eval()
            with torch.no_grad():
                X_tensor = torch.FloatTensor(X).to(self.device)
                reconstructed = self(X_tensor)
                errors = torch.mean((reconstructed - X_tensor) ** 2, dim=(1, 2))
                errors_np = errors.cpu().numpy()

            return errors_np > self.threshold

        def get_reconstruction_errors(self, X: np.ndarray) -> np.ndarray:
            """Get reconstruction errors for input sequences.

            Args:
                X: Input sequences

            Returns:
                Array of reconstruction errors
            """
            self.eval()
            with torch.no_grad():
                X_tensor = torch.FloatTensor(X).to(self.device)
                reconstructed = self(X_tensor)
                errors = torch.mean((reconstructed - X_tensor) ** 2, dim=(1, 2))
                return errors.cpu().numpy()

        def save_model(self, path: str | Path) -> None:
            """Save the trained model.

            Args:
                path: Path to save the model
            """
            path = Path(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            torch.save({
                "model_state_dict": self.state_dict(),
                "input_size": self.input_size,
                "hidden_size": self.hidden_size,
                "num_layers": self.num_layers,
                "sequence_length": self.sequence_length,
                "threshold": self.threshold,
            }, path)
            logger.info(f"Model saved to {path}")

        def load_model(self, path: str | Path) -> None:
            """Load a trained model.

            Args:
                path: Path to the saved model
            """
            checkpoint = torch.load(path, map_location=self.device)
            self.load_state_dict(checkpoint["model_state_dict"])
            self.threshold = checkpoint["threshold"]
            logger.info(f"Model loaded from {path}")

        def export_onnx(self, path: str | Path, batch_size: int = 1) -> None:
            """Export model to ONNX format.

            Args:
                path: Output ONNX file path
                batch_size: Batch size for ONNX export
            """
            path = Path(path)
            path.parent.mkdir(parents=True, exist_ok=True)

            self.eval()
            dummy_input = torch.randn(batch_size, self.sequence_length, self.input_size)
            dummy_input = dummy_input.to(self.device)

            torch.onnx.export(
                self,
                dummy_input,
                str(path),
                export_params=True,
                opset_version=15,
                do_constant_folding=True,
                input_names=["input"],
                output_names=["output"],
                dynamic_axes={
                    "input": {0: "batch_size"},
                    "output": {0: "batch_size"},
                },
            )
            logger.info(f"ONNX model exported to {path}")

else:
    # Fallback when PyTorch is not available
    class LSTMAnomalyDetector:  # type: ignore
        def __init__(self, *args, **kwargs) -> None:
            raise ImportError("PyTorch is required for LSTMAnomalyDetector. Install with: pip install torch")
