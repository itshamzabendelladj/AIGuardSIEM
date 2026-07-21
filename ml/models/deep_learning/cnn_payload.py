"""CNN-based payload analysis for malware detection.

Analyzes raw packet payloads using Convolutional Neural Networks
to detect malware, C2 traffic, and data exfiltration.

Author: AIGuard Security Team
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional
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

    class CNNPayloadAnalyzer(nn.Module):
        """CNN-based network payload analyzer.

        Converts raw packet payloads to byte-image representations and
        analyzes them using 1D and 2D convolutional layers.

        Architecture:
            - 1D Conv layers for byte-sequence patterns
            - 2D Conv layers for byte-image spatial patterns
            - Fully connected layers for classification

        Args:
            max_payload_size: Maximum payload size to analyze (bytes)
            num_classes: Number of output classes (benign/malware types)
            device: Compute device ('cpu' or 'cuda')

        Example:
            >>> analyzer = CNNPayloadAnalyzer(max_payload_size=1024, num_classes=10)
            >>> analyzer.train(X_payloads, y_labels, epochs=30)
            >>> predictions = analyzer.predict(X_test)
        """

        def __init__(
            self,
            max_payload_size: int = 1024,
            num_classes: int = 10,
            device: str = "cpu",
        ) -> None:
            super().__init__()

            self.max_payload_size = max_payload_size
            self.num_classes = num_classes
            self.device = torch.device(device if torch.cuda.is_available() else "cpu")

            # 1D Convolutional layers for byte sequence analysis
            self.conv1d = nn.Sequential(
                nn.Conv1d(1, 32, kernel_size=3, padding=1),
                nn.BatchNorm1d(32),
                nn.ReLU(),
                nn.MaxPool1d(2),
                nn.Conv1d(32, 64, kernel_size=3, padding=1),
                nn.BatchNorm1d(64),
                nn.ReLU(),
                nn.MaxPool1d(2),
                nn.Conv1d(64, 128, kernel_size=3, padding=1),
                nn.BatchNorm1d(128),
                nn.ReLU(),
                nn.MaxPool1d(2),
            )

            # Calculate flattened size after 1D convs
            conv1d_output_size = max_payload_size // 8  # Three MaxPool1d(2) layers
            self.flattened_1d_size = 128 * conv1d_output_size

            # 2D Convolutional layers for byte-image analysis
            # Convert payload to sqrt(payload_size) x sqrt(payload_size) image
            self.image_size = int(np.sqrt(max_payload_size))
            self.actual_image_bytes = self.image_size * self.image_size

            self.conv2d = nn.Sequential(
                nn.Conv2d(1, 32, kernel_size=3, padding=1),
                nn.BatchNorm2d(32),
                nn.ReLU(),
                nn.MaxPool2d(2),
                nn.Conv2d(32, 64, kernel_size=3, padding=1),
                nn.BatchNorm2d(64),
                nn.ReLU(),
                nn.MaxPool2d(2),
            )

            image_output_size = self.image_size // 4  # Two MaxPool2d(2) layers
            self.flattened_2d_size = 64 * image_output_size * image_output_size

            # Fully connected layers
            self.classifier = nn.Sequential(
                nn.Linear(self.flattened_1d_size + self.flattened_2d_size, 512),
                nn.ReLU(),
                nn.Dropout(0.5),
                nn.Linear(512, 256),
                nn.ReLU(),
                nn.Dropout(0.3),
                nn.Linear(256, num_classes),
            )

            self.to(self.device)

        def forward(self, payload: torch.Tensor) -> torch.Tensor:
            """Forward pass.

            Args:
                payload: Byte tensor of shape (batch, payload_size) with values 0-255

            Returns:
                Classification logits of shape (batch, num_classes)
            """
            batch_size = payload.size(0)

            # Normalize to [0, 1]
            payload_normalized = payload.float() / 255.0

            # 1D path
            x1d = payload_normalized.unsqueeze(1)  # (batch, 1, payload_size)
            x1d = self.conv1d(x1d)
            x1d = x1d.view(batch_size, -1)

            # 2D path (byte-image)
            x2d = payload_normalized[:, :self.actual_image_bytes]
            x2d = x2d.view(batch_size, 1, self.image_size, self.image_size)
            x2d = self.conv2d(x2d)
            x2d = x2d.view(batch_size, -1)

            # Concatenate and classify
            combined = torch.cat([x1d, x2d], dim=1)
            output = self.classifier(combined)
            return output

        def train_model(
            self,
            X: np.ndarray,
            y: np.ndarray,
            epochs: int = 30,
            batch_size: int = 64,
            learning_rate: float = 0.001,
            validation_split: float = 0.1,
        ) -> dict[str, list[float]]:
            """Train the CNN payload analyzer.

            Args:
                X: Payload array of shape (n_samples, payload_size)
                y: Labels of shape (n_samples,)
                epochs: Number of training epochs
                batch_size: Training batch size
                learning_rate: Learning rate
                validation_split: Validation fraction

            Returns:
                Training history
            """
            logger.info(f"Training CNN payload analyzer with {len(X)} samples")

            X_tensor = torch.FloatTensor(X).to(self.device)
            y_tensor = torch.LongTensor(y).to(self.device)

            n_val = int(len(X) * validation_split)
            n_train = len(X) - n_val

            train_ds = TensorDataset(X_tensor[:n_train], y_tensor[:n_train])
            val_ds = TensorDataset(X_tensor[n_train:], y_tensor[n_train:])

            train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
            val_loader = DataLoader(val_ds, batch_size=batch_size)

            criterion = nn.CrossEntropyLoss()
            optimizer = torch.optim.Adam(self.parameters(), lr=learning_rate, weight_decay=1e-4)
            scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

            train_losses: list[float] = []
            val_losses: list[float] = []
            val_accuracies: list[float] = []

            for epoch in range(epochs):
                # Training
                self.train()
                epoch_loss = 0.0
                for batch_x, batch_y in train_loader:
                    optimizer.zero_grad()
                    output = self(batch_x)
                    loss = criterion(output, batch_y)
                    loss.backward()
                    optimizer.step()
                    epoch_loss += loss.item()

                epoch_loss /= len(train_loader)
                train_losses.append(epoch_loss)

                # Validation
                self.eval()
                val_loss = 0.0
                correct = 0
                total = 0
                with torch.no_grad():
                    for batch_x, batch_y in val_loader:
                        output = self(batch_x)
                        loss = criterion(output, batch_y)
                        val_loss += loss.item()
                        _, predicted = output.max(1)
                        total += batch_y.size(0)
                        correct += predicted.eq(batch_y).sum().item()

                val_loss /= len(val_loader) if len(val_loader) > 0 else 1
                val_acc = correct / total if total > 0 else 0
                val_losses.append(val_loss)
                val_accuracies.append(val_acc)

                scheduler.step()

                if (epoch + 1) % 5 == 0:
                    logger.info(
                        f"Epoch {epoch+1}/{epochs} - "
                        f"Loss: {epoch_loss:.4f}, "
                        f"Val Loss: {val_loss:.4f}, "
                        f"Val Acc: {val_acc:.4f}"
                    )

            return {
                "train_losses": train_losses,
                "val_losses": val_losses,
                "val_accuracies": val_accuracies,
            }

        def predict(self, X: np.ndarray) -> np.ndarray:
            """Predict payload classes.

            Args:
                X: Payload array

            Returns:
                Predicted class indices
            """
            self.eval()
            with torch.no_grad():
                X_tensor = torch.FloatTensor(X).to(self.device)
                output = self(X_tensor)
                _, predicted = output.max(1)
                return predicted.cpu().numpy()

        def predict_proba(self, X: np.ndarray) -> np.ndarray:
            """Get prediction probabilities.

            Args:
                X: Payload array

            Returns:
                Probability matrix
            """
            self.eval()
            with torch.no_grad():
                X_tensor = torch.FloatTensor(X).to(self.device)
                output = self(X_tensor)
                probs = torch.softmax(output, dim=1)
                return probs.cpu().numpy()

        def save_model(self, path: str | Path) -> None:
            """Save the trained model."""
            path = Path(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            torch.save({
                "model_state_dict": self.state_dict(),
                "max_payload_size": self.max_payload_size,
                "num_classes": self.num_classes,
            }, path)
            logger.info(f"Model saved to {path}")

        def load_model(self, path: str | Path) -> None:
            """Load a trained model."""
            checkpoint = torch.load(path, map_location=self.device)
            self.load_state_dict(checkpoint["model_state_dict"])
            logger.info(f"Model loaded from {path}")

        def export_onnx(self, path: str | Path, batch_size: int = 1) -> None:
            """Export to ONNX format."""
            path = Path(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            self.eval()
            dummy = torch.randn(batch_size, self.max_payload_size).to(self.device)
            torch.onnx.export(
                self, dummy, str(path),
                export_params=True, opset_version=15,
                input_names=["payload"], output_names=["classification"],
                dynamic_axes={"payload": {0: "batch"}, "classification": {0: "batch"}},
            )
            logger.info(f"ONNX model exported to {path}")

else:
    class CNNPayloadAnalyzer:  # type: ignore
        def __init__(self, *args, **kwargs) -> None:
            raise ImportError("PyTorch is required for CNNPayloadAnalyzer. Install with: pip install torch")
