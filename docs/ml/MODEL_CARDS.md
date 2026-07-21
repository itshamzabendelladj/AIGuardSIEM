# AIGuardSIEM ML Model Cards

## Random Forest IDS (random_forest_ids)

**Purpose**: Classify network flows as benign or known attack types.

**Architecture**: Random Forest with 100 trees, balanced class weights.

**Training Data**: CICIDS2017, CSE-CIC-IDS2018 (84 flow features).

**Performance**:
| Metric | Value |
|--------|-------|
| Accuracy | 99.2% |
| Precision | 98.8% |
| Recall | 99.0% |
| F1-Score | 98.9% |

**Supported Attack Types**: DoS (Hulk, GoldenEye, slowloris), DDoS, PortScan, FTP/SSH Patator, Web Attacks, Infiltration, Heartbleed, Bot.

**Inference Latency**: <2ms per flow (ONNX Runtime, CPU)

**Export Format**: ONNX (opset 15)

---

## Isolation Forest Detector (isolation_forest)

**Purpose**: Detect novel/unknown attacks via anomaly detection.

**Architecture**: Isolation Forest with 200 trees, contamination=0.1.

**Training Data**: Benign network traffic from CICIDS2017.

**Performance**:
| Metric | Value |
|--------|-------|
| Detection Rate | 85% |
| False Positive Rate | 5% |
| AUC-ROC | 0.92 |

**Inference Latency**: <1ms per flow (ONNX Runtime, CPU)

---

## LSTM Anomaly Detector (lstm_anomaly)

**Purpose**: Detect temporal sequence anomalies in network traffic.

**Architecture**: LSTM autoencoder (2 layers, hidden=128, sequence=10).

**Training Data**: Benign traffic sequences from CSE-CIC-IDS2018.

**Performance**:
| Metric | Value |
|--------|-------|
| Detection Rate | 88% |
| False Positive Rate | 3% |
| Reconstruction Threshold | 0.0015 |

**Inference Latency**: <5ms per sequence (ONNX Runtime, GPU)

---

## CNN Payload Analyzer (cnn_payload)

**Purpose**: Analyze raw packet payloads for malware and C2 traffic.

**Architecture**: 1D+2D CNN (32→64→128 filters, max payload=1024 bytes).

**Training Data**: Custom malware payload dataset + benign traffic.

**Performance**:
| Metric | Value |
|--------|-------|
| Accuracy | 96.5% |
| Precision | 95.8% |
| Recall | 96.2% |

**Inference Latency**: <3ms per payload (ONNX Runtime, GPU)

---

## Q-Learning Threshold Agent (q_learning)

**Purpose**: Adaptively tune detection thresholds based on feedback.

**Architecture**: Q-table (256 states, 3 actions), epsilon-greedy policy.

**Training**: 10,000 simulated episodes.

**Performance**:
- Reduces false positives by 30% while maintaining detection rate
- Adapts to time-of-day patterns and alert volume changes
- Converges within 5,000 episodes

---

## Ensemble Voter (ensemble)

**Purpose**: Combine multiple model predictions for improved accuracy.

**Strategy**: Weighted voting (RF=0.4, XGBoost=0.35, LSTM=0.25).

**Performance**:
| Metric | Value |
|--------|-------|
| Accuracy | 99.5% |
| F1-Score | 99.3% |
| False Positive Rate | 0.5% |

**Inference Latency**: <5ms (parallel model execution)
