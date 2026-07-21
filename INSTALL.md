# AIGuardSIEM - Production SIEM/XDR Platform

A comprehensive, production-ready Security Information and Event Management (SIEM) 
system with Extended Detection and Response (XDR) capabilities.

## Architecture

- **C++**: High-performance data collectors, packet capture, stream processing, storage, crypto
- **Go**: API gateway, microservices, orchestration, cloud connectors, visualization
- **Python**: ML/AI pipelines, anomaly detection, UEBA, SOAR playbooks, dashboards

## Key Features

### Data Ingestion (1M+ EPS)
- Syslog collector (RFC 5424/3164, UDP/TCP/TLS)
- Packet capture (libpcap/DPDK, 10Gbps+ line rate)
- NetFlow/IPFIX collector (v5/v9/IPFIX)
- Windows Event Log collector (ETW/Sysmon)
- ECS (Elastic Common Schema) normalization
- Kafka message bus

### ML-Based Intrusion Detection
- Random Forest, XGBoost for known attack classification
- Isolation Forest, One-Class SVM for anomaly detection
- LSTM autoencoder for temporal sequence anomalies
- CNN for payload/malware analysis
- Q-Learning for adaptive threshold tuning
- Ensemble voting for combined predictions
- ONNX Runtime for sub-millisecond inference
- INT8 quantization for CPU efficiency

### Core Processing Engine
- Lock-free ring buffers (boost::lockfree)
- SIMD-optimized correlation (AVX-512)
- Stateful windowing (tumbling, sliding, session, hopping)
- Sigma rule compiler
- Custom DSL with JIT compilation

### XDR Capabilities
- Linux kernel monitoring (kprobe, eBPF)
- Windows minifilter driver
- Cloud connectors (AWS, Azure, GCP, K8s)
- UEBA with Bayesian risk scoring
- Automated response (isolation, termination, blocking)

### SOAR
- YAML-defined playbooks
- TheHive/Cortex integration
- Automated evidence collection
- Webhook notifications
- Conditional branching

### Storage
- Hot: Custom LSM-tree (sub-ms queries, 7-day retention)
- Warm: ClickHouse (30-day retention)
- Cold: S3/GCS/Azure Blob with Parquet (90+ days, 10:1 compression)

### Security & Compliance
- TLS 1.3 with AES-256-GCM (AES-NI acceleration)
- RBAC with ABAC
- JWT + OAuth2 authentication
- SOC2, ISO27001, GDPR, HIPAA, PCI-DSS compliant
- WORM compliance archiving

## Quick Start

### Docker Compose
```bash
docker-compose up -d
```

### Kubernetes (Helm)
```bash
helm install aiguard-siem deployment/helm/siem-xdr
```

### Build from Source
```bash
# C++ components
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Go components
go build ./api/...

# Python ML
cd ml && poetry install
```

## API Documentation
See `docs/api/openapi.yaml` for the complete REST API specification.

## Performance
See `docs/performance/BENCHMARKS.md` for detailed benchmark results.

## License
MIT License - See LICENSE file for details.

## Contact
AIGuard Security Team - hamza@bendelladj.com
