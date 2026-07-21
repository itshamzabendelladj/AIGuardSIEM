# AIGuardSIEM Architecture - C4 System Context

## System Context

```
                                    ┌──────────────────┐
                                    │   SOC Analysts   │
                                    │  & Security Team │
                                    └────────┬─────────┘
                                             │
                                    ┌────────▼─────────┐
                                    │   AIGuardSIEM    │
                                    │  SIEM/XDR Platform│
                                    └────────┬─────────┘
                                             │
                          ┌──────────────────┼──────────────────┐
                          │                  │                  │
                   ┌──────▼──────┐  ┌───────▼───────┐  ┌──────▼──────┐
                   │  Data Sources│  │ Cloud Services│  │  Endpoints  │
                   │  (Syslog,    │  │ (AWS, Azure,  │  │  (Agents)   │
                   │   NetFlow,   │  │  GCP, K8s)    │  │             │
                   │   PCAP)      │  │               │  │             │
                   └──────────────┘  └───────────────┘  └─────────────┘
```

## Container Diagram

### Data Ingestion Layer
- **C++ Syslog Collector**: RFC 5424/3164, UDP/TCP/TLS, 500K+ EPS
- **C++ PCAP Collector**: libpcap/DPDK, 10Gbps+ line rate, flow tracking
- **C++ NetFlow Collector**: v5/v9/IPFIX support
- **C++ WinLog Collector**: Windows Event Log, ETW, Sysmon

### Processing Engine
- **C++ Stream Processor**: Lock-free ring buffers, SIMD correlation, windowing
- **C++ Rule Engine**: Sigma rule compiler, custom DSL, YARA-L
- **C++ Correlation Engine**: Real-time event matching, threshold alerting

### ML/AI Layer
- **Python ML Pipeline**: Random Forest, XGBoost, LSTM, CNN, Isolation Forest
- **C++ ONNX Inference**: Sub-millisecond inference, INT8 quantization, ensemble voting
- **Python UEBA Engine**: User behavior baselines, peer group analysis, risk scoring
- **Python Q-Learning Agent**: Adaptive threshold tuning

### XDR Layer
- **C++ Endpoint Agent**: Kernel monitoring (LKM, minifilter, eBPF)
- **Go Cloud Connectors**: AWS, Azure, GCP, Kubernetes
- **Go Response Engine**: Host isolation, process termination, firewall rules

### SOAR Layer
- **Go Case Management**: REST/gRPC API, WebSocket updates, RBAC
- **Python Playbook Engine**: YAML workflows, TheHive/Cortex integration
- **C++ Timeline Reconstruction**: Attack graph generation

### Storage Layer
- **C++ Hot Storage**: Custom LSM-tree, sub-ms query latency
- **Go Warm Storage**: ClickHouse integration, time-series queries
- **Go Cold Storage**: S3/GCS/Azure Blob, Parquet, WORM compliance

### Visualization Layer
- **Go Backend**: WebSocket streaming, GraphQL, MITRE ATT&CK heatmap
- **Python Frontend**: Dash/Plotly SOC dashboards, network graphs, threat maps

### API Layer
- **Go API Gateway**: OpenAPI 3.0, gRPC, webhooks, JWT auth
- **Integrations**: ServiceNow, Jira, Splunk, QRadar, MISP, VirusTotal, STIX/TAXII

## Deployment
- **Kubernetes**: Operators, Helm charts, auto-scaling
- **Terraform**: Multi-cloud (AWS/Azure/GCP) infrastructure
- **Ansible**: Configuration management
- **Docker Compose**: Development environment
