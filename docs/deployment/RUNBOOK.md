# AIGuardSIEM Production Deployment Runbook

## Prerequisites

### Hardware Requirements
- **Minimum**: 8 CPU cores, 32GB RAM, 1TB SSD
- **Recommended**: 32 CPU cores, 128GB RAM, 10TB NVMe SSD
- **High-throughput**: 64 CPU cores, 256GB RAM, 50TB NVMe SSD

### Software Requirements
- Linux kernel 5.15+ (for eBPF support)
- Docker 24.0+ or Kubernetes 1.28+
- CMake 3.22+, GCC 13+, Go 1.22+, Python 3.11+
- Boost 1.82+, OpenSSL 3.0+, librdkafka 2.0+

## Deployment Options

### Option 1: Docker Compose (Development)
```bash
git clone https://github.com/aiguard/siem-xdr.git
cd siem-xdr
docker-compose up -d
```

### Option 2: Kubernetes (Production)
```bash
# Create namespace
kubectl apply -f deployment/kubernetes/namespace.yaml

# Deploy infrastructure
kubectl apply -f deployment/kubernetes/kafka.yaml
kubectl apply -f deployment/kubernetes/clickhouse.yaml

# Deploy collectors
kubectl apply -f deployment/kubernetes/syslog-collector.yaml
kubectl apply -f deployment/kubernetes/stream-processor.yaml
kubectl apply -f deployment/kubernetes/api-gateway.yaml

# Or use Helm
helm install aiguard-siem deployment/helm/siem-xdr
```

### Option 3: Ansible (Bare Metal)
```bash
ansible-playbook -i inventory.ini deployment/ansible/deploy.yml
```

## Configuration

### Kafka Topics
- `aiguard-syslog` - Syslog events
- `aiguard-network` - Network/PCAP events
- `aiguard-netflow` - NetFlow records
- `aiguard-winlog` - Windows Event Log
- `aiguard-endpoint` - Endpoint agent events
- `aiguard-alerts` - Generated alerts
- `aiguard-cloud` - Cloud connector events

### Environment Variables
| Variable | Default | Description |
|----------|---------|-------------|
| `KAFKA_BROKERS` | localhost:9092 | Kafka broker addresses |
| `AIGUARD_JWT_SECRET` | (required) | JWT signing secret |
| `AIGUARD_ETCD_ENDPOINTS` | localhost:2379 | etcd endpoints |
| `AIGUARD_LOG_LEVEL` | info | Log level |
| `SIGMA_RULES_DIR` | /etc/aiguard/sigma_rules | Sigma rules directory |

## Scaling

### Horizontal Scaling
- Collectors: Add more pods, distribute across nodes
- Stream processors: Increase replicas, Kafka handles partitioning
- Storage: Add ClickHouse shards

### Vertical Scaling
- Increase CPU for higher EPS
- Increase RAM for larger flow tables
- Add GPU nodes for ML inference

## Monitoring

### Health Checks
- `GET /health` - Service health
- `GET /ready` - Readiness probe
- `GET /metrics` - Prometheus metrics

### Key Metrics
- `events_consumed_total` - Total events consumed
- `alerts_generated_total` - Total alerts generated
- `processing_latency_ms` - Processing latency
- `kafka_consumer_lag` - Kafka consumer lag

## Troubleshooting

### High Kafka Lag
1. Check consumer health: `kubectl get pods -n aiguard-siem`
2. Scale stream processors: `kubectl scale deployment stream-processor --replicas=8`
3. Check for slow consumers in logs

### High Alert Volume
1. Review Sigma rules for overly broad matches
2. Adjust Q-learning threshold agent
3. Tune correlation rule thresholds

### Storage Full
1. Check hot storage: `df -h /var/lib/aiguard/hot`
2. Trigger compaction: API `POST /api/v1/system/storage/compact`
3. Archive to cold storage: API `POST /api/v1/system/storage/archive`

## Security

### TLS Configuration
- All inter-service communication uses TLS 1.3
- Certificates managed via cert-manager (K8s) or manual rotation
- API gateway supports mTLS for endpoint agents

### RBAC
- Admin: Full access to all features
- Analyst: Read alerts/events, manage cases
- Responder: Execute playbooks, isolate hosts
- Viewer: Read-only dashboard access

### Audit Logging
All API actions are logged to the audit log:
```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://api.aiguard.io/v1/system/audit-log
```
