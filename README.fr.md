Voici un README GitHub en français, prêt à coller dans `README.md`.

```markdown
# AIGuardSIEM

Plateforme SIEM / XDR open source, conçue pour l’ingestion massive de télémétrie de sécurité, la détection temps réel et la réponse automatisée.

> **Objectif annoncé** : plus d’**1 million d’événements par seconde (EPS)** par cluster, latence de détection **< 15 ms (P99.9)**.  
> Ces chiffres viennent du whitepaper du projet. Ils n’ont pas été validés de façon indépendante.

**Stack** : C++20 · Go 1.22+ · Python 3.11+  
**Licence** : MIT

---

## Qu’est-ce que c’est ?

AIGuardSIEM centralise les logs, le trafic réseau et la télémétrie endpoints, les normalise, les corrèle, les passe dans des modèles ML, puis génère des alertes et peut déclencher des playbooks SOAR.

Elle vise les SOC qui saturent avec des SIEM JVM classiques (pauses GC, corrélation trop lente, ML uniquement en batch).

| Capacité | AIGuardSIEM (revendiqué) | SIEM traditionnel |
|---|---|---|
| Ingestion | 1M+ EPS / cluster | 50k–250k EPS |
| Latence P99 | < 15 ms | 500 ms – 5 s |
| Inférence ML / événement | < 5 ms (ONNX) | souvent batch |
| Requête hot storage | < 1 ms (point) | 100 ms – 2 s |
| Visibilité endpoint | noyau (eBPF, LKM, minifilter) | agent userland |
| Seuils | agent Q-Learning | seuils statiques |
| Déploiement | Kubernetes + Helm | VM / scaling manuel |

---

## Fonctionnalités

- Collecteurs C++ : syslog (RFC 5424 / 3164), PCAP / **DPDK**, NetFlow v5/v9 / IPFIX, Windows Event Log / ETW
- Normalisation **ECS** (Elastic Common Schema)
- Bus d’événements **Kafka**
- Moteur de corrélation C++ : règles Sigma, fenêtres tumbling / sliding / session / hopping, matching **AVX-512**
- Détection ML hybride : Random Forest, XGBoost, Isolation Forest, LSTM autoencoder, CNN payload, vote d’ensemble
- Inférence **ONNX** (INT8, CPU ou GPU)
- **UEBA** : baselines utilisateurs, score de risque 0–100
- Agents **XDR** Linux (kprobes / eBPF) et Windows (minifilter / ETW)
- Connecteurs cloud : AWS CloudTrail / GuardDuty, Azure Sentinel, GCP SCC, audit Kubernetes
- **SOAR** : playbooks YAML (isolation host, kill process, blocage IP, tickets, evidence)
- Stockage 3 tiers : LSM-tree (hot), ClickHouse (warm), S3/Parquet (cold)
- API REST OpenAPI 3.0 + gRPC interne + dashboard SOC
- Déploiement K8s / Helm / Terraform / Ansible / Docker Compose

---

## Architecture (vue rapide)

```
Sources (syslog, PCAP, NetFlow, WinLog, cloud, agents)
        │
        ▼
 Collecteurs C++  →  parse zero-copy  →  Kafka
        │
        ▼
 Normalisation ECS
        │
        ▼
 Stream processor C++  →  règles Sigma + fenêtres
        │
        ▼
 Inférence ONNX (ensemble ML + UEBA)
        │
        ▼
 Alertes  →  dashboards / API / playbooks SOAR
        │
        ▼
 Hot (LSM) · Warm (ClickHouse) · Cold (S3/Parquet)
```

Pipeline en 7 étapes : **collecte → ingestion Kafka → normalisation → corrélation → ML → alerting → réponse**.

---

## Stack technique

### C++
Collecteurs, capture paquets, stream processing, stockage hot, crypto.  
Boost, librdkafka, OpenSSL 3, ONNX Runtime, RocksDB, fmt, spdlog.

### Go
API gateway, orchestration, connecteurs cloud, backend viz, opérateur K8s.  
Gin, gRPC, kafka-go, JWT, etcd.

### Python
Entraînement et pipelines ML, dashboard Dash/Plotly.  
scikit-learn, XGBoost, PyTorch, ONNX Runtime, pandas.

### Infra
Kafka (KRaft) · etcd · ClickHouse · MinIO/S3 · Kubernetes · Helm · Prometheus/Grafana

---

## Détection ML

Ensemble pondéré (valeurs du whitepaper) :

| Modèle | Rôle | Poids |
|---|---|---|
| Random Forest | attaques connues (CICIDS2017, 15 classes) | 0.40 |
| XGBoost | scoring boosté | 0.35 |
| LSTM autoencoder | anomalies temporelles | 0.15 |
| Isolation Forest | attaques inédites | 0.10 |

Features réseau : **84 descripteurs type CICFlowMeter** extraits en temps réel.

Réglage des seuils par **Q-Learning**. Drift surveillé via PSI et test de Kolmogorov-Smirnov.

Le whitepaper annonce **99,5 %** de précision et **0,5 %** de faux positifs sur CICIDS2018. À traiter comme résultat interne, pas comme benchmark public.

---

## Installation

### Dev (Docker Compose)

```bash
git clone https://github.com/itshamzabendelladj/AIGuardSIEM.git
cd AIGuardSIEM
docker compose up -d
```

Services typiques : Kafka, etcd, ClickHouse, MinIO, collecteurs, engine, API, dashboard, SOAR.

### Kubernetes (Helm)

```bash
helm install aiguard-siem deployment/helm/siem-xdr \
  --set global.storageClass=gp3 \
  --set collectors.syslog.replicas=5 \
  --set engine.streamProcessor.replicas=8 \
  --set mlInference.gpuEnabled=true \
  --set apiGateway.ingress.hostname=siem.exemple.com
```

### Bare metal

Playbook Ansible dans `deployment/` : dépendances OS, build CMake/Go, pip, services systemd.

Le détail d’install est dans `docs/INSTALL.md` si le fichier est présent dans le dépôt.

---

## API (aperçu)

Gateway Go, JWT, rate limiting, RBAC (Admin / Analyst / Responder / Viewer).

| Groupe | Exemples |
|---|---|
| `/auth` | login, refresh, logout |
| `/alerts` | CRUD, ack, resolve, stream |
| `/events` | recherche, agrégation |
| `/rules` | CRUD, reload Sigma |
| `/cases` | dossier incident, timeline |
| `/agents` | liste, isolation |
| `/playbooks` | CRUD, exécution |
| `/system` | santé, config, audit |

Communication interne : **gRPC + Protobuf**. Bus async : **Kafka**.

---

## Sécurité

- TLS 1.3 inter-services
- AES-256-GCM (AES-NI) au repos
- HMAC-SHA256, comparaison en temps constant
- Rotation de clés
- Audit des actions d’admin
- Isolation multi-tenant
- Alignement déclaré : SOC 2, ISO 27001, GDPR, HIPAA, PCI-DSS, NIST 800-53

---

## Structure du dépôt

```
api/            API gateway (Go)
collectors/     Collecteurs C++
engine/         Stream + corrélation
ml/             Features, training, inférence ONNX
xdr/            Agents endpoints
playbooks/      Workflows SOAR (YAML)
storage/        Hot / warm / cold
viz/            Backend visualisation
connectors/     AWS, Azure, GCP, K8s
crypto/         Chiffrement
deployment/     Helm, Terraform, Ansible, Docker
docs/           Whitepaper, install, benchmarks
config/         Configuration
```

---

## Glossaire express

| Terme | Sens |
|---|---|
| SIEM | Centralisation, corrélation et alerte sur les logs sécu |
| XDR | SIEM + visibilité endpoint / réseau / cloud |
| SOAR | Automatisation de la réponse (playbooks) |
| EPS | Events per second |
| DPDK | Capture paquets en contournant le noyau |
| eBPF | Tracing noyau Linux programmable |
| Sigma | Format ouvert de règles de détection |
| ONNX | Format portable de modèles ML |
| ECS | Schéma de champs unifié (Elastic) |

---

## Statut

Version documentée : **1.0 — juin 2025**.  
Projet en développement. Certaines parties du whitepaper décrivent une architecture cible plus qu’un produit déjà déployé en production nationale.

Roadmap évoquée : GNN (mouvement latéral), transformers, YARA-L, federated learning, chasse temps réel, crypto post-quantique.

---

## Licence

MIT — © 2025 AIGuard.

