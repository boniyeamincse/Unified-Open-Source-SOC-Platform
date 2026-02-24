# 📊 Capacity Planning Guide
## Unified Open-Source SOC Platform

> **Author**: Boni Yeamin | **Version**: 1.0 | **Last Updated**: 2024-01-01

---

## Resource Sizing Matrix

### Minimum (< 50 agents, dev/test)

| Service | CPU | Memory | Storage | Replicas |
|---|---|---|---|---|
| Wazuh Manager | 1 vCPU | 2 GB | 50 GB | 1 |
| Wazuh Indexer | 2 vCPU | 4 GB | 100 GB | 1 |
| Wazuh Dashboard | 0.5 vCPU | 1 GB | — | 1 |
| TheHive | 1 vCPU | 2 GB | 20 GB | 1 |
| Cortex | 1 vCPU | 2 GB | 10 GB | 1 |
| MISP | 1 vCPU | 2 GB | 30 GB | 1 |
| Keycloak | 0.5 vCPU | 1 GB | — | 1 |
| PostgreSQL | 0.5 vCPU | 1 GB | 20 GB | 1 |
| Nginx | 0.25 vCPU | 256 MB | — | 1 |
| **Total** | **~8 vCPU** | **~15 GB** | **~230 GB** | |

### Medium (50–500 agents, production)

| Service | CPU | Memory | Storage | Replicas |
|---|---|---|---|---|
| Wazuh Manager | 2 vCPU | 4 GB | 100 GB | 2 (HA) |
| Wazuh Indexer | 4 vCPU | 8 GB | 500 GB | 3 |
| Wazuh Dashboard | 1 vCPU | 2 GB | — | 2 |
| TheHive | 2 vCPU | 4 GB | 50 GB | 1 |
| Cortex | 2 vCPU | 4 GB | 20 GB | 1 |
| MISP | 2 vCPU | 4 GB | 100 GB | 1 |
| Keycloak | 1 vCPU | 2 GB | — | 2 |
| PostgreSQL | 2 vCPU | 4 GB | 50 GB | 1 |
| Prometheus | 1 vCPU | 2 GB | 50 GB | 1 |
| Grafana | 0.5 vCPU | 1 GB | — | 1 |
| **Total** | **~20 vCPU** | **~40 GB** | **~900 GB** | |

### Large (500+ agents, enterprise)

| Service | CPU | Memory | Storage | Replicas |
|---|---|---|---|---|
| Wazuh Manager | 4 vCPU | 8 GB | 200 GB | 2 (HA) |
| Wazuh Indexer (master) | 2 vCPU | 4 GB | 20 GB | 3 |
| Wazuh Indexer (data) | 8 vCPU | 16 GB | 1 TB | 3+ |
| Wazuh Indexer (coord) | 2 vCPU | 2 GB | — | 2 |
| TheHive | 4 vCPU | 8 GB | 100 GB | 2 |
| Cortex | 4 vCPU | 8 GB | 50 GB | 2 |
| MISP | 2 vCPU | 4 GB | 200 GB | 1 |
| Keycloak | 2 vCPU | 4 GB | — | 3 |
| PostgreSQL | 4 vCPU | 8 GB | 200 GB | 2 (primary+replica) |
| Prometheus | 2 vCPU | 4 GB | 100 GB | 1 |
| Grafana | 1 vCPU | 2 GB | — | 2 |
| **Total** | **~45 vCPU** | **~84 GB** | **~2+ TB** | |

---

## Storage Growth Estimates

| Data Source | Daily Growth | 90-Day | 1-Year |
|---|---|---|---|
| Wazuh alerts (100 agents) | ~500 MB | ~45 GB | ~180 GB |
| Wazuh archives | ~2 GB | ~180 GB | ~730 GB |
| Suricata EVE | ~1 GB | ~90 GB | ~365 GB |
| TheHive cases | ~50 MB | ~4.5 GB | ~18 GB |
| Audit logs | ~100 MB | ~9 GB | ~36 GB |
| Prometheus metrics | ~200 MB | ~18 GB | ~73 GB |
| **Total** | **~4 GB/day** | **~350 GB** | **~1.4 TB** |

---

## Auto-Scaling Policies

### Kubernetes HPA (Horizontal Pod Autoscaler)

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: wazuh-dashboard-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: wazuh-dashboard
  minReplicas: 1
  maxReplicas: 5
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
```

### Alert-Based Scaling Triggers

| Metric | Threshold | Action |
|---|---|---|
| CPU > 70% sustained 10m | Warning | Scale up 1 replica |
| CPU > 85% sustained 5m | Critical | Scale up 2 replicas |
| Memory > 80% sustained 10m | Warning | Scale up 1 replica |
| Disk > 85% | Warning | Expand PVC + alert |
| Disk > 95% | Critical | Emergency ILM rollover |
| Event queue depth > 10k | Warning | Scale indexer data nodes |

---

## Performance Benchmarks

### Expected Throughput

| Tier | Agents | EPS (Events/sec) | Indexer Nodes | Query Latency |
|---|---|---|---|---|
| Small | < 50 | 100–500 | 1 | < 2s |
| Medium | 50–500 | 500–5,000 | 3 | < 3s |
| Large | 500–2,000 | 5,000–20,000 | 5+ | < 5s |
| Enterprise | 2,000+ | 20,000+ | 8+ | < 10s |

### Key Performance Indicators

- **Alert ingestion latency**: < 5 seconds from event to indexed alert
- **Dashboard query time**: < 3 seconds for 90-day range
- **Case creation API**: < 500ms p95
- **Keycloak login**: < 1 second p95
- **Backup duration**: < 30 minutes for full backup

---

## Disaster Recovery Targets

| Metric | Target | How |
|---|---|---|
| **RPO** (Recovery Point Objective) | ≤ 24 hours | Daily automated backups |
| **RTO** (Recovery Time Objective) | ≤ 4 hours | `backup-dr.sh restore` |
| **Backup retention** | 30 days local, 7 years archive | ILM + S3 lifecycle |
| **Cross-region replication** | Async to secondary region | S3/GCS replication |
