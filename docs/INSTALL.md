<!-- ================================================================
  Unified Open-Source SOC Platform
  Author : Boni Yeamin
  Open Source V:1.0
  File   : docs/INSTALL.md
  Purpose: Step-by-step installation guide covering prerequisites,
           deployment, post-deployment, and security hardening.
================================================================= -->

# 📖 Installation Guide — Unified SOC Platform

## Prerequisites

- **OS:** Ubuntu 22.04+ / Debian 12+ / CentOS 8+ (Linux only)
- **Docker:** v24+ with Compose v2
- **RAM:** Minimum 16GB (32GB recommended)
- **Disk:** Minimum 100GB free
- **Network:** Open ports: 443, 5601, 8080, 9000, 9001, 9392, 3001, 1514, 1515, 55000

---

## Step 1: System Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y curl git openssl jq

# Install Docker (if not installed)
curl -fsSL https://get.docker.com | sh
sudo systemctl enable --now docker

# Set kernel parameters for OpenSearch
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

## Step 2: Clone & Configure

```bash
git clone <repo-url> soc-platform
cd soc-platform

# Create your environment file
cp .env.example .env

# Edit passwords and settings
nano .env
```

### Key `.env` variables to customize:

| Variable | Description | Default |
|---|---|---|
| `WAZUH_VERSION` | Wazuh stack version | `4.7.2` |
| `WAZUH_PASSWORD` | Wazuh API password | `PleaseChangeMe123!` |
| `MISP_DB_PASSWORD` | MISP database password | `misp_db_secret_pass` |
| `POSTGRES_PASSWORD` | PostgreSQL password | `postgres_secure_pass` |
| `THEHIVE_SECRET` | TheHive encryption key | (generate one) |
| `GVMD_PASSWORD` | OpenVAS admin password | `admin` |

> ⚠️ **Change ALL default passwords before production deployment!**

## Step 3: Deploy

### Automated Deployment (Recommended)
```bash
sudo bash deploy.sh deploy
```

### Manual Deployment
```bash
# Pull all images
docker compose pull

# Start core services first
docker compose up -d wazuh.manager wazuh.indexer wazuh.dashboard
sleep 30

# Start network monitoring
docker compose up -d suricata
sleep 10

# Start MISP
docker compose up -d misp
sleep 20

# Start TheHive + Cortex
docker compose up -d postgres thehive cortex
sleep 30

# Start OpenVAS
docker compose up -d openvas

# Start Shuffle SOAR
docker compose up -d shuffle
```

## Step 4: Post-Deployment

### Generate TLS Certificates
```bash
cd nginx/certs
bash generate_certs.sh
```

### Register Wazuh Agents
On each endpoint:
```bash
# Linux
curl -s https://packages.wazuh.com/4.x/apt/install.sh | \
  WAZUH_MANAGER="<YOUR_SOC_IP>" bash

# Windows (PowerShell)
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent.msi -OutFile wazuh-agent.msi
msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER="<YOUR_SOC_IP>"
```

### Update OpenVAS Feeds
```bash
bash openvas/setup.sh
```

## Step 5: Verify

```bash
# Check all service health
sudo bash deploy.sh health

# View logs
sudo bash deploy.sh logs              # All services
sudo bash deploy.sh logs wazuh.manager # Specific service
```

---

## 🔧 Management Commands

| Command | Description |
|---|---|
| `sudo bash deploy.sh deploy` | Full deployment |
| `sudo bash deploy.sh health` | Service health check |
| `sudo bash deploy.sh stop` | Stop all services |
| `sudo bash deploy.sh restart` | Restart all services |
| `sudo bash deploy.sh logs [svc]` | View service logs |
| `sudo bash deploy.sh update` | Pull latest images & restart |

---

## 🔒 Security Hardening Checklist

- [ ] Change all default passwords in `.env`
- [ ] Replace self-signed TLS certs with real ones
- [ ] Restrict network access to management ports
- [ ] Enable firewall rules (UFW / iptables)
- [ ] Configure RBAC in Wazuh, TheHive, MISP
- [ ] Set up MFA for admin accounts
- [ ] Review Suricata rules for your environment
- [ ] Schedule regular OpenVAS scans

---

## 📊 Observability Stack (Optional)

Deploy Prometheus + Grafana for monitoring all SOC services:

```bash
# Start the observability overlay
docker compose -f docker-compose.yml \
  -f observability/docker-compose.observability.yml up -d

# Access points:
# Prometheus:  http://localhost:9090
# Grafana:     http://localhost:3000  (admin / admin — change on first login)
```

Grafana auto-provisions Prometheus and OpenSearch datasources via
`observability/grafana/provisioning/datasources/`.

### Monitored Targets (12)
Nginx, Keycloak, Wazuh, OpenSearch, TheHive, Cortex, MISP,
Shuffle, PostgreSQL, Redis, Node Exporter, cAdvisor.

### Alert Rules (15)
High CPU, memory pressure, service down, disk > 90%, TLS expiry,
and SOC-specific thresholds.

---

## ⏰ Automated Operations

Install the example crontab for scheduled SOC tasks:

```bash
# Review first
cat config/crontab.example

# Install (as root)
sudo crontab config/crontab.example
```

Includes: backups (02:00 daily), anomaly detection (15m), alert dedup (10m),
risk scoring (hourly), compliance reports (weekly), OpenVAS feeds (04:00).

