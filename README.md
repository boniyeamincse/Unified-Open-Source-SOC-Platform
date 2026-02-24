<!-- ================================================================
  Unified Open-Source SOC Platform
  Author : Boni Yeamin
  Open Source V:1.0
  File   : README.md
  Purpose: Project overview, quick start guide, and architecture map.
================================================================= -->

# 🛡 Unified Open-Source SOC Platform

A fully integrated, Docker-based Security Operations Center (SOC) built entirely on open-source tools.

## 🏗 Architecture Overview

```
                    ┌────────────────────┐
                    │     Endpoints      │
                    └─────────┬──────────┘
                              │
                        Wazuh Agents
                              │
┌─────────────── Docker SOC Cluster ────────────────┐
│                                                    │
│  Suricata  →  Wazuh Manager  → OpenSearch         │
│                                                    │
│  MISP  ←→  Wazuh  ←→  TheHive  ←→  Cortex        │
│                                                    │
│  OpenVAS  →  Wazuh                                │
│                                                    │
│  Shuffle Automation Engine                        │
│                                                    │
└────────────────────────────────────────────────────┘
```

## ✅ Capabilities

| Feature | Tool | Status |
|---|---|---|
| SIEM / XDR | Wazuh | ✔ |
| IDS / IPS | Suricata | ✔ |
| Threat Intelligence | MISP | ✔ |
| Case Management | TheHive | ✔ |
| Analysis / Enrichment | Cortex | ✔ |
| Vulnerability Mgmt | OpenVAS | ✔ |
| SOAR Automation | Shuffle | ✔ |
| Reverse Proxy / TLS | Nginx | ✔ |

## 📁 Project Structure

```
soc-platform/
├── docker-compose.yml          # Core orchestration
├── .env                        # Environment variables
├── deploy.sh                   # One-click deployment script
├── nginx/                      # Reverse proxy config + TLS certs
│   ├── nginx.conf
│   └── certs/
├── wazuh/                      # Wazuh manager configuration
│   ├── ossec.conf
│   └── wazuh-integration.py
├── suricata/                   # IDS/IPS configuration
│   ├── suricata.yaml
│   └── rules/local.rules
├── misp/                       # Threat intelligence config
│   └── config.php
├── thehive/                    # Case management
│   └── application.conf
├── cortex/                     # Analysis engine
│   └── application.conf
├── openvas/                    # Vulnerability scanner
│   └── setup.sh
├── shuffle/                    # SOAR automation
│   └── .env.shuffle
└── docs/                       # Documentation
    ├── BLUEPRINT.md
    ├── INSTALL.md
    ├── ARCHITECTURE.md
    └── soc_response_playbook.py
```

## 🚀 Quick Start

```bash
# 1. Clone the repository
git clone <repo-url> && cd soc-platform

# 2. Review/edit environment variables
cp .env.example .env
nano .env

# 3. Deploy the full SOC stack
sudo bash deploy.sh deploy

# 4. Check service health
sudo bash deploy.sh health
```

## 🖥 Hardware Requirements

| Type | CPU | RAM | Storage |
|---|---|---|---|
| Lab | 8 Core | 16GB | 300GB |
| SME | 16 Core | 32GB | 1TB |
| Enterprise | 32+ Core | 64GB+ | 5TB+ |

## 🔗 Service URLs (Default)

| Service | URL | Default Port |
|---|---|---|
| Wazuh Dashboard | https://wazuh.soc.local | 5601 |
| MISP | https://misp.soc.local | 8080 |
| TheHive | https://thehive.soc.local | 9000 |
| Cortex | https://cortex.soc.local | 9001 |
| OpenVAS | https://openvas.soc.local | 9392 |
| Shuffle | https://shuffle.soc.local | 3001 |

## 📖 Documentation

- [BLUEPRINT.md](docs/BLUEPRINT.md) — SOC Architecture Blueprint
- [INSTALL.md](docs/INSTALL.md) — Step-by-Step Installation Guide
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) — Detailed Architecture Reference

## 📜 License

This project uses open-source tools. Each component retains its own license:
- Wazuh: GPL v2
- Suricata: GPL v2
- MISP: AGPL v3
- TheHive: AGPL v3
- Cortex: AGPL v3
- OpenVAS: GPL v2
- Shuffle: AGPL v3
