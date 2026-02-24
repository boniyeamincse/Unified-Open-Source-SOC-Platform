<!-- ================================================================
  Unified Open-Source SOC Platform
  Author : Boni Yeamin
  Open Source V:1.0
  File   : README.md
  Purpose: Main project README — overview, features, architecture,
           installation, usage, and contribution guide.
================================================================= -->

<div align="center">

# 🛡 Unified Open-Source SOC Platform

### Enterprise-Grade Security Operations Center — Fully Dockerized

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![Open Source](https://img.shields.io/badge/Open%20Source-V1.0-brightgreen)](#)
[![Issues](https://img.shields.io/github/issues/boniyeamincse/Unified-Open-Source-SOC-Platform)](https://github.com/boniyeamincse/Unified-Open-Source-SOC-Platform/issues)
[![Stars](https://img.shields.io/github/stars/boniyeamincse/Unified-Open-Source-SOC-Platform?style=social)](https://github.com/boniyeamincse/Unified-Open-Source-SOC-Platform)
[![Contributors](https://img.shields.io/github/contributors/boniyeamincse/Unified-Open-Source-SOC-Platform)](https://github.com/boniyeamincse/Unified-Open-Source-SOC-Platform/graphs/contributors)

**A production-ready, open-source SOC platform that integrates 7+ best-of-breed security tools into a single Docker Compose deployment.**

[Quick Start](#-quick-start) •
[Architecture](#-architecture) •
[Features](#-features) •
[Documentation](#-documentation) •
[Contributing](CONTRIBUTING.md) •
[Open Issues](https://github.com/boniyeamincse/Unified-Open-Source-SOC-Platform/issues)

---

</div>

## 📋 Table of Contents

- [Why This Project?](#-why-this-project)
- [Features](#-features)
- [Architecture](#-architecture)
- [Tech Stack](#-tech-stack)
- [Quick Start](#-quick-start)
- [Service Access](#-service-access)
- [Project Structure](#-project-structure)
- [Documentation](#-documentation)
- [Contributing](#-contributing)
- [Roadmap](#-roadmap)
- [Open Issues](#-open-issues)
- [License](#-license)
- [Author](#-author)

---

## 💡 Why This Project?

Building a Security Operations Center typically requires months of integration work, expensive vendor licenses, and deep expertise across dozens of tools. **This project eliminates that barrier.**

With a single `docker compose up -d`, you get a fully integrated SOC platform that covers:

| Capability | Traditional Approach | This Platform |
|---|---|---|
| SIEM & XDR | Splunk / QRadar ($50K+/yr) | ✅ Wazuh (free) |
| Network IDS/IPS | Commercial Snort/Zeek | ✅ Suricata (free) |
| Threat Intelligence | Anomali / ThreatConnect | ✅ MISP (free) |
| Case Management | ServiceNow SecOps | ✅ TheHive (free) |
| Automated Analysis | Carbon Black | ✅ Cortex (free) |
| Vulnerability Mgmt | Tenable / Qualys | ✅ OpenVAS (free) |
| SOAR Automation | Palo Alto XSOAR | ✅ Shuffle (free) |

**Total Cost: $0 in licensing** — all 100% open source.

---

## ✨ Features

<table>
<tr>
<td width="50%">

### ✔ Full SIEM & XDR
- Real-time log collection and analysis
- File Integrity Monitoring (FIM)
- Vulnerability detection on endpoints
- Rootkit and trojan detection
- Agent-based endpoint monitoring
- MITRE ATT&CK mapping

</td>
<td width="50%">

### ✔ Network IDS/IPS
- Deep packet inspection with Suricata
- Custom detection rules (scanning, C2, web attacks)
- EVE JSON output for SIEM correlation
- Protocol-aware detection (HTTP, DNS, TLS, SSH)
- Lateral movement detection
- Data exfiltration alerting

</td>
</tr>
<tr>
<td>

### ✔ Threat Intelligence
- MISP integration for IOC management
- Automated IOC sync to Wazuh CDB lists
- IP, domain, hash, and URL matching
- ZeroMQ event publishing
- Correlation engine for threat linking
- TAXII/STIX feed support

</td>
<td>

### ✔ SOAR & Automation
- Shuffle workflow automation engine
- Automated incident response playbooks
- Auto-block malicious IPs
- Auto-enrich IOCs via MISP & VirusTotal
- Auto-create TheHive cases from alerts
- Slack/Email notification on incidents

</td>
</tr>
<tr>
<td>

### ✔ Case Management
- TheHive 5 case tracking
- Automated task creation per incident
- MITRE ATT&CK tagging
- TLP/PAP classification
- Cortex-powered IOC enrichment
- Full case lifecycle management

</td>
<td>

### ✔ Vulnerability Management
- OpenVAS / Greenbone vulnerability scanning
- NVT, SCAP, and CERT feed synchronization
- Scheduled automated scans
- CVE-based vulnerability detection
- Risk scoring and prioritization
- Results integrated into Wazuh

</td>
</tr>
<tr>
<td colspan="2">

### ✔ Dockerized Unified SOC
- **Single `docker compose up`** deploys all 10+ services
- Isolated Docker network (`soc_net`) for security
- TLS termination via Nginx reverse proxy
- Automated deployment script with health checks
- Environment-based configuration (`.env` file)
- One-click deployment on any Linux server

</td>
</tr>
</table>

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                      NGINX REVERSE PROXY (TLS)                      │
│              Port 443 — Routes to all SOC services                  │
└──────┬──────────┬──────────┬──────────┬──────────┬──────────┬───────┘
       │          │          │          │          │          │
       ▼          ▼          ▼          ▼          ▼          ▼
┌──────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌─────────┐
│  Wazuh   │ │  MISP  │ │TheHive │ │ Cortex │ │OpenVAS │ │ Shuffle │
│Dashboard │ │  TIP   │ │ Cases  │ │Analysis│ │VulnMgmt│ │  SOAR   │
│  :5601   │ │ :8080  │ │ :9000  │ │ :9001  │ │ :9392  │ │ :3001   │
└────┬─────┘ └───┬────┘ └───┬────┘ └───┬────┘ └────────┘ └────┬────┘
     │           │          │          │                       │
     ▼           ▼          ▼          ▼                       ▼
┌──────────────────────────────────────────────────────────────────────┐
│                        DOCKER NETWORK (soc_net)                      │
└──────┬───────────────────────┬───────────────────────────────────────┘
       │                       │
       ▼                       ▼
┌──────────────┐    ┌─────────────────────┐
│ Wazuh Manager│    │   OpenSearch/Indexer │
│  :1514 (UDP) │    │     :9200 (Data)     │
│  :55000 (API)│    └─────────────────────┘
└──────┬───────┘
       │
       ▼
┌──────────────┐    ┌─────────────────────┐
│   Suricata   │───▶│   EVE JSON Logs      │───▶ Wazuh ingestion
│ (host network│    │ /var/log/suricata/   │
│   IDS/IPS)   │    └─────────────────────┘
└──────────────┘
```

### Data Flow

```
Endpoints (Wazuh Agents)
    │
    ▼
Wazuh Manager ──▶ OpenSearch ──▶ Wazuh Dashboard
    │                                    │
    ├── Suricata EVE Logs ◀── Network Traffic
    │
    ├── Alert (level ≥ 7) ──▶ Shuffle SOAR Playbook
    │                              │
    │                              ├──▶ MISP (IOC enrichment)
    │                              ├──▶ VirusTotal (reputation)
    │                              ├──▶ TheHive (create case)
    │                              ├──▶ Cortex (analyze IOCs)
    │                              └──▶ Firewall (block IP)
    │
    └── Vulnerability Scan ◀── OpenVAS ──▶ CVE Database
```

---

## 🛠 Tech Stack

| Component | Tool | Version | Purpose |
|---|---|---|---|
| **SIEM / XDR** | [Wazuh](https://wazuh.com/) | 4.7.2 | Log analysis, FIM, vulnerability detection |
| **Network IDS** | [Suricata](https://suricata.io/) | Latest | Deep packet inspection, rule-based detection |
| **Threat Intel** | [MISP](https://www.misp-project.org/) | Latest | IOC management, threat sharing |
| **Case Mgmt** | [TheHive](https://thehive-project.org/) | 5.x | Incident tracking, case lifecycle |
| **Analysis** | [Cortex](https://thehive-project.org/) | 3.x | Automated IOC enrichment |
| **Vuln Mgmt** | [OpenVAS/Greenbone](https://www.greenbone.net/) | CE | Vulnerability scanning |
| **SOAR** | [Shuffle](https://shuffler.io/) | Latest | Workflow automation |
| **Reverse Proxy** | [Nginx](https://nginx.org/) | Latest | TLS termination, routing |
| **Database** | [PostgreSQL](https://www.postgresql.org/) | 15 | TheHive data storage |
| **Search** | [OpenSearch](https://opensearch.org/) | Wazuh Indexer | Log indexing and search |
| **Orchestration** | [Docker Compose](https://docs.docker.com/compose/) | 3.9 | Service orchestration |

---

## 🚀 Quick Start

### Prerequisites

| Requirement | Minimum |
|---|---|
| **OS** | Ubuntu 22.04+ / Debian 12+ / CentOS 9+ |
| **RAM** | 16 GB (32 GB recommended) |
| **Disk** | 100 GB free |
| **Docker** | 24.0+ |
| **Docker Compose** | v2.20+ |

### 1. Clone the Repository

```bash
git clone https://github.com/boniyeamincse/Unified-Open-Source-SOC-Platform.git
cd Unified-Open-Source-SOC-Platform
```

### 2. Configure Environment

```bash
cp .env.example .env
nano .env  # ⚠️ Change ALL default passwords!
```

### 3. Deploy the SOC Stack

**Option A — Automated (recommended):**
```bash
sudo bash docs/deploy.sh deploy
```

**Option B — Manual:**
```bash
# Generate TLS certificates
bash nginx/certs/generate_certs.sh

# Start all services
docker compose up -d

# Check health
docker compose ps
```

### 4. Access the Platform

Add to `/etc/hosts`:
```
<YOUR_SERVER_IP>  wazuh.soc.local misp.soc.local thehive.soc.local
<YOUR_SERVER_IP>  cortex.soc.local openvas.soc.local shuffle.soc.local
```

Then open `https://wazuh.soc.local` in your browser.

---

## 🌐 Service Access

| Service | URL | Default Port |
|---|---|---|
| **Wazuh Dashboard** | `https://wazuh.soc.local` | 5601 |
| **MISP** | `https://misp.soc.local` | 8080 |
| **TheHive** | `https://thehive.soc.local` | 9000 |
| **Cortex** | `https://cortex.soc.local` | 9001 |
| **OpenVAS** | `https://openvas.soc.local` | 9392 |
| **Shuffle** | `https://shuffle.soc.local` | 3001 |
| **Wazuh API** | `https://<host>:55000` | 55000 |

> ⚠️ **Change all default passwords before production use!** See `.env` file.

---

## 📁 Project Structure

```
Unified-Open-Source-SOC-Platform/
├── docker-compose.yml          # Main orchestration file
├── .env.example                # Environment variable template
├── .env                        # Your local config (git-ignored)
├── README.md                   # This file
├── CONTRIBUTING.md             # Contribution guidelines
├── LICENSE                     # MIT License
│
├── nginx/                      # Reverse proxy
│   ├── nginx.conf              # TLS termination & routing
│   └── certs/
│       └── generate_certs.sh   # Self-signed cert generator
│
├── wazuh/                      # SIEM / XDR
│   ├── ossec.conf              # Wazuh Manager configuration
│   └── wazuh-misp-integration.py  # IOC sync script
│
├── suricata/                   # Network IDS/IPS
│   ├── suricata.yaml           # IDS engine configuration
│   └── rules/
│       └── local.rules         # Custom detection rules
│
├── misp/                       # Threat Intelligence
│   └── config.php              # MISP configuration
│
├── thehive/                    # Case Management
│   └── application.conf        # TheHive 5 configuration
│
├── cortex/                     # Automated Analysis
│   └── application.conf        # Cortex 3 configuration
│
├── openvas/                    # Vulnerability Management
│   └── setup.sh                # Feed sync & setup script
│
├── shuffle/                    # SOAR Automation
│   └── .env.shuffle            # Shuffle environment config
│
└── docs/                       # Documentation & reference
    ├── ARCHITECTURE.md          # Detailed architecture reference
    ├── INSTALL.md               # Step-by-step installation guide
    ├── BLUEPRINT.md             # SOC architecture blueprint
    ├── ENTERPRISE_SECURITY_AUDIT.md  # Security audit report
    ├── deploy.sh                # Automated deployment script
    ├── soc_response_playbook.py # Incident response playbook
    ├── docker-compose.yml       # Full reference compose (16 services)
    ├── nginx.conf               # Full reference Nginx config
    ├── ossec.conf               # Full reference Wazuh config
    ├── suricata.yaml            # Full reference Suricata config
    └── .env.example             # Full reference env template
```

---

## 📚 Documentation

| Document | Description |
|---|---|
| [📖 Installation Guide](docs/INSTALL.md) | Step-by-step deployment instructions |
| [🏗 Architecture Reference](docs/ARCHITECTURE.md) | Integration maps, data flows, port mapping |
| [🛡 SOC Blueprint](docs/BLUEPRINT.md) | Architecture decisions and component overview |
| [📋 Security Audit](docs/ENTERPRISE_SECURITY_AUDIT.md) | Enterprise security audit with findings and roadmap |
| [🚀 Deploy Script](docs/deploy.sh) | Automated one-click deployment |
| [⚡ Response Playbook](docs/soc_response_playbook.py) | Automated incident response code |

---

## 🤝 Contributing

We welcome contributions from the cybersecurity community! This is an open-source project and we need your help to make it better.

**📜 Please read our [Contributing Guide](CONTRIBUTING.md) before submitting any changes.**

### Quick Contribution Steps

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/amazing-feature`
3. **Commit** your changes: `git commit -m "Add amazing feature"`
4. **Push** to the branch: `git push origin feature/amazing-feature`
5. **Open** a Pull Request

### Ways to Contribute

- 🐛 **Report Bugs** — [Open an Issue](https://github.com/boniyeamincse/Unified-Open-Source-SOC-Platform/issues/new?template=bug_report.md)
- 💡 **Request Features** — [Open an Issue](https://github.com/boniyeamincse/Unified-Open-Source-SOC-Platform/issues/new?template=feature_request.md)
- 📝 **Improve Documentation** — Fix typos, add examples, improve clarity
- 🔧 **Submit Code** — New features, bug fixes, security hardening
- 🧪 **Write Tests** — Add integration tests and validation scripts
- 🌍 **Translate** — Help translate documentation to other languages

---

## 🗺 Roadmap

### Phase 1 — Security Hardening *(In Progress)*
- [ ] Secrets management (HashiCorp Vault / Docker Secrets)
- [ ] TLS for all inter-service communication
- [ ] Nginx security headers (HSTS, CSP, X-Frame-Options)
- [ ] API rate limiting
- [ ] Docker resource limits

### Phase 2 — Enterprise Access Control
- [ ] SSO integration (Keycloak / OIDC / SAML)
- [ ] Multi-factor authentication (MFA)
- [ ] Role-based access control (RBAC)
- [ ] Audit logging for all user actions

### Phase 3 — Enterprise Features
- [ ] SOC Dashboard with MTTR/SLA tracking
- [ ] SIEM correlation rules engine
- [ ] Alert risk scoring and prioritization
- [ ] Compliance reporting (ISO 27001, SOC2, GDPR)
- [ ] Immutable audit logs
- [ ] ML-based anomaly detection

### Phase 4 — Production Infrastructure
- [ ] Kubernetes Helm charts
- [ ] High Availability clustering
- [ ] Automated backup & disaster recovery
- [ ] Prometheus + Grafana observability
- [ ] CI/CD pipeline with image scanning

---

## 🐛 Open Issues

We track bugs, features, and improvements via [GitHub Issues](https://github.com/boniyeamincse/Unified-Open-Source-SOC-Platform/issues).

### Issue Labels

| Label | Purpose |
|---|---|
| `bug` | Something isn't working |
| `enhancement` | New feature or improvement |
| `security` | Security-related issue |
| `documentation` | Documentation improvements |
| `good first issue` | Good for newcomers |
| `help wanted` | Looking for contributors |

### Report a Bug

Found a problem? [Open a bug report](https://github.com/boniyeamincse/Unified-Open-Source-SOC-Platform/issues/new?template=bug_report.md) with:
1. Steps to reproduce
2. Expected vs actual behavior
3. System info (OS, Docker version, RAM)
4. Logs (`docker compose logs <service>`)

### Request a Feature

Have an idea? [Open a feature request](https://github.com/boniyeamincse/Unified-Open-Source-SOC-Platform/issues/new?template=feature_request.md) with:
1. Problem you're solving
2. Proposed solution
3. Alternatives considered

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

You are free to use, modify, and distribute this software for any purpose, including commercial use.

---

## 👤 Author

**Boni Yeamin**

- 🔗 GitHub: [@boniyeamincse](https://github.com/boniyeamincse)
- 📧 Open to collaboration and feedback

---

## ⭐ Star History

If this project helps you, please give it a ⭐ to show your support!

---

<div align="center">

**Built with ❤️ for the cybersecurity community**

*Protecting networks, one alert at a time.*

</div>
