<!-- ================================================================
  Unified Open-Source SOC Platform
  Author : Boni Yeamin
  Open Source V:1.0
  File   : docs/BLUEPRINT.md
  Purpose: SOC architecture blueprint with component overview,
           integration strategy, and hardware requirements.
================================================================= -->

# 🛡 Unified Open-Source SOC Platform Blueprint

This document outlines the architecture and integration strategy for the Unified Open-Source SOC Platform.

## Architecture Overview

This platform follows a **modular monolith** architecture orchestrated by Docker Compose,
with services segmented across **three isolated networks**:

| Tier | Network | Purpose | Services |
|---|---|---|---|
| **Management** | `net-mgmt` | Admin access, SSO, reverse proxy | Nginx, Keycloak |
| **Application** | `net-app` | Case management, SOAR, analytics | TheHive, Cortex, MISP, Shuffle, OpenVAS |
| **Data** | `net-data` | Storage, indexing, agents | Wazuh, OpenSearch, PostgreSQL, Redis, Suricata |

### Service Roles

| Component | Role | Network Tier |
|---|---|---|
| **Nginx** | TLS termination, reverse proxy, rate limiting, security headers | Management |
| **Keycloak** | SSO (OIDC), MFA, 5-role RBAC, session management | Management |
| **Wazuh Manager** | SIEM — log collection, FIM, vulnerability detection, agent management | Data |
| **Suricata** | IDS/IPS — network traffic analysis, EVE JSON → Wazuh | Data |
| **OpenSearch** | Search/analytics backend for Wazuh alerts and Suricata events | Data |
| **MISP** | Threat intelligence sharing, IOC feeds, ZMQ publishing | Application |
| **TheHive** | Case management, incident tracking, Cortex integration | Application |
| **Cortex** | Observable analysis, 100+ analyzers, response actions | Application |
| **OpenVAS** | Vulnerability scanning, NVT/SCAP/CERT feeds | Application |
| **Shuffle** | SOAR automation — 20 playbooks, Wazuh/MISP/TheHive orchestration | Application |
| **Redis** | Cache + message broker for MISP | Data |
| **PostgreSQL** | Relational database for TheHive | Data |
| **Prometheus** | Metrics collection — 12 scrape targets, 15 alert rules | Observability |
| **Grafana** | Dashboards + visualization for all metrics and alerts | Observability |

## 🔵 Core SIEM + XDR: Wazuh
- **Role:** Central Brain / Single-Pane-of-Glass.
- **Functions:** Log management, FIM, Vulnerability detection, Compliance, Agent-based monitoring.

## 🟢 Network IDS/IPS: Suricata
- **Role:** Network monitoring layer.
- **Integration:** Generates logs shipped via Filebeat to Wazuh for correlation.

## 🟣 Threat Intelligence: MISP
- **Role:** IOC management and feed synchronization.
- **Integration:** Matches IOCs in Wazuh and generates Suricata rules.

## 🟡 SOAR + Case Management: TheHive + Cortex
- **Role:** Incident response and case tracking.
- **Functions:** Analyst workflows, automated enrichment, malware sandboxing.

## 🔴 Vulnerability Management: OpenVAS
- **Role:** Asset scanning and risk scoring.
- **Integration:** Scan results fed back into Wazuh SIEM.

## 🧠 Automation Layer: Shuffle
- **Role:** Security orchestration.
- **Functions:** Blocking IPs, disabling users, automated enrichment.

## 🐳 Deployment Strategy
- **Network:** `soc_net` (Docker network).
- **Security:** TLS encryption, Reverse proxy (Nginx), RBAC.
