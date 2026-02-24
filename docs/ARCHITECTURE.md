# 🏗 Architecture Reference — Unified SOC Platform

## Component Integration Map

```
┌──────────────────────────────────────────────────────────────────────┐
│                        INTERNET / EXTERNAL                          │
└────────────────────────────────┬─────────────────────────────────────┘
                                 │
                        ┌────────▼────────┐
                        │   NGINX (TLS)   │  ← Reverse Proxy
                        │   Port 443      │
                        └────────┬────────┘
                                 │
     ┌───────────────────────────┼───────────────────────────────┐
     │                  Docker SOC Network (soc_net)             │
     │                                                           │
     │  ┌─────────────┐    ┌──────────────┐    ┌──────────────┐ │
     │  │   Suricata   │───▶│    Wazuh     │───▶│  OpenSearch  │ │
     │  │   IDS/IPS    │    │   Manager    │    │   Indexer    │ │
     │  └─────────────┘    └──────┬───────┘    └──────────────┘ │
     │                            │                              │
     │         ┌──────────────────┼──────────────────┐          │
     │         │                  │                  │          │
     │  ┌──────▼──────┐   ┌──────▼──────┐   ┌──────▼──────┐   │
     │  │    MISP      │   │   TheHive   │   │   OpenVAS   │   │
     │  │ Threat Intel │   │ Case Mgmt   │   │  Vuln Scan  │   │
     │  └─────────────┘   └──────┬──────┘   └─────────────┘   │
     │                           │                              │
     │                    ┌──────▼──────┐                       │
     │                    │   Cortex    │                       │
     │                    │  Analyzers  │                       │
     │                    └─────────────┘                       │
     │                                                           │
     │  ┌──────────────────────────────────────────────────────┐│
     │  │              Shuffle (SOAR Engine)                   ││
     │  │  Automate: Block IP, Enrich IOC, Create Case, Notify││
     │  └──────────────────────────────────────────────────────┘│
     └───────────────────────────────────────────────────────────┘
```

## Data Flow

### 1. Log Collection Flow
```
Endpoints (Wazuh Agents) ──UDP/1514──▶ Wazuh Manager ──▶ OpenSearch
Network Traffic ──▶ Suricata ──eve.json──▶ Wazuh Manager ──▶ OpenSearch
```

### 2. Threat Detection Flow
```
Wazuh Rules Engine ──match──▶ Alert Generated
  ├──▶ OpenSearch (stored & indexed)
  ├──▶ Wazuh Dashboard (visualization)
  ├──▶ Shuffle Webhook (automation trigger)
  └──▶ TheHive (case creation)
```

### 3. Incident Response Flow
```
Alert ──▶ Shuffle Playbook
  ├──▶ MISP (IOC lookup)
  ├──▶ Cortex (IP/Hash analysis)
  ├──▶ TheHive (create case + tasks)
  ├──▶ Wazuh Active Response (block IP)
  └──▶ Slack/Email (notification)
```

### 4. Vulnerability Management Flow
```
OpenVAS Scan ──results──▶ Wazuh Manager
  ├──▶ CVE correlation
  ├──▶ Risk scoring
  └──▶ Dashboard visualization
```

## Port Map

| Port | Service | Protocol | Purpose |
|------|---------|----------|---------|
| 443 | Nginx | HTTPS | Reverse proxy (all UIs) |
| 1514 | Wazuh | UDP/TCP | Agent communication |
| 1515 | Wazuh | TCP | Agent enrollment |
| 5601 | Wazuh Dashboard | HTTPS | SIEM UI |
| 8080 | MISP | HTTP | Threat Intel UI |
| 9000 | TheHive | HTTP | Case Management UI |
| 9001 | Cortex | HTTP | Analyzer UI |
| 9392 | OpenVAS | HTTPS | Vulnerability Scanner UI |
| 3001 | Shuffle | HTTP | SOAR UI |
| 55000 | Wazuh API | HTTPS | Management API |

## Network Security

- **soc_net**: Isolated Docker bridge network
- **TLS termination** at Nginx reverse proxy
- **Inter-service communication** stays internal to Docker network
- **Only Nginx port 443** exposed to external traffic (recommended)

## Blue Team vs Red Team Usage

### Blue Team (Defense)
| Tool | Function |
|---|---|
| Wazuh | Real-time monitoring, FIM, log analysis |
| Suricata | Network threat detection |
| TheHive | Incident tracking & response |
| OpenVAS | Vulnerability assessment |
| MISP | Threat intelligence sharing |

### Red Team (Offense)
| Tool | Function |
|---|---|
| Metasploit | Exploitation framework |
| Caldera | Adversary emulation (MITRE ATT&CK) |
| Atomic Red Team | Technique-level testing |

> All Red Team activity logs feed back into Wazuh to validate detection coverage.
