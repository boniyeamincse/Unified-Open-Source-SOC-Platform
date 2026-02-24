####################################################################
#  Unified Open-Source SOC Platform
#  Author : Boni Yeamin
#  Open Source V:1.0
#  File   : playbooks/README.md
#  Purpose: SOAR Playbook Library — 20 pre-built incident response
#           playbooks for the most common SOC alert types.
####################################################################

# 📘 SOAR Playbook Library

Pre-built incident response playbooks for the **top 20 alert types** seen in SOC operations.

## Playbook Structure

Each playbook YAML defines:
- **trigger**: Alert conditions that activate the playbook
- **severity**: Override severity assessment
- **steps**: Ordered list of response actions
- **escalation**: When/how to escalate to humans
- **containment**: Automated containment actions
- **evidence**: What to collect for forensics

## Playbook Index

| # | File | Alert Type | Auto-Contain |
|---|---|---|---|
| 01 | `01-malware-detected.yaml` | Malware/virus detection | ✅ Isolate host |
| 02 | `02-phishing-email.yaml` | Phishing email reported | ✅ Block sender |
| 03 | `03-brute-force-ssh.yaml` | SSH brute force | ✅ Block source IP |
| 04 | `04-brute-force-rdp.yaml` | RDP brute force | ✅ Block source IP |
| 05 | `05-ransomware.yaml` | Ransomware behavior | ✅ Isolate + alert |
| 06 | `06-data-exfiltration.yaml` | Large outbound transfer | ✅ Block destination |
| 07 | `07-privilege-escalation.yaml` | Priv esc attempt | ⚠️ Alert only |
| 08 | `08-lateral-movement.yaml` | Internal pivot detected | ✅ Isolate source |
| 09 | `09-dns-tunneling.yaml` | DNS exfiltration | ✅ Block domain |
| 10 | `10-web-attack-sqli.yaml` | SQL injection | ✅ Block + WAF rule |
| 11 | `11-web-attack-xss.yaml` | Cross-site scripting | ⚠️ Alert + log |
| 12 | `12-tor-usage.yaml` | Tor/anonymizer usage | ⚠️ Alert + investigate |
| 13 | `13-crypto-mining.yaml` | Cryptomining detected | ✅ Kill process |
| 14 | `14-c2-beacon.yaml` | C2 communication | ✅ Isolate host |
| 15 | `15-insider-threat.yaml` | Anomalous user behavior | ⚠️ Alert + monitor |
| 16 | `16-account-compromise.yaml` | Credential theft indicators | ✅ Disable account |
| 17 | `17-vulnerability-exploit.yaml` | Known CVE exploitation | ✅ Patch + isolate |
| 18 | `18-policy-violation.yaml` | Policy breach detected | ⚠️ Alert + document |
| 19 | `19-dos-ddos.yaml` | Denial of service | ✅ Rate limit + GeoBlock |
| 20 | `20-log-tampering.yaml` | Log deletion/modification | ✅ Snapshot + alert |

## Severity Levels

- **P1 Critical**: Automated containment + immediate escalation (< 15 min)
- **P2 High**: Automated containment + analyst review (< 1 hour)
- **P3 Medium**: Alert + analyst triage (< 4 hours)
- **P4 Low**: Log + periodic review (< 24 hours)
