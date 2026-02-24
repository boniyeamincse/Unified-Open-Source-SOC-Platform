# 🛠 Development Task Board
## Unified Open-Source SOC Platform

> **Enterprise Readiness: 58/100** | Phase 1 ✅ | Phase 2–4 ⬜

---

## ✅ Phase 1 — Security Hardening (COMPLETE)

- [x] SEC-01: Rotate all default passwords to 24-char random strings
- [x] SEC-02: Replace `verify=False` with CA bundle TLS validation
- [x] SEC-03: Randomize MISP `cipherSeed` via env var + `random_bytes()`
- [x] SEC-04: Remove `acceptAnyCertificate=true` from TheHive
- [x] SEC-05: Add HMAC-SHA256 webhook authentication
- [x] SEC-06: Remove `X-Remote-User` header auth
- [x] SEC-07: Bind all Docker ports to `127.0.0.1`
- [x] SEC-08: Add Nginx rate limiting (10r/s general, 3r/s login)
- [x] SEC-11: Add 7 security headers (HSTS, CSP, X-Frame, etc.)
- [x] SEC-13: Add ZeroMQ authentication
- [x] SEC-14: Enable email TLS on port 587
- [x] Pin all Docker image versions
- [x] Add `mem_limit` + `cpus` to all services
- [x] Add healthchecks to 8 services
- [x] Add `no-new-privileges:true` to all containers
- [x] Nginx `read_only` + `tmpfs` + `server_tokens off`

---

## ⬜ Phase 2 — Enterprise Access Control (Weeks 5–8)

> **Goal**: Proper identity, roles, and network segmentation

- [ ] **2.1 SSO Integration** — Deploy Keycloak/authentik, configure OIDC/SAML for all services
- [ ] **2.2 Multi-Factor Auth** — Enforce MFA on Wazuh, MISP, TheHive, OpenVAS
- [ ] **2.3 RBAC Model** — Define roles: SOC Analyst, SOC Lead, Threat Hunter, Admin, Read-Only
- [ ] **2.4 API Key Rotation** — 30-day max lifetime, automated rotation scripts
- [ ] **2.5 Session Timeout** — Enforce ≤ 15 min idle timeout across all services
- [ ] **2.6 Audit Logging** — Log all auth events, config changes, data access
- [ ] **2.7 Network Segmentation** — Split `soc_net` into `net-data`, `net-app`, `net-mgmt`

**Open Security Findings addressed:** SEC-09 (RBAC)

---

## ⬜ Phase 3 — Enterprise Features (Weeks 9–16)

> **Goal**: SOC operational capabilities at enterprise scale

- [ ] **3.1 SOC Dashboard** — Real-time alert counts, MTTR, SLA tracking, analyst metrics
- [ ] **3.2 Correlation Engine** — Custom multi-event rules beyond Wazuh built-in
- [ ] **3.3 Risk Scoring** — Asset-weighted severity + environmental context
- [ ] **3.4 Compliance Reports** — Automated ISO 27001, SOC2, PCI DSS report generation
- [ ] **3.5 Audit Log Immutability** — Write-once storage with cryptographic chaining
- [ ] **3.6 Forensic Evidence Export** — Chain-of-custody compliant packaging
- [ ] **3.7 ML Anomaly Detection** — UEBA baselines, behavioral analytics
- [ ] **3.8 Alert Deduplication** — Intelligent clustering to reduce noise
- [ ] **3.9 Multi-Tenant Support** — Org-based data isolation, per-tenant RBAC
- [ ] **3.10 Playbook Library** — Pre-built playbooks for top 20 alert types

**Open Security Findings addressed:** SEC-10 (Multi-tenancy), SEC-12 (Log immutability)

---

## ⬜ Phase 4 — Production Infrastructure (Weeks 17–24)

> **Goal**: HA, observability, and enterprise-grade operations

- [ ] **4.1 Kubernetes Migration** — Helm charts for all services, namespace isolation
- [ ] **4.2 HA Clustering** — OpenSearch 3-node cluster, Wazuh active-passive
- [ ] **4.3 Backup & DR** — Automated daily backups, cross-region replication, RTO ≤ 4h
- [ ] **4.4 Observability Stack** — Prometheus + Grafana + node-exporter + cAdvisor
- [ ] **4.5 CI/CD Pipeline** — GitHub Actions + ArgoCD, Trivy scanning, blue-green deploy
- [ ] **4.6 Log Retention** — ILM policies: 90-day hot, 365-day warm, 7-year cold
- [ ] **4.7 Capacity Planning** — Auto-scaling policies, load-based resource allocation

---

## 📊 Progress Tracker

| Phase | Tasks | Done | Remaining | Score Impact |
|---|---|---|---|---|
| Phase 1 | 16 | 16 | 0 | 32 → 58 (+26) |
| Phase 2 | 7 | 0 | 7 | 58 → ~72 (+14) |
| Phase 3 | 10 | 0 | 10 | ~72 → ~86 (+14) |
| Phase 4 | 7 | 0 | 7 | ~86 → ~100 (+14) |
| **Total** | **40** | **16** | **24** | **32 → 100** |
