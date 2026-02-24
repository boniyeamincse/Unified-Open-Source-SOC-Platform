#!/usr/bin/env python3
"""
####################################################################
  Unified Open-Source SOC Platform
  Author : Boni Yeamin
  Open Source V:1.0
  File   : docs/soc_response_playbook.py
  Purpose: Automated incident response playbook triggered by Wazuh
           webhooks. Enriches IOCs via MISP & Cortex, creates
           TheHive cases, blocks malicious IPs, and sends alerts.
####################################################################

How it works:
  Step 1: Wazuh sends a webhook alert (level >= 7)
  Step 2: Script parses the alert and extracts IOCs
  Step 3: IOCs are enriched via MISP and Cortex API
  Step 4: A TheHive case is created with tasks
  Step 5: Malicious IPs are blocked via Wazuh Active Response
  Step 6: Notification is sent to Slack/Email

═══════════════════════════════════════════════════════════
 Shuffle SOAR Playbook — Wazuh Alert Response
 Unified SOC Platform
═══════════════════════════════════════════════════════════

 Playbook: Automated SOC Incident Response
 Trigger:  Wazuh webhook (level >= 7)

 Actions:
  1. Parse Wazuh alert
  2. Enrich IP with threat intelligence (MISP + VirusTotal)
  3. Create TheHive case
  4. Block malicious IP via firewall
  5. Notify via Slack / Email
"""

import json
import requests
import logging
import os
from datetime import datetime
from typing import Optional

# ── Logging ───────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S"
)
logger = logging.getLogger("soc-playbook")

# ── Configuration ─────────────────────────────────────────
class Config:
    # Service URLs
    THEHIVE_URL     = os.getenv("THEHIVE_URL", "http://thehive:9000")
    THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "")
    MISP_URL        = os.getenv("MISP_URL", "http://misp:80")
    MISP_API_KEY    = os.getenv("MISP_API_KEY", "")
    WAZUH_API_URL   = os.getenv("WAZUH_API_URL", "https://wazuh-manager:55000")
    WAZUH_USER      = os.getenv("WAZUH_USER", "wazuh")
    WAZUH_PASS      = os.getenv("WAZUH_PASS", "")
    VIRUSTOTAL_KEY  = os.getenv("VIRUSTOTAL_API_KEY", "")
    SLACK_WEBHOOK   = os.getenv("SLACK_WEBHOOK_URL", "")

    # Thresholds
    BLOCK_THRESHOLD     = 9     # Alert level to auto-block IP
    CASE_THRESHOLD      = 7     # Alert level to auto-create case
    VT_MALICIOUS_THRESH = 5     # VirusTotal detections to flag as malicious


# ── Wazuh Alert Parser ────────────────────────────────────
class WazuhAlert:
    """Parse and normalize a raw Wazuh JSON alert."""

    def __init__(self, raw: dict):
        self.raw = raw
        self.id         = raw.get("id", "unknown")
        self.timestamp  = raw.get("timestamp", datetime.utcnow().isoformat())
        self.level      = int(raw.get("rule", {}).get("level", 0))
        self.rule_id    = raw.get("rule", {}).get("id", "")
        self.rule_desc  = raw.get("rule", {}).get("description", "")
        self.agent_name = raw.get("agent", {}).get("name", "unknown")
        self.agent_ip   = raw.get("agent", {}).get("ip", "")
        self.full_log   = raw.get("full_log", "")
        self.src_ip     = self._extract_src_ip()
        self.mitre      = raw.get("rule", {}).get("mitre", {})

    def _extract_src_ip(self) -> Optional[str]:
        """Extract source IP from various alert fields."""
        locations = [
            ("data", "srcip"),
            ("data", "src_ip"),
            ("data", "remote_ip"),
        ]
        for *keys, leaf in locations:
            node = self.raw
            for k in keys:
                node = node.get(k, {})
            ip = node.get(leaf, "")
            if ip and ip not in ("127.0.0.1", "::1", self.agent_ip):
                return ip
        return None

    def to_summary(self) -> str:
        lines = [
            f"*Alert ID:* {self.id}",
            f"*Level:* {self.level}",
            f"*Rule:* [{self.rule_id}] {self.rule_desc}",
            f"*Agent:* {self.agent_name} ({self.agent_ip})",
        ]
        if self.src_ip:
            lines.append(f"*Source IP:* {self.src_ip}")
        if self.mitre:
            tactics = ", ".join(self.mitre.get("tactic", []))
            techniques = ", ".join(self.mitre.get("id", []))
            lines.append(f"*MITRE:* {tactics} — {techniques}")
        return "\n".join(lines)


# ── Threat Intelligence ───────────────────────────────────
class ThreatIntel:
    """Query MISP and VirusTotal for IOC enrichment."""

    def __init__(self):
        self.misp_headers = {
            "Authorization": Config.MISP_API_KEY,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

    def check_ip_misp(self, ip: str) -> dict:
        """Search MISP for known malicious IP."""
        try:
            resp = requests.post(
                f"{Config.MISP_URL}/attributes/restSearch",
                headers=self.misp_headers,
                json={"value": ip, "type": "ip-src", "returnFormat": "json"},
                timeout=10,
                verify=False
            )
            data = resp.json()
            attrs = data.get("response", {}).get("Attribute", [])
            return {
                "found": len(attrs) > 0,
                "count": len(attrs),
                "events": [a.get("event_id") for a in attrs[:5]]
            }
        except Exception as e:
            logger.warning(f"MISP lookup failed for {ip}: {e}")
            return {"found": False, "error": str(e)}

    def check_ip_virustotal(self, ip: str) -> dict:
        """Check IP reputation via VirusTotal."""
        if not Config.VIRUSTOTAL_KEY:
            return {"skipped": True, "reason": "No API key configured"}
        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": Config.VIRUSTOTAL_KEY},
                timeout=15
            )
            if resp.status_code == 200:
                stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                return {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "is_malicious": malicious >= Config.VT_MALICIOUS_THRESH,
                    "stats": stats
                }
        except Exception as e:
            logger.warning(f"VirusTotal lookup failed for {ip}: {e}")
        return {"malicious": 0, "suspicious": 0, "is_malicious": False}


# ── TheHive Case Manager ──────────────────────────────────
class TheHiveManager:
    """Create and manage incident cases in TheHive."""

    def __init__(self):
        self.headers = {
            "Authorization": f"Bearer {Config.THEHIVE_API_KEY}",
            "Content-Type": "application/json"
        }

    def create_case(self, alert: WazuhAlert, enrichment: dict) -> Optional[str]:
        """Create a new TheHive case from a Wazuh alert."""
        severity = self._map_severity(alert.level)
        tags = [f"wazuh-rule-{alert.rule_id}", f"agent-{alert.agent_name}"]

        if alert.mitre:
            tags += [f"mitre-{t}" for t in alert.mitre.get("id", [])]

        # Build description
        desc = f"""## Wazuh Alert Details

{alert.to_summary()}

## Raw Log
```
{alert.full_log[:2000]}
```

## Enrichment
```json
{json.dumps(enrichment, indent=2)[:3000]}
```
"""
        case_data = {
            "title": f"[Wazuh {alert.level}] {alert.rule_desc}",
            "description": desc,
            "severity": severity,
            "startDate": int(datetime.utcnow().timestamp() * 1000),
            "tags": tags,
            "flag": alert.level >= 10,
            "tlp": 2,  # TLP:AMBER
            "pap": 2,
            "customFields": {
                "wazuh-alert-id": {"string": alert.id},
                "wazuh-rule-id": {"string": alert.rule_id},
                "agent-name": {"string": alert.agent_name},
                "source-ip": {"string": alert.src_ip or "N/A"},
            }
        }

        try:
            resp = requests.post(
                f"{Config.THEHIVE_URL}/api/case",
                headers=self.headers,
                json=case_data,
                timeout=15
            )
            if resp.status_code == 201:
                case_id = resp.json().get("_id")
                logger.info(f"TheHive case created: {case_id}")

                # Add task
                self._add_task(case_id, "Investigate source IP")
                self._add_task(case_id, "Review affected endpoint logs")
                self._add_task(case_id, "Determine attack vector")
                self._add_task(case_id, "Contain and remediate")

                return case_id
            else:
                logger.error(f"TheHive case creation failed: {resp.status_code} {resp.text}")
        except Exception as e:
            logger.error(f"TheHive request failed: {e}")
        return None

    def _add_task(self, case_id: str, title: str):
        """Add a task to a TheHive case."""
        try:
            requests.post(
                f"{Config.THEHIVE_URL}/api/case/{case_id}/task",
                headers=self.headers,
                json={"title": title, "status": "Waiting"},
                timeout=10
            )
        except Exception as e:
            logger.warning(f"Failed to add task '{title}': {e}")

    @staticmethod
    def _map_severity(level: int) -> int:
        """Map Wazuh alert level (0-15) to TheHive severity (1-4)."""
        if level >= 12:
            return 4  # Critical
        elif level >= 9:
            return 3  # High
        elif level >= 7:
            return 2  # Medium
        return 1       # Low


# ── Firewall Response ─────────────────────────────────────
class FirewallManager:
    """Block malicious IPs via Wazuh active response."""

    def __init__(self):
        self.token = None
        self._authenticate()

    def _authenticate(self):
        """Get Wazuh API auth token."""
        try:
            resp = requests.get(
                f"{Config.WAZUH_API_URL}/security/user/authenticate",
                auth=(Config.WAZUH_USER, Config.WAZUH_PASS),
                verify=False,
                timeout=10
            )
            if resp.status_code == 200:
                self.token = resp.json().get("data", {}).get("token")
        except Exception as e:
            logger.warning(f"Wazuh API auth failed: {e}")

    def block_ip(self, ip: str, agent_id: str = "000") -> bool:
        """Block an IP using Wazuh active response."""
        if not self.token:
            logger.warning("No Wazuh API token — cannot block IP")
            return False
        try:
            resp = requests.put(
                f"{Config.WAZUH_API_URL}/active-response",
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json"
                },
                json={
                    "command": "firewall-drop",
                    "arguments": [ip],
                    "alert": {"data": {"srcip": ip}}
                },
                verify=False,
                timeout=10
            )
            if resp.status_code == 200:
                logger.info(f"IP blocked via Wazuh active response: {ip}")
                return True
        except Exception as e:
            logger.error(f"IP block failed: {e}")
        return False


# ── Notification Manager ──────────────────────────────────
class NotificationManager:
    """Send SOC notifications to Slack."""

    def slack(self, alert: WazuhAlert, case_id: Optional[str], enrichment: dict, blocked: bool):
        """Send Slack notification for a SOC incident."""
        if not Config.SLACK_WEBHOOK:
            return

        color = "#ff0000" if alert.level >= 10 else "#ff9900" if alert.level >= 7 else "#36a64f"
        actions = []
        if case_id:
            actions.append(f"• TheHive case created: <{Config.THEHIVE_URL}/cases/{case_id}|View Case>")
        if blocked and alert.src_ip:
            actions.append(f"• Source IP blocked: `{alert.src_ip}`")

        payload = {
            "attachments": [{
                "color": color,
                "pretext": f":rotating_light: *SOC Alert — Level {alert.level}*",
                "text": alert.to_summary(),
                "fields": [
                    {"title": "MISP Hit", "value": "Yes" if enrichment.get("misp", {}).get("found") else "No", "short": True},
                    {"title": "VT Detections", "value": str(enrichment.get("vt", {}).get("malicious", 0)), "short": True},
                ],
                "footer": "\n".join(actions) if actions else "No automated actions taken",
                "ts": int(datetime.utcnow().timestamp())
            }]
        }
        try:
            requests.post(Config.SLACK_WEBHOOK, json=payload, timeout=10)
        except Exception as e:
            logger.warning(f"Slack notification failed: {e}")


# ── Main Playbook ─────────────────────────────────────────
def run_playbook(raw_alert: dict):
    """
    Main SOC incident response playbook.

    Steps:
      1. Parse Wazuh alert
      2. Enrich IOCs (MISP + VirusTotal)
      3. Create TheHive case (if level >= threshold)
      4. Block IP (if level >= block threshold or confirmed malicious)
      5. Notify via Slack
    """
    logger.info("═" * 60)
    logger.info("Playbook triggered")

    # ── Step 1: Parse alert ───────────────────────────────
    alert = WazuhAlert(raw_alert)
    logger.info(f"Alert [{alert.id}] Level={alert.level} Rule={alert.rule_id}: {alert.rule_desc}")

    if alert.level < Config.CASE_THRESHOLD:
        logger.info(f"Alert level {alert.level} below threshold {Config.CASE_THRESHOLD} — skipping")
        return {"status": "skipped", "reason": "below_threshold"}

    # ── Step 2: Enrich IOCs ───────────────────────────────
    enrichment = {}
    ti = ThreatIntel()

    if alert.src_ip:
        logger.info(f"Enriching source IP: {alert.src_ip}")
        enrichment["misp"] = ti.check_ip_misp(alert.src_ip)
        enrichment["vt"]   = ti.check_ip_virustotal(alert.src_ip)
        logger.info(f"MISP hit: {enrichment['misp']['found']} | "
                    f"VT malicious: {enrichment['vt'].get('malicious', 0)}")

    # ── Step 3: Create TheHive case ───────────────────────
    case_id = None
    hive = TheHiveManager()
    case_id = hive.create_case(alert, enrichment)

    # ── Step 4: Block malicious IP ────────────────────────
    blocked = False
    if alert.src_ip:
        should_block = (
            alert.level >= Config.BLOCK_THRESHOLD or
            enrichment.get("misp", {}).get("found") or
            enrichment.get("vt", {}).get("is_malicious")
        )
        if should_block:
            logger.info(f"Auto-blocking IP: {alert.src_ip}")
            fw = FirewallManager()
            blocked = fw.block_ip(alert.src_ip)

    # ── Step 5: Notify ────────────────────────────────────
    notifier = NotificationManager()
    notifier.slack(alert, case_id, enrichment, blocked)

    result = {
        "status": "completed",
        "alert_id": alert.id,
        "alert_level": alert.level,
        "case_id": case_id,
        "src_ip_blocked": blocked,
        "enrichment": enrichment
    }
    logger.info(f"Playbook complete: {json.dumps(result)}")
    return result


# ── Webhook Receiver (simple Flask server) ────────────────
def run_webhook_server(host="0.0.0.0", port=9999):
    """Minimal HTTP server to receive Wazuh webhook calls."""
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import json

    class WebhookHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            logger.debug(f"HTTP: {format % args}")

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')

            try:
                payload = json.loads(body)
                # Run in background thread
                import threading
                t = threading.Thread(target=run_playbook, args=(payload,), daemon=True)
                t.start()
            except Exception as e:
                logger.error(f"Webhook parse error: {e}")

    logger.info(f"Starting SOC webhook receiver on {host}:{port}")
    server = HTTPServer((host, port), WebhookHandler)
    server.serve_forever()


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "server":
        run_webhook_server()
    else:
        # Test with sample alert
        sample_alert = {
            "id": "test-001",
            "timestamp": datetime.utcnow().isoformat(),
            "rule": {
                "level": 10,
                "id": "5763",
                "description": "SSHD brute force — multiple failed logins",
                "mitre": {
                    "tactic": ["Credential Access"],
                    "id": ["T1110"]
                }
            },
            "agent": {"name": "web-server-01", "ip": "10.0.0.5"},
            "data": {"srcip": "192.0.2.100"},
            "full_log": "sshd[1234]: Failed password for root from 192.0.2.100 port 54321 ssh2"
        }
        result = run_playbook(sample_alert)
        print(json.dumps(result, indent=2))
