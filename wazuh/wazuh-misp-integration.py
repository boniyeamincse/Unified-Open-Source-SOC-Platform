#!/usr/bin/env python3
"""
Wazuh ←→ MISP Integration Script
Fetches IOCs from MISP and creates Wazuh CDB lists for real-time matching.
"""

import json
import requests
import os
import sys
import logging
from datetime import datetime, timedelta

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("wazuh-misp-sync")

# ── Configuration ─────────────────────────────────────────
MISP_URL     = os.getenv("MISP_URL", "http://misp:80")
MISP_API_KEY = os.getenv("MISP_API_KEY", "")
WAZUH_CDB_DIR = os.getenv("WAZUH_CDB_DIR", "/var/ossec/etc/lists")

# IOC types to fetch
IOC_TYPES = {
    "ip-src":     "misp-ip-list",
    "ip-dst":     "misp-ip-list",
    "domain":     "misp-domain-list",
    "hostname":   "misp-domain-list",
    "md5":        "misp-hash-list",
    "sha1":       "misp-hash-list",
    "sha256":     "misp-hash-list",
    "url":        "misp-url-list",
}

HEADERS = {
    "Authorization": MISP_API_KEY,
    "Accept": "application/json",
    "Content-Type": "application/json"
}


def fetch_iocs(days_back: int = 30) -> dict:
    """Fetch IOCs from MISP for the last N days."""
    since = (datetime.utcnow() - timedelta(days=days_back)).strftime("%Y-%m-%d")
    results = {}

    for ioc_type, list_name in IOC_TYPES.items():
        try:
            resp = requests.post(
                f"{MISP_URL}/attributes/restSearch",
                headers=HEADERS,
                json={
                    "type": ioc_type,
                    "to_ids": True,
                    "last": f"{days_back}d",
                    "returnFormat": "json",
                    "limit": 10000
                },
                timeout=30,
                verify=False
            )

            if resp.status_code == 200:
                attrs = resp.json().get("response", {}).get("Attribute", [])
                if list_name not in results:
                    results[list_name] = set()
                for attr in attrs:
                    value = attr.get("value", "").strip()
                    if value:
                        results[list_name].add(value)
                logger.info(f"Fetched {len(attrs)} {ioc_type} IOCs from MISP")
            else:
                logger.warning(f"MISP returned {resp.status_code} for {ioc_type}")

        except Exception as e:
            logger.error(f"Failed to fetch {ioc_type}: {e}")

    return results


def write_cdb_lists(iocs: dict):
    """Write IOCs to Wazuh CDB list format."""
    os.makedirs(WAZUH_CDB_DIR, exist_ok=True)

    for list_name, values in iocs.items():
        filepath = os.path.join(WAZUH_CDB_DIR, list_name)
        with open(filepath, "w") as f:
            for value in sorted(values):
                # CDB format: key:value (value can be empty)
                f.write(f"{value}:\n")

        logger.info(f"Wrote {len(values)} entries to {filepath}")


def generate_wazuh_rules():
    """Generate Wazuh custom rules for matching MISP IOCs."""
    rules = """
<!-- ======================================================= -->
<!-- MISP IOC Matching Rules - Auto-generated                -->
<!-- ======================================================= -->
<group name="misp,threat_intel,">

  <!-- Match source IP against MISP threat intel -->
  <rule id="100100" level="12">
    <if_sid>5700</if_sid>
    <list field="srcip" lookup="address_match_key">etc/lists/misp-ip-list</list>
    <description>MISP: Source IP $(srcip) found in threat intelligence feed</description>
    <group>misp,threat_intel,malicious_ip,</group>
  </rule>

  <!-- Match destination domain against MISP -->
  <rule id="100101" level="10">
    <if_sid>5700</if_sid>
    <list field="hostname" lookup="match_key">etc/lists/misp-domain-list</list>
    <description>MISP: Domain $(hostname) found in threat intelligence feed</description>
    <group>misp,threat_intel,malicious_domain,</group>
  </rule>

  <!-- Match file hash against MISP -->
  <rule id="100102" level="12">
    <if_sid>550</if_sid>
    <list field="md5" lookup="match_key">etc/lists/misp-hash-list</list>
    <description>MISP: File hash matched threat intelligence - possible malware</description>
    <group>misp,threat_intel,malware,</group>
  </rule>

  <!-- Match URL against MISP -->
  <rule id="100103" level="10">
    <if_sid>31100</if_sid>
    <list field="url" lookup="match_key">etc/lists/misp-url-list</list>
    <description>MISP: URL matched threat intelligence feed</description>
    <group>misp,threat_intel,malicious_url,</group>
  </rule>

</group>
"""
    rules_path = os.path.join(os.path.dirname(WAZUH_CDB_DIR), "rules", "misp_rules.xml")
    os.makedirs(os.path.dirname(rules_path), exist_ok=True)
    with open(rules_path, "w") as f:
        f.write(rules)
    logger.info(f"Generated MISP matching rules at {rules_path}")


if __name__ == "__main__":
    if not MISP_API_KEY:
        logger.error("MISP_API_KEY not set. Export it before running.")
        sys.exit(1)

    logger.info("=" * 60)
    logger.info("Wazuh ←→ MISP IOC Synchronization")
    logger.info("=" * 60)

    days = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    logger.info(f"Fetching IOCs from the last {days} days...")

    iocs = fetch_iocs(days)
    total = sum(len(v) for v in iocs.values())
    logger.info(f"Total unique IOCs fetched: {total}")

    if total > 0:
        write_cdb_lists(iocs)
        generate_wazuh_rules()
        logger.info("Sync complete. Restart Wazuh manager to load new lists.")
    else:
        logger.warning("No IOCs found. Check MISP connection and API key.")
