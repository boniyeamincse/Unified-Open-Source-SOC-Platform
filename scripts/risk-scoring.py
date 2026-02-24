#!/usr/bin/env python3
"""
####################################################################
  Unified Open-Source SOC Platform
  Author : Boni Yeamin
  File   : scripts/risk-scoring.py
  Purpose: Asset-weighted risk scoring engine. Calculates risk scores
           based on alert severity, asset criticality, and exposure.
####################################################################

Formula: risk = severity × asset_weight × exposure_factor × confidence

Usage:
  python3 scripts/risk-scoring.py --score alert.json
  python3 scripts/risk-scoring.py --assets                # List assets
  python3 scripts/risk-scoring.py --report                # Risk report
"""

import json
import sys
import os
from datetime import datetime, timezone
from typing import Optional
from dataclasses import dataclass, asdict, field

# ── Asset Criticality Weights ────────────────────────────

ASSET_WEIGHTS = {
    # Infrastructure
    "domain_controller":  10.0,
    "database_server":    9.5,
    "certificate_authority": 9.0,
    "email_server":       8.5,
    "dns_server":         8.0,
    "web_server":         7.5,
    "file_server":        7.0,
    "application_server": 7.0,
    "backup_server":      8.0,

    # Security Infrastructure
    "siem_server":        9.5,
    "firewall":           9.0,
    "ids_ips":            8.5,
    "vpn_gateway":        8.0,
    "jump_host":          8.5,
    "log_collector":      8.0,

    # Endpoints
    "executive_workstation": 7.0,
    "developer_workstation": 6.5,
    "analyst_workstation":   6.0,
    "standard_workstation":  5.0,
    "kiosk":              3.0,

    # IoT / OT
    "industrial_controller": 9.0,
    "iot_sensor":         4.0,
    "camera_system":      5.0,
    "printer":            2.0,

    # Network
    "core_switch":        8.5,
    "edge_router":        8.0,
    "access_point":       4.0,

    # Default
    "unknown":            5.0,
}

# ── Exposure Factors ─────────────────────────────────────

EXPOSURE_FACTORS = {
    "internet_facing":    1.5,   # Directly exposed to internet
    "dmz":                1.3,   # In DMZ
    "internal_sensitive":  1.2,  # Internal but holds sensitive data
    "internal_standard":  1.0,   # Standard internal
    "isolated":           0.7,   # Air-gapped or heavily segmented
    "cloud_public":       1.4,   # Public cloud instance
    "cloud_private":      1.1,   # Private cloud / VPC
}

# ── Severity Mapping ─────────────────────────────────────

SEVERITY_MAP = {
    # Wazuh rule levels
    "1": 0.5, "2": 1.0, "3": 1.5,
    "4": 2.0, "5": 2.5, "6": 3.0,
    "7": 3.5, "8": 4.0, "9": 4.5,
    "10": 5.0, "11": 6.0, "12": 7.0,
    "13": 8.0, "14": 9.0, "15": 10.0,
    # Named severities
    "low": 2.0, "medium": 5.0, "high": 7.5,
    "critical": 10.0, "informational": 0.5,
}


@dataclass
class Asset:
    """Represents a network asset with risk attributes."""
    hostname: str
    ip_address: str
    asset_type: str = "unknown"
    exposure: str = "internal_standard"
    owner: str = ""
    department: str = ""
    data_classification: str = "internal"  # public, internal, confidential, restricted
    tags: list = field(default_factory=list)

    @property
    def weight(self) -> float:
        return ASSET_WEIGHTS.get(self.asset_type, 5.0)

    @property
    def exposure_factor(self) -> float:
        return EXPOSURE_FACTORS.get(self.exposure, 1.0)


@dataclass
class RiskScore:
    """Calculated risk score for an alert."""
    alert_id: str
    timestamp: str
    source_ip: str
    destination_ip: str
    rule_id: str
    rule_description: str
    severity: float
    asset_weight: float
    exposure_factor: float
    confidence: float
    raw_score: float
    normalized_score: float  # 0-100
    risk_level: str          # Critical, High, Medium, Low, Info
    mitre_techniques: list = field(default_factory=list)


class RiskScoringEngine:
    """Asset-weighted risk scoring engine."""

    def __init__(self, asset_inventory_path: str = "config/assets.yaml"):
        self.assets: dict[str, Asset] = {}
        self.scores: list[RiskScore] = []
        self._load_default_assets()

    def _load_default_assets(self):
        """Load default SOC platform assets."""
        defaults = [
            Asset("wazuh-manager", "10.0.1.10", "siem_server", "internal_sensitive"),
            Asset("wazuh-indexer", "10.0.1.11", "database_server", "internal_sensitive"),
            Asset("thehive", "10.0.1.20", "application_server", "internal_sensitive"),
            Asset("cortex", "10.0.1.21", "application_server", "internal_standard"),
            Asset("misp", "10.0.1.30", "application_server", "internal_sensitive"),
            Asset("openvas", "10.0.1.40", "application_server", "internal_standard"),
            Asset("nginx", "10.0.1.1", "web_server", "internet_facing"),
            Asset("keycloak", "10.0.1.2", "application_server", "internet_facing"),
            Asset("postgres", "10.0.1.50", "database_server", "isolated"),
        ]
        for asset in defaults:
            self.assets[asset.ip_address] = asset
            self.assets[asset.hostname] = asset

    def get_asset(self, identifier: str) -> Asset:
        """Look up asset by IP or hostname."""
        return self.assets.get(identifier, Asset(identifier, identifier))

    def score_alert(self, alert: dict) -> RiskScore:
        """Calculate risk score for a single alert."""
        # Extract fields
        src_ip = alert.get("data", {}).get("srcip", alert.get("srcip", "unknown"))
        dst_ip = alert.get("data", {}).get("dstip", alert.get("agent", {}).get("ip", "unknown"))
        rule_level = str(alert.get("rule", {}).get("level", "5"))
        rule_id = str(alert.get("rule", {}).get("id", "0"))
        rule_desc = alert.get("rule", {}).get("description", "Unknown rule")
        mitre = alert.get("rule", {}).get("mitre", {}).get("id", [])
        alert_id = alert.get("id", f"alert-{datetime.now(timezone.utc).timestamp()}")

        # Look up target asset
        asset = self.get_asset(dst_ip)

        # Calculate components
        severity = SEVERITY_MAP.get(rule_level, 5.0)
        asset_weight = asset.weight
        exposure = asset.exposure_factor
        confidence = self._calculate_confidence(alert)

        # Risk formula
        raw_score = severity * asset_weight * exposure * confidence
        max_possible = 10.0 * 10.0 * 1.5 * 1.0  # 150
        normalized = min(100.0, (raw_score / max_possible) * 100)

        # Risk level
        if normalized >= 80:
            risk_level = "Critical"
        elif normalized >= 60:
            risk_level = "High"
        elif normalized >= 40:
            risk_level = "Medium"
        elif normalized >= 20:
            risk_level = "Low"
        else:
            risk_level = "Info"

        score = RiskScore(
            alert_id=alert_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            source_ip=src_ip,
            destination_ip=dst_ip,
            rule_id=rule_id,
            rule_description=rule_desc,
            severity=severity,
            asset_weight=asset_weight,
            exposure_factor=exposure,
            confidence=confidence,
            raw_score=round(raw_score, 2),
            normalized_score=round(normalized, 1),
            risk_level=risk_level,
            mitre_techniques=mitre
        )

        self.scores.append(score)
        return score

    def _calculate_confidence(self, alert: dict) -> float:
        """Calculate confidence based on alert quality indicators."""
        confidence = 0.5  # Base confidence

        # Higher confidence for MITRE-mapped rules
        if alert.get("rule", {}).get("mitre"):
            confidence += 0.2

        # Higher confidence for high-level rules
        level = int(alert.get("rule", {}).get("level", 0))
        if level >= 12:
            confidence += 0.2
        elif level >= 8:
            confidence += 0.1

        # Higher confidence if multiple data sources
        if alert.get("data", {}).get("srcip"):
            confidence += 0.1

        return min(1.0, confidence)

    def generate_report(self) -> dict:
        """Generate a risk summary report."""
        if not self.scores:
            return {"total_alerts": 0, "message": "No alerts scored"}

        by_level = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        total_score = 0
        top_risks = []

        for score in self.scores:
            by_level[score.risk_level] += 1
            total_score += score.normalized_score
            if score.normalized_score >= 60:
                top_risks.append(asdict(score))

        top_risks.sort(key=lambda x: x["normalized_score"], reverse=True)

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_alerts_scored": len(self.scores),
            "average_risk_score": round(total_score / len(self.scores), 1),
            "distribution": by_level,
            "top_risks": top_risks[:20],
            "assets_at_risk": len(set(s.destination_ip for s in self.scores if s.normalized_score >= 60)),
            "recommendation": self._get_recommendation(by_level)
        }

    def _get_recommendation(self, distribution: dict) -> str:
        if distribution["Critical"] > 0:
            return "IMMEDIATE ACTION REQUIRED: Critical risk alerts detected. Initiate incident response."
        elif distribution["High"] > 5:
            return "HIGH PRIORITY: Multiple high-risk alerts require investigation within 1 hour."
        elif distribution["Medium"] > 10:
            return "ATTENTION: Elevated medium-risk activity. Review within 4 hours."
        else:
            return "NORMAL: Risk levels within acceptable thresholds."


def main():
    engine = RiskScoringEngine()

    if len(sys.argv) < 2 or sys.argv[1] == "--help":
        print("Usage: risk-scoring.py [command]")
        print("  --score FILE    Score alerts from JSON file")
        print("  --assets        List known assets and weights")
        print("  --report        Generate risk summary from scored alerts")
        print("  --demo          Run demo with sample alerts")
        return

    cmd = sys.argv[1]

    if cmd == "--assets":
        print(f"{'Asset Type':<30} {'Weight':>6} {'Max Risk':>8}")
        print("-" * 50)
        for asset_type, weight in sorted(ASSET_WEIGHTS.items(), key=lambda x: -x[1]):
            max_risk = round(weight * 10 * 1.5, 1)
            print(f"{asset_type:<30} {weight:>6.1f} {max_risk:>8.1f}")

    elif cmd == "--score":
        if len(sys.argv) < 3:
            print("Error: provide alert JSON file path")
            sys.exit(1)
        with open(sys.argv[2]) as f:
            alerts = json.load(f)
        if isinstance(alerts, dict):
            alerts = [alerts]
        for alert in alerts:
            score = engine.score_alert(alert)
            print(json.dumps(asdict(score), indent=2))

    elif cmd == "--report":
        report = engine.generate_report()
        print(json.dumps(report, indent=2))

    elif cmd == "--demo":
        demo_alerts = [
            {"rule": {"id": "100001", "level": 10, "description": "SSH Brute Force", "mitre": {"id": ["T1110"]}}, "data": {"srcip": "203.0.113.50"}, "agent": {"ip": "10.0.1.10"}},
            {"rule": {"id": "100030", "level": 15, "description": "Ransomware Behavior", "mitre": {"id": ["T1486"]}}, "data": {"srcip": "10.0.1.100"}, "agent": {"ip": "10.0.1.50"}},
            {"rule": {"id": "100040", "level": 12, "description": "Large Data Exfil", "mitre": {"id": ["T1048"]}}, "data": {"srcip": "10.0.1.25", "dstip": "198.51.100.1"}, "agent": {"ip": "10.0.1.1"}},
        ]
        for alert in demo_alerts:
            score = engine.score_alert(alert)
            print(f"  [{score.risk_level:>8}] {score.normalized_score:>5.1f}/100  {score.rule_description}")
        print(f"\n{json.dumps(engine.generate_report(), indent=2)}")


if __name__ == "__main__":
    main()
