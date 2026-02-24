#!/usr/bin/env python3
"""
####################################################################
  Unified Open-Source SOC Platform
  Author : Boni Yeamin
  File   : scripts/alert-dedup.py
  Purpose: Alert deduplication and grouping engine. Clusters similar
           alerts by source IP + rule ID within time windows to
           reduce noise and produce consolidated alerts.
####################################################################

Usage:
  python3 scripts/alert-dedup.py --process alerts.json
  python3 scripts/alert-dedup.py --stats                # Show dedup stats
  python3 scripts/alert-dedup.py --demo                  # Demo mode
"""

import json, sys, os, hashlib
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from dataclasses import dataclass, asdict, field

WINDOW_SECONDS = int(os.getenv("DEDUP_WINDOW_SECONDS", "300"))  # 5 minutes
MAX_GROUP_SIZE = int(os.getenv("DEDUP_MAX_GROUP", "100"))


@dataclass
class AlertGroup:
    """A group of deduplicated alerts."""
    group_id: str
    fingerprint: str
    rule_id: str
    rule_description: str
    severity: int
    source_ips: list = field(default_factory=list)
    destination_ips: list = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    count: int = 0
    sample_alert: dict = field(default_factory=dict)
    suppressed: int = 0


class AlertDeduplicator:
    """Intelligent alert clustering and deduplication."""

    def __init__(self, window_seconds: int = WINDOW_SECONDS):
        self.window = timedelta(seconds=window_seconds)
        self.active_groups: dict[str, AlertGroup] = {}
        self.closed_groups: list[AlertGroup] = []
        self.total_input = 0
        self.total_output = 0
        self.total_suppressed = 0

    def fingerprint(self, alert: dict) -> str:
        """Generate dedup fingerprint for an alert."""
        rule_id = str(alert.get("rule", {}).get("id", "0"))
        src_ip = alert.get("data", {}).get("srcip", "unknown")
        agent = alert.get("agent", {}).get("name", "unknown")
        level = str(alert.get("rule", {}).get("level", 0))

        raw = f"{rule_id}|{src_ip}|{agent}|{level}"
        return hashlib.md5(raw.encode()).hexdigest()[:16]

    def process(self, alerts: list[dict]) -> list[AlertGroup]:
        """Process a batch of alerts through deduplication."""
        self.total_input += len(alerts)

        # Sort by timestamp
        def parse_ts(a):
            ts = a.get("timestamp", "")
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                return datetime.now(timezone.utc)

        alerts.sort(key=parse_ts)

        for alert in alerts:
            fp = self.fingerprint(alert)
            ts = parse_ts(alert)

            if fp in self.active_groups:
                group = self.active_groups[fp]
                first_ts = datetime.fromisoformat(group.first_seen.replace("Z", "+00:00"))

                # Check if still within window
                if (ts - first_ts) <= self.window and group.count < MAX_GROUP_SIZE:
                    # Merge into existing group
                    group.count += 1
                    group.suppressed += 1
                    group.last_seen = ts.isoformat()
                    src = alert.get("data", {}).get("srcip")
                    if src and src not in group.source_ips:
                        group.source_ips.append(src)
                    dst = alert.get("agent", {}).get("ip")
                    if dst and dst not in group.destination_ips:
                        group.destination_ips.append(dst)
                    # Escalate severity if higher
                    level = alert.get("rule", {}).get("level", 0)
                    if level > group.severity:
                        group.severity = level
                    self.total_suppressed += 1
                    continue
                else:
                    # Window expired — close group and start new
                    self.closed_groups.append(group)
                    del self.active_groups[fp]

            # Create new group
            src_ip = alert.get("data", {}).get("srcip", "unknown")
            dst_ip = alert.get("agent", {}).get("ip", "unknown")
            self.active_groups[fp] = AlertGroup(
                group_id=f"GRP-{fp[:8]}-{ts.strftime('%H%M%S')}",
                fingerprint=fp,
                rule_id=str(alert.get("rule", {}).get("id", "0")),
                rule_description=alert.get("rule", {}).get("description", "Unknown"),
                severity=alert.get("rule", {}).get("level", 0),
                source_ips=[src_ip] if src_ip != "unknown" else [],
                destination_ips=[dst_ip] if dst_ip != "unknown" else [],
                first_seen=ts.isoformat(),
                last_seen=ts.isoformat(),
                count=1,
                sample_alert=alert
            )

        # Close remaining active groups
        all_groups = list(self.closed_groups) + list(self.active_groups.values())
        self.total_output = len(all_groups)
        return all_groups

    def get_stats(self) -> dict:
        """Return deduplication statistics."""
        suppression_rate = (self.total_suppressed / max(self.total_input, 1)) * 100
        return {
            "total_input_alerts": self.total_input,
            "total_output_groups": self.total_output,
            "total_suppressed": self.total_suppressed,
            "suppression_rate_pct": round(suppression_rate, 1),
            "dedup_window_seconds": WINDOW_SECONDS,
            "active_groups": len(self.active_groups),
            "closed_groups": len(self.closed_groups),
        }


def main():
    dedup = AlertDeduplicator()

    if len(sys.argv) < 2 or sys.argv[1] == "--help":
        print("Usage: alert-dedup.py [command]")
        print("  --process FILE   Process alerts and output grouped results")
        print("  --stats          Show deduplication statistics")
        print("  --demo           Run with demo data")
        return

    cmd = sys.argv[1]

    if cmd == "--process" and len(sys.argv) > 2:
        with open(sys.argv[2]) as f:
            alerts = json.load(f)
        if isinstance(alerts, dict):
            alerts = [alerts]
        groups = dedup.process(alerts)
        for g in groups:
            d = asdict(g)
            del d["sample_alert"]  # Don't include full alert in output
            print(json.dumps(d))
        print(f"\n--- Stats ---", file=sys.stderr)
        print(json.dumps(dedup.get_stats(), indent=2), file=sys.stderr)

    elif cmd == "--demo":
        # Simulate 20 similar alerts (should dedup to ~1 group)
        demo_alerts = []
        base = datetime(2024, 1, 15, 14, 0, 0, tzinfo=timezone.utc)
        for i in range(20):
            demo_alerts.append({
                "timestamp": (base + timedelta(seconds=i * 10)).isoformat(),
                "rule": {"id": "100001", "level": 10, "description": "SSH Brute Force Attack"},
                "data": {"srcip": "203.0.113.50"},
                "agent": {"name": "web-01", "ip": "10.0.1.10"}
            })
        # Add one different alert
        demo_alerts.append({
            "timestamp": (base + timedelta(seconds=30)).isoformat(),
            "rule": {"id": "100030", "level": 15, "description": "Ransomware Behavior"},
            "data": {"srcip": "10.0.1.100"},
            "agent": {"name": "db-01", "ip": "10.0.1.50"}
        })

        groups = dedup.process(demo_alerts)
        print(f"Input:  {len(demo_alerts)} alerts")
        print(f"Output: {len(groups)} groups")
        print(f"Suppressed: {dedup.total_suppressed} ({dedup.get_stats()['suppression_rate_pct']}%)")
        print()
        for g in groups:
            print(f"  [{g.group_id}] {g.rule_description} × {g.count} (severity: {g.severity})")
            print(f"    Sources: {', '.join(g.source_ips)}")
            print(f"    Window:  {g.first_seen} → {g.last_seen}")


if __name__ == "__main__":
    main()
