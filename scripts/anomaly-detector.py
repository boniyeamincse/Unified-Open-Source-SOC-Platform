#!/usr/bin/env python3
"""
####################################################################
  Unified Open-Source SOC Platform
  Author : Boni Yeamin
  File   : scripts/anomaly-detector.py
  Purpose: Statistical anomaly detection / UEBA engine.
           Builds baselines from historical data and flags deviations.
           Uses Z-score (no heavy ML dependencies required).
####################################################################

Usage:
  python3 scripts/anomaly-detector.py --learn data.json    # Build baselines
  python3 scripts/anomaly-detector.py --detect data.json   # Detect anomalies
  python3 scripts/anomaly-detector.py --profiles            # Show user profiles
"""

import json, os, sys, math
from datetime import datetime, timezone
from collections import defaultdict
from pathlib import Path
from dataclasses import dataclass, asdict, field

BASELINE_DIR = os.getenv("SOC_BASELINE_DIR", "/var/lib/soc/baselines")
Z_THRESHOLD = float(os.getenv("ANOMALY_Z_THRESHOLD", "2.5"))


@dataclass
class Baseline:
    """Statistical baseline for a metric."""
    metric: str
    entity: str        # user or host
    mean: float
    std_dev: float
    sample_count: int
    last_updated: str
    min_val: float = 0
    max_val: float = 0


@dataclass
class Anomaly:
    """Detected anomaly."""
    timestamp: str
    entity: str
    metric: str
    observed_value: float
    expected_mean: float
    std_dev: float
    z_score: float
    severity: str
    description: str


class AnomalyDetector:
    """Statistical anomaly detection engine using Z-scores."""

    def __init__(self):
        self.baselines: dict[str, Baseline] = {}
        self.anomalies: list[Anomaly] = []
        self.baseline_dir = Path(BASELINE_DIR)
        self.baseline_dir.mkdir(parents=True, exist_ok=True)
        self._load_baselines()

    def _baseline_key(self, entity: str, metric: str) -> str:
        return f"{entity}::{metric}"

    def _load_baselines(self):
        """Load saved baselines from disk."""
        baseline_file = self.baseline_dir / "baselines.json"
        if baseline_file.exists():
            data = json.loads(baseline_file.read_text())
            for item in data:
                key = self._baseline_key(item["entity"], item["metric"])
                self.baselines[key] = Baseline(**item)

    def _save_baselines(self):
        """Persist baselines to disk."""
        data = [asdict(b) for b in self.baselines.values()]
        baseline_file = self.baseline_dir / "baselines.json"
        baseline_file.write_text(json.dumps(data, indent=2))

    def learn(self, events: list[dict]):
        """Build/update baselines from historical events."""
        # Group events by entity
        metrics = defaultdict(lambda: defaultdict(list))

        for event in events:
            user = event.get("user", event.get("data", {}).get("srcuser", "unknown"))
            host = event.get("agent", {}).get("name", event.get("host", "unknown"))

            # Extract metrics
            hour = datetime.fromisoformat(event.get("timestamp", datetime.now(timezone.utc).isoformat().replace("Z", "+00:00"))).hour

            # Login time metric
            if "login" in json.dumps(event).lower():
                metrics[user]["login_hour"].append(hour)

            # Data volume metric
            bytes_sent = event.get("data", {}).get("bytes_sent", 0)
            if bytes_sent:
                metrics[host]["bytes_sent"].append(float(bytes_sent))

            # Alert count metric
            level = event.get("rule", {}).get("level", 0)
            metrics[host]["alert_level"].append(float(level))

            # Connection count
            metrics[user]["event_count"].append(1.0)

        # Build baselines
        for entity, entity_metrics in metrics.items():
            for metric, values in entity_metrics.items():
                if len(values) < 3:
                    continue

                mean = sum(values) / len(values)
                variance = sum((x - mean) ** 2 for x in values) / len(values)
                std_dev = math.sqrt(variance) if variance > 0 else 0.1

                key = self._baseline_key(entity, metric)
                self.baselines[key] = Baseline(
                    metric=metric,
                    entity=entity,
                    mean=round(mean, 4),
                    std_dev=round(std_dev, 4),
                    sample_count=len(values),
                    last_updated=datetime.now(timezone.utc).isoformat(),
                    min_val=min(values),
                    max_val=max(values)
                )

        self._save_baselines()
        print(f"✅ Learned {len(self.baselines)} baselines from {len(events)} events")

    def detect(self, events: list[dict]) -> list[Anomaly]:
        """Detect anomalies in real-time events against baselines."""
        anomalies = []

        for event in events:
            user = event.get("user", event.get("data", {}).get("srcuser", "unknown"))
            host = event.get("agent", {}).get("name", event.get("host", "unknown"))
            timestamp = event.get("timestamp", datetime.now(timezone.utc).isoformat())

            # Check login time
            try:
                hour = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).hour
            except (ValueError, AttributeError):
                hour = 12

            login_key = self._baseline_key(user, "login_hour")
            if login_key in self.baselines and "login" in json.dumps(event).lower():
                baseline = self.baselines[login_key]
                z = self._z_score(hour, baseline.mean, baseline.std_dev)
                if abs(z) > Z_THRESHOLD:
                    anomalies.append(Anomaly(
                        timestamp=timestamp, entity=user, metric="login_hour",
                        observed_value=hour, expected_mean=baseline.mean,
                        std_dev=baseline.std_dev, z_score=round(z, 2),
                        severity=self._severity(abs(z)),
                        description=f"Unusual login time: {hour}:00 (normal: {baseline.mean:.0f}:00 ± {baseline.std_dev:.0f}h)"
                    ))

            # Check data volume
            bytes_sent = event.get("data", {}).get("bytes_sent", 0)
            if bytes_sent:
                vol_key = self._baseline_key(host, "bytes_sent")
                if vol_key in self.baselines:
                    baseline = self.baselines[vol_key]
                    z = self._z_score(float(bytes_sent), baseline.mean, baseline.std_dev)
                    if abs(z) > Z_THRESHOLD:
                        anomalies.append(Anomaly(
                            timestamp=timestamp, entity=host, metric="bytes_sent",
                            observed_value=float(bytes_sent), expected_mean=baseline.mean,
                            std_dev=baseline.std_dev, z_score=round(z, 2),
                            severity=self._severity(abs(z)),
                            description=f"Unusual data volume: {bytes_sent:,.0f} bytes (normal: {baseline.mean:,.0f} ± {baseline.std_dev:,.0f})"
                        ))

            # Check alert severity
            level = event.get("rule", {}).get("level", 0)
            if level > 0:
                lvl_key = self._baseline_key(host, "alert_level")
                if lvl_key in self.baselines:
                    baseline = self.baselines[lvl_key]
                    z = self._z_score(float(level), baseline.mean, baseline.std_dev)
                    if abs(z) > Z_THRESHOLD:
                        anomalies.append(Anomaly(
                            timestamp=timestamp, entity=host, metric="alert_level",
                            observed_value=float(level), expected_mean=baseline.mean,
                            std_dev=baseline.std_dev, z_score=round(z, 2),
                            severity=self._severity(abs(z)),
                            description=f"Unusual alert severity: level {level} (normal: {baseline.mean:.1f} ± {baseline.std_dev:.1f})"
                        ))

        self.anomalies.extend(anomalies)
        return anomalies

    @staticmethod
    def _z_score(value: float, mean: float, std_dev: float) -> float:
        if std_dev == 0:
            return 0.0
        return (value - mean) / std_dev

    @staticmethod
    def _severity(z_abs: float) -> str:
        if z_abs >= 4.0:
            return "Critical"
        elif z_abs >= 3.5:
            return "High"
        elif z_abs >= 3.0:
            return "Medium"
        else:
            return "Low"

    def get_profiles(self) -> dict:
        """Get UEBA profiles grouped by entity."""
        profiles = defaultdict(list)
        for baseline in self.baselines.values():
            profiles[baseline.entity].append({
                "metric": baseline.metric,
                "mean": baseline.mean,
                "std_dev": baseline.std_dev,
                "samples": baseline.sample_count,
                "range": f"{baseline.min_val:.1f} - {baseline.max_val:.1f}"
            })
        return dict(profiles)


def main():
    detector = AnomalyDetector()

    if len(sys.argv) < 2 or sys.argv[1] == "--help":
        print("Usage: anomaly-detector.py [command]")
        print("  --learn FILE     Build baselines from historical data")
        print("  --detect FILE    Detect anomalies against baselines")
        print("  --profiles       Show UEBA user/host profiles")
        print("  --demo           Run with demo data")
        return

    cmd = sys.argv[1]

    if cmd == "--learn" and len(sys.argv) > 2:
        with open(sys.argv[2]) as f:
            events = json.load(f)
        if isinstance(events, dict):
            events = [events]
        detector.learn(events)

    elif cmd == "--detect" and len(sys.argv) > 2:
        with open(sys.argv[2]) as f:
            events = json.load(f)
        if isinstance(events, dict):
            events = [events]
        anomalies = detector.detect(events)
        for a in anomalies:
            print(f"  🚨 [{a.severity:>8}] Z={a.z_score:+.1f}  {a.entity}: {a.description}")
        print(f"\n--- {len(anomalies)} anomalies detected ---")

    elif cmd == "--profiles":
        profiles = detector.get_profiles()
        print(json.dumps(profiles, indent=2))

    elif cmd == "--demo":
        # Build baseline from normal data
        normal = [
            {"user": "analyst1", "timestamp": "2024-01-01T09:00:00Z", "rule": {"level": 3}, "data": {"srcuser": "analyst1"}, "agent": {"name": "ws-01"}},
            {"user": "analyst1", "timestamp": "2024-01-02T09:30:00Z", "rule": {"level": 4}, "data": {"srcuser": "analyst1"}, "agent": {"name": "ws-01"}},
            {"user": "analyst1", "timestamp": "2024-01-03T08:45:00Z", "rule": {"level": 3}, "data": {"srcuser": "analyst1"}, "agent": {"name": "ws-01"}},
            {"user": "analyst1", "timestamp": "2024-01-04T10:00:00Z", "rule": {"level": 5}, "data": {"srcuser": "analyst1"}, "agent": {"name": "ws-01"}},
            {"user": "analyst1", "timestamp": "2024-01-05T09:15:00Z", "rule": {"level": 3}, "data": {"srcuser": "analyst1"}, "agent": {"name": "ws-01"}},
        ]
        detector.learn(normal)

        # Detect anomalies
        suspicious = [
            {"user": "analyst1", "timestamp": "2024-01-06T03:00:00Z", "rule": {"level": 14}, "data": {"srcuser": "analyst1"}, "agent": {"name": "ws-01"}},
        ]
        anomalies = detector.detect(suspicious)
        for a in anomalies:
            print(f"  🚨 [{a.severity:>8}] Z={a.z_score:+.1f}  {a.entity}: {a.description}")
        if not anomalies:
            print("  ✅ No anomalies detected in demo data")


if __name__ == "__main__":
    main()
