#!/usr/bin/env python3
"""
####################################################################
  Unified Open-Source SOC Platform
  Author : Boni Yeamin
  Open Source V:1.0
  File   : scripts/audit-logger.py
  Purpose: Centralized audit log collector for SOC platform.
           Captures authentication, configuration, and API events
           from all services and writes structured JSON logs.
####################################################################

How it works:
  Step 1: Monitors Docker container logs for audit-relevant events
  Step 2: Parses events into structured JSON format
  Step 3: Writes to /var/log/soc/audit.json with rotation
  Step 4: Optionally forwards to Wazuh for SIEM correlation

Usage:
  python3 scripts/audit-logger.py                    # Start collector
  python3 scripts/audit-logger.py --query user=admin # Search logs
  python3 scripts/audit-logger.py --stats            # Show stats
"""

import json
import os
import sys
import time
import re
import logging
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from collections import defaultdict

# ── Configuration ─────────────────────────────────────────

AUDIT_LOG_DIR = os.getenv("SOC_AUDIT_DIR", "/var/log/soc")
AUDIT_LOG_FILE = os.path.join(AUDIT_LOG_DIR, "audit.json")
MAX_LOG_SIZE_MB = int(os.getenv("AUDIT_MAX_SIZE_MB", "100"))
MAX_LOG_FILES = int(os.getenv("AUDIT_MAX_FILES", "10"))
HASH_CHAIN = True  # Enable cryptographic hash chaining

# ── Logging Setup ─────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S"
)
logger = logging.getLogger("soc-audit")

# ── Audit Event Types ─────────────────────────────────────

class AuditEventType:
    # Authentication Events
    LOGIN_SUCCESS = "AUTH_LOGIN_SUCCESS"
    LOGIN_FAILURE = "AUTH_LOGIN_FAILURE"
    LOGOUT = "AUTH_LOGOUT"
    MFA_SETUP = "AUTH_MFA_SETUP"
    MFA_FAILURE = "AUTH_MFA_FAILURE"
    PASSWORD_CHANGE = "AUTH_PASSWORD_CHANGE"
    SESSION_EXPIRED = "AUTH_SESSION_EXPIRED"

    # Access Control Events
    ROLE_ASSIGNED = "RBAC_ROLE_ASSIGNED"
    ROLE_REVOKED = "RBAC_ROLE_REVOKED"
    PERMISSION_DENIED = "RBAC_PERMISSION_DENIED"

    # Configuration Events
    CONFIG_CHANGE = "CONFIG_CHANGE"
    KEY_ROTATION = "CONFIG_KEY_ROTATION"
    SERVICE_START = "SVC_START"
    SERVICE_STOP = "SVC_STOP"
    SERVICE_RESTART = "SVC_RESTART"

    # Data Access Events
    CASE_CREATE = "DATA_CASE_CREATE"
    CASE_UPDATE = "DATA_CASE_UPDATE"
    CASE_DELETE = "DATA_CASE_DELETE"
    IOC_CREATE = "DATA_IOC_CREATE"
    ALERT_ACKNOWLEDGE = "DATA_ALERT_ACK"

    # API Events
    API_CALL = "API_CALL"
    API_KEY_USED = "API_KEY_USED"
    WEBHOOK_RECEIVED = "API_WEBHOOK"
    WEBHOOK_REJECTED = "API_WEBHOOK_REJECTED"


# ── Audit Logger Class ────────────────────────────────────

class AuditLogger:
    """Centralized audit logger with hash-chain integrity."""

    def __init__(self, log_dir: str = AUDIT_LOG_DIR):
        self.log_dir = Path(log_dir)
        self.log_file = self.log_dir / "audit.json"
        self.chain_file = self.log_dir / ".audit_chain"
        self.last_hash = self._load_chain()

        # Create log directory
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def _load_chain(self) -> str:
        """Load the last hash from the chain file."""
        chain_path = Path(AUDIT_LOG_DIR) / ".audit_chain"
        if chain_path.exists():
            return chain_path.read_text().strip()
        return "GENESIS"

    def _save_chain(self, hash_value: str):
        """Save the current hash to the chain file."""
        self.chain_file.write_text(hash_value)

    def _compute_hash(self, event: dict) -> str:
        """Compute SHA-256 hash including previous hash for chain integrity."""
        data = json.dumps(event, sort_keys=True) + self.last_hash
        return hashlib.sha256(data.encode()).hexdigest()

    def _rotate_if_needed(self):
        """Rotate log file if it exceeds max size."""
        if not self.log_file.exists():
            return

        size_mb = self.log_file.stat().st_size / (1024 * 1024)
        if size_mb >= MAX_LOG_SIZE_MB:
            # Rotate: audit.json → audit.json.1, audit.json.1 → audit.json.2, etc.
            for i in range(MAX_LOG_FILES - 1, 0, -1):
                old = self.log_dir / f"audit.json.{i}"
                new = self.log_dir / f"audit.json.{i + 1}"
                if old.exists():
                    old.rename(new)

            self.log_file.rename(self.log_dir / "audit.json.1")
            logger.info(f"Rotated audit log (was {size_mb:.1f} MB)")

    def log(
        self,
        event_type: str,
        user: str = "system",
        source_ip: str = "127.0.0.1",
        resource: str = "",
        detail: str = "",
        result: str = "success",
        service: str = "platform",
        metadata: Optional[dict] = None
    ):
        """Write a structured audit event."""

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "user": user,
            "source_ip": source_ip,
            "service": service,
            "resource": resource,
            "detail": detail,
            "result": result,
        }

        if metadata:
            event["metadata"] = metadata

        # Hash chain for tamper detection
        if HASH_CHAIN:
            event["prev_hash"] = self.last_hash[:16]  # First 16 chars only
            event_hash = self._compute_hash(event)
            event["hash"] = event_hash
            self.last_hash = event_hash
            self._save_chain(event_hash)

        # Rotate if needed
        self._rotate_if_needed()

        # Append to log file
        with open(self.log_file, "a") as f:
            f.write(json.dumps(event) + "\n")

        return event

    def query(self, **filters) -> list:
        """Search audit logs by field values."""
        results = []
        if not self.log_file.exists():
            return results

        with open(self.log_file) as f:
            for line in f:
                try:
                    event = json.loads(line.strip())
                    match = all(
                        event.get(k) == v or (k == "detail" and v in event.get(k, ""))
                        for k, v in filters.items()
                    )
                    if match:
                        results.append(event)
                except (json.JSONDecodeError, KeyError):
                    continue

        return results

    def verify_chain(self) -> dict:
        """Verify the integrity of the audit log hash chain."""
        if not self.log_file.exists():
            return {"status": "empty", "verified": 0, "errors": 0}

        verified = 0
        errors = 0
        prev_hash = "GENESIS"

        with open(self.log_file) as f:
            for line_num, line in enumerate(f, 1):
                try:
                    event = json.loads(line.strip())
                    stored_hash = event.pop("hash", None)

                    if stored_hash:
                        # Rebuild hash to verify
                        event["prev_hash"] = prev_hash[:16]
                        data = json.dumps(event, sort_keys=True) + prev_hash
                        expected = hashlib.sha256(data.encode()).hexdigest()

                        if stored_hash == expected:
                            verified += 1
                        else:
                            errors += 1
                            logger.error(f"Chain broken at line {line_num}")

                        prev_hash = stored_hash
                    else:
                        verified += 1  # Legacy entry without hash

                except (json.JSONDecodeError, KeyError) as e:
                    errors += 1
                    logger.error(f"Parse error at line {line_num}: {e}")

        status = "intact" if errors == 0 else "TAMPERED"
        return {"status": status, "verified": verified, "errors": errors}

    def stats(self) -> dict:
        """Generate audit log statistics."""
        if not self.log_file.exists():
            return {"total_events": 0}

        counts = defaultdict(int)
        users = defaultdict(int)
        services = defaultdict(int)
        failures = 0
        total = 0

        with open(self.log_file) as f:
            for line in f:
                try:
                    event = json.loads(line.strip())
                    total += 1
                    counts[event.get("event_type", "unknown")] += 1
                    users[event.get("user", "unknown")] += 1
                    services[event.get("service", "unknown")] += 1
                    if event.get("result") == "failure":
                        failures += 1
                except json.JSONDecodeError:
                    continue

        return {
            "total_events": total,
            "failures": failures,
            "by_type": dict(counts),
            "by_user": dict(users),
            "by_service": dict(services),
            "log_size_mb": round(self.log_file.stat().st_size / (1024 * 1024), 2)
        }


# ── Service Log Patterns ──────────────────────────────────

PATTERNS = {
    "keycloak": {
        "login_success": re.compile(r"type=LOGIN,.*realmId=(?P<realm>\S+),.*userId=(?P<user>\S+),.*ipAddress=(?P<ip>\S+)"),
        "login_failure": re.compile(r"type=LOGIN_ERROR,.*realmId=(?P<realm>\S+),.*error=(?P<error>\S+),.*ipAddress=(?P<ip>\S+)"),
        "logout": re.compile(r"type=LOGOUT,.*userId=(?P<user>\S+)"),
    },
    "thehive": {
        "case_create": re.compile(r"Creating case #(?P<case_id>\d+).*user=(?P<user>\S+)"),
        "login": re.compile(r"Authentication.*user=(?P<user>\S+).*from (?P<ip>\S+)"),
    },
    "nginx": {
        "access": re.compile(r'(?P<ip>\S+) - (?P<user>\S+) \[.*\] "(?P<method>\S+) (?P<path>\S+).*" (?P<status>\d+)'),
        "rate_limit": re.compile(r"limiting requests.*client: (?P<ip>\S+)"),
    }
}


# ── CLI Interface ─────────────────────────────────────────

def main():
    audit = AuditLogger()

    if len(sys.argv) > 1:
        cmd = sys.argv[1]

        if cmd == "--stats":
            stats = audit.stats()
            print(json.dumps(stats, indent=2))

        elif cmd == "--verify":
            result = audit.verify_chain()
            print(json.dumps(result, indent=2))
            sys.exit(0 if result["status"] == "intact" else 1)

        elif cmd == "--query":
            # Parse key=value pairs
            filters = {}
            for arg in sys.argv[2:]:
                if "=" in arg:
                    k, v = arg.split("=", 1)
                    filters[k] = v
            results = audit.query(**filters)
            for event in results:
                print(json.dumps(event))
            print(f"\n--- {len(results)} events found ---")

        elif cmd == "--test":
            # Write a test event
            event = audit.log(
                event_type=AuditEventType.LOGIN_SUCCESS,
                user="test-user",
                source_ip="192.168.1.100",
                service="audit-test",
                resource="/api/login",
                detail="Test audit event"
            )
            print(f"✅ Test event written: {json.dumps(event, indent=2)}")

        elif cmd == "--help":
            print("Usage: audit-logger.py [command]")
            print("")
            print("Commands:")
            print("  --stats           Show audit log statistics")
            print("  --verify          Verify hash chain integrity")
            print("  --query k=v ...   Search audit logs")
            print("  --test            Write a test event")
            print("  (no args)         Start log collector daemon")

        else:
            print(f"Unknown command: {cmd}")
            sys.exit(1)
    else:
        # Daemon mode — monitor Docker logs
        logger.info("Starting SOC Audit Log Collector")
        logger.info(f"Log file: {audit.log_file}")
        logger.info(f"Hash chain: {'enabled' if HASH_CHAIN else 'disabled'}")

        audit.log(
            event_type=AuditEventType.SERVICE_START,
            service="audit-logger",
            detail="Audit log collector started"
        )

        # Monitor stdin for piped Docker logs
        logger.info("Reading from stdin (pipe Docker logs here)")
        logger.info("Example: docker compose logs -f --no-color | python3 scripts/audit-logger.py")

        try:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue

                # Match against known patterns
                for service, patterns in PATTERNS.items():
                    for event_name, pattern in patterns.items():
                        match = pattern.search(line)
                        if match:
                            groups = match.groupdict()
                            audit.log(
                                event_type=f"{service}.{event_name}",
                                user=groups.get("user", "unknown"),
                                source_ip=groups.get("ip", "127.0.0.1"),
                                service=service,
                                detail=line[:500]
                            )
                            break
        except KeyboardInterrupt:
            logger.info("Audit collector stopped")
            audit.log(
                event_type=AuditEventType.SERVICE_STOP,
                service="audit-logger",
                detail="Audit log collector stopped"
            )


if __name__ == "__main__":
    main()
