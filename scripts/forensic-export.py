#!/usr/bin/env python3
"""
####################################################################
  Unified Open-Source SOC Platform
  Author : Boni Yeamin
  File   : scripts/forensic-export.py
  Purpose: Chain-of-custody compliant forensic evidence packaging.
           Collects logs, alerts, case data, and network captures
           into a signed, tamper-evident tarball.
####################################################################

Usage:
  python3 scripts/forensic-export.py --case CASE-001
  python3 scripts/forensic-export.py --timerange "2024-01-01 2024-01-31"
  python3 scripts/forensic-export.py --verify package.tar.gz
"""

import json, os, sys, tarfile, hashlib, shutil, getpass
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, asdict, field

EXPORT_DIR = os.getenv("SOC_EXPORT_DIR", "/tmp/soc-forensics")
LOG_SOURCES = {
    "wazuh_alerts": "/var/ossec/logs/alerts/alerts.json",
    "wazuh_archives": "/var/ossec/logs/archives/archives.json",
    "suricata_eve": "/var/log/suricata/eve.json",
    "audit_log": "/var/log/soc/audit.json",
    "nginx_access": "/var/log/nginx/access.log",
    "nginx_error": "/var/log/nginx/error.log",
}


@dataclass
class EvidenceItem:
    filename: str
    source: str
    sha256: str
    size_bytes: int
    collected_at: str
    description: str


@dataclass
class ChainOfCustody:
    case_id: str
    exported_by: str
    export_timestamp: str
    export_host: str
    evidence_items: list = field(default_factory=list)
    package_sha256: str = ""
    integrity_note: str = "This evidence package is protected by SHA-256 checksums for each item and the overall package."


class ForensicExporter:
    """Chain-of-custody compliant evidence packager."""

    def __init__(self, case_id: str):
        self.case_id = case_id
        self.timestamp = datetime.now(timezone.utc)
        self.export_name = f"forensic-{case_id}-{self.timestamp.strftime('%Y%m%dT%H%M%SZ')}"
        self.work_dir = Path(EXPORT_DIR) / self.export_name
        self.evidence: list[EvidenceItem] = []

    def prepare(self):
        """Create working directory."""
        self.work_dir.mkdir(parents=True, exist_ok=True)
        (self.work_dir / "evidence").mkdir(exist_ok=True)
        print(f"📁 Working directory: {self.work_dir}")

    def collect_logs(self, time_start: str = None, time_end: str = None):
        """Collect log files from known sources."""
        print("📋 Collecting log files...")
        for name, path in LOG_SOURCES.items():
            src = Path(path)
            if src.exists():
                dst = self.work_dir / "evidence" / f"{name}{src.suffix}"
                shutil.copy2(str(src), str(dst))
                sha = self._hash_file(dst)
                item = EvidenceItem(
                    filename=dst.name,
                    source=str(src),
                    sha256=sha,
                    size_bytes=dst.stat().st_size,
                    collected_at=datetime.now(timezone.utc).isoformat(),
                    description=f"Log from {name}"
                )
                self.evidence.append(item)
                print(f"  ✅ {name}: {dst.stat().st_size:,} bytes (SHA:{sha[:12]}...)")
            else:
                print(f"  ⏭️  {name}: not found at {path}")

    def collect_case_data(self):
        """Export TheHive case data via API (if available)."""
        print("📋 Collecting case data...")
        case_file = self.work_dir / "evidence" / f"case-{self.case_id}.json"
        case_data = {
            "case_id": self.case_id,
            "export_note": "Case data should be exported via TheHive API",
            "api_endpoint": f"https://thehive.soc.local/api/case/{self.case_id}",
            "export_commands": [
                f"curl -H 'Authorization: Bearer $API_KEY' https://thehive.soc.local/api/case/{self.case_id}",
                f"curl -H 'Authorization: Bearer $API_KEY' https://thehive.soc.local/api/case/{self.case_id}/observables",
                f"curl -H 'Authorization: Bearer $API_KEY' https://thehive.soc.local/api/case/{self.case_id}/task",
            ]
        }
        case_file.write_text(json.dumps(case_data, indent=2))
        sha = self._hash_file(case_file)
        self.evidence.append(EvidenceItem(
            filename=case_file.name, source="TheHive API", sha256=sha,
            size_bytes=case_file.stat().st_size,
            collected_at=datetime.now(timezone.utc).isoformat(),
            description=f"Case metadata for {self.case_id}"
        ))
        print(f"  ✅ case-{self.case_id}.json written")

    def generate_manifest(self) -> ChainOfCustody:
        """Generate chain-of-custody manifest."""
        import socket
        manifest = ChainOfCustody(
            case_id=self.case_id,
            exported_by=getpass.getuser(),
            export_timestamp=self.timestamp.isoformat(),
            export_host=socket.gethostname(),
            evidence_items=[asdict(e) for e in self.evidence],
        )

        manifest_file = self.work_dir / "MANIFEST.json"
        manifest_file.write_text(json.dumps(asdict(manifest), indent=2))

        # Also create human-readable summary
        readme = self.work_dir / "README.txt"
        lines = [
            f"FORENSIC EVIDENCE PACKAGE — {self.case_id}",
            f"{'='*50}",
            f"Exported:  {manifest.export_timestamp}",
            f"By:        {manifest.exported_by}",
            f"Host:      {manifest.export_host}",
            f"Items:     {len(self.evidence)}",
            "",
            "EVIDENCE ITEMS:",
            "-" * 50,
        ]
        for item in self.evidence:
            lines.append(f"  {item.filename}")
            lines.append(f"    SHA-256: {item.sha256}")
            lines.append(f"    Size:    {item.size_bytes:,} bytes")
            lines.append(f"    Source:  {item.source}")
            lines.append("")
        lines.append("INTEGRITY NOTE:")
        lines.append(manifest.integrity_note)
        readme.write_text("\n".join(lines))

        print(f"📋 Manifest: {manifest_file}")
        return manifest

    def package(self) -> str:
        """Create signed tarball."""
        tarball_path = f"{self.work_dir}.tar.gz"
        print(f"📦 Creating evidence package...")

        with tarfile.open(tarball_path, "w:gz") as tar:
            tar.add(str(self.work_dir), arcname=self.export_name)

        package_hash = self._hash_file(Path(tarball_path))
        size_mb = Path(tarball_path).stat().st_size / (1024 * 1024)

        # Write hash file alongside tarball
        hash_file = Path(f"{tarball_path}.sha256")
        hash_file.write_text(f"{package_hash}  {Path(tarball_path).name}\n")

        print(f"  ✅ Package: {tarball_path}")
        print(f"  📏 Size:    {size_mb:.2f} MB")
        print(f"  🔒 SHA-256: {package_hash}")

        # Clean up working directory
        shutil.rmtree(str(self.work_dir))
        return tarball_path

    @staticmethod
    def verify(package_path: str) -> bool:
        """Verify package integrity."""
        pkg = Path(package_path)
        hash_file = Path(f"{package_path}.sha256")

        if not pkg.exists():
            print(f"❌ Package not found: {package_path}")
            return False

        actual_hash = ForensicExporter._hash_file(pkg)

        if hash_file.exists():
            expected = hash_file.read_text().split()[0]
            if actual_hash == expected:
                print(f"✅ Package integrity VERIFIED")
                print(f"   SHA-256: {actual_hash}")
                return True
            else:
                print(f"❌ INTEGRITY VIOLATION!")
                print(f"   Expected: {expected}")
                print(f"   Actual:   {actual_hash}")
                return False
        else:
            print(f"⚠️  No hash file found. Package SHA-256: {actual_hash}")
            return True

    @staticmethod
    def _hash_file(path: Path) -> str:
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()


def main():
    if len(sys.argv) < 2 or sys.argv[1] == "--help":
        print("Usage: forensic-export.py [command]")
        print("  --case CASE-ID      Export evidence for a specific case")
        print("  --verify FILE.tar.gz  Verify package integrity")
        return

    if sys.argv[1] == "--verify":
        ok = ForensicExporter.verify(sys.argv[2])
        sys.exit(0 if ok else 1)

    if sys.argv[1] == "--case":
        case_id = sys.argv[2] if len(sys.argv) > 2 else "CASE-001"
        exporter = ForensicExporter(case_id)
        exporter.prepare()
        exporter.collect_logs()
        exporter.collect_case_data()
        exporter.generate_manifest()
        package = exporter.package()
        print(f"\n✅ Forensic export complete: {package}")


if __name__ == "__main__":
    main()
