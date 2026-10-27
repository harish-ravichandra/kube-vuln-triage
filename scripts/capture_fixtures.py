"""Refresh tests/fixtures from the demo cluster and the local Trivy cache.

kubectl output is saved with managedFields removed. Trivy output keeps its
real structure but drops fields cva never reads (descriptions, CVSS,
references), which keeps the fixtures small enough to commit.

    python scripts/capture_fixtures.py            # kubectl + trivy
    python scripts/capture_fixtures.py --trivy-only
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
KEEP_VULN = ("VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity", "Status")
KUBECTL = {
    "pods": ["get", "pods", "-A", "-o", "json"],
    "namespaces": ["get", "ns", "-o", "json"],
    "services": ["get", "svc", "-A", "-o", "json"],
    "ingresses": ["get", "ingress", "-A", "-o", "json"],
}


def slim_trivy(report: dict) -> dict:
    return {
        "SchemaVersion": report.get("SchemaVersion"),
        "ArtifactName": report.get("ArtifactName"),
        "ArtifactType": report.get("ArtifactType"),
        "Metadata": {"OS": report.get("Metadata", {}).get("OS", {})},
        "Results": [
            {
                "Target": r.get("Target"),
                "Class": r.get("Class"),
                "Type": r.get("Type"),
                "Vulnerabilities": [
                    {k: v[k] for k in KEEP_VULN if k in v} for v in r.get("Vulnerabilities") or []
                ],
            }
            for r in report.get("Results") or []
        ],
    }


def strip_managed_fields(obj: dict) -> dict:
    for item in obj.get("items", []):
        item.get("metadata", {}).pop("managedFields", None)
    return obj


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--trivy-only", action="store_true")
    p.add_argument("--cache-dir", default=str(ROOT / ".cache"))
    args = p.parse_args()

    out = FIXTURES / "trivy"
    out.mkdir(parents=True, exist_ok=True)
    for path in sorted((Path(args.cache_dir) / "trivy").glob("*.json")):
        (out / path.name).write_text(json.dumps(slim_trivy(json.loads(path.read_text())), indent=1) + "\n")
        print(f"trivy fixture {path.name}")

    if args.trivy_only:
        return
    kdir = FIXTURES / "kubectl"
    kdir.mkdir(parents=True, exist_ok=True)
    for name, cmd in KUBECTL.items():
        raw = subprocess.run(["kubectl", *cmd], check=True, capture_output=True, text=True).stdout
        (kdir / f"{name}.json").write_text(json.dumps(strip_managed_fields(json.loads(raw)), indent=1) + "\n")
        print(f"kubectl fixture {name}.json")


if __name__ == "__main__":
    main()
