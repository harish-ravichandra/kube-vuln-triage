"""Scan each unique image digest once with Trivy, caching raw JSON on disk."""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cva.models import ImageScan, Vuln, Workload

LAYER_BY_CLASS = {"os-pkgs": "os", "lang-pkgs": "app"}


@dataclass
class ScanStats:
    unique_digests: int = 0
    scanned: int = 0
    cache_hits: int = 0
    failed: int = 0


def run_trivy(ref: str, trivy_bin: str = "trivy") -> dict[str, Any]:
    cmd = [trivy_bin, "image", "--format", "json", "--quiet", "--scanners", "vuln", ref]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"trivy failed for {ref}: {proc.stderr.strip()[-500:]}")
    return json.loads(proc.stdout)


def parse_trivy(digest: str, ref: str, report: dict[str, Any]) -> ImageScan:
    os_meta = report.get("Metadata", {}).get("OS", {}) or {}
    vulns: dict[tuple[str, str, str, str], Vuln] = {}
    for result in report.get("Results", []) or []:
        layer = LAYER_BY_CLASS.get(result.get("Class", ""))
        if layer is None:
            continue
        for v in result.get("Vulnerabilities", []) or []:
            vuln = Vuln(
                vuln_id=v["VulnerabilityID"],
                pkg=v["PkgName"],
                installed=v.get("InstalledVersion", ""),
                fixed=v.get("FixedVersion", "") or "",
                severity=v.get("Severity", "UNKNOWN"),
                status=v.get("Status", ""),
                layer=layer,
                target=result.get("Target", ""),
            )
            vulns.setdefault((vuln.vuln_id, vuln.pkg, vuln.installed, vuln.target), vuln)
    return ImageScan(
        digest=digest,
        ref=ref,
        os_family=os_meta.get("Family", ""),
        os_name=os_meta.get("Name", ""),
        eosl=bool(os_meta.get("EOSL", False)),
        vulns=tuple(vulns.values()),
    )


def cache_path(cache_dir: Path, digest: str) -> Path:
    return cache_dir / "trivy" / f"{digest}.json"


def scan_workloads(
    workloads: list[Workload],
    cache_dir: Path,
    rescan: bool = False,
    offline: bool = False,
    trivy_bin: str = "trivy",
) -> tuple[dict[str, ImageScan], ScanStats]:
    """Return scans keyed by digest. Each digest is scanned at most once per run."""
    refs: dict[str, str] = {}
    for w in workloads:
        refs.setdefault(w.digest, w.image_id)

    stats = ScanStats(unique_digests=len(refs))
    scans: dict[str, ImageScan] = {}
    for digest, ref in sorted(refs.items()):
        path = cache_path(cache_dir, digest)
        if path.exists() and not rescan:
            report = json.loads(path.read_text())
            stats.cache_hits += 1
        elif offline:
            print(f"warning: --offline and no cached scan for {ref}; skipping", file=sys.stderr)
            stats.failed += 1
            continue
        else:
            print(f"scanning {ref}", file=sys.stderr)
            try:
                report = run_trivy(ref, trivy_bin)
            except RuntimeError as exc:
                print(f"warning: {exc}", file=sys.stderr)
                stats.failed += 1
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(report))
            stats.scanned += 1
        scans[digest] = parse_trivy(digest, ref, report)
    return scans, stats
