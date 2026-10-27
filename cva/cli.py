"""Entry point: `python -m cva run --out reports/`."""

from __future__ import annotations

import argparse
import sys
from dataclasses import asdict
from pathlib import Path

from cva.attribution import owner_of
from cva.enrich import EnrichInfo, load_epss, load_kev
from cva.inventory import DEFAULT_SKIP_NAMESPACES, build_inventory, fetch_cluster_state
from cva.models import Finding, ImageScan, Workload
from cva.report import generated_line, tier_counts, write_reports
from cva.scanner import scan_workloads
from cva.scoring import score_findings


def build_findings(workloads: list[Workload], scans: dict[str, ImageScan]) -> list[Finding]:
    findings = []
    for w in workloads:
        scan = scans.get(w.digest)
        if scan is None:
            continue
        owner, source = owner_of(w)
        for v in scan.vulns:
            findings.append(Finding(w, v, scan.os_key, scan.eosl, owner, source))
    return findings


def cmd_run(args: argparse.Namespace) -> int:
    cache = Path(args.cache_dir)
    skip = frozenset() if args.include_system else DEFAULT_SKIP_NAMESPACES

    state = fetch_cluster_state(args.context)
    workloads, unresolved = build_inventory(state, skip)
    print(f"inventory: {len({w.workload_id for w in workloads})} workloads, "
          f"{len(workloads)} containers, {len({w.digest for w in workloads})} unique digests", file=sys.stderr)
    for u in unresolved:
        print(f"warning: unresolved {u}", file=sys.stderr)

    scans, stats = scan_workloads(workloads, cache, rescan=args.rescan, offline=args.offline, trivy_bin=args.trivy)
    print(f"scan: {stats.scanned} scanned, {stats.cache_hits} from cache, {stats.failed} failed", file=sys.stderr)

    findings = build_findings(workloads, scans)
    info = EnrichInfo(offline=args.offline)
    kev = load_kev(cache, args.offline, info)
    epss = load_epss({f.vuln.vuln_id for f in findings}, cache, args.offline, info)
    score_findings(findings, kev, epss)

    iso, line = generated_line()
    summary = write_reports(
        Path(args.out),
        findings,
        workloads,
        scans,
        {
            "generated_at": iso,
            "generated_line": line,
            "scan": asdict(stats),
            "enrichment": asdict(info),
            "unresolved": unresolved,
        },
    )
    counts = tier_counts(findings)
    print(
        f"findings: {counts['total']} (P1 {counts['P1']}, P2 {counts['P2']}, P3 {counts['P3']}, P4 {counts['P4']}); "
        f"orphans: {summary['counts']['orphans']['workload_count']}; "
        f"base image fix items: {len(summary['base_image_fix_items'])}; reports in {args.out}",
        file=sys.stderr,
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cva", description="Container vulnerability attribution")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="inventory, scan, attribute, prioritise and report")
    run.add_argument("--out", default="reports", help="report directory (default: reports)")
    run.add_argument("--cache-dir", default=".cache", help="scan and feed cache (default: .cache)")
    run.add_argument("--offline", action="store_true", help="use cached scans, KEV and EPSS only")
    run.add_argument("--rescan", action="store_true", help="ignore cached Trivy results")
    run.add_argument("--include-system", action="store_true",
                     help=f"also scan {', '.join(sorted(DEFAULT_SKIP_NAMESPACES))}")
    run.add_argument("--context", help="kubectl context (default: current)")
    run.add_argument("--trivy", default="trivy", help="trivy binary (default: trivy on PATH)")
    run.set_defaults(func=cmd_run)
    args = parser.parse_args(argv)
    return args.func(args)
