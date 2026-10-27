"""Write summary.json, findings.csv and the Markdown remediation reports."""

from __future__ import annotations

import csv
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cva.attribution import ORPHAN, owner_of
from cva.grouping import FixItem, group_app, group_base_image
from cva.models import Finding, ImageScan, Workload

TIERS = ("P1", "P2", "P3", "P4")
TIER_LABEL = {
    "P1": "P1: fix now (exploited or likely, fixable, exposed)",
    "P2": "P2: fix this sprint (exploited, likely, or critical, and fixable)",
    "P3": "P3: normal patch cadence (high and fixable)",
    "P4": "P4: tracked, not paged",
}
CSV_FIELDS = [
    "tier", "owner", "owner_source", "namespace", "workload", "container", "image", "digest",
    "layer", "os", "eosl", "vuln_id", "pkg", "installed", "fixed", "fixable", "severity",
    "status", "kev", "epss", "exposed", "exposure", "affected_workloads", "target",
]
MAX_CVES_SHOWN = 4


def tier_counts(findings: list[Finding]) -> dict[str, int]:
    c = Counter(f.tier for f in findings)
    return {t: c.get(t, 0) for t in TIERS} | {"total": len(findings)}


def eol_images(scans: dict[str, ImageScan], workloads: list[Workload]) -> list[dict[str, Any]]:
    by_digest: dict[str, list[Workload]] = defaultdict(list)
    for w in workloads:
        by_digest[w.digest].append(w)
    return [
        {
            "image": sorted({w.image for w in by_digest[d]})[0],
            "digest": d,
            "os": f"{s.os_family} {s.os_name}".strip(),
            "workloads": sorted({w.workload_id for w in by_digest[d]}),
        }
        for d, s in sorted(scans.items())
        if s.eosl
    ]


def _safe_name(team: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", team)


def _cves(item: FixItem) -> str:
    cves = sorted(item.cves)
    shown = ", ".join(cves[:MAX_CVES_SHOWN])
    return shown + (f" +{len(cves) - MAX_CVES_SHOWN} more" if len(cves) > MAX_CVES_SHOWN else "")


def _items_table(items: list[FixItem], with_layer: bool = True) -> list[str]:
    head = "| # | Tier | " + ("Layer | " if with_layer else "") + "Action | CVEs | KEV | Max EPSS | Severity | Workloads |"
    sep = "|---|---|" + ("---|" if with_layer else "") + "---|---|---|---|---|---|"
    rows = [head, sep]
    for i, it in enumerate(items, 1):
        layer = ("base image | " if it.layer == "os" else "app | ") if with_layer else ""
        rows.append(
            f"| {i} | {it.tier} | {layer}{it.action} | {_cves(it)} | {'yes' if it.kev else ''} | "
            f"{it.epss:.3f} | {it.severity} | {', '.join(sorted(it.workloads))} |"
        )
    return rows


def _workloads_table(workloads: list[Workload]) -> list[str]:
    rows = ["| Workload | Container | Image | Exposure | Owner source |", "|---|---|---|---|---|"]
    for w in sorted(workloads, key=lambda w: (w.workload_id, w.container)):
        exposure = ", ".join(w.exposure) or "internal"
        rows.append(f"| {w.workload_id} | {w.container} | `{w.image}` | {exposure} | {owner_of(w)[1]} |")
    return rows


def remediation_md(title: str, intro: list[str], findings: list[Finding], workloads: list[Workload]) -> str:
    """Per-owner remediation list: P1 first, one row per concrete upgrade action."""
    counts = tier_counts(findings)
    items = sorted(group_base_image(findings) + group_app(findings), key=FixItem.sort_key)
    lines = [f"# {title}", "", *intro]
    lines += [
        f"Findings: **{counts['total']}** (P1 {counts['P1']}, P2 {counts['P2']}, P3 {counts['P3']}, P4 {counts['P4']}). "
        f"Fix items: **{len(items)}**.",
        "",
        "## Workloads",
        "",
        *_workloads_table(workloads),
        "",
    ]
    for tier in ("P1", "P2", "P3"):
        tier_items = [i for i in items if i.tier == tier]
        lines += [f"## {TIER_LABEL[tier]}", ""]
        lines += _items_table(tier_items) if tier_items else ["None."]
        lines.append("")
    p4_items = [i for i in items if i.tier == "P4"]
    unfixed = sum(1 for f in findings if not f.fixable)
    lines += [
        f"## {TIER_LABEL['P4']}",
        "",
        f"{counts['P4']} findings: {len(p4_items)} fixable low/medium items and {unfixed} with no fix "
        "available yet. Full rows are in `findings.csv`.",
        "",
    ]
    return "\n".join(lines)


def base_images_md(fix_items: list[FixItem], eol: list[dict[str, Any]], unfixed_os: int) -> str:
    shared = [i for i in fix_items if len(i.workloads) > 1]
    lines = [
        "# Base image fix items",
        "",
        "OS-package (`os-pkgs`) findings come from the base image layer, so they are grouped by "
        "(OS release, package, fixed version) into one rebuild item instead of one ticket per app.",
        "",
        f"Fix items: **{len(fix_items)}**, of which **{len(shared)}** span 2+ workloads. "
        f"{unfixed_os} OS findings have no fix yet and are tracked in `findings.csv`.",
        "",
        "## End-of-life base images",
        "",
    ]
    if eol:
        lines += ["| Image | OS | Workloads |", "|---|---|---|"]
        lines += [f"| `{e['image']}` | {e['os']} | {', '.join(e['workloads'])} |" for e in eol]
        lines += ["", "No further fixes will ship for these. Migrate to a supported base."]
    else:
        lines.append("None.")
    lines += ["", "## Fix items", ""]
    lines += _items_table(fix_items, with_layer=False) if fix_items else ["None."]
    lines.append("")
    return "\n".join(lines)


def write_reports(
    out: Path,
    findings: list[Finding],
    workloads: list[Workload],
    scans: dict[str, ImageScan],
    meta: dict[str, Any],
) -> dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    teams_dir = out / "teams"
    teams_dir.mkdir(exist_ok=True)
    for stale in teams_dir.glob("*.md"):
        stale.unlink()

    with (out / "findings.csv").open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for f in findings:
            writer.writerow({
                "tier": f.tier, "owner": f.owner, "owner_source": f.owner_source,
                "namespace": f.workload.namespace, "workload": f.workload.workload_id,
                "container": f.workload.container, "image": f.workload.image, "digest": f.workload.digest,
                "layer": f.vuln.layer, "os": f.os_key, "eosl": f.eosl, "vuln_id": f.vuln.vuln_id,
                "pkg": f.vuln.pkg, "installed": f.vuln.installed, "fixed": f.vuln.fixed,
                "fixable": f.fixable, "severity": f.vuln.severity, "status": f.vuln.status,
                "kev": f.kev, "epss": f"{f.epss:.5f}", "exposed": f.workload.exposed,
                "exposure": ";".join(f.workload.exposure), "affected_workloads": f.affected_workloads,
                "target": f.vuln.target,
            })

    # Owners come from workloads, not findings, so a clean or unscanned workload
    # still gets a team report or an orphan entry.
    owners = {w.workload_id: owner_of(w)[0] for w in workloads}
    by_owner: dict[str, list[Finding]] = {o: [] for o in owners.values()}
    for f in findings:
        by_owner.setdefault(f.owner, []).append(f)

    for team, team_findings in sorted(by_owner.items()):
        if team == ORPHAN:
            continue
        (teams_dir / f"{_safe_name(team)}.md").write_text(
            remediation_md(
                f"Remediation: team `{team}`",
                [meta["generated_line"], ""],
                team_findings,
                [w for w in workloads if owners[w.workload_id] == team],
            )
        )

    orphan_findings = by_owner.get(ORPHAN, [])
    orphan_workloads = sorted(w for w, o in owners.items() if o == ORPHAN)
    (out / "ORPHANS.md").write_text(
        remediation_md(
            "Orphaned workloads",
            [
                meta["generated_line"],
                "",
                f"**{len(orphan_workloads)}** workload(s) have no owner: no pod label `team`, no namespace "
                "label `team`, and no pod annotation `owner`. Their findings reach nobody until an owner is "
                "assigned. Add a `team` label (enforced at admission by `require-team-label` in `secure`).",
                "",
            ],
            orphan_findings,
            [w for w in workloads if owners[w.workload_id] == ORPHAN],
        )
        if orphan_workloads
        else f"# Orphaned workloads\n\n{meta['generated_line']}\n\nNone. Every workload has an owner.\n"
    )

    fix_items = group_base_image(findings)
    eol = eol_images(scans, workloads)
    unfixed_os = sum(1 for f in findings if f.vuln.layer == "os" and not f.fixable)
    (out / "BASE_IMAGES.md").write_text(base_images_md(fix_items, eol, unfixed_os))

    summary = {
        "generated_at": meta["generated_at"],
        "scan": meta["scan"],
        "enrichment": meta["enrichment"],
        "workloads": len({w.workload_id for w in workloads}),
        "counts": {
            "by_tier": tier_counts(findings),
            "by_team": {t: tier_counts(fs) for t, fs in sorted(by_owner.items()) if t != ORPHAN},
            "orphans": {
                "workloads": orphan_workloads,
                "workload_count": len(orphan_workloads),
                "findings": tier_counts(orphan_findings),
            },
        },
        "base_image_fix_items": [i.to_dict() for i in fix_items],
        "eol_images": eol,
        "unresolved_containers": meta.get("unresolved", []),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def generated_line(now: datetime | None = None) -> tuple[str, str]:
    now = now or datetime.now(timezone.utc)
    iso = now.replace(microsecond=0).isoformat()
    return iso, f"Generated {iso} by `python -m cva run`."
