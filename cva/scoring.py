"""Explainable priority tiers. Each tier is one sentence a human can repeat."""

from __future__ import annotations

from collections import Counter

from cva.models import SEVERITY_RANK, Finding

EPSS_P1 = 0.5
EPSS_P2 = 0.1


def tier_for(kev: bool, epss: float, severity: str, fixable: bool, exposed: bool) -> str:
    """Assign P1..P4.

    P1: known or likely exploited (KEV, or EPSS >= 0.5), a fix exists, and the
        workload is reachable from outside the cluster. Fix now.
    P2: exploited, likely exploited (EPSS >= 0.1) or CRITICAL, and a fix exists.
        Fix this sprint.
    P3: HIGH severity and a fix exists. Fix in normal patch cadence.
    P4: everything else, including findings with no fix yet. Tracked, not paged.
    """
    if not fixable:
        return "P4"
    if (kev or epss >= EPSS_P1) and exposed:
        return "P1"
    if kev or epss >= EPSS_P2 or severity == "CRITICAL":
        return "P2"
    if severity == "HIGH":
        return "P3"
    return "P4"


def sort_key(f: Finding) -> tuple:
    """Tier first, then KEV, EPSS (desc), severity (desc), affected workloads (desc).

    Exposed workloads break any remaining tie, ahead of the stable ID ordering.
    """
    return (
        f.tier,
        not f.kev,
        -f.epss,
        -SEVERITY_RANK.get(f.vuln.severity, 0),
        -f.affected_workloads,
        not f.workload.exposed,
        f.vuln.vuln_id,
        f.workload.workload_id,
    )


def score_findings(findings: list[Finding], kev: set[str], epss: dict[str, float]) -> list[Finding]:
    """Enrich, tier and sort findings in place; returns them sorted."""
    spread = Counter()
    seen: set[tuple[str, str, str]] = set()
    for f in findings:
        key = (f.vuln.vuln_id, f.vuln.pkg, f.workload.workload_id)
        if key not in seen:
            seen.add(key)
            spread[(f.vuln.vuln_id, f.vuln.pkg)] += 1
    for f in findings:
        f.kev = f.vuln.vuln_id in kev
        f.epss = epss.get(f.vuln.vuln_id, 0.0)
        f.affected_workloads = spread[(f.vuln.vuln_id, f.vuln.pkg)]
        f.tier = tier_for(f.kev, f.epss, f.vuln.severity, f.fixable, f.workload.exposed)
    findings.sort(key=sort_key)
    return findings
