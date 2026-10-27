import pytest

from cva.scoring import score_findings, tier_for

from conftest import make_finding, make_workload


@pytest.mark.parametrize(
    "kev, epss, severity, fixable, exposed, expected",
    [
        # P1 needs exploit signal + fix + exposure
        (True, 0.0, "LOW", True, True, "P1"),
        (False, 0.5, "MEDIUM", True, True, "P1"),
        (False, 0.4999, "MEDIUM", True, True, "P2"),  # below P1 EPSS, still above P2's
        # Same exploit signal without exposure drops to P2
        (True, 0.0, "LOW", True, False, "P2"),
        (False, 0.9, "LOW", True, False, "P2"),
        # P2 EPSS boundary
        (False, 0.1, "MEDIUM", True, False, "P2"),
        (False, 0.0999, "MEDIUM", True, False, "P4"),
        # CRITICAL alone with a fix is P2
        (False, 0.0, "CRITICAL", True, False, "P2"),
        # HIGH with a fix is P3
        (False, 0.0, "HIGH", True, True, "P3"),
        (False, 0.0999, "HIGH", True, False, "P3"),
        # No fix: always P4, even KEV + CRITICAL + exposed
        (True, 0.99, "CRITICAL", False, True, "P4"),
        (False, 0.0, "HIGH", False, False, "P4"),
        (False, 0.0, "MEDIUM", True, True, "P4"),
    ],
)
def test_tier_boundaries(kev, epss, severity, fixable, exposed, expected):
    assert tier_for(kev, epss, severity, fixable, exposed) == expected


def test_enrichment_and_sort_order_within_tier():
    a = make_finding(vuln_id="CVE-A", severity="CRITICAL")  # P2 by severity
    b = make_finding(vuln_id="CVE-B", severity="LOW")  # P2 by KEV
    c = make_finding(vuln_id="CVE-C", severity="MEDIUM")  # P2 by EPSS 0.3
    d = make_finding(vuln_id="CVE-D", severity="MEDIUM")  # P2 by EPSS 0.2
    e = make_finding(vuln_id="CVE-E", severity="HIGH", exposed=True)  # P3
    out = score_findings([e, a, d, c, b], kev={"CVE-B"}, epss={"CVE-C": 0.3, "CVE-D": 0.2})
    assert [(f.vuln.vuln_id, f.tier) for f in out] == [
        ("CVE-B", "P2"), ("CVE-C", "P2"), ("CVE-D", "P2"), ("CVE-A", "P2"), ("CVE-E", "P3"),
    ]


def test_affected_workloads_breaks_ties():
    w1, w2, w3 = (make_workload(n) for n in ("a", "b", "c"))
    shared = [make_finding(vuln_id="CVE-SHARED", workload=w) for w in (w1, w2)]
    single = make_finding(vuln_id="CVE-ALONE", workload=w3)
    out = score_findings([single, *shared], kev=set(), epss={})
    assert [f.vuln.vuln_id for f in out] == ["CVE-SHARED", "CVE-SHARED", "CVE-ALONE"]
    assert out[0].affected_workloads == 2


def test_exposed_payments_api_ranks_highest(inventory, scans):
    from cva.cli import build_findings

    findings = build_findings(inventory, scans)
    # Point-in-time KEV/EPSS can change; pick a fixable CVE present in every
    # Debian 12 image and mark it KEV to check exposure decides the order.
    cve = next(f.vuln.vuln_id for f in findings if f.workload.owner_name == "orders-worker" and f.fixable
               and f.vuln.layer == "os" and any(g.vuln.vuln_id == f.vuln.vuln_id and g.workload.owner_name == "payments-api" for g in findings))
    out = score_findings(findings, kev={cve}, epss={})
    assert out[0].workload.owner_name == "payments-api"
    assert out[0].tier == "P1"
    assert {f.tier for f in out if f.vuln.vuln_id == cve and f.workload.owner_name == "orders-worker"} == {"P2"}
