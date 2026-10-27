from cva.cli import build_findings
from cva.grouping import EOL_NOTE, group_app, group_base_image
from cva.scoring import score_findings

from conftest import DISTROLESS, NGINX, NODE14, PYTHON, load_scan, make_finding, make_workload


def test_debian_point_releases_share_a_grouping_key():
    assert load_scan(NGINX).os_name != load_scan(PYTHON).os_name  # 12.5 vs 12.15
    assert load_scan(NGINX).os_key == load_scan(PYTHON).os_key == "debian 12"


def test_two_images_sharing_a_base_collapse_into_one_item():
    w1 = make_workload("api", image="nginx:1.25.3")
    w2 = make_workload("worker", image="python:3.12")
    findings = [
        make_finding(vuln_id="CVE-1", workload=w1, owner="payments"),
        make_finding(vuln_id="CVE-1", workload=w2, owner="orders"),
        make_finding(vuln_id="CVE-2", workload=w2, owner="orders"),  # same pkg + fix -> same item
    ]
    items = group_base_image(score_findings(findings, set(), {}))
    assert len(items) == 1
    item = items[0]
    assert item.cves == {"CVE-1", "CVE-2"}
    assert item.images == {"nginx:1.25.3", "python:3.12"}
    assert item.owners == {"payments", "orders"}
    assert item.action == (
        "Rebuild on a base where `pkg` ≥ `1.1`; affects 2 images, 2 workloads, owners: orders, payments."
    )


def test_different_os_or_fixed_version_stay_separate():
    findings = [
        make_finding(vuln_id="CVE-1", fixed="1.1"),
        make_finding(vuln_id="CVE-2", fixed="1.2"),
        make_finding(vuln_id="CVE-1", os_key="debian 10"),
    ]
    assert len(group_base_image(findings)) == 3


def test_unfixed_and_app_findings_are_not_base_image_items():
    findings = [make_finding(fixed=""), make_finding(layer="app")]
    assert group_base_image(findings) == []
    assert [i.action for i in group_app(findings)] == ["Upgrade `pkg` 1.0 → 1.1 in `app:1.0`."]


def test_demo_cluster_has_shared_base_items(inventory, scans):
    items = group_base_image(score_findings(build_findings(inventory, scans), set(), {}))
    shared = [i for i in items if len(i.workloads) >= 2]
    assert shared, "nginx and python share Debian 12, so some rebuilds span both"
    assert all(i.os_key == "debian 12" for i in shared)
    assert {"demo/deployment/payments-api", "demo/deployment/orders-worker"} <= shared[0].workloads


def test_eol_flag_carries_through(inventory, scans):
    assert scans[NODE14].eosl and not scans[NGINX].eosl and not scans[DISTROLESS].eosl
    items = group_base_image(score_findings(build_findings(inventory, scans), set(), {}))
    eol_items = [i for i in items if i.eosl]
    assert eol_items and all(i.os_key == "debian 10" for i in eol_items)
    assert all(i.action.endswith(EOL_NOTE) for i in eol_items)
    assert not any(i.action.endswith(EOL_NOTE) for i in items if not i.eosl)


def test_app_layer_stays_per_image(inventory, scans):
    items = group_app(score_findings(build_findings(inventory, scans), set(), {}))
    assert items
    assert all(len(i.images) == 1 for i in items)
    assert any("node:14" in next(iter(i.images)) for i in items)
