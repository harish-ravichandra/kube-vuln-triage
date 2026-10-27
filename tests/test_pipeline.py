"""End to end on fixtures: dedupe, cache reuse, and all five reports."""

import json
import shutil

from cva import cli, scanner

from conftest import FIXTURES, kube_state


def test_each_digest_scanned_once_then_cached(tmp_path, monkeypatch, inventory):
    calls = []

    def fake_trivy(ref, trivy_bin="trivy"):
        calls.append(ref)
        digest = ref.split("@", 1)[1]
        return json.loads((FIXTURES / "trivy" / f"{digest}.json").read_text())

    monkeypatch.setattr(scanner, "run_trivy", fake_trivy)
    _, first = scanner.scan_workloads(inventory, tmp_path)
    assert first.unique_digests == 4 and first.scanned == 4 and first.cache_hits == 0
    assert len(calls) == len(set(calls)) == 4

    _, second = scanner.scan_workloads(inventory, tmp_path)
    assert second.scanned == 0 and second.cache_hits == 4
    assert len(calls) == 4

    _, third = scanner.scan_workloads(inventory, tmp_path, rescan=True)
    assert third.scanned == 4


def test_run_offline_writes_all_reports(tmp_path, monkeypatch):
    cache = tmp_path / "cache"
    shutil.copytree(FIXTURES / "trivy", cache / "trivy")
    # Point-in-time KEV/EPSS snapshots, trimmed to the CVEs in the fixtures.
    shutil.copy(FIXTURES / "kev.json", cache / "kev.json")
    shutil.copy(FIXTURES / "epss.json", cache / "epss.json")
    monkeypatch.setattr(cli, "fetch_cluster_state", lambda context=None: kube_state())
    out = tmp_path / "reports"

    assert cli.main(["run", "--offline", "--out", str(out), "--cache-dir", str(cache)]) == 0

    for name in ("summary.json", "findings.csv", "ORPHANS.md", "BASE_IMAGES.md"):
        assert (out / name).exists(), name
    assert {p.name for p in (out / "teams").glob("*.md")} == {"payments.md", "orders.md", "platform.md"}

    summary = json.loads((out / "summary.json").read_text())
    assert summary["scan"]["cache_hits"] == 4 and summary["scan"]["scanned"] == 0
    assert summary["counts"]["orphans"]["workloads"] == ["demo/deployment/legacy-report"]
    assert any(len(i["workloads"]) >= 2 for i in summary["base_image_fix_items"])
    assert [e["workloads"] for e in summary["eol_images"]] == [["demo/deployment/legacy-report"]]
    assert "legacy-report" in (out / "ORPHANS.md").read_text()

    header, first_row = (out / "findings.csv").read_text().splitlines()[:2]
    assert header.split(",")[:3] == ["tier", "owner", "owner_source"]
    assert first_row.startswith("P1,payments,pod-label,") and "payments-api" in first_row
    assert summary["counts"]["by_tier"]["P1"] > 0
    assert summary["counts"]["by_team"]["payments"]["P1"] == summary["counts"]["by_tier"]["P1"]
