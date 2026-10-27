"""Offline fixtures: real kubectl and Trivy JSON captured from the demo cluster."""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from cva.inventory import build_inventory
from cva.models import Finding, ImageScan, Vuln, Workload
from cva.scanner import cache_path, parse_trivy

FIXTURES = Path(__file__).parent / "fixtures"

NGINX = "sha256:c7a6ad68be85142c7fe1089e48faa1e7c7166a194caa9180ddea66345876b9d2"
PYTHON = "sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2"
NODE14 = "sha256:198142146b4c47193348f6415da769bdb5035c16fcab051c38c256a6b48f2e1c"
DISTROLESS = "sha256:d5563cc7f2f44313f332e91138cc8c6a158899afeeeab2fce3b0f9ccdb3cf9ee"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Fail loudly if any test tries to reach the network."""

    def guard(*args, **kwargs):
        raise AssertionError("tests must not use the network")

    monkeypatch.setattr(socket, "create_connection", guard)
    monkeypatch.setattr(socket.socket, "connect", guard)


def kube_state() -> dict:
    if not (FIXTURES / "kubectl" / "pods.json").exists():
        pytest.skip("kubectl fixtures not captured yet: run scripts/capture_fixtures.py against the demo cluster")
    return {
        name: json.loads((FIXTURES / "kubectl" / f"{name}.json").read_text())
        for name in ("pods", "namespaces", "services", "ingresses")
    }


@pytest.fixture
def inventory() -> list[Workload]:
    workloads, _ = build_inventory(kube_state())
    return workloads


def load_scan(digest: str) -> ImageScan:
    report = json.loads(cache_path(FIXTURES, digest).read_text())
    return parse_trivy(digest, report.get("ArtifactName", ""), report)


@pytest.fixture
def scans() -> dict[str, ImageScan]:
    return {d: load_scan(d) for d in (NGINX, PYTHON, NODE14, DISTROLESS)}


def make_workload(name: str = "app", ns: str = "demo", exposure: tuple[str, ...] = (), **kw) -> Workload:
    return Workload(
        namespace=ns, pod=f"{name}-abc", owner_kind="Deployment", owner_name=name,
        container="c", image=kw.pop("image", f"{name}:1.0"), image_id=f"{name}@sha256:0",
        digest=kw.pop("digest", "sha256:0"), exposure=exposure, **kw,
    )


def make_finding(
    *, vuln_id: str = "CVE-2024-0001", severity: str = "HIGH", fixed: str = "1.1",
    exposed: bool = False, layer: str = "os", workload: Workload | None = None,
    os_key: str = "debian 12", eosl: bool = False, owner: str = "team-a",
) -> Finding:
    w = workload or make_workload(exposure=("svc/app:NodePort",) if exposed else ())
    v = Vuln(vuln_id, "pkg", "1.0", fixed, severity, "fixed" if fixed else "affected", layer, "target")
    return Finding(w, v, os_key, eosl, owner, "pod-label")
