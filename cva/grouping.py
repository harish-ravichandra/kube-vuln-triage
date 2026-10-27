"""Turn findings into fix items: one per base image package fix, one per app dependency upgrade."""

from __future__ import annotations

from dataclasses import dataclass, field

from cva.models import SEVERITY_RANK, Finding

EOL_NOTE = "OS is end-of-life: migrate the base image, since no further fixes will ship."


@dataclass
class FixItem:
    layer: str  # "os" or "app"
    pkg: str
    fixed: str
    installed: set[str] = field(default_factory=set)
    os_key: str = ""
    cves: set[str] = field(default_factory=set)
    images: set[str] = field(default_factory=set)
    workloads: set[str] = field(default_factory=set)
    owners: set[str] = field(default_factory=set)
    tier: str = "P4"
    kev: bool = False
    epss: float = 0.0
    severity: str = "UNKNOWN"
    eosl: bool = False

    def add(self, f: Finding) -> None:
        self.installed.add(f.vuln.installed)
        self.cves.add(f.vuln.vuln_id)
        self.images.add(f.workload.image)
        self.workloads.add(f.workload.workload_id)
        self.owners.add(f.owner)
        self.tier = min(self.tier, f.tier)
        self.kev = self.kev or f.kev
        self.epss = max(self.epss, f.epss)
        if SEVERITY_RANK.get(f.vuln.severity, 0) > SEVERITY_RANK.get(self.severity, 0):
            self.severity = f.vuln.severity
        self.eosl = self.eosl or f.eosl

    @property
    def action(self) -> str:
        if self.layer == "app":
            installed = ", ".join(sorted(self.installed))
            return f"Upgrade `{self.pkg}` {installed} → {self.fixed} in `{next(iter(sorted(self.images)))}`."
        text = (
            f"Rebuild on a base where `{self.pkg}` ≥ `{self.fixed}`; affects {len(self.images)} "
            f"image{'s' if len(self.images) != 1 else ''}, {len(self.workloads)} "
            f"workload{'s' if len(self.workloads) != 1 else ''}, owners: {', '.join(sorted(self.owners))}."
        )
        if self.eosl:
            text += " " + EOL_NOTE
        return text

    def sort_key(self) -> tuple:
        return (
            self.tier,
            not self.kev,
            -self.epss,
            -SEVERITY_RANK.get(self.severity, 0),
            -len(self.workloads),
            self.pkg,
            self.fixed,
        )

    def to_dict(self) -> dict:
        return {
            "layer": self.layer,
            "os": self.os_key,
            "package": self.pkg,
            "installed": sorted(self.installed),
            "fixed_version": self.fixed,
            "tier": self.tier,
            "kev": self.kev,
            "max_epss": round(self.epss, 5),
            "max_severity": self.severity,
            "cves": sorted(self.cves),
            "images": sorted(self.images),
            "workloads": sorted(self.workloads),
            "owners": sorted(self.owners),
            "eosl": self.eosl,
            "action": self.action,
        }


def group_base_image(findings: list[Finding]) -> list[FixItem]:
    """Collapse fixable OS-package findings by (OS release, package, fixed version).

    The same CVE in the same Debian package is one rebuild, no matter how many
    apps inherit it, so it becomes one item listing every affected image.
    """
    items: dict[tuple[str, str, str], FixItem] = {}
    for f in findings:
        if f.vuln.layer != "os" or not f.fixable:
            continue
        key = (f.os_key, f.vuln.pkg, f.vuln.fixed)
        item = items.get(key)
        if item is None:
            item = items[key] = FixItem(layer="os", pkg=f.vuln.pkg, fixed=f.vuln.fixed, os_key=f.os_key)
        item.add(f)
    return sorted(items.values(), key=FixItem.sort_key)


def group_app(findings: list[Finding]) -> list[FixItem]:
    """Fixable app-layer findings, kept per image: (image, package, fixed version)."""
    items: dict[tuple[str, str, str], FixItem] = {}
    for f in findings:
        if f.vuln.layer != "app" or not f.fixable:
            continue
        key = (f.workload.image, f.vuln.pkg, f.vuln.fixed)
        item = items.get(key)
        if item is None:
            item = items[key] = FixItem(layer="app", pkg=f.vuln.pkg, fixed=f.vuln.fixed, os_key=f.os_key)
        item.add(f)
    return sorted(items.values(), key=FixItem.sort_key)
