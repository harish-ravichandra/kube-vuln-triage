"""Shared record types passed between pipeline stages."""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


@dataclass(frozen=True)
class Workload:
    """One container of one top-level workload, as seen in the cluster."""

    namespace: str
    pod: str
    owner_kind: str
    owner_name: str
    container: str
    image: str
    image_id: str  # pullable ref, e.g. docker.io/library/nginx@sha256:...
    digest: str  # sha256:...
    pod_labels: dict[str, str] = field(default_factory=dict, hash=False, compare=False)
    pod_annotations: dict[str, str] = field(default_factory=dict, hash=False, compare=False)
    ns_labels: dict[str, str] = field(default_factory=dict, hash=False, compare=False)
    exposure: tuple[str, ...] = ()

    @property
    def workload_id(self) -> str:
        return f"{self.namespace}/{self.owner_kind.lower()}/{self.owner_name}"

    @property
    def exposed(self) -> bool:
        return bool(self.exposure)


@dataclass(frozen=True)
class Vuln:
    """One vulnerability row from a Trivy result."""

    vuln_id: str
    pkg: str
    installed: str
    fixed: str
    severity: str
    status: str
    layer: str  # "os" for os-pkgs (base image), "app" for lang-pkgs
    target: str


@dataclass(frozen=True)
class ImageScan:
    digest: str
    ref: str
    os_family: str
    os_name: str
    eosl: bool
    vulns: tuple[Vuln, ...]

    @property
    def os_key(self) -> str:
        """Distro release used for grouping, e.g. 'debian 12' for 12.5 and 12.15.

        Debian point releases share one package archive, so a fix in 12.x
        applies to every 12.y image. Other distros keep their full name.
        """
        if not self.os_family:
            return "unknown"
        name = self.os_name
        if self.os_family == "debian":
            name = name.split(".")[0]
        elif self.os_family == "alpine":
            name = ".".join(name.split(".")[:2])
        return f"{self.os_family} {name}"


@dataclass
class Finding:
    """A vulnerability in a specific workload, enriched and attributed."""

    workload: Workload
    vuln: Vuln
    os_key: str
    eosl: bool
    owner: str
    owner_source: str
    kev: bool = False
    epss: float = 0.0
    tier: str = "P4"
    affected_workloads: int = 1

    @property
    def fixable(self) -> bool:
        return bool(self.vuln.fixed)

    @property
    def severity_rank(self) -> int:
        return SEVERITY_RANK.get(self.vuln.severity, 0)
