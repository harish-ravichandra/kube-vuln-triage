"""Resolve which team owns a workload, from labels and annotations only."""

from __future__ import annotations

from cva.models import Workload

ORPHAN = "ORPHAN"
TEAM_LABEL = "team"
OWNER_ANNOTATION = "owner"


def resolve_owner(
    pod_labels: dict[str, str],
    ns_labels: dict[str, str],
    pod_annotations: dict[str, str],
) -> tuple[str, str]:
    """Return (owner, owner_source), checking the most specific source first.

    1. pod label `team`        -> source "pod-label"
    2. namespace label `team`  -> source "namespace-label"
    3. pod annotation `owner`  -> source "pod-annotation"
    4. nothing                 -> (ORPHAN, "none")

    Blank values count as missing so `team: ""` cannot hide an orphan.
    """
    for value, source in (
        (pod_labels.get(TEAM_LABEL), "pod-label"),
        (ns_labels.get(TEAM_LABEL), "namespace-label"),
        (pod_annotations.get(OWNER_ANNOTATION), "pod-annotation"),
    ):
        if value and value.strip():
            return value.strip(), source
    return ORPHAN, "none"


def owner_of(w: Workload) -> tuple[str, str]:
    return resolve_owner(w.pod_labels, w.ns_labels, w.pod_annotations)
