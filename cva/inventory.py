"""Build a container inventory from read-only kubectl JSON.

Only `get`/`list` on pods, namespaces, services and ingresses is used.
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

from cva.models import Workload

DEFAULT_SKIP_NAMESPACES = frozenset({"kube-system", "kyverno", "local-path-storage"})
EXPOSING_SERVICE_TYPES = frozenset({"NodePort", "LoadBalancer"})

KubeList = dict[str, Any]


def kubectl_get(resource: str, all_namespaces: bool = True, context: str | None = None) -> KubeList:
    cmd = ["kubectl", "get", resource, "-o", "json"]
    if all_namespaces:
        cmd.append("-A")
    if context:
        cmd += ["--context", context]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        if resource == "ingress":
            # Ingress is optional for exposure; a cluster without the API is not fatal.
            print(f"warning: could not list ingresses: {proc.stderr.strip()}", file=sys.stderr)
            return {"items": []}
        raise RuntimeError(f"{' '.join(cmd)} failed: {proc.stderr.strip()}")
    return json.loads(proc.stdout)


def fetch_cluster_state(context: str | None = None) -> dict[str, KubeList]:
    return {
        "pods": kubectl_get("pods", context=context),
        "namespaces": kubectl_get("namespaces", all_namespaces=False, context=context),
        "services": kubectl_get("services", context=context),
        "ingresses": kubectl_get("ingress", context=context),
    }


def top_level_owner(pod: dict[str, Any]) -> tuple[str, str]:
    """Resolve a pod to the workload that manages it.

    A Deployment's ReplicaSet is named `<deployment>-<pod-template-hash>` and the
    pod carries that hash as a label, so the Deployment is recovered without
    needing read access to ReplicaSets.
    """
    meta = pod["metadata"]
    refs = [r for r in meta.get("ownerReferences", []) if r.get("controller", True)]
    if not refs:
        return "Pod", meta["name"]
    ref = refs[0]
    kind, name = ref["kind"], ref["name"]
    template_hash = meta.get("labels", {}).get("pod-template-hash")
    if kind == "ReplicaSet" and template_hash and name.endswith(f"-{template_hash}"):
        return "Deployment", name[: -len(template_hash) - 1]
    return kind, name


def parse_image_id(image_id: str) -> tuple[str, str]:
    """Return (pullable ref, digest) from a containerStatus imageID."""
    image_id = image_id.removeprefix("docker-pullable://")
    if "@" in image_id:
        return image_id, image_id.split("@", 1)[1]
    # Locally loaded images only expose a config digest, with no registry ref.
    return "", image_id


def selects(selector: dict[str, str] | None, labels: dict[str, str]) -> bool:
    return bool(selector) and all(labels.get(k) == v for k, v in selector.items())


def ingress_backends(ingress: dict[str, Any]) -> set[str]:
    spec = ingress.get("spec", {})
    names = set()
    default = spec.get("defaultBackend", {}).get("service", {}).get("name")
    if default:
        names.add(default)
    for rule in spec.get("rules", []):
        for path in rule.get("http", {}).get("paths", []):
            name = path.get("backend", {}).get("service", {}).get("name")
            if name:
                names.add(name)
    return names


def exposure_for(pod: dict[str, Any], services: list[dict], ingresses: list[dict]) -> tuple[str, ...]:
    """Reasons a pod is reachable from outside the cluster, empty if it is not."""
    ns = pod["metadata"]["namespace"]
    labels = pod["metadata"].get("labels", {})
    selecting = [
        s for s in services
        if s["metadata"]["namespace"] == ns and selects(s.get("spec", {}).get("selector"), labels)
    ]
    reasons = [
        f"svc/{s['metadata']['name']}:{s['spec']['type']}"
        for s in selecting
        if s["spec"].get("type") in EXPOSING_SERVICE_TYPES
    ]
    selecting_names = {s["metadata"]["name"] for s in selecting}
    for ing in ingresses:
        if ing["metadata"]["namespace"] != ns:
            continue
        for svc in sorted(ingress_backends(ing) & selecting_names):
            reasons.append(f"ingress/{ing['metadata']['name']}->svc/{svc}")
    return tuple(sorted(reasons))


def build_inventory(
    state: dict[str, KubeList],
    skip_namespaces: frozenset[str] = DEFAULT_SKIP_NAMESPACES,
) -> tuple[list[Workload], list[str]]:
    """Return one Workload per (workload, container, digest) plus unresolved containers.

    Replicas of the same Deployment collapse into one record.
    """
    ns_labels = {
        n["metadata"]["name"]: n["metadata"].get("labels", {}) for n in state["namespaces"]["items"]
    }
    services = state["services"]["items"]
    ingresses = state["ingresses"]["items"]

    workloads: dict[tuple[str, str, str], Workload] = {}
    unresolved: list[str] = []
    for pod in state["pods"]["items"]:
        meta = pod["metadata"]
        ns = meta["namespace"]
        if ns in skip_namespaces:
            continue
        owner_kind, owner_name = top_level_owner(pod)
        exposure = exposure_for(pod, services, ingresses)
        status = pod.get("status", {})
        statuses = {
            s["name"]: s
            for s in status.get("initContainerStatuses", []) + status.get("containerStatuses", [])
        }
        spec = pod.get("spec", {})
        for c in spec.get("initContainers", []) + spec.get("containers", []):
            image_id = statuses.get(c["name"], {}).get("imageID", "")
            if not image_id:
                unresolved.append(f"{ns}/{meta['name']}/{c['name']} ({c['image']}): no imageID yet")
                continue
            ref, digest = parse_image_id(image_id)
            w = Workload(
                namespace=ns,
                pod=meta["name"],
                owner_kind=owner_kind,
                owner_name=owner_name,
                container=c["name"],
                image=c["image"],
                image_id=ref or c["image"],
                digest=digest,
                pod_labels=meta.get("labels", {}),
                pod_annotations=meta.get("annotations", {}),
                ns_labels=ns_labels.get(ns, {}),
                exposure=exposure,
            )
            workloads.setdefault((w.workload_id, w.container, w.digest), w)
    return sorted(workloads.values(), key=lambda w: (w.workload_id, w.container)), unresolved
