from cva.attribution import ORPHAN, owner_of, resolve_owner


def test_pod_label_wins_over_everything():
    assert resolve_owner({"team": "payments"}, {"team": "platform"}, {"owner": "bob"}) == ("payments", "pod-label")


def test_namespace_label_used_when_pod_has_none():
    assert resolve_owner({}, {"team": "platform"}, {"owner": "bob"}) == ("platform", "namespace-label")


def test_annotation_is_last_resort():
    assert resolve_owner({"app": "x"}, {}, {"owner": "reporting"}) == ("reporting", "pod-annotation")


def test_nothing_means_orphan():
    assert resolve_owner({"app": "x"}, {"kubernetes.io/metadata.name": "demo"}, {}) == (ORPHAN, "none")


def test_blank_values_do_not_count_as_owner():
    assert resolve_owner({"team": " "}, {"team": ""}, {"owner": ""}) == (ORPHAN, "none")
    assert resolve_owner({"team": ""}, {"team": "platform"}, {}) == ("platform", "namespace-label")


def test_demo_cluster_owners(inventory):
    owners = {w.owner_name: owner_of(w) for w in inventory}
    assert owners == {
        "payments-api": ("payments", "pod-label"),
        "orders-worker": ("orders", "pod-label"),
        "clean-app": ("platform", "pod-label"),
        "legacy-report": (ORPHAN, "none"),
    }


def test_inventory_resolves_deployments_and_collapses_replicas(inventory):
    payments = [w for w in inventory if w.owner_name == "payments-api"]
    assert len(payments) == 1, "2 replicas share one digest, so they are one workload record"
    assert payments[0].owner_kind == "Deployment"
    assert payments[0].digest.startswith("sha256:")
    assert "@sha256:" in payments[0].image_id


def test_inventory_skips_system_namespaces(inventory):
    assert {w.namespace for w in inventory} == {"demo"}


def test_exposure_from_nodeport_service(inventory):
    exposure = {w.owner_name: w.exposure for w in inventory}
    assert exposure["payments-api"] == ("svc/payments-api:NodePort",)
    assert all(not e for name, e in exposure.items() if name != "payments-api")
