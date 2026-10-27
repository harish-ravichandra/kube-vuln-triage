#!/usr/bin/env bash
# End-to-end demo: kind cluster, Kyverno, sample workloads, admission proof,
# then two cva runs (the second must be served entirely from the scan cache).
# Used by .github/workflows/e2e-demo.yaml and runnable locally.
set -euo pipefail
cd "$(dirname "$0")/.."

CLUSTER=${CLUSTER:-cva}
KYVERNO_CHART_VERSION=3.9.1
OUT=${OUT:-reports}
PYTHON=${PYTHON:-python3}
mkdir -p "$OUT"

if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  # kind copies HTTP(S)_PROXY into the node container, where a localhost proxy
  # is the node itself and image pulls would fail. Drop only that case.
  KIND_ENV=()
  case "${HTTPS_PROXY:-${https_proxy:-}}" in
    *127.0.0.1*|*localhost*)
      KIND_ENV=(env -u HTTP_PROXY -u HTTPS_PROXY -u NO_PROXY -u http_proxy -u https_proxy -u no_proxy)
      echo "note: ignoring localhost proxy for the kind node" ;;
  esac
  "${KIND_ENV[@]}" kind create cluster --name "$CLUSTER" --config demo/kind-config.yaml --wait 180s
fi

helm repo add kyverno https://kyverno.github.io/kyverno/ --force-update >/dev/null
helm upgrade --install kyverno kyverno/kyverno -n kyverno --create-namespace \
  --version "$KYVERNO_CHART_VERSION" --wait --timeout 10m
kubectl apply -f policies/
kubectl wait --for=condition=Ready clusterpolicy --all --timeout=180s
kubectl apply -f demo/namespaces.yaml

# Kyverno registers its webhooks asynchronously; wait until a server-side dry
# run of a non-compliant pod is actually rejected before testing admission.
for _ in $(seq 1 60); do
  if ! kubectl apply --dry-run=server -n secure -f demo/bad-pods/01-missing-team-label.yaml >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

echo "== admission proof (Enforce in namespace secure)"
declare -A EXPECTED=(
  [demo/bad-pods/01-missing-team-label.yaml]=require-team-label
  [demo/bad-pods/02-latest-tag.yaml]=disallow-latest-tag
  [demo/bad-pods/03-runs-as-root.yaml]=require-non-root
)
: > "$OUT/admission.txt"
fail=0
for f in $(printf '%s\n' "${!EXPECTED[@]}" | sort); do
  policy=${EXPECTED[$f]}
  echo "\$ kubectl apply -n secure -f $f" >> "$OUT/admission.txt"
  if out=$(kubectl apply -n secure -f "$f" 2>&1); then
    echo "$out" >> "$OUT/admission.txt"
    echo "FAIL: $f was admitted" | tee -a "$OUT/admission.txt"
    kubectl delete -n secure -f "$f" --ignore-not-found >/dev/null
    fail=1
    continue
  fi
  echo "$out" >> "$OUT/admission.txt"
  echo >> "$OUT/admission.txt"
  if grep -q "$policy" <<<"$out"; then
    echo "rejected by $policy: $f"
  else
    echo "FAIL: $f rejected, but not by $policy"
    fail=1
  fi
done
cat "$OUT/admission.txt"
[ "$fail" -eq 0 ] || { echo "admission proof failed"; exit 1; }

echo "== demo workloads (policies in Audit)"
kubectl apply -f demo/workloads.yaml
kubectl -n demo wait --for=condition=Available deploy --all --timeout=600s
kubectl get pods -n demo -o wide

echo "== cva run #1"
$PYTHON -m cva run --out "$OUT" 2>&1 | tee "$OUT/run1.log"
echo "== cva run #2 (expect every digest from cache)"
$PYTHON -m cva run --out "$OUT" 2>&1 | tee "$OUT/run2.log"
$PYTHON - "$OUT/summary.json" <<'EOF'
import json, sys
s = json.load(open(sys.argv[1]))["scan"]
assert s["scanned"] == 0 and s["cache_hits"] == s["unique_digests"] > 0, s
print(f"second run: {s['cache_hits']}/{s['unique_digests']} digests from cache, 0 scanned")
EOF

# Audit-mode results for the demo namespace (background scans can lag a little).
sleep 20
kubectl get policyreports -n demo -o wide > "$OUT/policyreports-demo.txt" 2>&1 || true
cat "$OUT/policyreports-demo.txt"
