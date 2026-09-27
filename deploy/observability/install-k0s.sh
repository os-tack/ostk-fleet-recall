#!/usr/bin/env bash
# Install/update the isolated local k0s observability namespace.
# Usage: KUBECONFIG=/path/to/k0s/kubeconfig ./install-k0s.sh [render|up|verify|forward]
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
namespace=fleet-observability
command=${1:-render}
for tool in kubectl python3; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done

# A worktree may not contain the other agent's local deployment state. The
# explicit kubeconfig prevents accidentally installing into a default cluster.
if [ "$command" != render ]; then
  : "${KUBECONFIG:?Set KUBECONFIG to deploy/local/.state/kubeconfig for the local k0s cluster}"
  kubectl --request-timeout=10s get nodes -o json | python3 -c '
import json,sys
nodes=json.load(sys.stdin)["items"]
if len(nodes)!=1 or "k0s" not in nodes[0]["status"]["nodeInfo"]["kubeletVersion"]:
    sys.exit("This hostPath stack requires exactly one local k0s node; inspect the kubeconfig.")
'
fi
render() {
  kubectl kustomize "$here/k0s" --load-restrictor LoadRestrictionsNone
  printf '\n---\n'
  kubectl -n "$namespace" create configmap fleet-prometheus-rules \
    --from-file=alerts.yml="$here/alerts.yml" \
    --from-file=k0s-alerts.yml="$here/k0s-alerts.yml" --dry-run=client -o yaml
  printf '\n---\n'
  kubectl -n "$namespace" create configmap fleet-grafana-dashboards \
    --from-file="$here/grafana/dashboards" --dry-run=client -o yaml
  printf '\n---\n'
  kubectl -n "$namespace" create configmap fleet-grafana-provisioning \
    --from-file=datasources.yaml="$here/grafana/provisioning/datasources/fleet.yaml" \
    --from-file=dashboards.yaml="$here/grafana/provisioning/dashboards/fleet.yaml" \
    --dry-run=client -o yaml
}
verify() {
  for resource in deployment/grafana deployment/prometheus deployment/loki deployment/alloy deployment/kube-state-metrics daemonset/node-exporter; do
    kubectl -n "$namespace" rollout status "$resource" --timeout=300s
  done
  kubectl -n "$namespace" get pods,services
  python3 "$here/verify_k0s.py"
  echo 'Open Grafana with: install-k0s.sh forward'
}
case "$command" in
  render) render ;;
  up)
    kubectl apply --server-side --field-manager=fleet-observability -f "$here/k0s/namespace.yaml"
    if ! kubectl -n "$namespace" get secret fleet-grafana-admin >/dev/null 2>&1; then
      # Keep the generated credential out of argv, logs, and checked-in files.
      python3 -c 'import base64,json,secrets; print(json.dumps({"apiVersion":"v1","kind":"Secret","metadata":{"name":"fleet-grafana-admin","namespace":"fleet-observability"},"type":"Opaque","data":{"user":base64.b64encode(b"admin").decode(),"password":base64.b64encode(secrets.token_urlsafe(32).encode()).decode()}}))' | kubectl apply -f -
    fi
    # Dashboard JSON exceeds the client-side last-applied annotation limit.
    render | kubectl apply --server-side --field-manager=fleet-observability -f -
    # Rules and datasource provisioning are loaded at startup. Roll only when
    # their contents change; dashboard JSON itself is refreshed by Grafana.
    for component in prometheus grafana; do
      digest=$(python3 - "$here" "$component" <<'PY'
import hashlib,pathlib,sys
root=pathlib.Path(sys.argv[1])
paths=[root/'alerts.yml',root/'k0s-alerts.yml'] if sys.argv[2]=='prometheus' else sorted((root/'grafana/provisioning').glob('*/*.yaml'))
print(hashlib.sha256(b'\0'.join(p.read_bytes() for p in paths)).hexdigest())
PY
)
      kubectl -n "$namespace" patch deployment "$component" --type=merge \
        -p "{\"spec\":{\"template\":{\"metadata\":{\"annotations\":{\"fleet-recall.dev/provisioning-digest\":\"$digest\"}}}}}"
    done
    verify
    ;;
  verify) verify ;;
  forward)
    echo 'Grafana: http://127.0.0.1:3000 (admin; credential in secret fleet-grafana-admin)' >&2
    exec kubectl -n "$namespace" port-forward --address 127.0.0.1 service/grafana 3000:3000
    ;;
  *) echo 'usage: install-k0s.sh [render|up|verify|forward]' >&2; exit 2 ;;
esac
