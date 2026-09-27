#!/usr/bin/env bash
# Local production-shaped Fleet Recall environment: Lima -> k0s -> CockroachDB
# (secure), migrate + boundary Jobs, the recall workloads, Ory Hydra + Kratos,
# and LocalStack. See deploy/local/README.md.
#
#   deploy/local/bootstrap.sh up                # every phase, in order
#   deploy/local/bootstrap.sh phase <name>      # one phase
#   deploy/local/bootstrap.sh verify            # the checklist
#   deploy/local/bootstrap.sh down              # stop the VM, keep state
#   deploy/local/bootstrap.sh reset --db|--all  # asks before deleting
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../.." && pwd)
state="$here/.state"
# shellcheck source=lib.sh
. "$here/lib.sh"

VM=${FLEET_LOCAL_VM:-k0s}
NS=fleet-recall
ORY_NS=ory
LOCALSTACK_NS=localstack
K0S_VERSION=${K0S_VERSION:-v1.35.8+k0s.1}
CRDB_IMAGE=cockroachdb/cockroach:v26.2.3
ORY_CHART_VERSION=${ORY_CHART_VERSION:-0.64.0}
LOCALSTACK_CHART_VERSION=${LOCALSTACK_CHART_VERSION:-0.7.1}
MODEL_BUNDLE_DIR=${FLEET_RECALL_MODEL_BUNDLE:-$repo/.models/potion-retrieval-32M-6fc8051fab2a1e0ee76689cf08c853792ac285e7}
TENANT_ID=0198a849-f6ae-7d61-9800-000000000001
PROJECT=local-k0s
CRDB_HOST=cockroach.fleet-recall.svc.cluster.local:26257
export KUBECONFIG="$state/kubeconfig"

PHASES=(preflight vm images certs secrets cockroach migrate authority boundary ory localstack recall verify)

usage() {
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
    printf '\nphases: %s\n' "${PHASES[*]}"
    printf 'optional phases: observability (Prometheus, Grafana, Loki, Alloy)\n'
}

image_tag() { cat "$state/image.tag"; }
model_sha() { cat "$state/model.sha256"; }

# Render the kustomize overlay once, substituting the values only the script
# knows, and apply the resources of one phase by label.
render() {
    kubectl kustomize "$here/kustomize/overlays/dev" --load-restrictor LoadRestrictionsNone \
        | sed -e "s#__IMAGE_TAG__#$(image_tag)#g" \
              -e "s#__MODEL_BUNDLE_DIR__#$MODEL_BUNDLE_DIR#g" \
              -e "s#__MODEL_SHA256__#$(model_sha)#g" \
        > "$state/rendered.yaml"
}

apply_phase() {
    render
    kubectl apply -f "$state/rendered.yaml" -l "fleet-recall.dev/phase=$1" >/dev/null
}

run_job() {
    local name=$1
    kubectl -n "$NS" delete job "$name" --ignore-not-found --wait=true >/dev/null
    apply_phase "$name"
    log "waiting for job $name"
    wait_job "$NS" "$name" "${2:-600}"
}

wait_cluster_network() {
    local resource deadline
    log "waiting for cluster networking and DNS"
    for resource in deployment/coredns daemonset/kube-router daemonset/kube-proxy; do
        deadline=$((SECONDS + 300))
        until kubectl --request-timeout=10s -n kube-system get "$resource" >/dev/null 2>&1; do
            [ "$SECONDS" -lt "$deadline" ] || die "$resource did not appear in kube-system"
            sleep 3
        done
        kubectl -n kube-system rollout status "$resource" --timeout=300s >/dev/null \
            || die "$resource did not become ready"
    done
}

wait_cockroach_ready() {
    local deadline
    kubectl --request-timeout=10s -n "$NS" get statefulset/cockroach >/dev/null 2>&1 \
        || die "CockroachDB is not deployed; run bootstrap.sh phase cockroach first"
    log "waiting for CockroachDB through cluster DNS and verified TLS"
    kubectl -n "$NS" rollout status statefulset/cockroach --timeout=300s >/dev/null \
        || die "CockroachDB did not become ready"
    deadline=$((SECONDS + 300))
    until kubectl --request-timeout=10s -n "$NS" exec cockroach-0 -- \
        curl --connect-timeout 3 --max-time 5 --fail --silent \
        --cacert /cockroach/certs/ca.crt \
        "https://${CRDB_HOST%:*}:8080/health?ready=1" >/dev/null 2>&1; do
        [ "$SECONDS" -lt "$deadline" ] \
            || die "CockroachDB service did not answer its readiness probe through cluster DNS"
        sleep 3
    done
}

phase_preflight() {
    need limactl docker kubectl helm jq openssl cargo curl git
    docker info >/dev/null 2>&1 || die "docker is not running"
    for name in config.json model.safetensors tokenizer.json; do
        [ -f "$MODEL_BUNDLE_DIR/$name" ] || die "model bundle file missing: $MODEL_BUNDLE_DIR/$name"
        [ ! -L "$MODEL_BUNDLE_DIR/$name" ] || die "model bundle file is a symlink: $name"
    done
    if [ "${FLEET_LOCAL_SKIP_LOCALSTACK:-0}" != 1 ]; then
        resolve_localstack_token "$repo" >/dev/null
    fi
    mkdir -p "$state/certs" "$state/images"
    chmod 700 "$state"
    log "preflight ok (bundle $MODEL_BUNDLE_DIR)"
}

phase_vm() {
    if ! limactl list --json 2>/dev/null | jq -e --arg n "$VM" 'select(.name == $n)' >/dev/null; then
        log "creating Lima VM $VM"
        K0S_VERSION="$K0S_VERSION" limactl start --name "$VM" --tty=false "$here/lima/k0s.yaml"
    else
        limactl start "$VM" >/dev/null 2>&1 || true
    fi
    log "waiting for k0s"
    local waited=0
    until limactl shell "$VM" sudo k0s status >/dev/null 2>&1; do
        sleep 5
        waited=$((waited + 5))
        [ "$waited" -lt 600 ] || die "k0s did not start"
    done
    limactl shell "$VM" sudo k0s kubeconfig admin \
        | sed -E 's#server: https://[^:]+:6443#server: https://127.0.0.1:6443#' > "$state/kubeconfig"
    chmod 600 "$state/kubeconfig"
    log "waiting for the node to register"
    waited=0
    until [ "$(kubectl get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ')" -ge 1 ]; do
        sleep 5
        waited=$((waited + 5))
        [ "$waited" -lt 600 ] || die "no node registered with the API server"
    done
    kubectl wait --for=condition=Ready node --all --timeout=300s >/dev/null
    wait_cluster_network
    if kubectl --request-timeout=10s -n "$NS" get statefulset/cockroach >/dev/null 2>&1; then
        wait_cockroach_ready
    fi
    log "cluster ready: $(kubectl get nodes --no-headers | awk '{print $1, $2, $5}')"
}

phase_images() {
    local sha tag
    sha=$(git -C "$repo" rev-parse --short=12 HEAD)
    tag="local-$sha"
    log "building ostk-fleet-recall:$tag (linux/arm64)"
    docker buildx build --platform linux/arm64 --target production \
        --build-arg "VCS_REF=$(git -C "$repo" rev-parse HEAD)" \
        -t "ostk-fleet-recall:$tag" --load "$repo"
    docker save -o "$state/images/ostk-fleet-recall.tar" "ostk-fleet-recall:$tag"
    limactl shell "$VM" sudo k0s ctr images import "$state/images/ostk-fleet-recall.tar" >/dev/null
    docker run --rm --user "$(id -u)" -v "$MODEL_BUNDLE_DIR:/model:ro" \
        --entrypoint /usr/local/bin/ostk-fleet-recall "ostk-fleet-recall:$tag" model-digest /model \
        > "$state/model.sha256"
    printf '%s\n' "$tag" > "$state/image.tag"
    log "image $tag imported; model digest $(model_sha)"
}

phase_certs() {
    apply_phase namespaces
    if [ ! -f "$state/certs/ca.crt" ]; then
        log "generating CockroachDB certificates"
        docker run --rm -v "$state/certs:/certs" "$CRDB_IMAGE" \
            cert create-ca --certs-dir=/certs --ca-key=/certs/ca.key
        docker run --rm -v "$state/certs:/certs" "$CRDB_IMAGE" \
            cert create-node localhost 127.0.0.1 cockroach cockroach.fleet-recall \
            cockroach.fleet-recall.svc cockroach.fleet-recall.svc.cluster.local \
            cockroach-0.cockroach.fleet-recall.svc.cluster.local \
            cockroach-public.fleet-recall.svc.cluster.local \
            --certs-dir=/certs --ca-key=/certs/ca.key
        docker run --rm -v "$state/certs:/certs" "$CRDB_IMAGE" \
            cert create-client root --certs-dir=/certs --ca-key=/certs/ca.key
        chmod 600 "$state"/certs/*.key
    fi
    kube_upsert create secret generic crdb-node-certs -n "$NS" \
        --from-file=ca.crt="$state/certs/ca.crt" \
        --from-file=node.crt="$state/certs/node.crt" \
        --from-file=node.key="$state/certs/node.key"
    kube_upsert create secret generic crdb-root-client -n "$NS" \
        --from-file=ca.crt="$state/certs/ca.crt" \
        --from-file=client.root.crt="$state/certs/client.root.crt" \
        --from-file=client.root.key="$state/certs/client.root.key"
    for ns in "$NS" "$ORY_NS"; do
        kube_upsert create secret generic crdb-ca -n "$ns" --from-file=ca.crt="$state/certs/ca.crt"
    done
    log "certificates in place"
}

phase_secrets() {
    local f="$state/passwords.env"
    if [ ! -f "$f" ]; then
        log "generating passwords and secrets"
        umask 077
        {
            for k in MIGRATOR WRITER PUBLICATION INGRESS HYDRA_DB KRATOS_DB; do
                printf '%s_PASSWORD=%s\n' "$k" "$(random_hex 24)"
            done
            printf 'HYDRA_SYSTEM_SECRET=%s\n' "$(random_hex 32)"
            printf 'HYDRA_COOKIE_SECRET=%s\n' "$(random_hex 32)"
            printf 'KRATOS_DEFAULT_SECRET=%s\n' "$(random_hex 32)"
            printf 'KRATOS_COOKIE_SECRET=%s\n' "$(random_hex 32)"
            printf 'KRATOS_CIPHER_SECRET=%s\n' "$(random_hex 16)"
            printf 'SLACK_SIGNING_SECRET=%s\n' "$(random_hex 24)"
            printf 'CONTENT_KEK_HEX=%s\n' "$(random_hex 32)"
        } > "$f"
        umask 022
    fi
    local ca=/etc/crdb/ca.crt
    local url_tail="fleet_recall?sslmode=verify-full&sslrootcert=$ca"
    kube_upsert create secret generic crdb-passwords -n "$NS" \
        --from-literal=MIGRATOR_PASSWORD="$(env_value "$f" MIGRATOR_PASSWORD)" \
        --from-literal=WRITER_PASSWORD="$(env_value "$f" WRITER_PASSWORD)" \
        --from-literal=PUBLICATION_PASSWORD="$(env_value "$f" PUBLICATION_PASSWORD)" \
        --from-literal=INGRESS_PASSWORD="$(env_value "$f" INGRESS_PASSWORD)" \
        --from-literal=HYDRA_DB_PASSWORD="$(env_value "$f" HYDRA_DB_PASSWORD)" \
        --from-literal=KRATOS_DB_PASSWORD="$(env_value "$f" KRATOS_DB_PASSWORD)"
    kube_upsert create secret generic db-url-migrator -n "$NS" \
        --from-literal=FLEET_RECALL_DATABASE_URL="postgresql://fleet_migrator:$(env_value "$f" MIGRATOR_PASSWORD)@$CRDB_HOST/$url_tail"
    kube_upsert create secret generic db-url-writer -n "$NS" \
        --from-literal=FLEET_RECALL_DATABASE_URL="postgresql://fleet_writer:$(env_value "$f" WRITER_PASSWORD)@$CRDB_HOST/$url_tail"
    kube_upsert create secret generic db-url-publication -n "$NS" \
        --from-literal=FLEET_RECALL_PUBLICATION_DATABASE_URL="postgresql://fleet_publication:$(env_value "$f" PUBLICATION_PASSWORD)@$CRDB_HOST/$url_tail"
    kube_upsert create secret generic db-url-ingress -n "$NS" \
        --from-literal=FLEET_RECALL_INGRESS_DATABASE_URL="postgresql://fleet_ingress:$(env_value "$f" INGRESS_PASSWORD)@$CRDB_HOST/$url_tail"
    kube_upsert create secret generic fleet-content-kek -n "$NS" \
        --from-literal=FLEET_RECALL_CONTENT_KEK_HEX="$(env_value "$f" CONTENT_KEK_HEX)"
    kube_upsert create secret generic ingress-slack -n "$NS" \
        --from-literal=FLEET_RECALL_SLACK_SIGNING_SECRET="$(env_value "$f" SLACK_SIGNING_SECRET)"
    kube_upsert create secret generic hydra-secrets -n "$ORY_NS" \
        --from-literal=dsn="cockroach://hydra:$(env_value "$f" HYDRA_DB_PASSWORD)@$CRDB_HOST/hydra?sslmode=verify-full&sslrootcert=$ca" \
        --from-literal=secretsSystem="$(env_value "$f" HYDRA_SYSTEM_SECRET)" \
        --from-literal=secretsCookie="$(env_value "$f" HYDRA_COOKIE_SECRET)"
    kube_upsert create secret generic kratos-secrets -n "$ORY_NS" \
        --from-literal=dsn="cockroach://kratos:$(env_value "$f" KRATOS_DB_PASSWORD)@$CRDB_HOST/kratos?sslmode=verify-full&sslrootcert=$ca" \
        --from-literal=secretsDefault="$(env_value "$f" KRATOS_DEFAULT_SECRET)" \
        --from-literal=secretsCookie="$(env_value "$f" KRATOS_COOKIE_SECRET)" \
        --from-literal=secretsCipher="$(env_value "$f" KRATOS_CIPHER_SECRET)" \
        --from-literal=smtpConnectionURI="smtps://unused:unused@mail.invalid:1025/?skip_ssl_verify=true"
    apply_phase config
    log "secrets and shared configuration applied"
}

phase_cockroach() {
    apply_phase cockroach
    kubectl -n "$NS" rollout status statefulset/cockroach --timeout=300s >/dev/null
    run_job db-bootstrap 300
    log "CockroachDB is up and bootstrapped"
}

phase_migrate() {
    run_job migrate 900
    log "migrations applied"
}

# The ceremony binaries are deliberately absent from the image, so the writer
# authority is installed from the Mac against the forwarded SQL port while the
# migrator can still log in (the boundary retires it).
authority_report_valid() {
    jq -e -s '
        length == 1 and (.[0] |
            .generation >= 3 and (.generation | type == "number" and floor == .) and
            .package == "collected_items_generation3" and
            (.activation_id | type == "string" and test("^[0-9a-f]{64}$")) and
            (.pins | type == "object" and length == 3) and
            .pins.FLEET_RECALL_CONTRACT_TENANT_NAMESPACE == "tenant.local" and
            .pins.FLEET_RECALL_CONTRACT_PROJECT_NAMESPACE == "project.local" and
            (.pins.FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST |
                type == "string" and test("^[0-9a-f]{64}$"))
        )
    ' "$1" >/dev/null 2>&1
}

phase_authority() {
    local f="$state/passwords.env" report="$state/authority.json" output archive
    if [ -f "$report" ] && authority_report_valid "$report"; then
        log "authority already installed ($report)"
    else
        if [ -e "$report" ]; then
            mkdir -p "$state/archive"
            archive=$(mktemp -d "$state/archive/authority.XXXXXX")
            mv "$report" "$archive/authority.json"
            warn "invalid authority report preserved at $archive/authority.json"
        fi
        log "installing writer authority (generation 3) from the Mac"
        (cd "$repo" && cargo build --locked --bin ostk-authority-install)
        output=$(mktemp "$state/authority.json.XXXXXX")
        if ! env -i PATH="$PATH" HOME="$HOME" \
            FLEET_RECALL_DATABASE_URL="postgresql://fleet_migrator:$(env_value "$f" MIGRATOR_PASSWORD)@127.0.0.1:26258/fleet_recall?sslmode=verify-full&sslrootcert=$state/certs/ca.crt" \
            FLEET_RECALL_TENANT_ID="$TENANT_ID" \
            FLEET_RECALL_PROJECT="$PROJECT" \
            FLEET_RECALL_AGENT=authority-install \
            FLEET_RECALL_MAX_CONNECTIONS=4 \
            FLEET_RECALL_EMBEDDING_MODEL=minishlab/potion-retrieval-32M \
            FLEET_RECALL_EMBEDDING_MODEL_PATH="$MODEL_BUNDLE_DIR" \
            FLEET_RECALL_EMBEDDING_MODEL_SHA256="$(model_sha)" \
            FLEET_RECALL_CONTRACT_TENANT_NAMESPACE=tenant.local \
            FLEET_RECALL_CONTRACT_PROJECT_NAMESPACE=project.local \
            RUST_LOG=ostk_fleet_recall=info \
            "$repo/target/debug/ostk-authority-install" apply --target generation-3 \
            > "$output"; then
            die "authority installation failed; partial report preserved at $output"
        fi
        authority_report_valid "$output" || die "invalid authority report preserved at $output"
        mv "$output" "$report"
    fi
    local pins
    pins=$(jq -r '.pins | to_entries[] | "--from-literal=\(.key)=\(.value)"' "$state/authority.json")
    # shellcheck disable=SC2086
    kube_upsert create secret generic fleet-pins -n "$NS" $pins
    log "writer-authority pins stored in secret fleet-pins"
}

phase_boundary() {
    wait_cluster_network
    wait_cockroach_ready
    run_job boundary 600
    log "database boundary applied"
}

phase_ory() {
    run_job ory-db-bootstrap 300
    helm repo add ory https://k8s.ory.com/helm/charts >/dev/null 2>&1 || true
    helm repo update ory >/dev/null
    log "installing Ory Hydra, Kratos, and the self-service UI (chart $ORY_CHART_VERSION)"
    helm upgrade --install hydra ory/hydra -n "$ORY_NS" --version "$ORY_CHART_VERSION" \
        -f "$here/helm/hydra-values.yaml" --wait --timeout 15m
    helm upgrade --install kratos ory/kratos -n "$ORY_NS" --version "$ORY_CHART_VERSION" \
        -f "$here/helm/kratos-values.yaml" --wait --timeout 15m
    helm upgrade --install kratos-ui ory/kratos-selfservice-ui-node -n "$ORY_NS" --version "$ORY_CHART_VERSION" \
        -f "$here/helm/kratos-ui-values.yaml" --wait --timeout 10m
    apply_phase ory-nodeports
    log "Ory is up"
}

phase_localstack() {
    if [ "${FLEET_LOCAL_SKIP_LOCALSTACK:-0}" = 1 ]; then
        log "skipping LocalStack; S3 download and AWS STS validation are deferred"
        return 0
    fi
    local token override="$state/localstack-override.yaml"
    token=$(resolve_localstack_token "$repo")
    umask 077
    cat > "$override" <<YAML
extraEnvVars:
  - name: SERVICES
    value: "s3,sts,iam,secretsmanager"
  - name: PERSISTENCE
    value: "0"
  - name: LOCALSTACK_AUTH_TOKEN
    value: "$token"
volumes:
  - name: seed-model
    hostPath:
      path: "$MODEL_BUNDLE_DIR"
      type: Directory
volumeMounts:
  - name: seed-model
    mountPath: /seed-model
    readOnly: true
YAML
    umask 022
    helm repo add localstack https://localstack.github.io/helm-charts >/dev/null 2>&1 || true
    helm repo update localstack >/dev/null
    log "installing LocalStack (chart $LOCALSTACK_CHART_VERSION)"
    helm upgrade --install localstack localstack/localstack -n "$LOCALSTACK_NS" \
        --version "$LOCALSTACK_CHART_VERSION" -f "$here/helm/localstack-values.yaml" -f "$override" \
        --wait --timeout 10m
    log "LocalStack is up"
}

phase_recall() {
    run_job seed 600
    apply_phase recall
    for d in writer demo ingress; do
        kubectl -n "$NS" rollout status "deployment/$d" --timeout=300s >/dev/null
    done
    log "recall workloads are up"
}

phase_verify() {
    "$here/bin/verify.sh"
}

phase_observability() {
    "$repo/deploy/observability/install-k0s.sh" up
}

cmd_up() {
    for p in "${PHASES[@]}"; do
        log "phase $p"
        "phase_$p"
    done
}

cmd_down() {
    limactl stop "$VM"
}

cmd_reset() {
    case "${1:-}" in
        --db)
            printf 'This deletes the fleet-recall, ory and localstack namespaces and wipes the\nCockroachDB data directory inside the VM. Type "reset-db" to continue: '
            read -r answer
            [ "$answer" = "reset-db" ] || die "aborted"
            kubectl delete namespace "$NS" "$ORY_NS" "$LOCALSTACK_NS" --ignore-not-found --wait=true
            limactl shell "$VM" sudo sh -c 'rm -rf /var/lib/fleet-recall/crdb/* /var/lib/fleet-recall/spool/*'
            local stamp
            stamp=$(date +%Y%m%d%H%M%S)
            mkdir -p "$state/archive/$stamp"
            for f in passwords.env authority.json; do
                [ -f "$state/$f" ] && mv "$state/$f" "$state/archive/$stamp/$f"
            done
            log "reset done; rerun: bootstrap.sh up"
            ;;
        --all)
            printf 'This deletes the Lima VM "%s" (cluster, images, data) and the local state. Type "reset-all" to continue: ' "$VM"
            read -r answer
            [ "$answer" = "reset-all" ] || die "aborted"
            limactl delete -f "$VM" || true
            rm -rf "$state"
            log "VM and state removed"
            ;;
        *) die "reset needs --db or --all" ;;
    esac
}

main() {
    case "${1:-}" in
        up) cmd_up ;;
        phase)
            [ -n "${2:-}" ] || die "phase name required"
            "phase_$2"
            ;;
        verify) phase_verify ;;
        down) cmd_down ;;
        reset) shift; cmd_reset "$@" ;;
        -h|--help|help|'') usage ;;
        *) die "unknown command: $1" ;;
    esac
}

main "$@"
