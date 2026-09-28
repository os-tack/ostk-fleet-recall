# Troubleshoot the local HTTPS deployment

Start with the installation variables in [Operating](OPERATING.md#select-the-installation-before-running-commands).
These checks run on the Mac against its existing k0s VM. Preserve the original
state directory and failed helper results. Read summaries/status first; private
logs can contain credentials or content and should not be pasted wholesale.

## Identify the failing layer

```sh
limactl list
kubectl get nodes
kubectl -n fleet-recall get pods
kubectl -n ory get pods
kubectl -n fleet-edge get pods
python3 deploy/local/bin/verify-https.py \
  --ca-path "$FLEET_RECALL_CA_PATH" --kubeconfig "$KUBECONFIG"
```

Then use the matching symptom below. The HTTPS verifier is unauthenticated and
read-only; it deliberately tests refused requests. OAuth/sandbox smoke helpers
create state and exercise writes. Network-policy verification creates retained
probe pods. Use those deeper checks intentionally during acceptance, not as an
unexplained first repair action.

| Symptom | First check and interpretation | Next procedure |
| --- | --- | --- |
| kubectl cannot reach the API | `limactl list`; a stopped VM makes every workload unavailable. Check `KUBECONFIG` points to the original state directory. | Start the existing VM with `limactl start k0s --tty=false`, then use the [startup checks](OPERATING.md#start-after-reboot-or-sleep). Do not create/reset a VM to restart it. |
| Canonical HTTPS names fail on the Mac | Run `python3 deploy/local/bin/install-macos-https-hosts.py` without `--apply` to check the narrow hosts mapping. Confirm edge pods are ready. | Follow [name resolution](../../deploy/local/https/README.md#name-resolution-and-the-mac-boundary). The Mac uses loopback names and a Lima 8443 forward; host mappings alone do not establish that forward. |
| TLS works with explicit CA but fails in Codex desktop | The terminal and an already running GUI app have different launch environments. Check whether the actual harness can call Recall, not just whether curl works. | Reapply the public-root/`CODEX_CA_CERTIFICATE` setup in [startup](OPERATING.md#start-after-reboot-or-sleep), then restart the harness. Never use insecure TLS or distribute a private key. |
| Mac works, Docker sandbox cannot connect | Inspect the retained launch arguments/configuration for the canonical URL, public CA, and `--docker-host-gateway`. | Use the [HTTPS launch example](OPERATING.md#run-and-finish-sandbox-work). Preserve the hostname and audience; route only that hostname through Docker's gateway. |
| Mac works, Kubernetes clients fail resolving the issuer or Recall | `python3 deploy/local/bin/configure-https-dns.py --state "$FLEET_LOCAL_STATE"` prepares/checks the managed CoreDNS block without changing the cluster. | If its prepared change matches the current edge Service and no conflicting unmanaged block exists, rerun with `--apply` and verify from a pod using the [network procedure](../../deploy/local/https/network/README.md). This helper does not repair Mac/Docker DNS. |
| Public `/healthz`, `/readyz`, or `/metrics` returns 404 | Those paths are not exposed by the HTTPS edge. | Use Kubernetes readiness, monitoring, or the [private diagnostic forward](OPERATING.md#check-service-authorization-and-memory-separately). Do not add a public route to make this check pass. |
| `/healthz` succeeds but Recall is unready / gateway returns 503 | Check `kubectl -n fleet-recall get pods`, then private `/readyz`. Liveness is independent of database/schema/grant checks; an unready receiver is withdrawn from service. | Inspect CockroachDB state and bounded runtime readiness events privately. Allow normal cold-start recovery. For schema/grant failures, use [migration policy](../MIGRATIONS.md), not an ad hoc grant or migration replay. |
| Unauthenticated MCP returns 401 | A Bearer challenge pointing to canonical protected-resource metadata is expected. | Follow [Connect an enrolled client](OPERATING.md#connect-an-enrolled-client), including the [Claude preregistration path](OPERATING.md#claude-code-with-the-pinned-hydra) when applicable. The HTTPS verifier checks this expected 401. |
| Login succeeds but tools are refused | Login proves an Ory identity, not enrollment. Use `deploy/local/bin/serve-remote.sh enroll list` privately to check exact subject, `hydra` anchor, revocation, scope and agent pattern. | Have the enrollment operator correct the intended declaration; see [identity responsibilities](OPERATING.md#know-which-identity-you-are-using). Do not widen wildcard enrollment to hide a mismatch. |
| OAuth redirects, audience, or issuer no longer match | Read public discovery through the HTTPS verifier and the client's configured URL. Old HTTP registrations and copied credentials are not HTTPS registrations. | Re-register/re-login using the canonical URL and actual callback. Use the [HTTPS cutover runbook](../../deploy/local/https/README.md#identity-cutover-and-acceptance) if server identity configuration changed. |
| Existing reads work but new login fails, or a restart breaks authentication | Inspect Overview's issuer discovery/JWKS probes and Ory readiness. A warm key cache can work for up to 600 seconds; a cold/expired cache fails closed. | Restore the issuer's canonical trusted route and rerun verification. Refresh attempts have a 60-second cooldown. A healthy core `/readyz` does not prove issuer health. |
| Existing claims are readable but embedding work fails | Inspect Overview/Dependencies and `kubectl -n fleet-recall get deployment embed`. The tokenless embedding probe proves only transport and the authentication guard. | Diagnose authenticated descriptor/inference failures in private runtime events. Lexical fallback is expected during an embedding outage; do not report that as vector-search recovery. |
| Sandbox exits before running the provider | Check retained launch result and Pod/container status. Grant-derived latest-start allowance can expire while a Pod is pending; provider credentials can also be missing/expired. | Restore scheduling/provider access, complete teardown of the old launch, and create a fresh launch. Do not extend or edit a saved grant/deadline. |
| `launch down` reports `cleanup-pending` | Check canonical service access and availability of the original launcher anchor. An exited container does not prove both grants were revoked. | Retry `launch down --state` with the same private state file after recovery. Preserve state and transcript evidence; see [sandbox teardown](../../deploy/local/sandbox/README.md). |
| A shipped transcript is not searchable yet | Check receiver acknowledgement, then `kubectl -n fleet-recall get cronjob worker` and `kubectl -n fleet-recall get jobs`. The normal worker interval is five minutes. | Use Workers to distinguish suspended/stale/failed ticks from completed ingestion and projection. Follow [memory pipelines](../tutorials/MEMORY_PIPELINES.md); do not run overlapping manual workers to force progress. |
| Spool quota/I/O refusals or disk alerts | Inspect Overview's byte/inode capacity and spool refusal counters. The PV's declared size is not an enforced filesystem quota; per-file/per-scope/file-count limits are separate. | Pause new launches and preserve unshipped data. Inspect configured limits and the VM filesystem before planning capacity/retention work. No automatic transcript-pruning procedure is supplied. |
| Grafana's local URL is unreachable | Check the `install-k0s.sh forward` terminal. Port forwarding stops when its terminal/process ends or the selected pod is replaced. | Restart `deploy/observability/install-k0s.sh forward`; independently run remote-profile `verify` before reinstalling anything. |
| Dashboards lack remote lifecycle panels/series | Check monitoring installation profile and the application version. Base-profile updates omit remote rules/scrapes and suspend the dependency probe. | Review with `FLEET_OBSERVABILITY_REMOTE=true deploy/observability/install-k0s.sh render`; apply the same flag with `up` only when updating, then `verify`. See [monitoring](../../deploy/observability/README.md). |
| Alerts appear in Prometheus but nobody is notified | Local rule evaluation is installed; notification delivery is not configured. | Assign dashboard monitoring now. An Alertmanager receiver/route is additional implementation, not a restart fix. |
| A lifecycle helper fails or leaves worker suspended | Inspect its private `result.json`, failure phase and saved worker state. A failed recovery gate intentionally prevents automatic resume. | Restore the named dependency and satisfy the [lifecycle gates](../../deploy/local/https/OPERATIONS.md) before restoring the original suspension state. Do not blindly rerun bootstrap or overwrite the saved checkpoint. |
| A backup is refused as old or from another installation | Compare its manifest age, state path and cluster UID. A convenient nearby directory may be the wrong checkpoint. | Select the intended authenticated checkpoint. The [restore guide](../../deploy/local/https/RECOVERY.md) supports an explicit larger maximum age for disaster recovery, with a larger acknowledged RPO. |
| A restored database passes checks but cannot serve clients | The restore helper deliberately creates a network-disabled isolated copy and revokes unrevoked grants in that copy. | Run the separate restored-application proof. Public promotion requires principal/Ory-session reconciliation and a separate reviewed procedure; opening its network is not a supported promotion path. |

## Preserve useful evidence

Record the source commit/image tag, original state path, cluster UID, helper
result directory, symptom time and affected client/backend. Keep known claim IDs
and expected query terms so recovery can be checked without new writes. The
[local qualification records](../../deploy/local/https/LIFECYCLE_QUALIFICATION.md)
show what each rehearsal actually established.

Do not rotate CA, content, Ory or grant-signing keys to troubleshoot a connection
error. Leaf renewal has its own [verified procedure](../../deploy/local/https/OPERATIONS.md#leaf-renewal);
root/intermediate and application-key rotation require separate ceremonies.
Do not restore an older authorization database to roll back an image.
