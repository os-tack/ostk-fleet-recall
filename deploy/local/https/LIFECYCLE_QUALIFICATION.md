# M4.3 local lifecycle qualification: 2026-09-27

M4.3 is locally qualified on the existing single-Mac Lima/k0s installation.
This does not qualify LAN/VPN access from a second machine, an AWS deployment,
or the 24-hour release soak. Use the
[operations](OPERATIONS.md) and [recovery](RECOVERY.md) runbooks to repeat these
checks against a fresh authenticated checkpoint.

## Installed runtime and preserved authority

Recall uses `ostk-fleet-recall:m4-lifecycle-20260927`, imported with digest
`sha256:6233f5ec7e9d047a338b91f5e61e5ef1cc8cbc4855c5dcda6e3b68ba230e5630`.
It was built before this implementation was committed: its embedded VCS
reference `257df54` identifies the previous baseline, not the changed source.
Embedding, worker and sandbox images remain `m4-20260927b`. The HTTP readiness
change does not require rebuilding those processes.

The reference stack remains CockroachDB 26.2.3, Ory 26.2.0, k0s 1.35.8,
Traefik 3.7.13, cert-manager 1.21.2 and Gateway API 1.6.2. The three canonical
HTTPS URLs, enrolled operator identity, schema 39 and generation-3 writer
authority remain unchanged. Recall remains a single replica with `Recreate`;
the worker retains its original five-minute schedule and `Forbid` policy.
The leaf certificate was renewed; application keys and the CA were preserved.

`/readyz` now reflects a bounded background core-database/capability check;
`/healthz` remains process liveness. Embedding failure permits existing reads
and lexical search, including after a receiver restart. Issuer failure permits
verification with a valid cached key; a cold cache fails closed. These are
separate failure modes, with separate private metrics and alerts.

## Live evidence

Paths are relative to the original private `deploy/local/.state/`. They contain
credentials, SQL diagnostics, manifests and content and must stay outside Git.
Lifecycle and sandbox fault checks ran sequentially with maintenance locks and
worker suspension/draining. Protected keys and transcript bytes were compared around
lifecycle faults; rollback, VM and worker checks also compared the ordered
existing revocation ledger, including its timestamps and actors.

| Check | Result and retained evidence |
| --- | --- |
| Recovery input | `https-backup-20260927T183730-83d3486f/`: authenticated encrypted configuration, keys, spool and native database backup; native backup file validation passed. |
| Deployment | `lifecycle-deploy-20260927T193304-612601eb/`: imported-image checks, previous Deployment retained, readiness probe changed to `/readyz`, authenticated acceptance and preservation passed. |
| Database outage | `lifecycle-db-outage-20260927T193606-a7e1712b/`: private `/readyz` became 503, `/healthz` stayed 200, the same receiver pod stayed alive and Kubernetes withdrew its ready endpoint. Recovery passed without changing keys or spool. |
| Embedding outage | `lifecycle-embed-outage-20260927T193716-f356c37d/`: degraded embedding was reported; old claim reads, lexical hits and core readiness survived both the outage and a Recall restart. Recovery passed. |
| Issuer outage | `lifecycle-issuer-outage-20260927T194416-778bddc5/`: warm-cache verification worked; after a receiver restart the cold cache returned 503 instead of accepting an unverifiable token. Canonical issuer and authenticated reads recovered. |
| Application restarts | `lifecycle-restart-20260927T194554-b2333916/`: sequential Recall, Hydra, Kratos and login UI restarts preserved identity, keys, transcript bytes and authenticated access. |
| Image rollback | `lifecycle-rollback-20260927T194716-72650411/`: the previous image/probe served authenticated reads, then the new image/probe returned. Current authorization data and revoked grants were preserved throughout; no SQL snapshot rollback. |
| VM restart | `lifecycle-vm-restart-20260927T194810-afa7e9d7/`: a real Lima stop/start recovered Recall and Ory automatically, retained CoreDNS's managed block and matched keys, spool bytes and revoked-grant metadata. Cold-boot database retries caused a bounded interruption; this is not HA evidence. |
| Worker exclusion | `lifecycle-worker-exclusion-20260927T195106-252908c1/`: one controller-owned worker Job was held across two scheduled minute boundaries; both attempts produced `JobAlreadyActive` events, with no second active Job/pod. The original template/schedule returned and the held worker finished successfully. |
| Leaf renewal | `https-renewal-20260927T192012-30c2d95c/`: checksum-pinned cmctl 2.6.1 requested renewal; all three names served the same new trusted leaf with a new public key and extended expiry. CA and application keys matched the checkpoint. |
| Isolated restore | `fleet-restore-20260927T194029-41d23092/` and `application-20260927T194110-599abe6f/`: SQL restore took 26.53 seconds; the application proof took 25.66 seconds. Schema/authority, fresh OAuth, pre-backup claim decryption, write/read, scope denial and exactly one pending-turn evidence result after two worker ticks passed. Every container used a network-disabled namespace, no published ports, exact bind mounts and verified SQL TLS. All containers stopped; original recovered artifact hashes matched. |
| Sandbox baseline | `sandbox-smoke/20260927-195535-7940ec43/`: Docker and Kubernetes synthetic status/record/get, shipped transcripts, worker evidence and both revoked-token replays passed. |
| Interrupted restore cleanup | `fleet-restore-20260927T200444-23f8cda2/signal-proof.json`: a real SIGTERM immediately after isolated SQL startup interrupted the rehearsal. A repeated signal during cleanup was ignored; the owned container stopped and the restore correctly remained incomplete. |
| Receiver acknowledgement and replay | `sandbox-smoke/20260927-200338-fc1092d0/`: Docker and Kubernetes each held an incomplete TLS upload across a real receiver replacement. No success acknowledgement was received; the gateway kept the partial body until client timeout/close. Acknowledged prefix and original transcript bytes survived unchanged. Retrying the append committed once; duplicate prefix/append windows returned replayed without growth. Two worker ticks retained the same evidence identity; cleanup stopped both backends, revoked both grants and verified 401 replays. The final HTTPS/runtime verifier passed again after these restarts. |
| Native Codex and fresh OAuth | `codex-lifecycle-acceptance-20260927T195833/`: a fresh Codex CLI process used its native `recall-remote` tools to report Recall/embedding ready and retrieve pre-existing claim 13. `oauth-smoke/20260927-200056-bc6cb30d/`: the existing enrolled subject completed password login, consent, PKCE, CSRF/cookie checks, logout and refresh-token issuance after the VM and Ory restarts. |
| HTTPS and network boundary | `https-m4-lifecycle-final-verification.log`, `https-network-m4-lifecycle-final-verification.log`; retained pod prefix `https-network-proof-195738-3ade0c`: canonical TLS/discovery, protected routes, Origin, private edge and runtime checks passed. Unrelated pods could reach HTTPS but none of eight private backend sockets; allowed controls reached those same ready endpoints before and after. |
| Live monitoring and alert recovery | `observability-m4-lifecycle-final-install.log`: six dashboards, two healthy data sources, 13 checked scrape jobs and log ingestion passed. `lifecycle-embed-outage-20260927T200924-d768358e/`: the sustained embedding outage produced a fresh probe value of zero and a firing `FleetRemoteDependencyUnavailable` alert while lexical service survived. After dependency recovery the probe became one and the alert disappeared; worker scheduling resumed. HTTPS/runtime and full observability verification passed again in the two `*-m4-lifecycle-post-alert-verification.log` files. |

The observability installer and full live verifier passed after the bounded
probe retry fix. Its credential-free embedding probe establishes transport and
authentication-guard reachability; authenticated descriptor/inference behavior
is covered separately by Recall status and sandbox worker checks.

A final encrypted checkpoint, `https-backup-20260927T200826-3d2febed/`, captures
the installed runtime/probe configuration, renewed leaf and post-rehearsal
grant state. Native backup file validation passed. The full restore evidence
above uses the earlier checkpoint; this newer checkpoint has not itself been
through the complete restore exercise.

## Failures found and resolved during rehearsal

The first database-fault run was interrupted by a harness restart. A separate
recovery procedure verified restored dependencies, preserved state and worker
resumption; the complete database rehearsal then passed. The interrupted run
remains evidence of recovery, not a passing fault test.

An issuer rehearsal initially checked the edge before its replacement backend
was routable. The helper now waits within a fixed deadline for its expected
response; its Ory selector also excludes Hydra's maester controller. The full
issuer rehearsal passed after these fixes. Manual renewal similarly encountered
a brief mix of old/new leaves during hot reload; its bounded verifier now waits
for all names to agree, and the repeat passed.

The first interrupted-upload attempt received 415 before injecting its fault:
the helper omitted the required binary content type. Cleanup stopped the
sandbox, revoked both grants and restored the worker. The corrected helper's
rerun is recorded separately; the failed attempt is retained at
`sandbox-smoke/20260927-195626-272a249d/`.

The first observability verification also found intermittent embedding probe
failures. Five fresh diagnostic pods reproduced immediate connection refusal
in three pods, with all three recovering on the request one second later;
`probe-fresh-pod-diagnostics-20260927T200407/` retains the observations. This is
consistent with initial pod routing/policy convergence, not an established
embedding-service outage. The fixed probe retries refused/reset/aborted
connections inside one eight-second total deadline. TLS, status and schema
failures remain immediately visible; persistent refusal still produces failure.

## Automated checks and scope

The locked Rust 1.94 standard suite, strict all-target Clippy and formatting
passed. Library tests reported 2,320 passed and 18 ignored; binary tests
reported 38 passed. The full suite also passed its integration harnesses;
database-gated test bodies had no test database configured, so this is not new
live migration-test evidence. The local fault and isolated restore exercises
above supply separate live database evidence.

Python checks passed: 72 HTTPS/lifecycle/recovery tests, 19 sandbox tests,
20 network tests, 12 gateway tests, six Ory tests, five preflight tests and
nine dependency-probe tests. Prometheus validation passed 27 rule scenarios
with 82 alert assertions, both base/remote configurations, and 166 expressions
covering all six dashboards. These rule tests exercise failure and recovery;
they are separate from live alert delivery, for which no receiver is configured.

The required UBS staged scan ran and was reviewed independently. It reported
30 critical, 1,237 warning and 961 informational heuristic matches, with a
partial Rust scan because its staged shadow omitted unchanged modules/path
dependencies. Findings included test-only panics and fixtures, nonsecret
integrity comparisons, a header encoding mistaken for a JWT, shadow-workspace
compiler failures and existing dependency exceptions. No remaining material
introduced finding was identified. This is not an aggregate-clean scanner
result. Real-worktree tests/Clippy supplied compiler coverage; `Cargo.lock`
did not change. See [existing dependency exceptions](../../../docs/SECURITY.md).
Private scanner evidence is `ubs-m4-lifecycle.log`.
The final Python-only staged rerun after the upload/probe fixes reported five
critical, 108 warning and 480 informational matches; its five critical findings
were the same fixture and offline integrity comparisons already reviewed.
That report is `ubs-m4-lifecycle-python-final.log`.

## Remaining qualification

Second-machine LAN/VPN acceptance is explicitly deferred until hardware is
available. M4.4's AWS rollout/storage gates and M4.5's monitored 24-hour soak
remain pending. The local profile has no HA, Mac autostart or sleep availability
guarantee. Alert rules and private dashboards do not establish an operational
notification channel; no Alertmanager receiver is configured here.

The restore exercises fit the four-hour pilot target with locally available
inputs. They do not establish off-device retrieval time or a consistent
24-hour RPO: current backups capture SQL and spool sequentially. Quiesce the
writer/receiver/worker for that recovery-point qualification, retain encrypted
copies and the recovery key separately off the Mac, and reconcile current
principal/Ory revocations before any restored environment is exposed. Root,
intermediate and application signing-key rotation remain separate ceremonies.
