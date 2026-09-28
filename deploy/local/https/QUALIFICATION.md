# M4.2 qualification: 2026-09-27

The single-Mac service, CLI and container paths are deployed and tested.
macOS certificate trust and the restarted Codex harness are now verified.
The second-machine LAN/VPN journey is deferred because the user has no second
machine available as of 2026-09-27. It remains unqualified. This is not completion
of all M4.2 acceptance criteria or a cloud deployment.

## Installed profile

- Recall: `https://recall.fleet.test:8443/mcp`.
- Human issuer: `https://auth.fleet.test:8443/`; browser UI/API:
  `https://login.fleet.test:8443`.
- Mac names resolve to loopback; Lima forwards only loopback `8443` to
  NodePort `30443`. Docker uses its explicit host-gateway mapping; k0s uses
  split DNS pointing to the gateway Service.
- Gateway API v1.6.2, Traefik chart 41.6.0 / app v3.7.13, cert-manager v1.21.2;
  installer verifies pinned download checksums. Ory charts 0.64.0 use the
  existing v26.2.0 application images and existing databases/Secrets.
- Matching service/sandbox images: `m4-20260927b`, built from this implementation
  before its commit. Their embedded VCS reference is the M4.1 baseline
  `919cbf7`; it does not identify the uncommitted M4.2 source by itself.
- Image import digests: Recall
  `sha256:a903372c28aa4c9e7fcaf0d2dfdcad1750a09e41897bdbfc6802b724b4479866`;
  sandbox `sha256:d1b46bd5563b021f342e09dd8c899e2ecdbe254967c1dd4688e3b62c431b174a`.
- No migration, production principal re-enrollment or key rotation. Six
  protected Secret fingerprints matched the authenticated encrypted checkpoint
  before and after cutover. The worker resumed its original unsuspended schedule.

## Live evidence

All paths below are relative to the original private `deploy/local/.state/`.
Credentials, account files, response bodies, recovery keys and logs remain
outside version control. Do not publish those directories.

| Check | Result and retained evidence |
| --- | --- |
| Encrypted recovery inputs | Native database backup with file validation, encrypted off-VM copy, configuration/keys/spool archives; `https-backup-20260927T163652-09fa210c/`. A restore rehearsal and off-device copy remain separate work. |
| Isolated Ory preflight | Canonical registration/login/consent/PKCE, Secure/HttpOnly/host-only/Lax cookies and explicit CSRF rejection; `oauth-smoke/20260927-163630-8493ae44/`. |
| Production identity continuity | Existing enrolled subject and principal retained; fresh OAuth accepted; an unexpired old-issuer token rejected with 401. Kratos browser logout redirects to canonical login and makes whoami return 401; separately issued OAuth token still works. `oauth-smoke/20260927-164347-e1aa2f33/`. |
| Native Codex CLI | CLI 0.157.1 discovers both tools, performs status/record/get and succeeds again after a dedicated 90-second access token's expiry plus the server's 60-second leeway. Only that new client's lifespans were shortened, then restored. `codex-https-20260927T164525/`. |
| Docker and Kubernetes | Synthetic shim calls, separate grants, transcript shipping, scoped worker ingestion/embedding, recalled evidence and both revoked-token replays returning 401; `sandbox-smoke/20260927-164325-fa612fc8/`. Kubernetes uses its projected launcher identity; Docker uses the enrolled local key. |
| Real Codex sandbox | Native status/record/get, 80,633 transcript bytes matching durable receiver storage, worker ingestion, session evidence/source provenance, stopped containers and both grants rejected after revocation; `codex-sandbox-smoke/20260927-164644-https-99742d823a23/`. |
| TLS boundaries | Successful CA validation from Mac, Docker and k0s. Empty trust store rejected the chain; an unknown SNI name was rejected. `https-tls-negative-20260927T163738.json` records the negative cases. |
| Network isolation | Retained Pods with prefix `https-network-proof-164647-dacf66`: unrelated pod reaches HTTPS but cannot reach any of eight private service sockets. Allowed controls reach the exact ready backend IP/port pairs before and after the denials; endpoint snapshots remain unchanged. Controls remain unready and tokenless. |
| Gateway authority | Current Gateway/listener/routes report Accepted/Programmed/ResolvedRefs as applicable. Gateway SA cannot get/list/watch Secrets in Ory, Recall or PKI namespaces, including standard SA groups. Certificate issuance outside `fleet-edge` is denied by admission. Root private key stays outside the cluster. |
| Worker and telemetry | Original worker schedule restored; subsequent scheduled Jobs completed. All 14 existing Prometheus scrape targets report up after cutover; `https-cutover-20260927T164127-a21e0d47/prometheus-targets.json`. |
| Trust installation and harness restart | User confirmed both actions. macOS `security verify-cert` accepted the installed Fleet root; system curl reached the HTTPS login route with its expected 303 response and no CA override or verification bypass. The restarted harness's native `recall-remote` tools returned ready status and retrieved claim 13 from the real Codex sandbox proof. `https-cutover-20260927T164127-a21e0d47/harness-restart-acceptance.json`. |

The cutover directory is `https-cutover-20260927T164127-a21e0d47/`. Its first
read-only verification encountered a connection error immediately after policy
installation. The repeated verifier passed; the original failure, separate
verification retry and final authenticated acceptance record are retained.
No identity rollback or re-enrollment was performed.

A second checkpoint, `https-backup-20260927T165727-4775fad9/`, captures the
accepted HTTPS configuration and retired preflight logins. Its encrypted native
database backup also passed file validation. Keep the original pre-cutover
checkpoint for configuration rollback; neither checkpoint is a restore rehearsal.

Automated validation passed: 69 Python tests across gateway, cutover, network,
Ory, preflight and sandbox helpers; 23 Rust launcher tests; a locked Rust 1.94
build, strict all-target Clippy and formatting checks. Network-policy graph
tests used read-only Kubernetes schema discovery, alongside the separate live
packet proof above.

The required UBS staged scan was run and reviewed. Five unbounded subprocess
calls were fixed. The final report retained 11 critical, 385 warning and 514
informational heuristic matches: public/nonsecret comparisons, local installer
integrity checks without a remote timing oracle, deliberately invalid CSRF,
fixed probe code executed by a test, fail-closed parsing and reviewed ownership
patterns. No remaining material introduced finding was identified. This is not
an aggregate-clean scanner result. Its staged shadow omitted the Cargo manifest,
so separate real-worktree Rust tests/Clippy supplied compiler and test coverage.
The report is retained privately in the cutover directory as `ubs-staged.log`.

The isolated preflight initially inherited production Ory schema CREATE rights
through PUBLIC. Review found the gap; that capability was not exercised. Its
three deployments are now scaled to zero, it has no remaining SQL sessions,
and its two dedicated roles are NOLOGIN. Databases and evidence are retained.
The helper now refuses inherited PUBLIC schema/data access before creating
roles. Future preflight requires coordinated baseline grant hardening or a
separate database cluster; the helper never silently changes production grants.
See [the preflight record and gate](preflight/README.md).

## Client and remaining qualification

The saved native `recall-remote` client now uses the canonical HTTPS URL, with
fresh OAuth credentials stored by Codex. The public CA path is configured in
the macOS user launch environment for subsequently started GUI processes.
Existing terminal shells still need the documented `CODEX_CA_CERTIFICATE`
export. The user subsequently installed the root and restarted the harness;
the system trust check and native MCP calls from that restarted harness passed.
This confirms that harness's connection; it does not establish that every
terminal shell inherited the CA environment variable. No certificate warning
or TLS verification was bypassed, and no interactive browser rendering test is
claimed by the system curl check.

The second-machine check will resume when hardware is available; it does not
block M4.3 lifecycle and recovery work on this Mac. LAN/VPN exposure requires
a selected stable Mac address, restricted HTTPS bind
and firewall, client DNS/CA setup, and an actual second machine with fresh OAuth
state. The Docker test is not evidence of that journey. Subsequent M4.3 restart,
dependency failure, certificate renewal, restore and upload-durability results
are recorded in [the lifecycle qualification](LIFECYCLE_QUALIFICATION.md).
M4.4 cloud deployment remains pending. Production ingress policies do not
restrict egress or claim to isolate the privileged certificate-controller namespace.
