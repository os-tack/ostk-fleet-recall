# Isolated checkpoint recovery

`bin/restore-https-checkpoint.py` consumes a checkpoint from
`bin/backup-https-cutover.py`. Its initial qualification boundary is SQL/Ory
data, authority/schema, spool bytes and the protected key inventory. It never
connects to the running installation, modifies its keys, applies Kubernetes
resources, or publishes a restored endpoint.

The helper authenticates every AES-256-GCM artifact with filename-bound AAD,
checks the selected source installation and backup age, and validates all tar
paths before extraction. Links, devices, traversal, duplicate paths, archive
size bombs, and an existing extraction destination fail closed. The known
source `kube-system` UID and original state path identify the chosen checkpoint;
neither requires that the source cluster still exists. Retain the encrypted
checkpoint and recovery key separately off the VM/disk for disaster recovery.

Use the repository Python environment with `cryptography` installed. The
destination parent must already exist with mode 0700. The default command only
validates inputs; add `--apply` to execute the concrete rehearsal:

```sh
python3 deploy/local/bin/restore-https-checkpoint.py \
  --state /absolute/original/deploy/local/.state \
  --backup /absolute/checkpoint \
  --source-cluster-uid KNOWN-SOURCE-KUBE-SYSTEM-UID \
  --destination-parent /absolute/private/recovery
```

The default maximum backup age is 24 hours. An older disaster-recovery input
requires an explicit `--max-backup-age-hours` and an acknowledged larger RPO;
do not silently present an old checkpoint as meeting the pilot target.

An applied run creates a new `fleet-restore-*` child directory and Docker
container using locally present CockroachDB 26.2.3. There is no option to name
an existing SQL server, reuse a store, select a host network, or publish ports.
The container uses `--network=none`, loopback listeners, a private new store,
read-only backup/certificate mounts, and SQL `sslmode=verify-full`. The helper
checks its actual network, port and mount configuration before SQL restoration.
Full-cluster restore requires an empty destination and restores users and
privileges along with application data. See the
[CockroachDB 26.2 restore reference](https://docs.cockroachlabs.com/docs/v26.2/restore#full-cluster).

After `SHOW BACKUP ... check_files` and native `RESTORE`, the helper compares
every migration checksum/success flag to this checkout, and matches generation
3, activation ID, scope namespaces and bootstrap receipt against authenticated
checkpoint pins. Hydra and Kratos application tables must exist. Extracted
spool/workstation files and protected Secrets have SHA-256 inventories; the
workstation and deployment grant-signing key must agree. Those hashes and SQL
diagnostics stay in the private result directory. No tokens, passwords,
transcript contents, recovery passphrases or key values are printed.

All previously revoked grant rows retain their original revocation metadata.
Every previously unrevoked grant in the restored copy is revoked with a new
rehearsal operator UUID, including expired grants. This prevents backup age
from resurrecting a delegation. It does **not** reconcile post-backup principal
policy changes or invalidate backed-up Ory sessions/refresh tokens. Do not
attach a public network or reuse the copied production credentials as a
promotion shortcut. Full promotion needs the current principal/revocation
ledger, discarded/revoked old Ory sessions, fresh authentication/grants, and
verified scope/least-privilege boundaries before routing any client traffic.

The SQL container is stopped on both success and failure; its private data and
diagnostics are retained. A run with `complete=true` in `result.json` proves
only this restoration stage. `application_qualified` remains false in that
record: a separate application proof supplies the next evidence. Spool file recovery alone does
not prove that SQL and acknowledged upload offsets form a consistent recovery
point: the current checkpoint gathers them sequentially. For an RPO-qualified
recovery point, quiesce launches/receiver/worker while creating the checkpoint
and explicitly validate replay before reopening traffic. A VM restart is a
separate durability check, not a restore proof.

Rollback of a deployment uses previous images/configuration while retaining
the current authorization database and revoked rows. This isolated full-cluster
restore helper is not a rollback mechanism.

Tests: `python3 -m unittest discover -s deploy/local/https -p test_restore.py`.

## Restored application proof

`verify-restored-plane.py` starts the stopped, successful SQL restore and puts
every Ory, Recall, embedding, worker and browser helper container in its same
network-disabled namespace. No host port, Docker bridge, or outbound route is
created. A private hosts file resolves the original three canonical names to
loopback. SQL retains `verify-full`; only private backend addresses change.
Hydra/Kratos and UI use their restored Secrets and original issuer/resource
URLs. A short-lived rehearsal leaf uses the copied intermediate and unchanged
root. The private Python HTTPS proxy provides only the routing needed for this
exercise; it does not requalify the production Traefik/Kubernetes boundary.

Pull the three pinned `oryd/hydra:v26.2.0`, `oryd/kratos:v26.2.0` and
`oryd/kratos-selfservice-ui-node:v26.2.0` images before starting. The helper
uses locally present images, records immutable image IDs, and loads the model
bundle referenced by the checkpoint, whose digest the embedding process checks.
Use a known pre-backup claim and the existing operator's password file; no old
OAuth access/refresh token is copied into the browser test.

```sh
python3 deploy/local/bin/verify-restored-plane.py \
  --restore /absolute/private/recovery/fleet-restore-RUN \
  --image ostk-fleet-recall:QUALIFIED-IMAGE-TAG \
  --account-file /absolute/private/operator-account.json \
  --expected-subject EXISTING-KRATOS-SUBJECT-UUID \
  --known-claim-id 13 --apply
```

The proof repeats HTTPS password login, PKCE, nonce/state, secure cookies,
explicit CSRF rejection and browser logout. The fresh access token reads and
decrypts a pre-backup claim, writes/reads a new one, checks the runtime's exact
generation/activation pins, and receives a cross-project denial. The source
restore's hashed keys and spool remain unchanged. In a **separate spool working
copy**, the helper stages a unique pending transcript turn, runs the scope
worker twice, and requires exactly one matching evidence result plus unchanged
recovered prefix bytes. This tests processing/replay of pending work; it does
not simulate a receiver acknowledgement or interrupted network upload.

The `application-*/result.json` record is separate from the SQL restore record.
`complete=true` requires successful proof and cleanup of all application/SQL
containers. Use a fresh SQL restoration for a repeated complete rehearsal,
because successful application proof intentionally advances the isolated DB
and its ingestion cursors. Interrupted attempts retain private logs and never
publish their restored service. The HTTP runtime tests human Hydra identity
and preserved local authority; the Kubernetes machine issuer is omitted because
there is no Kubernetes API inside this isolated namespace. Existing Ory tokens
and enrollment changes still require reconciliation before a real promotion.

Initial rehearsal on 2026-09-27: checkpoint `https-backup-20260927T183730-83d3486f`
restored all 38 migration checksums through schema 39, generation 3,
16 Hydra/26 Kratos tables, and preserved all 17 revoked grants in 12.25 seconds.
The application phase completed in 26.55 seconds: pre-backup claim 13 decrypted,
fresh OAuth and scope denial passed, and a staged pending turn produced one
evidence result after two successful worker ticks. All containers stopped.
These measured stages fit the four-hour pilot target, but are local rehearsals
using an already available checkpoint and model; they do not establish offsite
retrieval time, a consistent 24-hour RPO, or recovery after complete Mac loss.

The final hardened repeat used `fleet-restore-20260927T194029-41d23092` and
`application-20260927T194110-599abe6f`: SQL restoration took 26.53 seconds and
the application phase took 25.66 seconds. It verified the runtime authority,
rechecked every original spool, workstation and resource artifact hash,
validated every container's exact bind-mount and network boundary, found
exactly one pending evidence match, and stopped all containers with no cleanup
or log-collection failures. The ten plaintext resource artifacts are bound to
the authenticated backup before and after application proof.

Tests cover 24 authentication, archive, isolation, cleanup, environment and
input-preservation cases, including SIGTERM interruption immediately after SQL
container start, repeated-signal protection during mandatory cleanup, and
log-collection failure still attempting every container stop. The automated
signal case uses real Python signals with mocked Docker ownership operations.
The separate live fault proof `fleet-restore-20260927T200444-23f8cda2` injected
SIGTERM immediately after a new isolated SQL container started, then injected
a second SIGTERM during cleanup. Cleanup stopped the owned container and
recorded `interrupted=true`, `complete=false`, as required; this interruption
case intentionally did not complete SQL restoration.

## Receiver acknowledgement across restart

Add `--restart-receiver` to the normal environment-parameterized
`sandbox-smoke.py` command to rehearse receiver durability in each selected
backend. This controlled test uses its existing agent/shipper grants and
requires one receiver replica with `Recreate`, plus a suspended worker. It
creates a separate synthetic JSONL file so the native sandbox shipper cannot
conflict with the probe's append window.

The helper uploads and verifies a complete prefix, starts an incomplete
verified-TLS PUT, then replaces the receiver pod with a resource-version guarded
template annotation. It requires a new Ready pod, bounded recovery through the
HTTPS edge, an unchanged acknowledged offset, unchanged prefix bytes and
unchanged original synthetic transcript.
It retries the complete pending window and replays both the prefix and append;
both duplicates must report `replayed=true` without increasing length. Two
worker ticks must retain the same final-turn evidence identity and spool hash.
Whether the incomplete request receives an error or the gateway retains its
body until the client closes is recorded privately; no success acknowledgement
is accepted. The durable byte/offset checks establish the outcome.

Launch cleanup still stops the runtime and revokes/replays both grants, and
the original worker schedule is restored by the existing protected cleanup.
No transcript or retained Kubernetes Job is deleted. A failed rollout retains
the before/after deployment evidence for repair. This receiver rehearsal is
separate from full backup recovery and does not promise survival for bytes
that were never acknowledged.
