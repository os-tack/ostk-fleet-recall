# Connected CockroachDB proof substrates

Connected correctness is authoritative only when it runs against the official
CockroachDB `v26.2.3` binary. CI downloads the Linux AMD64 archive, verifies the
frozen SHA-256
`3eca6d7bc6fefa3ba0847e89733fc69f61226c80b8fab0af6578e1be672f27d3`,
and requires `cockroach version --build-tag` to equal `v26.2.3` exactly.
`registry-activation-cli.sh` repeats that build-tag check, starts one secure
local server, runs `control_log_live`, `registry_activation_live`, and
`successor_activation_live`, then exercises the inspect/apply/replay state
machines of both private CLIs. The successor target is discovered by its exact
test name before the environment-bound invocation, so a zero-test or inert run
cannot count as connected proof.
The same isolated process also runs the DB-backed transactional-DDL rollback
library test, requires the exact successful migration prefix 1 through 14,
checks the three successor tables and both exact genesis-root indexes, replays
the resumable index migrations 10 and 11, and proves a failed migration 12 is
not masked by a later successful row.

Run the authoritative proof with an already checksum-verified binary:

```bash
FLEET_RECALL_CRDB_BINARY=/absolute/path/to/cockroach \
  ./deploy/cockroach/tests/registry-activation-cli.sh
```

The Docker jobs are secondary parity proofs only:

- `control-role-grants.sh` checks the control-role RBAC boundary.
- `registry-activation-role-grants.sh` checks the activation-role RBAC boundary.
- `control-bootstrap-cli.sh` checks container TLS, the control live repository,
  and the bootstrap CLI behavior.

Each Docker proof requires the running server's build tag to equal `v26.2.3`.
That confirms image-version parity, but Docker parity cannot substitute for the
checksum-pinned official-binary correctness proof. Report the authoritative
result and each Docker parity result separately; do not summarize one substrate
as evidence that another passed. Every script owns bounded temporary state and
cleans it on success, failure, or interruption.

Both RBAC proofs apply migrations 3 through 14 over explicit stand-ins for the
legacy v1/v2 objects, then synthesize the complete successful SQLx history 1
through 14. They retain the private commands' narrower semantic preflights
(bootstrap through 3, genesis activation through 9), inject successor-table
privilege and grant-option drift, then apply and reapply
`successor-schema-quarantine-grants.sql`. That dedicated policy first requires
all migration rows 1 through 14 to exist and be successful; only then does it
statically revoke every privilege on the three new authority tables from
`public`, runtime, bootstrap, and genesis activation. It is separate because
CockroachDB v26.2 cannot conditionally execute privilege DDL inside PL/pgSQL,
while the two base role policies must remain applicable at their original v3/v9
deployment stages.
