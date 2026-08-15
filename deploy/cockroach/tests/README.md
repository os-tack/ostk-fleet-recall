# Connected CockroachDB proof substrates

Connected correctness is authoritative only when it runs against the official
CockroachDB `v26.2.3` binary. CI downloads the Linux AMD64 archive, verifies the
frozen SHA-256
`3eca6d7bc6fefa3ba0847e89733fc69f61226c80b8fab0af6578e1be672f27d3`,
and requires `cockroach version --build-tag` to equal `v26.2.3` exactly.
`registry-activation-cli.sh` repeats that build-tag check, starts one secure
local server, runs both `control_log_live` and `registry_activation_live`, and
then exercises the inspect/apply/replay state machines of both private CLIs.

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
