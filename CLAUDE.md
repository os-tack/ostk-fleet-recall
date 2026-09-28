# Fleet Recall (`ostk-fleet-recall`)

Rust service: shared fleet memory over CockroachDB for agents. One binary
(`ostk-fleet-recall`) serves the Recall MCP protocol, runs the worker tick, the
demo viewer and the private ingress; ten workstation-only ceremony and
maintenance binaries live under `src/bin/`. Start with `README.md` and the
task index in `docs/README.md`; the disposable quickstart is under
`docs/tutorials/`. Read `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, and the ADRs under
`docs/adr/` (0009 covers the remote plane).

## Tooling rule for this repository

This project does not use the `ostk` kernel or the `ostk-recall` agent tooling.
Use the native tools (Read, Grep, Glob, Edit, Write, Bash). The `ostk-recall-*`
crates in `Cargo.toml` are ordinary library dependencies and are unaffected by
this rule.

## Working here

- `cargo build --locked`; `cargo clippy --all-targets` (pedantic and nursery
  lints are on); `cargo fmt`.
- Live tests (`tests/*_live.rs`) run only when `FLEET_RECALL_TEST_DATABASE_URL`
  points at a disposable CockroachDB; they migrate their own database.
- Migrations are append-only and numbered; every role policy under
  `deploy/cockroach/` is gated on an exact migration prefix and must be bumped
  when a migration is added (`docs/MIGRATIONS.md`).
- Any environment variable starting with `PG` makes the binary refuse to start.
- The local production-shaped environment (Lima → k0s → CockroachDB, Ory,
  LocalStack) lives under `deploy/local/`; its generated state is gitignored.
- Never delete files or run destructive git commands without explicit
  instruction (see the workspace `AGENTS.md`).
