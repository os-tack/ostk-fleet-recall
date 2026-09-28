# Memory pipelines: evidence, specs, and collected items

[Documentation](../README.md) · Previous: [Using Recall](USING_RECALL.md)

Ingest a scratch git repository, detect a deliberate spec nonconformance, and
collect documents and synthetic provider exports. Finish with a claim linked
to a collected message and searches that show the underlying evidence.

Complete [local development](LOCAL_DEVELOPMENT.md) and
[using Recall](USING_RECALL.md) first. Run commands from the repository root
in the same shell, with the private writer URL, pinned local model, generation-2
authority pins, and `FLEET_RECALL_QUICKSTART_DIR` still set. Keep
`local_pg_scheme` and `local_migrator_password` for step 10's brief installer
window. No LocalStack or live provider tokens are needed.

This tutorial extends the disposable Docker development database. For an
existing HTTPS Lima/k0s installation, follow the
[operator guide](../guides/OPERATING.md). The
[event-first operations guide](../guides/EVENT_FIRST_OPERATIONS.md) covers
ongoing operation after these examples, and the
[configuration reference](../reference/CONFIGURATION.md) records setting ownership.

### 8. Run the memory worker over a scratch repository

The worker's `ingest` and `project` steps need the pins exported above and a
content key-encryption key. Generate the key once and retain it with this
database: `project` unwraps with it everything `ingest` wrapped, and collected
capture uses it in step 10. The private file below is under the gitignored
quickstart directory; reusing it avoids replacing the key when a shell closes.
An already exported key is retained when creating the file. If both exist,
they must agree. Do not print or commit either value.

```bash
FLEET_RECALL_QUICKSTART_KEY="$FLEET_RECALL_QUICKSTART_DIR/content-kek.hex"
if [ -L "$FLEET_RECALL_QUICKSTART_DIR" ] || [ ! -d "$FLEET_RECALL_QUICKSTART_DIR" ] ||
   [ -L "$FLEET_RECALL_QUICKSTART_KEY" ] ||
   { [ -e "$FLEET_RECALL_QUICKSTART_KEY" ] && [ ! -f "$FLEET_RECALL_QUICKSTART_KEY" ]; }; then
  printf '%s\n' 'Expected a regular content-key file in the existing quickstart directory.' >&2
  exit 1
fi
quickstart_content_key=${FLEET_RECALL_CONTENT_KEK_HEX:-}
if [ -f "$FLEET_RECALL_QUICKSTART_KEY" ]; then
  quickstart_content_key=$(cat "$FLEET_RECALL_QUICKSTART_KEY") || exit 1
  if [ -n "${FLEET_RECALL_CONTENT_KEK_HEX:-}" ] &&
     [ "$(printf '%s' "$FLEET_RECALL_CONTENT_KEK_HEX" | tr 'A-F' 'a-f')" != \
       "$(printf '%s' "$quickstart_content_key" | tr 'A-F' 'a-f')" ]; then
    printf '%s\n' 'The exported and retained content keys disagree; neither was changed.' >&2
    exit 1
  fi
elif [ -z "$quickstart_content_key" ]; then
  quickstart_content_key=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
fi
case "$quickstart_content_key" in
  *[!0123456789abcdefABCDEF]*)
    printf '%s\n' 'The content key must be exactly 64 hexadecimal characters.' >&2
    exit 1 ;;
esac
if [ "${#quickstart_content_key}" -ne 64 ]; then
  printf '%s\n' 'The content key must be exactly 64 hexadecimal characters.' >&2
  exit 1
fi
chmod 700 "$FLEET_RECALL_QUICKSTART_DIR" || exit 1
if [ ! -e "$FLEET_RECALL_QUICKSTART_KEY" ]; then
  (umask 077; set -C; printf '%s' "$quickstart_content_key" > "$FLEET_RECALL_QUICKSTART_KEY") || exit 1
fi
chmod 600 "$FLEET_RECALL_QUICKSTART_KEY" || exit 1
export FLEET_RECALL_CONTENT_KEK_HEX="$quickstart_content_key"
unset quickstart_content_key
```

For a resumed database, the file or your previously retained key must already
exist. If both are missing, stop and recover that key; generating a new one
does not restore existing bodies.

For the first run, create a scratch repository holding a one-sentence spec
document and a Rust enum. The sources file names one git source plus the
observer identity that step 9 appends under:

```bash
export FLEET_RECALL_QUICKSTART_REPO="$FLEET_RECALL_QUICKSTART_DIR/repo"
git init --quiet -b main "$FLEET_RECALL_QUICKSTART_REPO"
mkdir -p "$FLEET_RECALL_QUICKSTART_REPO/docs" "$FLEET_RECALL_QUICKSTART_REPO/src"
printf '# Remember actions\n\nForget must not be a remember action.\n' \
  > "$FLEET_RECALL_QUICKSTART_REPO/docs/spec.md"
printf 'pub enum RememberAction {\n    Record,\n    Forget,\n}\n' \
  > "$FLEET_RECALL_QUICKSTART_REPO/src/service.rs"
git -C "$FLEET_RECALL_QUICKSTART_REPO" add docs src
git -C "$FLEET_RECALL_QUICKSTART_REPO" \
  -c user.name=Quickstart -c user.email=quickstart@example.invalid \
  commit --quiet --message 'Declare the Forget remember action'
export FLEET_RECALL_QUICKSTART_COMMIT=$(git -C "$FLEET_RECALL_QUICKSTART_REPO" rev-parse HEAD)

export FLEET_RECALL_QUICKSTART_SOURCES="$FLEET_RECALL_QUICKSTART_DIR/worker-sources.json"
cat > "$FLEET_RECALL_QUICKSTART_SOURCES" <<JSON
{
  "schema_version": 1,
  "git": [
    {
      "connector_principal": "connector.git",
      "connector_instance": "connector.git.quickstart",
      "installation_id": 1,
      "repository_id": "git.repo.quickstart",
      "git_dir": "$FLEET_RECALL_QUICKSTART_REPO/.git",
      "ref_name": "refs/heads/main",
      "provider_repository_id": 908172635
    }
  ],
  "observer": {
    "connector_principal": "connector.observer",
    "connector_instance": "connector.observer.quickstart"
  }
}
JSON

"$FLEET_RECALL_BIN" worker --once --sources "$FLEET_RECALL_QUICKSTART_SOURCES" |
  jq '.steps | map_values(.status)'
```

Every step reports `ok`; the transcript and CI steps have no sources. Search
the evidence the tick admitted, once for the commit and once for a word that
appears nowhere:

```bash
"$FLEET_RECALL_BIN" serve <<'JSONRPC' | jq --compact-output 'select(.id > 1) | .result.structuredContent.data | {absence, hits: [.hits[] | {matched_by, media_type, snippet}]}'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"readme-smoke","version":"1.0.0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"recall","arguments":{"action":"search","kind":"evidence","query":"Forget remember action","limit":5}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"recall","arguments":{"action":"search","kind":"evidence","query":"zeppelin","limit":5}}}
JSONRPC
```

The first search finds the commit and reads `present`. The second reads
`absent`, which evidence recall says only because the one source's last check
succeeded, is fresh, and covered its whole range, and nothing awaits
projection. Stop the worker from running and, after a day, the same search
reads `unknown` with the reason `source_stale`.

This is a useful stopping point if you only need repository evidence. No
scheduler runs this one-shot worker for you; see the
[worker reference](../reference/WORKER.md) for recurring execution.

#### Resume after step 8

In a new shell, first restore the binary, model, database, scope and authority
pins using [the resume instructions](LOCAL_DEVELOPMENT.md#stop-and-resume-without-losing-data).
Confirm `content-kek.hex` still exists, then run only the key-loading block at
the start of step 8. It validates and reuses the key. If it is missing, restore
your retained key before continuing. Restore these paths and the commit from
the existing scratch repository:

```bash
export FLEET_RECALL_QUICKSTART_REPO="$FLEET_RECALL_QUICKSTART_DIR/repo"
export FLEET_RECALL_QUICKSTART_SOURCES="$FLEET_RECALL_QUICKSTART_DIR/worker-sources.json"
test -d "$FLEET_RECALL_QUICKSTART_REPO/.git" && test -f "$FLEET_RECALL_QUICKSTART_SOURCES" || exit 1
FLEET_RECALL_QUICKSTART_COMMIT=$(git -C "$FLEET_RECALL_QUICKSTART_REPO" rev-parse HEAD) || exit 1
export FLEET_RECALL_QUICKSTART_COMMIT
```

Do not recreate the repository, overwrite the sources file, or repeat its
initial commit when resuming. Step 9 sets its own spec binary and output path.
After completing step 10, the scope remains at generation 3; you do not need
to reopen the migrator window on each restart.

### 9. Make a spec normative and check the commit

Bytes 20 to 57 of `docs/spec.md` are its sentence "Forget must not be a
remember action." Draft a statement that binds that span to the expectation
that `RememberAction` in `src/service.rs` does not declare `Forget`, have the
two approvers the active policy names sign it, and activate it. The approvers'
Ed25519 seeds are the public fixture seeds `0x01` and `0x02`, so these
approvals are nominal: the real gate is the `fleet_writer` credential that
`activate` runs under. The statement takes effect 30 seconds after the draft:

```bash
export FLEET_RECALL_SPEC_BIN="$PWD/target/debug/ostk-spec"
spec_dir="$FLEET_RECALL_QUICKSTART_DIR/spec"
"$FLEET_RECALL_SPEC_BIN" draft \
  --git-dir "$FLEET_RECALL_QUICKSTART_REPO/.git" \
  --repository-id git.repo.quickstart --installation-id 1 \
  --provider-repository-id 908172635 \
  --commit "$FLEET_RECALL_QUICKSTART_COMMIT" \
  --spec-path docs/spec.md --span 20..57 \
  --family spec.quickstart.no_forget \
  --member Forget --expected absent \
  --effective-in-seconds 30 \
  --proposer principal.dave --author principal.carol \
  --out "$spec_dir" | jq '{statement_id}'
printf '01%.0s' $(seq 32) > "$spec_dir/alice.seed"
printf '02%.0s' $(seq 32) > "$spec_dir/bob.seed"
for approver in alice bob; do
  "$FLEET_RECALL_SPEC_BIN" approve --proposal "$spec_dir/proposal.jsonl" \
    --principal "principal.$approver" --seed-file "$spec_dir/$approver.seed" \
    --out "$spec_dir/$approver.jsonl" >/dev/null
done
"$FLEET_RECALL_SPEC_BIN" activate \
  --proposal "$spec_dir/proposal.jsonl" \
  --expectation "$spec_dir/expectation.jsonl" \
  --approval "$spec_dir/alice.jsonl" --approval "$spec_dir/bob.jsonl" \
  | jq '{outcome, statement_id}'
```

Once the statement is in force, check the commit. `check` reads
`src/service.rs` at the commit through the worker's git source, runs the
genesis-admitted observer over the enum, and compares:

```bash
sleep 30
"$FLEET_RECALL_SPEC_BIN" check \
  --family spec.quickstart.no_forget \
  --sources "$FLEET_RECALL_QUICKSTART_SOURCES" \
  --git-source connector.git.quickstart \
  --commit "$FLEET_RECALL_QUICKSTART_COMMIT" \
  | jq '{verdict, observed_condition, discrepancy}'

"$FLEET_RECALL_BIN" serve <<'JSONRPC' | jq 'select(.id > 1) | .result.structuredContent.data | {discrepancies: [.discrepancies[] | {episode_id, lifecycle_state, observed, expectation: .spec.expectation}], specs: [.specs[] | {binding_family_id, effect, last_check}]}'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"readme-smoke","version":"1.0.0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"recall","arguments":{"action":"discrepancies"}}}
JSONRPC
```

The observer verified `Forget` present, so the check is `nonconforming` and
opened a `spec_nonconformance` episode, which `recall(discrepancies)` lists
with the statement it violates and the commit it observed. Had the commit not
declared `Forget`, the check would read `unknown`, not `conforming`: the
observer can verify a member present but never absent, so an empty episode
list is not proof of conformance, and the list's `specs[].last_check` says
what each spec's latest check found. For the same reason no later check closes
this episode; `ostk-spec episode resolve` or `ostk-spec episode dismiss` does
([ADR 0007](../adr/0007-spec-conformance-chain.md)). The check appended the
spec blob's git fact and the observer run as evidence. The next worker tick
projects the blob fact into evidence recall and counts the observer run, which
names no source version, under the `bodies` step's `events_unprojectable`;
`recall(discrepancies)` cites it as `observer_event_id`.

### 10. Collect documents, an import, and a Slack export

Collected items need the scope at generation 3
([ADR 0008](../adr/0008-collected-items.md)). Moving a scope is the
migrator's job, and step 4 retired the migrator, so enable it for this one
command and retire it again by rerunning the boundary helper. That helper
quiesces the writer and publication logins, reapplies their policies and
PUBLIC-default cleanup, and enables them only after the gates pass. The move
keeps the authority pins and rebases the spec family step 9 activated onto
the new head.

This is a privileged maintenance window even in the tutorial. Keep these
commands together and do not run other writers while the installer changes
the head. If installation or the report check fails, still rerun the boundary
helper to retire the migrator, then investigate the failure before continuing.
For a shared deployment, use the migration and authority procedures in
[event-first operations](../guides/EVENT_FIRST_OPERATIONS.md).

```bash
docker exec ostk-fleet-recall-crdb \
  cockroach sql --insecure --host=127.0.0.1:26257 \
  --execute='ALTER USER fleet_migrator WITH LOGIN; GRANT admin TO fleet_migrator;'
FLEET_RECALL_DATABASE_URL="${local_pg_scheme}://fleet_migrator:${local_migrator_password}@127.0.0.1:26257/fleet_recall?sslmode=disable" \
FLEET_RECALL_CONTRACT_TENANT_NAMESPACE=tenant.quickstart \
FLEET_RECALL_CONTRACT_PROJECT_NAMESPACE=project.quickstart \
  "$PWD/target/debug/ostk-authority-install" apply --target generation-3 \
  > "$FLEET_RECALL_QUICKSTART_DIR/authority-generation3.json"
jq '{generation, package, normative_families: [.normative_families[] | {binding_family_id, outcome}]}' \
  "$FLEET_RECALL_QUICKSTART_DIR/authority-generation3.json"
docker exec --interactive ostk-fleet-recall-crdb \
  /bin/sh -s < deploy/localstack/database-boundary.sh
```

The report reads `generation` 3, the `collected_items_generation3` package,
and `spec.quickstart.no_forget` `rebased`. Now add a documents collector over
the scratch repository's `docs/` to the scope's one sources file and run a
tick. This root contains the fixture spec from step 8, so the collector does
not ingest this tutorial's own search examples. The operator declares that
root visible to the whole project:

```bash
jq --arg root "$FLEET_RECALL_QUICKSTART_REPO/docs" '.collectors = [{
    "provider": "docs", "connector_principal": "principal.docs",
    "connector_instance": "docs.quickstart", "provider_scope_id": "quickstart-docs",
    "audience": {"operator_declared": true},
    "settings": {"root": $root, "extensions": ["md"]}}]' \
  "$FLEET_RECALL_QUICKSTART_SOURCES" > "$FLEET_RECALL_QUICKSTART_SOURCES.new"
mv "$FLEET_RECALL_QUICKSTART_SOURCES.new" "$FLEET_RECALL_QUICKSTART_SOURCES"
"$FLEET_RECALL_BIN" worker --once --sources "$FLEET_RECALL_QUICKSTART_SOURCES" |
  jq '{steps: (.steps | map_values(.status)), docs: [.steps.collect.sources[] | {connector_instance, outcome, files_staged: .counters.files_staged}]}'
```

Import two snapshots as the operator: a file of Linear items, and a Slack
workspace export (a directory here; a zip works the same). The export's
public channel is imported; its private channel is not listed with
`--private-container`, so it is never opened, and its direct conversation is
never read:

```bash
"$FLEET_RECALL_BIN" collect import --instance import.linear --principal principal.import \
  --provider linear --provider-scope 0a9c0000-0000-4000-8000-0000000ac3e1 \
  --audience operator-declared --format items-jsonl \
  --path tests/fixtures/collected/items-linear.jsonl | jq '{items_staged, refused, snapshot}'
"$FLEET_RECALL_BIN" collect import --instance import.slack --principal principal.import \
  --provider slack --provider-scope T07ACME0001 --audience operator-declared \
  --format slack-export --path tests/fixtures/collected/slack-export | jq '{items_staged, refused, snapshot}'
```

An agent can relay what it read through its own connectors. With capture
enabled (the content key from step 8 lets `serve` admit in the call), the
agent captures a message of the channel the export recorded as readable, and
records a claim that cites it:

```bash
FLEET_RECALL_COLLECTED_CAPTURE=enabled "$FLEET_RECALL_BIN" serve <<'JSONRPC' | jq --compact-output 'select(.id > 1) | .result.structuredContent.data // .error | .items // .claim // . | if type == "array" then [.[] | {disposition, item_id}] else {id, state, text} end'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"readme-smoke","version":"1.0.0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"remember","arguments":{"action":"capture","idempotency_key":"readme/capture/v1","via":"slack.conversations_history","items":[{"provider":"slack","provider_scope_id":"T07ACME0001","object_kind":"message","external_id":"C07PLATENG1:1790009400.000100","container":{"kind":"slack.channel","id":"C07PLATENG1"},"author":{"id":"U07BOB0002","kind":"human"},"created_at":"2026-09-21T16:50:00.000100Z","text":"p99 stays under the SLO with a retry budget of 5 and full jitter.","url":"https://acme-robotics.slack.com/archives/C07PLATENG1/p1790009400000100"}]}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"remember","arguments":{"action":"record","idempotency_key":"readme/record-cites/v1","kind":"fact","text":"The ingest worker retry budget is five attempts with full jitter.","subject":"ingest worker","predicate":"retry-budget","value":5,"support":[{"item":{"url":"https://acme-robotics.slack.com/archives/C07PLATENG1/p1790009400000100"},"relation":"supports"}]}}}
JSONRPC
```

The capture answers `admitted`, and the claim is `active`. Project what was
admitted, then recall it as items, get the captured one, and search the same
words as evidence:

```bash
"$FLEET_RECALL_BIN" worker --once --sources "$FLEET_RECALL_QUICKSTART_SOURCES" --steps project,embed |
  jq '.steps | map_values(.status)'
"$FLEET_RECALL_BIN" serve <<'JSONRPC' | jq --compact-output 'select(.id > 1) | .result.structuredContent.data | if .item then {item: .item.item | {provider, external_id, trust, lifecycle}, cited_by: [.item.cited_by[] | .claim_id]} else {absence: .absence.verdict, hits: [.hits[] | {provider: (.provider // .item.provider), trust: (.trust // .item.trust), current: (.current // .item.current), snippet: .snippet[:60]}]} end'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"readme-smoke","version":"1.0.0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"recall","arguments":{"action":"search","kind":"item","query":"retry budget jitter","limit":5}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"recall","arguments":{"action":"get","kind":"item","id":"https://acme-robotics.slack.com/archives/C07PLATENG1/p1790009400000100"}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"recall","arguments":{"action":"search","kind":"evidence","query":"retry budget jitter","limit":5}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"recall","arguments":{"action":"search","kind":"item","query":"zeppelin","limit":5}}}
JSONRPC
```

Item search finds the Slack thread, the Linear issue, and the capture, each
`reported` (an import and a capture are the operator's and the agent's word,
not a provider's), with its text labelled `untrusted_third_party`. The get
names the capture's item and the claim that cites it. The evidence search
returns the same bodies, each annotated with its item. The last search reads
`absent`: every collector and import covered its whole scope and nothing
awaits projection. Pulling a live Slack workspace, Linear organization, or
Granola account is a sources-file entry with the provider's token in the
worker's environment (see [memory worker](../reference/WORKER.md)), and webhooks
shorten its interval (see
[receiving provider webhooks](../reference/COLLECTION.md#receiving-provider-webhooks)); the
[collected-items runbook](../COLLECTED_ITEMS_RUNBOOK.md) puts every step in
order and records an end-to-end run against local stand-ins for the three
providers.

You have now exercised the full local path: assertions and conflicts,
repository evidence, a spec discrepancy, and collected items with claim
citations. The database stays at generation 3; rerunning an older default
installer command does not move it back to generation 2. Preserve both
authority reports, the content key, sources file, scratch repository, and
spec files with this database.

For the next task, use [event-first operations](../guides/EVENT_FIRST_OPERATIONS.md)
to operate these pipelines or the [collection reference](../reference/COLLECTION.md)
to configure providers. To pause, [stop the development database while
preserving its data](LOCAL_DEVELOPMENT.md#stop-and-resume-without-losing-data).
