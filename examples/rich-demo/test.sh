#!/bin/sh
set -eu

export LC_ALL=C
export TZ=UTC

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd)

for command_name in cmp git jq mktemp sort; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        printf 'required command not found: %s\n' "$command_name" >&2
        exit 69
    fi
done

test_root=$(mktemp -d "${TMPDIR:-/tmp}/fleet-rich-demo-test.XXXXXX")
case $test_root in
    "${TMPDIR:-/tmp}"/fleet-rich-demo-test.*) ;;
    *)
        printf 'unexpected temporary directory: %s\n' "$test_root" >&2
        exit 70
        ;;
esac

cleanup() {
    rm -rf "$test_root"
}
trap cleanup EXIT HUP INT TERM

first=$test_root/first.ndjson
second=$test_root/second.ndjson
duplicate=$test_root/duplicate.ndjson
authority=$test_root/authority.ndjson
sensitive=$test_root/sensitive.ndjson
unsafe_source=$test_root/unsafe-source.ndjson
malformed=$test_root/malformed.ndjson
whitespace_facet=$test_root/whitespace-facet.ndjson
control_facet=$test_root/control-facet.ndjson
broken_supersession=$test_root/broken-supersession.ndjson
blank_text=$test_root/blank-text.ndjson
escaped_sensitive=$test_root/escaped-sensitive.ndjson
dead_source=$test_root/dead-source.ndjson
missing_self_audit=$test_root/missing-self-audit.ndjson
wrong_self_audit_config=$test_root/wrong-self-audit-config.ndjson
wrong_self_audit_path=$test_root/wrong-self-audit-path.ndjson
wrong_self_audit_source=$test_root/wrong-self-audit-source.ndjson
nonzero_self_audit_index=$test_root/nonzero-self-audit-index.ndjson
mutated_tools_excerpt=$test_root/mutated-tools-excerpt.ndjson
mutated_docs_marker=$test_root/mutated-docs-marker.ndjson
mutated_primer_marker=$test_root/mutated-primer-marker.ndjson
mutated_architecture_marker=$test_root/mutated-architecture-marker.ndjson
missing_draft_status=$test_root/missing-draft-status.ndjson
malformed_source_revision=$test_root/malformed-source-revision.ndjson
widened_document_range=$test_root/widened-document-range.ndjson
narrowed_document_range=$test_root/narrowed-document-range.ndjson
shifted_code_range=$test_root/shifted-code-range.ndjson
nul_text=$test_root/nul-text.ndjson
missing_repository_source=$test_root/missing-repository-source.ndjson
wrong_repository_metadata=$test_root/wrong-repository-metadata.ndjson
mutated_repository_excerpt=$test_root/mutated-repository-excerpt.ndjson
widened_repository_range=$test_root/widened-repository-range.ndjson
long_token_expected=$test_root/long-token-expected.txt
long_token_actual=$test_root/long-token-actual.txt
mutated_long_token=$test_root/mutated-long-token.ndjson
expected_documents=$test_root/expected-documents.txt
actual_documents=$test_root/actual-documents.txt
expected_repository=$test_root/expected-repository.txt
actual_repository=$test_root/actual-repository.txt

# Independently derive the complete publication-safe tracked-text surface. The
# checked-in manifests are Docker build inputs, so this Git-backed test prevents
# a newly tracked source file from silently remaining absent from recall.
git -C "$repo_root" ls-files '*.md' |
    while IFS= read -r path; do
        case $path in
            licenses/README.md) continue ;;
        esac
        printf '%s\n' "$path"
    done |
    sort > "$expected_documents"
awk -F'|' '!/^#/ && NF { print $1 }' "$script_dir/documents.txt" |
    sort > "$actual_documents"
if ! cmp -s "$expected_documents" "$actual_documents"; then
    printf 'rich demo verification failed: document manifest is not the complete safe tracked Markdown set\n' >&2
    exit 1
fi

git -C "$repo_root" ls-files |
    while IFS= read -r path; do
        case $path in
            *.md|Cargo.lock|deploy/aws/.terraform.lock.hcl|deploy/aws/network/.terraform.lock.hcl) continue ;;
            *.png|*.jpg|*.jpeg|*.gif|*.webp|*.ico|*.pdf) continue ;;
            LICENSE|LICENSE-APACHE|LICENSE-MIT) continue ;;
            docs/evidence/*.json|docs/evidence/*.txt) continue ;;
            examples/demo.ndjson|examples/rich-demo/repository-files.txt) continue ;;
            demo/video/generated/.gitignore) continue ;;
            .env.example|deploy/aws/terraform.tfvars.example) continue ;;
            deploy/aws/tests/deployment.tftest.hcl) continue ;;
            deploy/aws/tests/reference-agent-wrapper.sh) continue ;;
            deploy/aws/tests/replacement-proof.sh) continue ;;
            deploy/aws/tests/seed-wrapper.sh) continue ;;
            deploy/aws/tests/self-audit-wrapper.sh) continue ;;
            # These connected proof harnesses construct password-bearing TLS
            # URLs. Keep them private just like the excluded AWS wrapper
            # fixtures; the decoded sensitive-pattern gate remains unchanged.
            deploy/cockroach/tests/control-bootstrap-cli.sh) continue ;;
            deploy/cockroach/tests/registry-activation-cli.sh) continue ;;
            deploy/cockroach/tests/successor-activation-cli.sh) continue ;;
            # LocalStack boundary fixtures contain deliberate local-only
            # passwords or credential-shaped database URLs. Keep the exact
            # harness files private; publication policy and connected proof
            # source remain admitted below through the complete manifest.
            deploy/localstack/app-entrypoint.sh) continue ;;
            deploy/localstack/database-bootstrap.sh) continue ;;
            deploy/localstack/database-boundary.sh) continue ;;
            deploy/localstack/init/ready.d/10-seed-aws.sh) continue ;;
            deploy/localstack/publication-entrypoint.sh) continue ;;
            deploy/localstack/secret-to-file.sh) continue ;;
            deploy/localstack/smoke.sh) continue ;;
            # Runtime configuration contains deliberate credential-shaped
            # negative fixtures. The connection-policy module is admitted via
            # the verifier's exact closed fixture projection instead.
            src/config.rs) continue ;;
        esac
        printf '%s\n' "$path"
    done |
    sort > "$expected_repository"
awk -F'|' '!/^#/ && NF { print $1 }' "$script_dir/repository-files.txt" |
    sort > "$actual_repository"
if ! cmp -s "$expected_repository" "$actual_repository"; then
    printf 'rich demo verification failed: repository manifest is not the complete safe tracked text set\n' >&2
    exit 1
fi

"$script_dir/generate.sh" > "$first"
"$script_dir/generate.sh" > "$second"
RICH_DEMO_EXPECTED_SOURCE_REVISION=0000000000000000000000000000000000000000 \
    "$script_dir/verify.sh" "$first"

if ! jq -s -e '
    length == 4227
    and ([.[] | select(.source_config_id == "rich-demo:docs:v1")] | length) == 841
    and ([.[] | select(.source_config_id == "rich-demo:self-audit:v1")] | length) == 2
    and ([.[] | select(.source_config_id == "rich-demo:repository:v1")] | length) == 3180
    and ([.[] | select(.source_config_id == "rich-demo:operations:v1")] | length) == 204
    and ([.[] | select(.source_config_id == "rich-demo:repository:v1"
        and .source_id == "src/bin/ostk-control-bootstrap.rs")] | length) == 11
    and ([.[] | select(.source_config_id == "rich-demo:repository:v1"
        and .source_id == "src/bin/ostk-registry-activate.rs")] | length) == 22
    and ([.[] | select(.source_config_id == "rich-demo:repository:v1"
        and .source_id == "src/bin/ostk-registry-successor-activate.rs")] | length) == 62
    and ([.[] | select(.source_config_id == "rich-demo:repository:v1"
        and .source_id == "src/bin/ostk-conflict-reconcile.rs")] | length) == 26
    and ([.[] | select(.source_config_id == "rich-demo:repository:v1"
        and .source_id == "src/ledger/reconciliation.rs")] | length) == 135
    and ([.[] | select(.source_config_id == "rich-demo:repository:v1"
        and .source_id == "deploy/cockroach/conflict-reconciliation-role-grants.sql")] | length) == 27
    and ([.[] | select(.source_config_id == "rich-demo:repository:v1"
        and .source_id == "deploy/cockroach/publication-reader-role-grants.sql")] | length) == 30
    and ([.[] | select(.source_config_id == "rich-demo:repository:v1"
        and .source_id == "deploy/cockroach/successor-activation-role-grants.sql")] | length) == 23
    and ([.[] | select(.source_config_id == "rich-demo:repository:v1"
        and .source_id == "deploy/cockroach/tests/conflict-reconciliation-role-grants.sh")] | length) == 95
    and ([.[] | select(.source_config_id == "rich-demo:repository:v1"
        and .source_id == "deploy/cockroach/tests/publication-reader-role-grants.sh")] | length) == 130
    and ([.[] | select(.source_config_id == "rich-demo:repository:v1"
        and .source_id == "deploy/cockroach/tests/successor-activation-role-grants.sh")] | length) == 77
    and ([.[] | select(.source_config_id == "rich-demo:repository:v1"
        and .source_id == "migrations/0015_conflict_detector_uniqueness.sql")] | length) == 5
    and ([.[] | select(.source_config_id == "rich-demo:repository:v1"
        and .source_id == "migrations/0016_claim_transition_provenance_index.sql")] | length) == 3
    and ([.[] | select(.source_config_id == "rich-demo:repository:v1"
        and .source_id == "migrations/0017_conflict_detector_projection_index.sql")] | length) == 3
    and ([.[] | select(.source_config_id == "rich-demo:repository:v1"
        and .source_id == "src/private_postgres.rs")] | length) == 15
    and ([.[] | select(.source_config_id == "rich-demo:repository:v1"
        and .source_id == "tests/publication_reader_live.rs")] | length) == 16
    and ([.[] | select(.source_id == "src/config.rs")] | length) == 0
' "$first" >/dev/null; then
    printf 'rich demo verification failed: exact repository corpus composition changed\n' >&2
    exit 1
fi

# Canonical JSON can be one long whitespace-free token. Require bounded,
# same-line UTF-8 fragments and prove that ordered bodies reconstruct the exact
# source bytes without loss, overlap, or duplication.
long_token_source=contracts/dynamic-memory/v1/genesis-registry-package.jsonl
long_token_prefix="Repository source $long_token_source; area memory_contracts; language jsonl. "
if ! jq -s -e --arg source_id "$long_token_source" '
    [.[] | select(
        .source_config_id == "rich-demo:repository:v1"
        and .source_id == $source_id
    )] as $fragments
    | ($fragments | length) > 1
    and all($fragments[];
        .extra.source_line_start == 1
        and .extra.source_line_end == 1
        and (.text | utf8bytelength) <= 1500)
' "$first" >/dev/null; then
    printf 'rich demo verification failed: long canonical token was not safely fragmented\n' >&2
    exit 1
fi
awk '{ sub(/\r$/, ""); printf "%s", $0 }' \
    "$repo_root/$long_token_source" > "$long_token_expected"
jq -s -jr \
    --arg source_id "$long_token_source" \
    --arg prefix "$long_token_prefix" '
    [.[] | select(
        .source_config_id == "rich-demo:repository:v1"
        and .source_id == $source_id
    )]
    | sort_by(.chunk_index)
    | .[]
    | .text
    | ltrimstr($prefix)
' "$first" > "$long_token_actual"
if ! cmp -s "$long_token_expected" "$long_token_actual"; then
    printf 'rich demo verification failed: long canonical token coverage changed\n' >&2
    exit 1
fi
jq -c --arg source_id "$long_token_source" '
    if .source_config_id == "rich-demo:repository:v1"
        and .source_id == $source_id
        and .chunk_index == 0
    then .text += "x"
    else .
    end
' "$first" > "$mutated_long_token"
if mutated_long_token_error=$(
    "$script_dir/verify.sh" "$mutated_long_token" 2>&1
); then
    printf 'rich demo verification failed: verifier accepted a mutated long-token fragment\n' >&2
    exit 1
fi
if ! printf '%s\n' "$mutated_long_token_error" |
    grep -Fq "repository source coordinates or metadata do not exactly bound $long_token_source"
then
    printf '%s\n' "$mutated_long_token_error" >&2
    printf 'rich demo verification failed: mutated long token failed outside source containment\n' >&2
    exit 1
fi

if ! cmp -s "$first" "$second"; then
    printf 'rich demo verification failed: generator output is not deterministic\n' >&2
    exit 1
fi

if RICH_DEMO_SOURCE_REVISION=main "$script_dir/generate.sh" >/dev/null 2>&1; then
    printf 'rich demo verification failed: generator accepted a non-immutable source revision\n' >&2
    exit 1
fi

if RICH_DEMO_EXPECTED_SOURCE_REVISION=1111111111111111111111111111111111111111 \
    "$script_dir/verify.sh" "$first" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted the wrong expected source revision\n' >&2
    exit 1
fi

jq -s -c '. + [.[0]] | .[]' "$first" > "$duplicate"
if "$script_dir/verify.sh" "$duplicate" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted duplicate coordinates\n' >&2
    exit 1
fi

jq -s -c '.[0].project = "caller-controlled" | .[]' "$first" > "$authority"
if "$script_dir/verify.sh" "$authority" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted an authority field\n' >&2
    exit 1
fi

jq -s -c '
    .[0].text += (" postgresql://" + "attacker:secret@" + "db.example:26257/fleet")
    | .[]
' "$first" > "$sensitive"
if "$script_dir/verify.sh" "$sensitive" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted a credential-like pattern\n' >&2
    exit 1
fi

jq -s -c '.[0].source_id = "docs/../README.md" | .[]' "$first" > "$unsafe_source"
if "$script_dir/verify.sh" "$unsafe_source" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted an unsafe source path\n' >&2
    exit 1
fi

sed '1s/$/ trailing-data/' "$first" > "$malformed"
if "$script_dir/verify.sh" "$malformed" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted malformed NDJSON\n' >&2
    exit 1
fi

jq -s -c '.[0].facets.tags[0] = " documentation " | .[]' "$first" > "$whitespace_facet"
if "$script_dir/verify.sh" "$whitespace_facet" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted facet whitespace\n' >&2
    exit 1
fi

jq -s -c '.[0].facets.tags[0] = "doc\u0085umentation" | .[]' "$first" > "$control_facet"
if "$script_dir/verify.sh" "$control_facet" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted a facet control character\n' >&2
    exit 1
fi

jq -s -c '
    map(if .source_id == "rich-demo/operations/week-02/supersession"
        then .facets.scenario = ["unrelated prior decision"]
        else .
        end)
    | .[]
' "$first" > "$broken_supersession"
if "$script_dir/verify.sh" "$broken_supersession" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted a mismatched supersession\n' >&2
    exit 1
fi

jq -s -c '.[0].text = (" " * 40) | .[]' "$first" > "$blank_text"
if "$script_dir/verify.sh" "$blank_text" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted blank text\n' >&2
    exit 1
fi

awk '
    BEGIN {
        marker = "\\u0041KIA"
        for (digit = 0; digit < 16; digit++) {
            marker = marker "0"
        }
    }
    NR == 1 {
        location = index($0, "\"text\":\"")
        if (location == 0) {
            exit 2
        }
        $0 = substr($0, 1, location + 7) marker " " substr($0, location + 8)
    }
    { print }
' "$first" > "$escaped_sensitive"
if "$script_dir/verify.sh" "$escaped_sensitive" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted an encoded credential-like pattern\n' >&2
    exit 1
fi

jq -s -c '
    map(if .source_id == "README.md"
        then .source_id = "docs/nonexistent-rich-demo-source.md"
        else .
        end)
    | .[]
' "$first" > "$dead_source"
if "$script_dir/verify.sh" "$dead_source" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted a dead documentation source\n' >&2
    exit 1
fi

jq -c 'select(.source_id != "src/application.rs")' "$first" > "$missing_self_audit"
if "$script_dir/verify.sh" "$missing_self_audit" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted a missing self-audit source\n' >&2
    exit 1
fi

jq -c 'select(.source_config_id != "rich-demo:repository:v1" or .source_id != "Dockerfile")' \
    "$first" > "$missing_repository_source"
if "$script_dir/verify.sh" "$missing_repository_source" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted a missing repository source\n' >&2
    exit 1
fi

jq -c '
    if .source_config_id == "rich-demo:repository:v1"
        and .source_id == "Dockerfile" and .chunk_index == 0
    then .facets.source_area = ["application_code"]
        | .facets.tags[2] = "application_code"
    else .
    end
' "$first" > "$wrong_repository_metadata"
if "$script_dir/verify.sh" "$wrong_repository_metadata" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted wrong repository metadata\n' >&2
    exit 1
fi

jq -c '
    if .source_config_id == "rich-demo:repository:v1"
        and .source_id == "Dockerfile" and .chunk_index == 0
    then .text += " unverified drift"
    else .
    end
' "$first" > "$mutated_repository_excerpt"
if "$script_dir/verify.sh" "$mutated_repository_excerpt" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted a mutated repository excerpt\n' >&2
    exit 1
fi

jq -c '
    if .source_config_id == "rich-demo:repository:v1"
        and .source_id == "Dockerfile" and .chunk_index == 0
    then .extra.source_line_end += 1
    else .
    end
' "$first" > "$widened_repository_range"
if "$script_dir/verify.sh" "$widened_repository_range" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted a widened repository source range\n' >&2
    exit 1
fi

jq -c '
    if .source_id == "src/mcp/tools.rs"
    then .source_config_id = "rich-demo:docs:v1"
    else .
    end
' "$first" > "$wrong_self_audit_config"
if "$script_dir/verify.sh" "$wrong_self_audit_config" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted a misconfigured self-audit source\n' >&2
    exit 1
fi

jq -c '
    if .source_id == "src/mcp/tools.rs"
    then .source_id = "src/mcp/renamed-tools.rs"
    else .
    end
' "$first" > "$wrong_self_audit_path"
if "$script_dir/verify.sh" "$wrong_self_audit_path" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted an unexpected self-audit path\n' >&2
    exit 1
fi

jq -c '
    if .source_id == "src/mcp/tools.rs"
    then .source = "markdown"
    else .
    end
' "$first" > "$wrong_self_audit_source"
if "$script_dir/verify.sh" "$wrong_self_audit_source" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted a non-code self-audit source\n' >&2
    exit 1
fi

jq -c '
    if .source_id == "src/application.rs"
    then .chunk_index = 1
    else .
    end
' "$first" > "$nonzero_self_audit_index"
if "$script_dir/verify.sh" "$nonzero_self_audit_index" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted a noncontiguous self-audit index\n' >&2
    exit 1
fi

jq -c '
    if .source_id == "src/mcp/tools.rs"
    then .text += "\n// unverified drift"
    else .
    end
' "$first" > "$mutated_tools_excerpt"
if "$script_dir/verify.sh" "$mutated_tools_excerpt" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted a mutated source excerpt\n' >&2
    exit 1
fi

jq -c '
    if .source_id == "examples/README.md"
    then .text |= gsub("Use MCP `remember` for deliberate claims"; "Use memory for deliberate claims")
    else .
    end
' "$first" > "$mutated_docs_marker"
if "$script_dir/verify.sh" "$mutated_docs_marker" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted a missing documentation marker\n' >&2
    exit 1
fi

jq -c '
    if .source_id == "docs/PROJECT_PRIMER.md"
    then .text |= gsub("SQLx 0.8 with its PostgreSQL driver"; "an unspecified database client")
    else .
    end
' "$first" > "$mutated_primer_marker"
if "$script_dir/verify.sh" "$mutated_primer_marker" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted a missing project-primer implementation marker\n' >&2
    exit 1
fi

jq -c '
    if .source_id == "docs/PROJECT_PRIMER.md"
    then .text |= gsub("C-SPANN indexes"; "an unspecified vector index")
    else .
    end
' "$first" > "$mutated_architecture_marker"
if "$script_dir/verify.sh" "$mutated_architecture_marker" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted a missing CockroachDB architecture marker\n' >&2
    exit 1
fi

jq -c '
    if .source_id == "docs/DYNAMIC_MEMORY_ARCHITECTURE.md" then
        .text |= sub("^Draft target architecture; not implemented[.] "; "")
        | del(.facets.document_status)
        | .facets.tags -= ["draft_target"]
    else .
    end
' "$first" > "$missing_draft_status"
if "$script_dir/verify.sh" "$missing_draft_status" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted unlabeled draft target architecture\n' >&2
    exit 1
fi

jq -c '
    if .source_id == "docs/PROJECT_PRIMER.md" and .chunk_index == 0
    then .extra.source_revision = "main"
    else .
    end
' "$first" > "$malformed_source_revision"
if "$script_dir/verify.sh" "$malformed_source_revision" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted a non-immutable source revision\n' >&2
    exit 1
fi

jq -c '
    if .source_id == "docs/PROJECT_PRIMER.md" and .chunk_index == 0
    then .extra.source_line_end += 1
    else .
    end
' "$first" > "$widened_document_range"
if "$script_dir/verify.sh" "$widened_document_range" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted a widened document source range\n' >&2
    exit 1
fi

jq -c '
    if .source_id == "README.md" and .chunk_index == 58
    then .extra.source_line_start = .extra.source_line_end
    else .
    end
' "$first" > "$narrowed_document_range"
if "$script_dir/verify.sh" "$narrowed_document_range" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted a narrowed document source range\n' >&2
    exit 1
fi

jq -c '
    if .source_id == "src/mcp/tools.rs"
    then .extra.source_line_start += 1
    else .
    end
' "$first" > "$shifted_code_range"
if "$script_dir/verify.sh" "$shifted_code_range" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted a shifted code source range\n' >&2
    exit 1
fi

jq -c 'if .source_id == "README.md" and .chunk_index == 0 then .text += "\u0000" else . end' \
    "$first" > "$nul_text"
if "$script_dir/verify.sh" "$nul_text" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted a NUL in text\n' >&2
    exit 1
fi

printf '%s\n' 'rich demo generator is deterministic'
