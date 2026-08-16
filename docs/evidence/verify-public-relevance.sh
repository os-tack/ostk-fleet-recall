#!/bin/sh
set -eu

export LC_ALL=C
export TZ=UTC

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd)
receipt=$script_dir/public-relevance-efe6fbf-20260814.json
capture_dir=${1:-$repo_root/target/aws-evidence/public-relevance-20260814T170553Z}

fail() {
    printf 'public relevance receipt verification failed: %s\n' "$1" >&2
    exit 1
}

for command_name in git jq mktemp rg tar; do
    command -v "$command_name" >/dev/null 2>&1 ||
        fail "required command not found: $command_name"
done
[ -f "$receipt" ] && [ ! -L "$receipt" ] || fail "receipt is missing or unsafe"
[ -d "$capture_dir" ] && [ ! -L "$capture_dir" ] || fail "capture directory is missing or unsafe"

jq -e '
    .schema == "fleet-public-relevance-smoke-v1" and
    .verified == true and
    .verification_scope.kind == "public_http_smoke" and
    (.verification_scope.query_text_provenance | contains("Operator-recorded")) and
    (.verification_scope.query_text_provenance | contains("does not echo query text")) and
    (.verification_scope.snippet_summary_provenance | contains("Human-reviewed paraphrases")) and
    (.verification_scope.snippet_summary_provenance | contains("not the prose itself")) and
    (.verification_scope.does_not_prove | length == 3) and
    .captured_at == "2026-08-14T17:06:31Z" and
    .public_url == "https://d13zrqfh66r7ub.cloudfront.net/" and
    .route == "POST /api/recall" and
    .release.git_commit == "efe6fbf4e2f1c5b9daab2c5f4f65ebf38a49770f" and
    .release.image_tag == "git-efe6fbf4e2f1" and
    .release.image_digest == "sha256:1df821f31bf26b7a7da503476dbaadcabdb7e8c74e132684968489e5e3f206b7" and
    .release.serving_revision == 7 and
    .release.platform == "linux/arm64" and
    .release.compressed_image_size_bytes == 47841090 and
    .seed.release_bound == true and
    .seed.ingest_exit_code == 0 and
    .seed.row_count == 548 and
    .seed.composition == {
        repository_documentation_chunks: 342,
        exact_self_audit_source_chunks: 2,
        synthetic_operations_narrative_chunks: 204
    } and
    ([.seed.composition[]] | add) == .seed.row_count and
    .ecr_scan.scan_type == "BASIC" and
    .ecr_scan.status == "COMPLETE" and
    .ecr_scan.completed_at == "2026-08-14T11:58:02-05:00" and
    .ecr_scan.finding_severity_counts == {} and
    (.ecr_scan.scope | contains("OS-package scan only")) and
    (.ecr_scan.scope | contains("does not claim Go, Rust, or application-dependency coverage")) and
    [.queries[].id] == ["spec", "migration", "cockroach", "rust", "purpose", "libraries", "nonsense"] and
    ([.queries[].id] | unique | length) == 7 and
    all(.queries[];
        .http_status == 200 and
        .retrieval.lanes == ["lexical", "dense"] and
        .retrieval.fusion == "rrf" and
        (.retrieval.dense_min_cosine_similarity >= 0.179 and
         .retrieval.dense_min_cosine_similarity <= 0.181) and
        .retrieval.stratified_code_prefetch == 0 and
        ([.top_hits[].rank] == [range(1; (.top_hits | length) + 1)]) and
        all(.top_hits[];
            (.source_id | type == "string" and length > 0) and
            (.snippet_summary | type == "string" and length > 0)))
' "$receipt" >/dev/null || fail "receipt schema or fixed release facts changed"

build_metadata=$repo_root/target/aws-evidence/build-git-efe6fbf4e2f1.json
seed_log=$repo_root/target/aws-evidence/rich-seed-20260814T170338Z.log
[ -f "$build_metadata" ] || fail "private build metadata is missing"
[ -f "$seed_log" ] || fail "private release-bound seed log is missing"
jq -e '
    .["buildx.build.provenance"].invocation.parameters.args["build-arg:VCS_REF"]
        == "efe6fbf4e2f1c5b9daab2c5f4f65ebf38a49770f" and
    .["buildx.build.provenance"].invocation.environment.platform == "linux/arm64" and
    .["containerimage.digest"]
        == "sha256:1df821f31bf26b7a7da503476dbaadcabdb7e8c74e132684968489e5e3f206b7" and
    (.["image.name"] | endswith(":git-efe6fbf4e2f1"))
' "$build_metadata" >/dev/null || fail "private build metadata does not match the release"
rg -q '^seed task exit code: 0$' "$seed_log" || fail "release-bound seed did not exit successfully"

release_tree=$(mktemp -d "${TMPDIR:-/tmp}/fleet-public-relevance-release.XXXXXX")
case $release_tree in
    "${TMPDIR:-/tmp}"/fleet-public-relevance-release.*) ;;
    *) fail "unexpected release-tree temporary directory" ;;
esac
generated=$release_tree/rich-demo.ndjson
cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    rm -rf "$release_tree"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM
git -C "$repo_root" archive efe6fbf4e2f1c5b9daab2c5f4f65ebf38a49770f |
    tar -xf - -C "$release_tree"
"$release_tree/examples/rich-demo/generate.sh" > "$generated"
"$release_tree/examples/rich-demo/verify.sh" "$generated" >/dev/null
jq -s -e '
    length == 548 and
    ([.[] | select(.source_config_id == "rich-demo:docs:v1")] | length) == 342 and
    ([.[] | select(.source_config_id == "rich-demo:self-audit:v1")] | length) == 2 and
    ([.[] | select(.source_config_id == "rich-demo:operations:v1")] | length) == 204
' "$generated" >/dev/null || fail "current release corpus does not match the receipt composition"

for query_id in spec migration cockroach rust purpose libraries nonsense; do
    response=$capture_dir/$query_id.json
    headers=$capture_dir/$query_id.headers
    [ -f "$response" ] && [ ! -L "$response" ] || fail "missing response for $query_id"
    [ -f "$headers" ] && [ ! -L "$headers" ] || fail "missing headers for $query_id"

    case $query_id in
        spec)
            expected_query='Does MCP remember support deliberate retractions?'
            expected_rfc_date='Fri, 14 Aug 2026 17:05:54 GMT'
            expected_iso_date='2026-08-14T17:05:54Z'
            ;;
        migration)
            expected_query='How are conflicting migration strategies represented and escalated?'
            expected_rfc_date='Fri, 14 Aug 2026 17:06:00 GMT'
            expected_iso_date='2026-08-14T17:06:00Z'
            ;;
        cockroach)
            expected_query='Why does Fleet Recall use CockroachDB for shared agent memory?'
            expected_rfc_date='Fri, 14 Aug 2026 17:06:06 GMT'
            expected_iso_date='2026-08-14T17:06:06Z'
            ;;
        rust)
            expected_query='How does Rust write memories to CockroachDB?'
            expected_rfc_date='Fri, 14 Aug 2026 17:06:12 GMT'
            expected_iso_date='2026-08-14T17:06:12Z'
            ;;
        purpose)
            expected_query='Why does this project exist?'
            expected_rfc_date='Fri, 14 Aug 2026 17:06:19 GMT'
            expected_iso_date='2026-08-14T17:06:19Z'
            ;;
        libraries)
            expected_query='What libraries are used to write to the datastore?'
            expected_rfc_date='Fri, 14 Aug 2026 17:06:25 GMT'
            expected_iso_date='2026-08-14T17:06:25Z'
            ;;
        nonsense)
            expected_query='quan''tum chrom''odynamics pen''guins'
            expected_rfc_date='Fri, 14 Aug 2026 17:06:31 GMT'
            expected_iso_date='2026-08-14T17:06:31Z'
            ;;
    esac

    jq -e \
        --arg id "$query_id" \
        --arg query "$expected_query" \
        --arg captured_at "$expected_iso_date" \
        --slurpfile receipt "$receipt" '
        ($receipt[0].queries[] | select(.id == $id)) as $expected |
        $expected.query == $query and
        $expected.captured_at == $captured_at and
        (.data.hits | length) == $expected.hit_count and
        (.conflicts | length) == $expected.conflict_count and
        [.data.hits[0:3][]?.source_id] == [$expected.top_hits[].source_id] and
        .diagnostics.retrieval.conflict_matches == $expected.conflict_matches and
        .diagnostics.retrieval.lanes == $expected.retrieval.lanes and
        .diagnostics.retrieval.fusion == $expected.retrieval.fusion and
        .diagnostics.retrieval.dense_min_cosine_similarity
            == $expected.retrieval.dense_min_cosine_similarity and
        .diagnostics.retrieval.stratified_code_prefetch
            == $expected.retrieval.stratified_code_prefetch
    ' "$response" >/dev/null || fail "response projection changed for $query_id"

    jq -e '
        . as $root
        | all(.diagnostics.retrieval.conflict_matches[];
            . as $match
            | ($root.conflicts | map(select(.id == $match.conflict_id))) as $matched_conflicts
            | ($matched_conflicts | length) == 1
              and (
                ([ $matched_conflicts[0].members[].id ] | sort | unique) as $member_ids
                | ($matched_conflicts[0].members_truncated == false)
                  and ($matched_conflicts[0].member_values_elided == false)
                  and all($match.direct_claim_ids[];
                      . as $claim_id | ($member_ids | index($claim_id)) != null)
                  and all($match.source_support[];
                      . as $support
                      | ($member_ids | index($support.claim_id)) != null
                        and ($support.fused_hit_rank | type == "number")
                        and ($support.fused_hit_rank >= 1)
                        and ($support.fused_hit_rank <= ($root.data.hits | length))
                        and ($root.data.hits[$support.fused_hit_rank - 1].chunk_id
                             == $support.chunk_id))
                  and (
                    [ $match.direct_claim_ids[] as $claim_id
                      | range(0; ($root.data.hits | length)) as $index
                      | select($root.data.hits[$index].source_id
                               == ("claim/" + ($claim_id | tostring)))
                      | $index + 1
                    ] as $direct_ranks
                    | ($direct_ranks | length) == ($match.direct_claim_ids | length)
                      and (
                        ($direct_ranks + [$match.source_support[].fused_hit_rank]) as $all_ranks
                        | ($all_ranks | length) > 0
                          and ($all_ranks | min) == $match.best_fused_hit_rank
                      )
                  )
              )
        )
    ' "$response" >/dev/null ||
        fail "conflict mapping is not bound to exact members and fused hits for $query_id"

    rg -q '^HTTP/2 200[[:space:]]*$' "$headers" || fail "HTTP status was not 200 for $query_id"
    rg -Fq "date: $expected_rfc_date" "$headers" || fail "capture date changed for $query_id"
    rg -q '^x-cache: Miss from cloudfront[[:space:]]*$' "$headers" ||
        fail "capture was not a public edge miss for $query_id"
    duration=$(sed -n 's/^server-timing: fleet-recall;dur=\([0-9.]*\).*/\1/p' "$headers" | tr -d '\r')
    [ -n "$duration" ] || fail "server timing is missing for $query_id"
    jq -e --arg id "$query_id" --argjson duration "$duration" '
        .queries[] | select(.id == $id) | .server_duration_ms == $duration
    ' "$receipt" >/dev/null || fail "server timing changed for $query_id"
done

if rg -ni 'arn:aws|[.]dkr[.]ecr[.]|postgres(ql)?://|(^|[^[:alnum:]])[0-9]{12}([^[:alnum:]]|$)' "$receipt" >/dev/null; then
    fail "receipt contains an AWS coordinate, account number, or database URL"
fi
jq -e '
    [paths(scalars) as $path
        | ($path[-1] | tostring | ascii_downcase)
        | select(test("password|secret|token|credential|access.?key|database.?url|log.?stream|task.?id"))]
    | length == 0
' "$receipt" >/dev/null || fail "receipt contains a sensitive field name"

printf '%s\n' 'public relevance receipt verified against seven private HTTP captures'
