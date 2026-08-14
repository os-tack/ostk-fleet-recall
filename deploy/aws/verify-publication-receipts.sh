#!/bin/sh
set -eu

fail() {
    echo "$1" >&2
    exit "${2:-65}"
}

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 REFERENCE_AGENT_RECEIPT [REPLACEMENT_RECEIPT]" >&2
    exit 64
fi

if ! command -v jq >/dev/null 2>&1; then
    fail "required command not found: jq" 69
fi

reference_receipt=$1
replacement_receipt=${2:-}
[ -f "$reference_receipt" ] || fail "reference-agent receipt not found: $reference_receipt"
[ -z "$replacement_receipt" ] || [ -f "$replacement_receipt" ] || \
    fail "replacement receipt not found: $replacement_receipt"

# Publication receipts intentionally retain bounded operational coordinates,
# but never full ARNs, account IDs, connection URLs, credentials, or raw log
# streams. Scan both keys and values before interpreting either schema.
reject_sensitive_content() {
    receipt=$1
    if ! jq -e 'type == "object"' "$receipt" >/dev/null 2>&1; then
        fail "receipt is not one valid JSON object: $receipt"
    fi
    if jq -e '
        any(.. | strings;
            test("arn:(aws|aws-us-gov|aws-cn):"; "i") or
            test("(^|[^0-9])[0-9]{12}([^0-9]|$)") or
            test("postgres(?:ql)?://"; "i") or
            test("[a-z][a-z0-9+.-]*://[^/@[:space:]]+@"; "i")) or
        any(paths(scalars) as $path |
            ($path[-1] | tostring | ascii_downcase);
            test("^(password|passwd|database_url|secret_arn|task_arn|task_definition_arn|log_stream|access_key|secret_access_key|session_token|authorization)$"))
    ' "$receipt" >/dev/null; then
        fail "receipt contains a prohibited secret or unsanitized infrastructure coordinate: $receipt"
    fi
}

reject_sensitive_content "$reference_receipt"
[ -z "$replacement_receipt" ] || reject_sensitive_content "$replacement_receipt"

if ! jq -e '
    def exact_keys($expected): (keys == ($expected | sort));
    def positive_integer: type == "number" and . > 0 and . == floor;
    def safe_name: type == "string" and test("^[A-Za-z0-9._+=,@-]+$");
    def safe_text:
        type == "string" and length > 0 and length <= 128 and
        test("^[^[:cntrl:]]+$");
    def safe_id: type == "string" and test("^[A-Za-z0-9_-]+$");
    def safe_run:
        type == "string" and length > 0 and length <= 64 and
        test("^[A-Za-z0-9._][A-Za-z0-9._-]*$");
    def https_url:
        type == "string" and
        test("^https://[^[:space:]@/#]+(?::[0-9]+)?(?:/[^[:space:]#]*)?$");
    exact_keys([
        "actions", "agents", "aws", "deployment", "memory", "project",
        "public_demo", "run_id", "schema", "verified"
    ]) and
    .schema == "fleet-reference-agent-run-v1" and
    .verified == true and
    .deployment == "amazon-ecs-fargate" and
    (.run_id | safe_run) and
    (.project | safe_text) and
    .agents == ["agent-a", "agent-b", "agent-c"] and
    (.memory | exact_keys([
        "fusion", "incompatible_claim_id", "open_conflict_id",
        "recalled_claim_id", "retrieval_lanes"
    ])) and
    (.memory.recalled_claim_id | positive_integer) and
    (.memory.incompatible_claim_id | positive_integer) and
    (.memory.open_conflict_id | positive_integer) and
    .memory.retrieval_lanes == ["lexical", "dense"] and
    .memory.fusion == "rrf" and
    (.actions | type == "array" and length == 2) and
    (.actions[0] | exact_keys(["action", "based_on_claim_id", "claim_id"])) and
    (.actions[1] | exact_keys(["action", "based_on_conflict_id", "claim_id"])) and
    (.actions[0].claim_id | positive_integer) and
    .actions[0].action == "hold workers until migration completes" and
    .actions[0].based_on_claim_id == .memory.recalled_claim_id and
    (.actions[1].claim_id | positive_integer) and
    .actions[1].action == "pause rollout for operator review" and
    .actions[1].based_on_conflict_id == .memory.open_conflict_id and
    ([.memory.recalled_claim_id, .memory.incompatible_claim_id,
      .actions[0].claim_id, .actions[1].claim_id] | unique | length) == 4 and
    (.aws | exact_keys([
        "cluster", "log_stream_prefix", "region", "task_definition", "tasks"
    ])) and
    (.aws.region | type == "string" and test("^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]+$")) and
    (.aws.cluster | safe_name) and
    (.aws.task_definition |
        type == "string" and test("^[A-Za-z0-9._+=,@-]+:[1-9][0-9]*$")) and
    (.aws.log_stream_prefix |
        type == "string" and test("^fleet/[A-Za-z0-9._+=,@-]+$")) and
    (.aws.tasks | type == "array" and length == 4) and
    [.aws.tasks[].step] == [
        "record_decision", "recall_and_act", "record_conflict",
        "recall_conflict_and_escalate"
    ] and
    [.aws.tasks[].agent] == ["agent-a", "agent-b", "agent-c", "agent-b"] and
    ([.aws.tasks[].task_id] | unique | length) == 4 and
    all(.aws.tasks[];
        . as $task |
        exact_keys(["agent", "log_stream_suffix", "step", "stopped_at", "task_id"]) and
        (.task_id | safe_id) and
        (.log_stream_suffix |
            type == "string" and test("^[A-Za-z0-9._+=,@-]+/[A-Za-z0-9_-]+$")) and
        ($task.log_stream_suffix | endswith("/" + $task.task_id)) and
        (.stopped_at == null or
            (.stopped_at | type == "string" and
             test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+(?:Z|[+-][0-9]{2}:[0-9]{2})$")))) and
    (.public_demo | exact_keys([
        "cockroachdb_capabilities", "cockroachdb_version", "database",
        "embedding_model", "exact_claim_ids_observed", "fusion", "health",
        "read_only_verification", "retrieval_lanes", "url"
    ])) and
    (.public_demo.url | https_url) and
    .public_demo.health == "ready" and
    .public_demo.read_only_verification == true and
    .public_demo.exact_claim_ids_observed ==
        [.actions[0].claim_id, .actions[1].claim_id] and
    .public_demo.retrieval_lanes == ["lexical", "dense"] and
    .public_demo.fusion == "rrf" and
    .public_demo.database == "CockroachDB" and
    (.public_demo.cockroachdb_version |
        type == "string" and (ascii_downcase | contains("cockroachdb"))) and
    (.public_demo.embedding_model | type == "string" and length > 0) and
    (.public_demo.cockroachdb_capabilities | exact_keys([
        "claim_support_chunk_index_enabled",
        "conflict_membership_index_enabled", "cosine_distance_supported",
        "embedding_dimension", "lexical_index_enabled", "schema_version",
        "vector_index_enabled"
    ])) and
    .public_demo.cockroachdb_capabilities.vector_index_enabled == true and
    .public_demo.cockroachdb_capabilities.lexical_index_enabled == true and
    .public_demo.cockroachdb_capabilities.conflict_membership_index_enabled == true and
    .public_demo.cockroachdb_capabilities.claim_support_chunk_index_enabled == true and
    .public_demo.cockroachdb_capabilities.cosine_distance_supported == true and
    .public_demo.cockroachdb_capabilities.schema_version == 2 and
    .public_demo.cockroachdb_capabilities.embedding_dimension == 512
' "$reference_receipt" >/dev/null; then
    fail "reference-agent receipt failed its complete schema and correlation contract"
fi

if [ -n "$replacement_receipt" ]; then
    if ! jq -e '
        def exact_keys($expected): (keys == ($expected | sort));
        def positive_integer: type == "number" and . > 0 and . == floor;
        def safe_name: type == "string" and test("^[A-Za-z0-9._+=,@-]+$");
        def safe_text:
            type == "string" and length > 0 and length <= 128 and
            test("^[^[:cntrl:]]+$");
        def safe_id: type == "string" and test("^[A-Za-z0-9_-]+$");
        def safe_run:
            type == "string" and length > 0 and length <= 64 and
            test("^[A-Za-z0-9._][A-Za-z0-9._-]*$");
        def https_url:
            type == "string" and
            test("^https://[^[:space:]@/#]+(?::[0-9]+)?(?:/[^[:space:]#]*)?$");
        def observation:
            exact_keys(["exact_claim_ids_observed", "fusion", "health", "retrieval_lanes"]) and
            .health == "ready" and
            (.exact_claim_ids_observed | type == "array" and length == 2 and
                all(.[]; positive_integer)) and
            .retrieval_lanes == ["lexical", "dense"] and
            .fusion == "rrf";
        . as $receipt |
        exact_keys([
            "aws", "deployment", "persistence", "project", "public_demo",
            "run_id", "schema", "verified"
        ]) and
        .schema == "fleet-ecs-replacement-run-v1" and
        .verified == true and
        .deployment == "amazon-ecs-fargate" and
        (.run_id | safe_run) and
        (.project | safe_text) and
        (.aws | exact_keys([
            "cluster", "desired_count_after", "desired_count_before", "region",
            "replacement_strategy", "service", "task_definition",
            "tasks_after", "tasks_before"
        ])) and
        (.aws.region | type == "string" and test("^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]+$")) and
        (.aws.cluster | safe_name) and
        (.aws.service | safe_name) and
        (.aws.task_definition |
            type == "string" and test("^[A-Za-z0-9._+=,@-]+:[1-9][0-9]*$")) and
        .aws.replacement_strategy == "ecs-force-new-deployment" and
        (.aws.desired_count_before | positive_integer) and
        (.aws.desired_count_after | positive_integer) and
        (.aws.tasks_before | type == "array" and length == $receipt.aws.desired_count_before and
            all(.[]; safe_id)) and
        (.aws.tasks_after | type == "array" and length == $receipt.aws.desired_count_after and
            all(.[]; safe_id)) and
        ([.aws.tasks_before[], .aws.tasks_after[]] | length) ==
            ([.aws.tasks_before[], .aws.tasks_after[]] | unique | length) and
        (.public_demo | exact_keys(["after", "before", "url"])) and
        (.public_demo.url | https_url) and
        (.public_demo.before | observation) and
        (.public_demo.after | observation) and
        .public_demo.before == .public_demo.after and
        (.persistence | exact_keys([
            "cockroachdb_memory_plane", "exact_claim_ids_survived",
            "serving_task_set_fully_replaced"
        ])) and
        .persistence.cockroachdb_memory_plane == true and
        .persistence.serving_task_set_fully_replaced == true and
        .persistence.exact_claim_ids_survived == .public_demo.after.exact_claim_ids_observed
    ' "$replacement_receipt" >/dev/null; then
        fail "replacement receipt failed its complete schema and persistence contract"
    fi

    if ! jq -en \
        --slurpfile reference "$reference_receipt" \
        --slurpfile replacement "$replacement_receipt" '
        ($reference | length) == 1 and
        ($replacement | length) == 1 and
        $reference[0].run_id == $replacement[0].run_id and
        $reference[0].project == $replacement[0].project and
        $reference[0].public_demo.url == $replacement[0].public_demo.url and
        $reference[0].aws.region == $replacement[0].aws.region and
        $reference[0].aws.cluster == $replacement[0].aws.cluster and
        $reference[0].public_demo.exact_claim_ids_observed ==
            $replacement[0].persistence.exact_claim_ids_survived
    ' >/dev/null; then
        fail "reference-agent and replacement receipts do not describe one deployment/run"
    fi
fi

jq -cn \
    --arg run_id "$(jq -er '.run_id' "$reference_receipt")" \
    --argjson replacement_verified "$([ -n "$replacement_receipt" ] && printf true || printf false)" '{
    schema: "fleet-publication-receipt-validation-v1",
    verified: true,
    validation_only: true,
    run_id: $run_id,
    receipts: (if $replacement_verified
        then ["reference-agent", "ecs-replacement"]
        else ["reference-agent"]
        end)
}'
