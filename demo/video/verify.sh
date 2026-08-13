#!/bin/sh
set -eu

[ "$#" -ge 2 ] && [ "$#" -le 3 ] || {
    printf 'usage: verify.sh MODE EVIDENCE [RUN_ID]\n' >&2
    exit 64
}

mode=$1
evidence=$2
requested_run=${3:-}

command -v jq >/dev/null 2>&1 || {
    printf 'video evidence: required command not found: jq\n' >&2
    exit 1
}
[ -f "$evidence" ] && [ ! -L "$evidence" ] || {
    printf 'video evidence: regular, non-symlink evidence file not found\n' >&2
    exit 1
}

safe_run_id() {
    candidate=$1
    label=$2
    case "$candidate" in
        ''|*[!A-Za-z0-9_-]*)
            printf 'video evidence: %s requires a safe run ID\n' "$label" >&2
            exit 64
            ;;
    esac
    [ "${#candidate}" -le 48 ] || {
        printf 'video evidence: run ID must be at most 48 characters\n' >&2
        exit 64
    }
}

verify_fleet_evidence() {
    expected_capture=$1
    expected_run=$2
    requires_timestamp=$3
    jq -e \
        --arg expected_capture "$expected_capture" \
        --arg expected_run "$expected_run" \
        --argjson requires_timestamp "$requires_timestamp" '
        def positive_integer:
            type == "number" and isfinite and . > 0 and . == floor;
        def timestamp_contract:
            if $requires_timestamp then
                (.generated_at | type == "string" and
                    test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$") and
                    (try fromdateiso8601 catch false | type == "number"))
            else
                (has("generated_at") | not)
            end;
        . as $root |
        .schema_version == 1 and
        .verified == true and
        .evidence_kind == "fleet-recall-mcp-scenario" and
        .capture == $expected_capture and
        .run_id == $expected_run and
        (.run_id | type == "string" and test("^[A-Za-z0-9_-]{1,48}$")) and
        .scenario == .run_id and
        timestamp_contract and
        .provenance == {
            generator: "deploy/localstack/fleet-demo.sh",
            backend: "cockroachdb",
            transport: "mcp-stdio",
            ostk_used: false,
            llm_used: false,
            cloud_used: false
        } and
        .identities == {
            writer: "agent-a",
            retriever: "agent-b",
            conflicting_writer: "agent-c",
            resumed: "agent-b"
        } and
        .agent_a.committed == true and
        .agent_a.replay_deduplicated == true and
        (.agent_a.claim_id | positive_integer) and
        (.agent_b.action_claim_id | positive_integer) and
        (.agent_b.escalation_claim_id | positive_integer) and
        (.agent_c.claim_id | positive_integer) and
        (.conflict.id | positive_integer) and
        ([
            .agent_a.claim_id,
            .agent_b.action_claim_id,
            .agent_c.claim_id,
            .agent_b.escalation_claim_id
        ] | unique | length) == 4 and
        .agent_b.cross_project_request_rejected == true and
        .agent_b.retrieval_lanes == ["lexical", "dense"] and
        .agent_b.fusion == "rrf" and
        .agent_b.recalled_claim_id == .agent_a.claim_id and
        .agent_b.action_based_on_claim_id == .agent_a.claim_id and
        .agent_b.action == "hold workers until migration completes" and
        .agent_b.escalation == "pause rollout for operator review" and
        .agent_b.escalation_conflict_id == .conflict.id and
        .agent_c.incompatible_value_recorded == true and
        .conflict.state == "open" and
        (.conflict.member_claim_ids | type == "array" and length == 2) and
        ((.conflict.member_claim_ids | sort) ==
            ([$root.agent_a.claim_id, $root.agent_c.claim_id] | sort))
    ' "$evidence" >/dev/null || {
        printf 'video evidence: %s evidence failed its contract\n' "$mode" >&2
        exit 1
    }
}

case "$mode" in
    rehearsal)
        [ -z "$requested_run" ] || exit 64
        verify_fleet_evidence sanitized-rehearsal local-evidence-v1 false
        ;;
    fleet-live)
        safe_run_id "$requested_run" fleet-live
        verify_fleet_evidence live "$requested_run" true
        ;;
    ostk-live)
        safe_run_id "$requested_run" ostk-live
        jq -e --arg requested_run "$requested_run" '
            def positive_integer:
                type == "number" and isfinite and . > 0 and . == floor;
            .run_id as $run |
            .schema_version == 1 and
            .verified == true and
            .run_id == $requested_run and
            ($run | type == "string" and test("^[A-Za-z0-9_-]{1,48}$")) and
            .orchestrator.product == "ostk" and
            .orchestrator.required_cli_version == "7.7.7" and
            .orchestrator.sessions == [
                ("ostk-recall-a-" + $run),
                ("ostk-recall-b-" + $run),
                ("ostk-recall-c-" + $run)
            ] and
            .orchestrator.resumed_session == .orchestrator.sessions[1] and
            (.memory.recalled_claim_id | positive_integer) and
            (.memory.incompatible_claim_id | positive_integer) and
            (.memory.open_conflict_id | positive_integer) and
            .memory.recalled_claim_id != .memory.incompatible_claim_id and
            .memory.retrieval_lanes == ["lexical", "dense"] and
            .memory.fusion == "rrf" and
            (.actions | type == "array" and length == 2) and
            .actions[0].action == "hold workers until migration completes" and
            .actions[1].action == "pause rollout and escalate for operator review" and
            .actions[0].based_on_claim_id == .memory.recalled_claim_id and
            .actions[1].based_on_conflict_id == .memory.open_conflict_id and
            .actions[0].receipt == (
                "s3://fleet-recall-local-actions/ostk-demo/" + $run +
                "/agent-b/hold-workers.json"
            ) and
            .actions[1].receipt == (
                "s3://fleet-recall-local-actions/ostk-demo/" + $run +
                "/agent-b/pause-rollout.json"
            )
        ' "$evidence" >/dev/null || {
            printf 'video evidence: OSTK evidence failed its contract\n' >&2
            exit 1
        }
        ;;
    *)
        printf 'video evidence: unknown mode: %s\n' "$mode" >&2
        exit 64
        ;;
esac
