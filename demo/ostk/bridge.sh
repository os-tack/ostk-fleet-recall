#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=demo/ostk/lib.sh
. "$script_dir/lib.sh"

if [ "${1:-}" != --run-id ] || [ "$#" -ne 3 ]; then
    printf 'usage: %s --run-id ID record-decision|recall-and-act|record-conflict|recall-conflict-and-pause\n' "$0" >&2
    exit 64
fi
run_id=$2
ostk_demo_validate_run_id "$run_id"

case "$3" in
    record-decision|recall-and-act|record-conflict|recall-conflict-and-pause)
        step=$3
        ;;
    *)
        printf 'usage: %s --run-id ID record-decision|recall-and-act|record-conflict|recall-conflict-and-pause\n' "$0" >&2
        exit 64
        ;;
esac

ostk_demo_require_command jq
repo_root=$(ostk_demo_repo_root "$0")
run_dir=$(ostk_demo_run_dir "$repo_root" "$run_id")
bucket=fleet-recall-local-actions

mcp_client=$script_dir/mcp-client.sh
if [ "${OSTK_DEMO_TESTING:-0}" = 1 ] && [ -n "${OSTK_DEMO_MCP_CLIENT:-}" ]; then
    mcp_client=$OSTK_DEMO_MCP_CLIENT
fi
[ -x "$mcp_client" ] || ostk_demo_die "MCP client is not executable: $mcp_client"

call_mcp() {
    "$mcp_client" "$1"
}

read_evidence_value() {
    evidence_file=$1
    evidence_filter=$2
    [ -f "$evidence_file" ] || ostk_demo_die "required prior evidence is missing: $evidence_file"
    jq -er "$evidence_filter" "$evidence_file"
}

case "$step" in
    record-decision)
        agent=$(ostk_demo_require_agent_role a "$run_id")
        response=$(
            jq -cn \
                --arg run "$run_id" \
                --arg agent "$agent" \
                '{
                    action: "record",
                    scope: {agent: $agent, session_id: $run},
                    idempotency_key: ("ostk-demo/" + $run + "/migration-decision"),
                    kind: "decision",
                    text: "Fleet schema migration runs through one dedicated migrator before serving traffic.",
                    subject: ("fleet deployment " + $run),
                    predicate: "migration strategy",
                    value: "single dedicated migrator",
                    actor: $agent
                }' | call_mcp remember
        )
        claim_id=$(printf '%s\n' "$response" | jq -e --arg agent "$agent" '
            if .data.receipt.committed == true and
               .data.claim.actor == $agent and
               .data.claim.state == "active" and
               .data.claim.value == "single dedicated migrator" and
               (.data.claim.id | type) == "number"
            then .data.claim.id | if floor == . then . else error("claim ID is not an integer") end
            else error("Agent A memory receipt did not satisfy the demo contract")
            end
        ')
        evidence=$(jq -cn \
            --arg run "$run_id" \
            --arg agent "$agent" \
            --argjson claim_id "$claim_id" \
            --arg timestamp "$(ostk_demo_timestamp)" \
            '{
                schema_version: 1,
                step: "agent_a_record",
                run_id: $run,
                ostk_agent: $agent,
                claim_id: $claim_id,
                subject: ("fleet deployment " + $run),
                predicate: "migration strategy",
                value: "single dedicated migrator",
                committed: true,
                observed_at: $timestamp
            }')
        ostk_demo_write_json "$run_dir/a-record.json" "$evidence"
        printf '%s\n' "$evidence"
        ;;

    recall-and-act)
        agent=$(ostk_demo_require_agent_role b "$run_id")
        claim_id=$(read_evidence_value "$run_dir/a-record.json" '.claim_id')
        response=$(
            jq -cn \
                --arg run "$run_id" \
                --arg agent "$agent" \
                '{
                    action: "search",
                    scope: {agent: $agent, session_id: $run},
                    query: "How should workers coordinate database schema changes before serving traffic?",
                    kind: "chunk",
                    limit: 10
                }' | call_mcp recall
        )
        printf '%s\n' "$response" | jq -e --argjson claim_id "$claim_id" '
            .diagnostics.retrieval.lanes == ["lexical", "dense"] and
            .diagnostics.retrieval.fusion == "rrf" and
            any(.data.hits[]; .extra.claim_id == $claim_id)
        ' >/dev/null || ostk_demo_die 'Agent B did not semantically recall Agent A claim through lexical+dense RRF'

        ostk_demo_require_command "${OSTK_DEMO_AWS_BIN:-aws}"
        key="ostk-demo/$run_id/agent-b/hold-workers.json"
        receipt=$(jq -cn \
            --arg run "$run_id" \
            --arg agent "$agent" \
            --argjson claim_id "$claim_id" \
            --arg bucket "$bucket" \
            --arg key "$key" \
            --arg timestamp "$(ostk_demo_timestamp)" \
            '{
                schema_version: 1,
                step: "agent_b_recall_action",
                run_id: $run,
                ostk_agent: $agent,
                action: "hold workers until migration completes",
                based_on_claim_id: $claim_id,
                retrieval: {lanes: ["lexical", "dense"], fusion: "rrf"},
                s3: {bucket: $bucket, key: $key},
                observed_at: $timestamp
            }')
        ostk_demo_write_json "$run_dir/b-action.json" "$receipt"
        ostk_demo_aws s3api put-object \
            --bucket "$bucket" \
            --key "$key" \
            --content-type application/json \
            --body "$run_dir/b-action.json" >/dev/null
        printf '%s\n' "$receipt"
        ;;

    record-conflict)
        agent=$(ostk_demo_require_agent_role c "$run_id")
        claim_a_id=$(read_evidence_value "$run_dir/a-record.json" '.claim_id')
        response=$(
            jq -cn \
                --arg run "$run_id" \
                --arg agent "$agent" \
                '{
                    action: "record",
                    scope: {agent: $agent, session_id: $run},
                    idempotency_key: ("ostk-demo/" + $run + "/conflicting-migration-decision"),
                    kind: "decision",
                    text: "Every application worker should run schema migration independently when it starts.",
                    subject: ("fleet deployment " + $run),
                    predicate: "migration strategy",
                    value: "every worker migrates independently",
                    actor: $agent
                }' | call_mcp remember
        )
        claim_c_id=$(printf '%s\n' "$response" | jq -e --arg agent "$agent" '
            if .data.receipt.committed == true and
               .data.claim.actor == $agent and
               .data.claim.state == "disputed" and
               (.data.claim.id | type) == "number"
            then .data.claim.id | if floor == . then . else error("claim ID is not an integer") end
            else error("Agent C incompatible claim was not committed as disputed")
            end
        ')
        conflict_id=$(printf '%s\n' "$response" | jq -er \
            --argjson claim_a_id "$claim_a_id" \
            --argjson claim_c_id "$claim_c_id" '
            [.conflicts[] |
                select(.state == "open") |
                select(.member_count == 2) |
                select(.members_truncated == false) |
                select((.members | length) == 2) |
                select(any(.members[]; .id == $claim_a_id and .state == "disputed")) |
                select(any(.members[]; .id == $claim_c_id and .state == "disputed"))
            ][0].id
        ')
        evidence=$(jq -cn \
            --arg run "$run_id" \
            --arg agent "$agent" \
            --argjson claim_a_id "$claim_a_id" \
            --argjson claim_c_id "$claim_c_id" \
            --argjson conflict_id "$conflict_id" \
            --arg timestamp "$(ostk_demo_timestamp)" \
            '{
                schema_version: 1,
                step: "agent_c_conflict",
                run_id: $run,
                ostk_agent: $agent,
                claim_id: $claim_c_id,
                incompatible_with_claim_id: $claim_a_id,
                conflict_id: $conflict_id,
                state: "open",
                member_count: 2,
                members_disputed: true,
                observed_at: $timestamp
            }')
        ostk_demo_write_json "$run_dir/c-conflict.json" "$evidence"
        printf '%s\n' "$evidence"
        ;;

    recall-conflict-and-pause)
        agent=$(ostk_demo_require_agent_role b "$run_id")
        claim_a_id=$(read_evidence_value "$run_dir/a-record.json" '.claim_id')
        claim_c_id=$(read_evidence_value "$run_dir/c-conflict.json" '.claim_id')
        response=$(
            jq -cn \
                --arg run "$run_id" \
                --arg agent "$agent" \
                '{
                    action: "conflicts",
                    scope: {agent: $agent, session_id: $run},
                    limit: 10,
                    include_resolved: false
                }' | call_mcp recall
        )
        conflict_id=$(printf '%s\n' "$response" | jq -er \
            --argjson claim_a_id "$claim_a_id" \
            --argjson claim_c_id "$claim_c_id" '
            [.conflicts[] |
                select(.state == "open") |
                select(.member_count == 2) |
                select(.members_truncated == false) |
                select((.members | length) == 2) |
                select(any(.members[]; .id == $claim_a_id and .state == "disputed")) |
                select(any(.members[]; .id == $claim_c_id and .state == "disputed"))
            ][0].id
        ')

        ostk_demo_require_command "${OSTK_DEMO_AWS_BIN:-aws}"
        key="ostk-demo/$run_id/agent-b/pause-rollout.json"
        receipt=$(jq -cn \
            --arg run "$run_id" \
            --arg agent "$agent" \
            --argjson conflict_id "$conflict_id" \
            --argjson claim_a_id "$claim_a_id" \
            --argjson claim_c_id "$claim_c_id" \
            --arg bucket "$bucket" \
            --arg key "$key" \
            --arg timestamp "$(ostk_demo_timestamp)" \
            '{
                schema_version: 1,
                step: "agent_b_conflict_pause",
                run_id: $run,
                ostk_agent: $agent,
                action: "pause rollout and escalate for operator review",
                based_on_conflict_id: $conflict_id,
                disputed_claim_ids: [$claim_a_id, $claim_c_id],
                conflict_member_count: 2,
                s3: {bucket: $bucket, key: $key},
                observed_at: $timestamp
            }')
        ostk_demo_write_json "$run_dir/b-pause.json" "$receipt"
        ostk_demo_aws s3api put-object \
            --bucket "$bucket" \
            --key "$key" \
            --content-type application/json \
            --body "$run_dir/b-pause.json" >/dev/null
        printf '%s\n' "$receipt"
        ;;
esac
