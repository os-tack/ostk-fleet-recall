//! Bounded reference policy agents for deployment and judging evidence.
//!
//! These agents are deliberately deterministic: they observe Fleet Recall,
//! apply an explicit deployment-safety policy, and persist the resulting
//! action with a citation. They prove the store → retrieve → act contract
//! without requiring OSTK, an LLM, or a third-party model provider.

use clap::ValueEnum;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::FleetScope;
use crate::ledger::normalize_key_part;
use crate::service::{
    FleetMemoryService, RecallAction, RecallRequest, RememberAction, RememberRequest, ServiceError,
    ServiceResult,
};

const EVIDENCE_SCHEMA: &str = "fleet-reference-agent-evidence-v1";
const DECISION_VALUE: &str = "single dedicated migrator";
const INCOMPATIBLE_DECISION_VALUE: &str = "every worker migrates independently";
const ACTION_HOLD: &str = "hold workers until migration completes";
const ACTION_ESCALATE: &str = "pause rollout for operator review";

/// One independently deployable step in the reference fleet scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReferenceAgentStep {
    RecordDecision,
    RecallAndAct,
    RecordConflict,
    RecallConflictAndEscalate,
}

impl ReferenceAgentStep {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RecordDecision => "record_decision",
            Self::RecallAndAct => "recall_and_act",
            Self::RecordConflict => "record_conflict",
            Self::RecallConflictAndEscalate => "recall_conflict_and_escalate",
        }
    }

    #[must_use]
    pub const fn trusted_agent(self) -> &'static str {
        match self {
            Self::RecordDecision => "agent-a",
            Self::RecallAndAct | Self::RecallConflictAndEscalate => "agent-b",
            Self::RecordConflict => "agent-c",
        }
    }
}

/// Run one policy-agent step against an already verified memory service.
pub async fn run_reference_agent(
    service: &dyn FleetMemoryService,
    scope: FleetScope,
    step: ReferenceAgentStep,
    run_id: &str,
) -> ServiceResult<Value> {
    validate_run_id(run_id)?;
    if scope.agent != step.trusted_agent() {
        return Err(ServiceError::InvalidRequest(format!(
            "reference step {} requires deployment-bound agent {:?}",
            step.as_str(),
            step.trusted_agent()
        )));
    }

    match step {
        ReferenceAgentStep::RecordDecision => record_decision(service, scope, run_id).await,
        ReferenceAgentStep::RecallAndAct => recall_and_act(service, scope, run_id).await,
        ReferenceAgentStep::RecordConflict => record_conflict(service, scope, run_id).await,
        ReferenceAgentStep::RecallConflictAndEscalate => {
            recall_conflict_and_escalate(service, scope, run_id).await
        }
    }
}

async fn record_decision(
    service: &dyn FleetMemoryService,
    scope: FleetScope,
    run_id: &str,
) -> ServiceResult<Value> {
    let key = reference_idempotency_key(&scope, run_id, "migration-decision")?;
    let arguments = decision_arguments(&scope, run_id, false);
    let first = service
        .remember(
            scope.clone(),
            RememberRequest::new(RememberAction::Record, Some(key.clone()), arguments.clone()),
        )
        .await?;
    let replay = service
        .remember(
            scope.clone(),
            RememberRequest::new(RememberAction::Record, Some(key), arguments),
        )
        .await?;
    let claim_id = mutation_claim_id(&first.data)?;
    if mutation_claim_id(&replay.data)? != claim_id
        || replay.data.get("idempotent_replay") != Some(&Value::Bool(true))
    {
        return Err(invariant("idempotent record/replay invariant failed"));
    }
    let first_was_replay = first
        .data
        .get("idempotent_replay")
        .and_then(Value::as_bool)
        .ok_or_else(|| invariant("first record result omitted replay status"))?;

    Ok(evidence(
        &scope,
        ReferenceAgentStep::RecordDecision,
        run_id,
        &json!({
            "claim_id": claim_id,
            "committed": true,
            "first_was_replay": first_was_replay,
            "replay_deduplicated": true,
        }),
    ))
}

async fn recall_and_act(
    service: &dyn FleetMemoryService,
    scope: FleetScope,
    run_id: &str,
) -> ServiceResult<Value> {
    let subject = scenario_subject(run_id);
    let claim_key = expected_claim_key(&subject, "migration strategy");
    let recall = service
        .recall(
            scope.clone(),
            RecallRequest::new(
                RecallAction::Search,
                object(&json!({
                    "query": format!(
                        "{subject}: coordinate schema changes with one dedicated migrator"
                    ),
                    "kind": "chunk",
                    "limit": 10,
                }))?,
            ),
        )
        .await?;
    let recalled_claim_id = recalled_claim_id(&recall.data, &claim_key)?;
    verify_hybrid_retrieval(&recall.diagnostics)?;

    let recalled_claim = recall_claim(service, scope.clone(), recalled_claim_id).await?;
    validate_claim(
        &recalled_claim,
        ExpectedClaim {
            id: recalled_claim_id,
            project: &scope.project,
            claim_key: &claim_key,
            kind: "decision",
            state: "active",
            actor: "agent-a",
            polarity: 1,
            value: &Value::String(DECISION_VALUE.into()),
        },
        "recalled migration decision",
    )?;

    let action_claim_id =
        persist_recalled_action(service, &scope, run_id, &subject, recalled_claim_id).await?;

    Ok(evidence(
        &scope,
        ReferenceAgentStep::RecallAndAct,
        run_id,
        &json!({
            "recalled_claim_id": recalled_claim_id,
            "retrieval_lanes": ["lexical", "dense"],
            "fusion": "rrf",
            "action": ACTION_HOLD,
            "action_claim_id": action_claim_id,
            "based_on_claim_id": recalled_claim_id,
        }),
    ))
}

async fn persist_recalled_action(
    service: &dyn FleetMemoryService,
    scope: &FleetScope,
    run_id: &str,
    subject: &str,
    recalled_claim_id: i64,
) -> ServiceResult<i64> {
    let mutation = service
        .remember(
            scope.clone(),
            RememberRequest::new(
                RememberAction::Record,
                Some(reference_idempotency_key(
                    scope,
                    run_id,
                    "recalled-action",
                )?),
                object(&json!({
                    "kind": "procedure",
                    "text": "The policy agent will hold application workers until the dedicated schema migrator completes.",
                    "subject": subject,
                    "predicate": "rollout action",
                    "polarity": 1,
                    "value": {
                        "action": ACTION_HOLD,
                        "based_on_claim_id": recalled_claim_id,
                    },
                    "actor": scope.agent,
                }))?,
            ),
        )
        .await?;
    let action_claim_id = mutation_claim_id(&mutation.data)?;
    if mutation.data.pointer("/claim/value/action") != Some(&Value::String(ACTION_HOLD.into()))
        || mutation.data.pointer("/claim/value/based_on_claim_id")
            != Some(&json!(recalled_claim_id))
    {
        return Err(invariant(
            "persisted action lost its recalled-claim citation",
        ));
    }
    let action_value = json!({
        "action": ACTION_HOLD,
        "based_on_claim_id": recalled_claim_id,
    });
    let action_claim = recall_claim(service, scope.clone(), action_claim_id).await?;
    validate_claim(
        &action_claim,
        ExpectedClaim {
            id: action_claim_id,
            project: &scope.project,
            claim_key: &expected_claim_key(subject, "rollout action"),
            kind: "procedure",
            state: "active",
            actor: "agent-b",
            polarity: 1,
            value: &action_value,
        },
        "persisted rollout action",
    )?;

    Ok(action_claim_id)
}

async fn record_conflict(
    service: &dyn FleetMemoryService,
    scope: FleetScope,
    run_id: &str,
) -> ServiceResult<Value> {
    let mutation = service
        .remember(
            scope.clone(),
            RememberRequest::new(
                RememberAction::Record,
                Some(reference_idempotency_key(
                    &scope,
                    run_id,
                    "conflicting-decision",
                )?),
                decision_arguments(&scope, run_id, true),
            ),
        )
        .await?;
    let claim_id = mutation_claim_id(&mutation.data)?;
    let subject = scenario_subject(run_id);
    let claim_key = expected_claim_key(&subject, "migration strategy");
    let conflict = matching_conflict(&mutation.conflicts, &scope.project, &claim_key)?;
    if conflict.incompatible_claim_id != claim_id {
        return Err(invariant(
            "new incompatible claim is not the conflict's trusted agent-c member",
        ));
    }

    Ok(evidence(
        &scope,
        ReferenceAgentStep::RecordConflict,
        run_id,
        &json!({
            "claim_id": claim_id,
            "incompatible_value_recorded": true,
            "conflict_id": conflict.id,
            "member_claim_ids": conflict.member_claim_ids,
            "decision_claim_id": conflict.decision_claim_id,
            "incompatible_claim_id": conflict.incompatible_claim_id,
        }),
    ))
}

async fn recall_conflict_and_escalate(
    service: &dyn FleetMemoryService,
    scope: FleetScope,
    run_id: &str,
) -> ServiceResult<Value> {
    let conflicts = service
        .recall(
            scope.clone(),
            RecallRequest::new(
                RecallAction::Conflicts,
                object(&json!({ "include_resolved": false, "limit": 100 }))?,
            ),
        )
        .await?;
    let subject = scenario_subject(run_id);
    let claim_key = expected_claim_key(&subject, "migration strategy");
    let conflict = matching_conflict(&conflicts.conflicts, &scope.project, &claim_key)?;

    let mutation = service
        .remember(
            scope.clone(),
            RememberRequest::new(
                RememberAction::Record,
                Some(reference_idempotency_key(
                    &scope,
                    run_id,
                    "conflict-escalation",
                )?),
                object(&json!({
                    "kind": "open_question",
                    "text": "The policy agent paused rollout and escalated the incompatible migration strategies for operator review.",
                    "subject": subject,
                    "predicate": "escalation status",
                    "polarity": 1,
                    "value": {
                        "action": ACTION_ESCALATE,
                        "conflict_id": conflict.id,
                        "next_step": "operator review",
                    },
                    "actor": scope.agent,
                }))?,
            ),
        )
        .await?;
    let escalation_claim_id = mutation_claim_id(&mutation.data)?;
    if mutation.data.pointer("/claim/value/conflict_id") != Some(&json!(conflict.id)) {
        return Err(invariant("persisted escalation lost its conflict citation"));
    }
    let escalation_value = json!({
        "action": ACTION_ESCALATE,
        "conflict_id": conflict.id,
        "next_step": "operator review",
    });
    let escalation_claim = recall_claim(service, scope.clone(), escalation_claim_id).await?;
    validate_claim(
        &escalation_claim,
        ExpectedClaim {
            id: escalation_claim_id,
            project: &scope.project,
            claim_key: &expected_claim_key(&subject, "escalation status"),
            kind: "open_question",
            state: "active",
            actor: "agent-b",
            polarity: 1,
            value: &escalation_value,
        },
        "persisted conflict escalation",
    )?;

    Ok(evidence(
        &scope,
        ReferenceAgentStep::RecallConflictAndEscalate,
        run_id,
        &json!({
            "conflict_id": conflict.id,
            "member_claim_ids": conflict.member_claim_ids,
            "decision_claim_id": conflict.decision_claim_id,
            "incompatible_claim_id": conflict.incompatible_claim_id,
            "action": ACTION_ESCALATE,
            "escalation_claim_id": escalation_claim_id,
            "based_on_conflict_id": conflict.id,
        }),
    ))
}

fn decision_arguments(scope: &FleetScope, run_id: &str, incompatible: bool) -> Map<String, Value> {
    let (text, value) = if incompatible {
        (
            "Every worker should run schema migration independently when it starts.",
            INCOMPATIBLE_DECISION_VALUE,
        )
    } else {
        (
            "Fleet schema migration runs through one dedicated migrator before serving traffic.",
            DECISION_VALUE,
        )
    };
    object(&json!({
        "kind": "decision",
        "text": text,
        "subject": scenario_subject(run_id),
        "predicate": "migration strategy",
        "polarity": 1,
        "value": value,
        "actor": scope.agent,
    }))
    .expect("static reference-agent arguments are objects")
}

fn recalled_claim_id(data: &Value, expected_key: &str) -> ServiceResult<i64> {
    data.get("hits")
        .and_then(Value::as_array)
        .and_then(|hits| {
            hits.iter().find_map(|hit| {
                (hit.pointer("/extra/claim_key").and_then(Value::as_str) == Some(expected_key))
                    .then(|| hit.pointer("/extra/claim_id").and_then(Value::as_i64))
                    .flatten()
            })
        })
        .filter(|id| *id > 0)
        .ok_or_else(|| invariant("semantic recall did not return the expected deliberate claim"))
}

fn verify_hybrid_retrieval(diagnostics: &Map<String, Value>) -> ServiceResult<()> {
    let retrieval = diagnostics
        .get("retrieval")
        .ok_or_else(|| invariant("recall result omitted retrieval diagnostics"))?;
    if retrieval.get("lanes") != Some(&json!(["lexical", "dense"]))
        || retrieval.get("fusion") != Some(&Value::String("rrf".into()))
    {
        return Err(invariant("reference recall did not use lexical+dense RRF"));
    }
    Ok(())
}

async fn recall_claim(
    service: &dyn FleetMemoryService,
    scope: FleetScope,
    claim_id: i64,
) -> ServiceResult<Value> {
    let result = service
        .recall(
            scope,
            RecallRequest::new(
                RecallAction::Get,
                object(&json!({ "kind": "claim", "id": claim_id }))?,
            ),
        )
        .await?;
    result
        .data
        .get("claim")
        .filter(|claim| !claim.is_null())
        .cloned()
        .ok_or_else(|| invariant("recall(get) did not return the requested durable claim"))
}

#[derive(Clone, Copy)]
struct ExpectedClaim<'a> {
    id: i64,
    project: &'a str,
    claim_key: &'a str,
    kind: &'a str,
    state: &'a str,
    actor: &'a str,
    polarity: i16,
    value: &'a Value,
}

fn validate_claim(
    claim: &Value,
    expected: ExpectedClaim<'_>,
    description: &str,
) -> ServiceResult<()> {
    if claim.get("id").and_then(Value::as_i64) != Some(expected.id)
        || claim.get("project").and_then(Value::as_str) != Some(expected.project)
        || claim.get("claim_key").and_then(Value::as_str) != Some(expected.claim_key)
        || claim.get("kind").and_then(Value::as_str) != Some(expected.kind)
        || claim.get("state").and_then(Value::as_str) != Some(expected.state)
        || claim.get("actor").and_then(Value::as_str) != Some(expected.actor)
        || claim.get("polarity").and_then(Value::as_i64) != Some(i64::from(expected.polarity))
        || claim.get("value") != Some(expected.value)
    {
        return Err(invariant(&format!(
            "{description} failed exact identity, provenance, value, or state validation"
        )));
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct MatchedConflict {
    id: i64,
    member_claim_ids: Vec<i64>,
    decision_claim_id: i64,
    incompatible_claim_id: i64,
}

fn matching_conflict(
    conflicts: &[Value],
    expected_project: &str,
    expected_key: &str,
) -> ServiceResult<MatchedConflict> {
    for conflict in conflicts {
        if conflict.get("project").and_then(Value::as_str) != Some(expected_project)
            || conflict.get("claim_key").and_then(Value::as_str) != Some(expected_key)
            || conflict.get("state").and_then(Value::as_str) != Some("open")
            || conflict.get("member_count").and_then(Value::as_u64) != Some(2)
            || conflict.get("members_truncated") != Some(&Value::Bool(false))
            || conflict.get("member_values_elided") != Some(&Value::Bool(false))
        {
            continue;
        }
        let Some(id) = conflict
            .get("id")
            .and_then(Value::as_i64)
            .filter(|id| *id > 0)
        else {
            continue;
        };
        let Some(members) = conflict.get("members").and_then(Value::as_array) else {
            continue;
        };
        if members.len() != 2 {
            continue;
        }
        let member_ids = members
            .iter()
            .filter_map(|member| member.get("id").and_then(Value::as_i64))
            .collect::<Vec<_>>();
        let decision_member = members.iter().find(|member| {
            exact_conflict_member(
                member,
                expected_project,
                expected_key,
                "agent-a",
                DECISION_VALUE,
            )
        });
        let incompatible_member = members.iter().find(|member| {
            exact_conflict_member(
                member,
                expected_project,
                expected_key,
                "agent-c",
                INCOMPATIBLE_DECISION_VALUE,
            )
        });
        if member_ids.len() == 2
            && member_ids.iter().all(|member_id| *member_id > 0)
            && member_ids[0] != member_ids[1]
            && decision_member.is_some()
            && incompatible_member.is_some()
        {
            let decision_claim_id = decision_member
                .and_then(|member| member.get("id"))
                .and_then(Value::as_i64)
                .expect("exact conflict member has a positive id");
            let incompatible_claim_id = incompatible_member
                .and_then(|member| member.get("id"))
                .and_then(Value::as_i64)
                .expect("exact conflict member has a positive id");
            return Ok(MatchedConflict {
                id,
                member_claim_ids: member_ids,
                decision_claim_id,
                incompatible_claim_id,
            });
        }
    }
    Err(invariant(
        "open two-member migration conflict was not surfaced",
    ))
}

fn exact_conflict_member(
    member: &Value,
    expected_project: &str,
    expected_key: &str,
    expected_actor: &str,
    expected_value: &str,
) -> bool {
    member
        .get("id")
        .and_then(Value::as_i64)
        .is_some_and(|id| id > 0)
        && member.get("project").and_then(Value::as_str) == Some(expected_project)
        && member.get("claim_key").and_then(Value::as_str) == Some(expected_key)
        && member.get("kind").and_then(Value::as_str) == Some("decision")
        && member.get("state").and_then(Value::as_str) == Some("disputed")
        && member.get("actor").and_then(Value::as_str) == Some(expected_actor)
        && member.get("polarity").and_then(Value::as_i64) == Some(1)
        && member.get("value").and_then(Value::as_str) == Some(expected_value)
}

fn mutation_claim_id(data: &Value) -> ServiceResult<i64> {
    data.pointer("/claim/id")
        .and_then(Value::as_i64)
        .filter(|id| *id > 0)
        .ok_or_else(|| invariant("remember result omitted a positive claim id"))
}

fn evidence(scope: &FleetScope, step: ReferenceAgentStep, run_id: &str, result: &Value) -> Value {
    json!({
        "schema": EVIDENCE_SCHEMA,
        "run_id": run_id,
        "step": step.as_str(),
        "agent": scope.agent,
        "project": scope.project,
        "policy": "bounded-schema-migration-safety-v1",
        "result": result,
    })
}

fn scenario_subject(run_id: &str) -> String {
    format!("fleet deployment {run_id}")
}

fn expected_claim_key(subject: &str, predicate: &str) -> String {
    format!(
        "{}::{}",
        normalize_key_part(subject),
        normalize_key_part(predicate)
    )
}

fn reference_idempotency_key(
    scope: &FleetScope,
    run_id: &str,
    operation: &str,
) -> ServiceResult<String> {
    let mut digest = Sha256::new();
    digest.update(b"fleet-reference-agent-project-v1\0");
    digest.update(scope.project.as_bytes());
    let key = format!(
        "reference-agent/v1/project-{}/{run_id}/{operation}",
        hex::encode(digest.finalize())
    );
    if key.len() > 256 {
        return Err(invariant(
            "reference-agent idempotency key exceeds the durable receipt limit",
        ));
    }
    Ok(key)
}

fn object(value: &Value) -> ServiceResult<Map<String, Value>> {
    value
        .as_object()
        .cloned()
        .ok_or_else(|| invariant("reference agent constructed a non-object request"))
}

fn validate_run_id(run_id: &str) -> ServiceResult<()> {
    if run_id.is_empty()
        || run_id.len() > 64
        || run_id.starts_with('-')
        || run_id
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')))
    {
        return Err(ServiceError::InvalidRequest(
            "reference agent run id must be 1-64 ASCII letters, digits, dot, underscore, or hyphen and cannot start with hyphen".into(),
        ));
    }
    Ok(())
}

fn invariant(message: &str) -> ServiceError {
    ServiceError::Internal(format!("reference agent invariant failed: {message}"))
}

#[cfg(test)]
fn test_scope(agent: &str) -> FleetScope {
    use ostk_recall_core::PrivacyTier;
    use uuid::Uuid;

    FleetScope::new(
        Uuid::from_u128(1),
        "reference-project",
        agent,
        None,
        PrivacyTier::T1Project,
    )
    .expect("test scope")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;

    use super::*;
    use crate::service::{RecallResult, RememberResult};

    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    enum Tamper {
        #[default]
        None,
        DecisionActor,
        DecisionValue,
        DecisionState,
        DecisionPolarity,
        ActionActor,
        ActionValue,
        ActionState,
        ActionPolarity,
        EscalationActor,
        EscalationValue,
        EscalationState,
        EscalationPolarity,
        ConflictActor,
        ConflictValue,
        ConflictMemberState,
        ConflictPolarity,
    }

    #[derive(Default)]
    struct FakeService {
        decision_calls: AtomicUsize,
        tamper: Tamper,
        recall_actions: Mutex<Vec<RecallAction>>,
        remember_keys: Mutex<Vec<String>>,
    }

    impl FakeService {
        fn with_tamper(tamper: Tamper) -> Self {
            Self {
                tamper,
                ..Self::default()
            }
        }

        fn recall_actions(&self) -> Vec<RecallAction> {
            self.recall_actions
                .lock()
                .expect("fake recall action lock")
                .clone()
        }

        fn remember_keys(&self) -> Vec<String> {
            self.remember_keys
                .lock()
                .expect("fake remember key lock")
                .clone()
        }
    }

    fn fake_claim(id: i64, tamper: Tamper) -> Value {
        let (kind, key, actor, state, mut value) = match id {
            101 => (
                "decision",
                "fleet-deployment-run-1::migration-strategy",
                "agent-a",
                "active",
                json!(DECISION_VALUE),
            ),
            102 => (
                "procedure",
                "fleet-deployment-run-1::rollout-action",
                "agent-b",
                "active",
                json!({
                    "action": ACTION_HOLD,
                    "based_on_claim_id": 101,
                }),
            ),
            204 => (
                "open_question",
                "fleet-deployment-run-1::escalation-status",
                "agent-b",
                "active",
                json!({
                    "action": ACTION_ESCALATE,
                    "conflict_id": 303,
                    "next_step": "operator review",
                }),
            ),
            _ => return Value::Null,
        };
        let mut actor = actor;
        let mut state = state;
        let mut polarity = 1;
        match (id, tamper) {
            (101, Tamper::DecisionActor)
            | (102, Tamper::ActionActor)
            | (204, Tamper::EscalationActor) => actor = "agent-c",
            (101, Tamper::DecisionValue) => value = json!(INCOMPATIBLE_DECISION_VALUE),
            (101, Tamper::DecisionState) => state = "disputed",
            (101, Tamper::DecisionPolarity)
            | (102, Tamper::ActionPolarity)
            | (204, Tamper::EscalationPolarity) => polarity = -1,
            (102, Tamper::ActionValue) => value["based_on_claim_id"] = json!(999),
            (204, Tamper::EscalationValue) => value["conflict_id"] = json!(999),
            (102, Tamper::ActionState) | (204, Tamper::EscalationState) => state = "retracted",
            _ => {}
        }
        json!({
            "id": id,
            "project": "reference-project",
            "kind": kind,
            "claim_key": key,
            "state": state,
            "actor": actor,
            "polarity": polarity,
            "value": value,
        })
    }

    fn fake_conflict(tamper: Tamper) -> Value {
        let mut conflict = json!({
            "id": 303,
            "project": "reference-project",
            "claim_key": "fleet-deployment-run-1::migration-strategy",
            "state": "open",
            "member_count": 2,
            "members_truncated": false,
            "member_values_elided": false,
            "members": [
                {
                    "id": 101,
                    "project": "reference-project",
                    "kind": "decision",
                    "claim_key": "fleet-deployment-run-1::migration-strategy",
                    "state": "disputed",
                    "actor": "agent-a",
                    "polarity": 1,
                    "value": DECISION_VALUE,
                },
                {
                    "id": 202,
                    "project": "reference-project",
                    "kind": "decision",
                    "claim_key": "fleet-deployment-run-1::migration-strategy",
                    "state": "disputed",
                    "actor": "agent-c",
                    "polarity": 1,
                    "value": INCOMPATIBLE_DECISION_VALUE,
                }
            ]
        });
        match tamper {
            Tamper::ConflictActor => conflict["members"][0]["actor"] = json!("agent-c"),
            Tamper::ConflictValue => conflict["members"][1]["value"] = json!(DECISION_VALUE),
            Tamper::ConflictMemberState => {
                conflict["members"][0]["state"] = json!("active");
            }
            Tamper::ConflictPolarity => conflict["members"][0]["polarity"] = json!(-1),
            _ => {}
        }
        conflict
    }

    #[async_trait]
    impl FleetMemoryService for FakeService {
        async fn recall(
            &self,
            _scope: FleetScope,
            request: RecallRequest,
        ) -> ServiceResult<RecallResult> {
            self.recall_actions
                .lock()
                .expect("fake recall action lock")
                .push(request.action);
            match request.action {
                RecallAction::Search => {
                    let mut result = RecallResult::new(json!({
                        "hits": [{
                            "extra": {
                                "claim_id": 101,
                                "claim_key": "fleet-deployment-run-1::migration-strategy",
                            }
                        }]
                    }));
                    result.diagnostics.insert(
                        "retrieval".into(),
                        json!({ "lanes": ["lexical", "dense"], "fusion": "rrf" }),
                    );
                    Ok(result)
                }
                RecallAction::Get => {
                    let id = request
                        .arguments
                        .get("id")
                        .and_then(Value::as_i64)
                        .ok_or_else(|| {
                            ServiceError::InvalidRequest("fake get omitted id".into())
                        })?;
                    Ok(RecallResult::new(json!({
                        "claim": fake_claim(id, self.tamper),
                    })))
                }
                RecallAction::Conflicts => {
                    let conflict = fake_conflict(self.tamper);
                    let mut result = RecallResult::new(json!({ "conflicts": [&conflict] }));
                    result.conflicts.push(conflict);
                    Ok(result)
                }
                _ => Err(ServiceError::InvalidRequest(
                    "unsupported fake recall".into(),
                )),
            }
        }

        async fn remember(
            &self,
            scope: FleetScope,
            request: RememberRequest,
        ) -> ServiceResult<RememberResult> {
            let key = request.idempotency_key.as_deref().unwrap_or_default();
            self.remember_keys
                .lock()
                .expect("fake remember key lock")
                .push(key.to_owned());
            let (id, kind, claim_key, state, replay, value, conflicts) =
                if key.ends_with("migration-decision") {
                    (
                        101,
                        "decision",
                        "fleet-deployment-run-1::migration-strategy",
                        "active",
                        self.decision_calls.fetch_add(1, Ordering::SeqCst) > 0,
                        request.arguments.get("value").cloned(),
                        Vec::new(),
                    )
                } else if key.ends_with("recalled-action") {
                    (
                        102,
                        "procedure",
                        "fleet-deployment-run-1::rollout-action",
                        "active",
                        false,
                        request.arguments.get("value").cloned(),
                        Vec::new(),
                    )
                } else if key.ends_with("conflicting-decision") {
                    (
                        202,
                        "decision",
                        "fleet-deployment-run-1::migration-strategy",
                        "disputed",
                        false,
                        request.arguments.get("value").cloned(),
                        vec![fake_conflict(self.tamper)],
                    )
                } else if key.ends_with("conflict-escalation") {
                    (
                        204,
                        "open_question",
                        "fleet-deployment-run-1::escalation-status",
                        "active",
                        false,
                        request.arguments.get("value").cloned(),
                        Vec::new(),
                    )
                } else {
                    return Err(ServiceError::InvalidRequest("unexpected fake key".into()));
                };
            let mut result = RememberResult::new(json!({
                "operation": "record",
                "claim": {
                    "id": id,
                    "project": scope.project,
                    "kind": kind,
                    "claim_key": claim_key,
                    "state": state,
                    "actor": scope.agent,
                    "polarity": request
                        .arguments
                        .get("polarity")
                        .cloned()
                        .unwrap_or_else(|| json!(1)),
                    "value": value,
                },
                "idempotent_replay": replay,
            }));
            result.conflicts = conflicts;
            Ok(result)
        }
    }

    #[test]
    fn run_ids_and_trusted_agents_fail_closed() {
        for invalid in [
            "",
            "-clap-option",
            "../escape",
            "contains space",
            &"a".repeat(65),
        ] {
            assert!(validate_run_id(invalid).is_err());
        }
        assert!(validate_run_id("cloud-proof_2026-08-13").is_ok());
        assert_eq!(ReferenceAgentStep::RecallAndAct.trusted_agent(), "agent-b");
        assert_eq!(
            ReferenceAgentStep::RecallConflictAndEscalate.trusted_agent(),
            "agent-b"
        );
    }

    #[test]
    fn idempotency_receipts_are_stable_and_project_scoped() {
        let first = test_scope("agent-a");
        let mut second = first.clone();
        second.project = "another-reference-project".into();

        let first_key = reference_idempotency_key(&first, "run-1", "migration-decision").unwrap();
        let first_replay_key =
            reference_idempotency_key(&first, "run-1", "migration-decision").unwrap();
        let second_key = reference_idempotency_key(&second, "run-1", "migration-decision").unwrap();

        assert_eq!(first_key, first_replay_key);
        assert_ne!(first_key, second_key);
        assert!(first_key.starts_with("reference-agent/v1/project-"));
        assert!(first_key.ends_with("/run-1/migration-decision"));
        assert!(first_key.len() <= 256);
    }

    #[test]
    fn recall_selection_requires_the_exact_claim_key() {
        let data = json!({
            "hits": [
                {"extra": {"claim_id": 7, "claim_key": "other::key"}},
                {"extra": {"claim_id": 9, "claim_key": "fleet-deployment-run-1::migration-strategy"}}
            ]
        });
        assert_eq!(
            recalled_claim_id(&data, "fleet-deployment-run-1::migration-strategy").unwrap(),
            9
        );
        assert!(recalled_claim_id(&data, "missing::key").is_err());
    }

    #[test]
    fn conflict_selection_requires_exact_members_and_values() {
        let conflict = fake_conflict(Tamper::None);
        assert_eq!(
            matching_conflict(
                &[conflict],
                "reference-project",
                "fleet-deployment-run-1::migration-strategy"
            )
            .unwrap(),
            MatchedConflict {
                id: 303,
                member_claim_ids: vec![101, 202],
                decision_claim_id: 101,
                incompatible_claim_id: 202,
            }
        );

        for tamper in [
            Tamper::ConflictActor,
            Tamper::ConflictValue,
            Tamper::ConflictMemberState,
            Tamper::ConflictPolarity,
        ] {
            assert!(
                matching_conflict(
                    &[fake_conflict(tamper)],
                    "reference-project",
                    "fleet-deployment-run-1::migration-strategy"
                )
                .is_err(),
                "tampered conflict {tamper:?} must fail closed"
            );
        }

        let mut elided = fake_conflict(Tamper::None);
        elided["member_values_elided"] = json!(true);
        assert!(
            matching_conflict(
                &[elided],
                "reference-project",
                "fleet-deployment-run-1::migration-strategy"
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn reference_policy_chain_retrieves_then_persists_citations() {
        let service = Arc::new(FakeService::default());
        let decision = run_reference_agent(
            service.as_ref(),
            test_scope("agent-a"),
            ReferenceAgentStep::RecordDecision,
            "run-1",
        )
        .await
        .unwrap();
        assert_eq!(decision["result"]["claim_id"], 101);
        assert_eq!(decision["result"]["replay_deduplicated"], true);
        let action = run_reference_agent(
            service.as_ref(),
            test_scope("agent-b"),
            ReferenceAgentStep::RecallAndAct,
            "run-1",
        )
        .await
        .unwrap();
        assert_eq!(action["result"]["recalled_claim_id"], 101);
        assert_eq!(action["result"]["based_on_claim_id"], 101);
        assert_eq!(action["result"]["action_claim_id"], 102);

        let conflict = run_reference_agent(
            service.as_ref(),
            test_scope("agent-c"),
            ReferenceAgentStep::RecordConflict,
            "run-1",
        )
        .await
        .unwrap();
        assert_eq!(conflict["result"]["conflict_id"], 303);

        let escalation = run_reference_agent(
            service.as_ref(),
            test_scope("agent-b"),
            ReferenceAgentStep::RecallConflictAndEscalate,
            "run-1",
        )
        .await
        .unwrap();
        assert_eq!(escalation["result"]["based_on_conflict_id"], 303);
        assert_eq!(escalation["result"]["escalation_claim_id"], 204);
        assert_eq!(
            service.recall_actions(),
            vec![
                RecallAction::Search,
                RecallAction::Get,
                RecallAction::Get,
                RecallAction::Conflicts,
                RecallAction::Get,
            ]
        );
        let keys = service.remember_keys();
        assert_eq!(keys.len(), 5);
        assert_eq!(keys[0], keys[1]);
        assert!(
            keys.iter()
                .all(|key| key.starts_with("reference-agent/v1/project-"))
        );
    }

    #[tokio::test]
    async fn recalled_decision_provenance_value_and_state_fail_closed_before_action() {
        for tamper in [
            Tamper::DecisionActor,
            Tamper::DecisionValue,
            Tamper::DecisionState,
            Tamper::DecisionPolarity,
        ] {
            let service = FakeService::with_tamper(tamper);
            let error = run_reference_agent(
                &service,
                test_scope("agent-b"),
                ReferenceAgentStep::RecallAndAct,
                "run-1",
            )
            .await
            .unwrap_err();
            assert!(
                matches!(error, ServiceError::Internal(_)),
                "tampered decision {tamper:?} must fail as an invariant"
            );
            assert_eq!(
                service.recall_actions(),
                vec![RecallAction::Search, RecallAction::Get]
            );
            assert!(service.remember_keys().is_empty());
        }
    }

    #[tokio::test]
    async fn persisted_action_is_reread_and_exactly_validated() {
        for tamper in [
            Tamper::ActionActor,
            Tamper::ActionValue,
            Tamper::ActionState,
            Tamper::ActionPolarity,
        ] {
            let service = FakeService::with_tamper(tamper);
            let error = run_reference_agent(
                &service,
                test_scope("agent-b"),
                ReferenceAgentStep::RecallAndAct,
                "run-1",
            )
            .await
            .unwrap_err();
            assert!(
                matches!(error, ServiceError::Internal(_)),
                "tampered action {tamper:?} must fail as an invariant"
            );
            assert_eq!(
                service.recall_actions(),
                vec![RecallAction::Search, RecallAction::Get, RecallAction::Get]
            );
            assert_eq!(service.remember_keys().len(), 1);
        }
    }

    #[tokio::test]
    async fn persisted_escalation_is_reread_and_exactly_validated() {
        for tamper in [
            Tamper::EscalationActor,
            Tamper::EscalationValue,
            Tamper::EscalationState,
            Tamper::EscalationPolarity,
        ] {
            let service = FakeService::with_tamper(tamper);
            let error = run_reference_agent(
                &service,
                test_scope("agent-b"),
                ReferenceAgentStep::RecallConflictAndEscalate,
                "run-1",
            )
            .await
            .unwrap_err();
            assert!(
                matches!(error, ServiceError::Internal(_)),
                "tampered escalation {tamper:?} must fail as an invariant"
            );
            assert_eq!(
                service.recall_actions(),
                vec![RecallAction::Conflicts, RecallAction::Get]
            );
            assert_eq!(service.remember_keys().len(), 1);
        }
    }

    #[tokio::test]
    async fn conflict_steps_reject_wrong_member_provenance_value_or_state() {
        for tamper in [
            Tamper::ConflictActor,
            Tamper::ConflictValue,
            Tamper::ConflictMemberState,
            Tamper::ConflictPolarity,
        ] {
            let record_service = FakeService::with_tamper(tamper);
            assert!(
                run_reference_agent(
                    &record_service,
                    test_scope("agent-c"),
                    ReferenceAgentStep::RecordConflict,
                    "run-1",
                )
                .await
                .is_err(),
                "record conflict accepted tamper {tamper:?}"
            );

            let recall_service = FakeService::with_tamper(tamper);
            assert!(
                run_reference_agent(
                    &recall_service,
                    test_scope("agent-b"),
                    ReferenceAgentStep::RecallConflictAndEscalate,
                    "run-1",
                )
                .await
                .is_err(),
                "recalled conflict accepted tamper {tamper:?}"
            );
            assert!(recall_service.remember_keys().is_empty());
        }
    }

    #[tokio::test]
    async fn reference_step_rejects_the_wrong_deployment_identity() {
        let error = run_reference_agent(
            &FakeService::default(),
            test_scope("agent-c"),
            ReferenceAgentStep::RecallAndAct,
            "run-1",
        )
        .await
        .unwrap_err();
        assert!(matches!(error, ServiceError::InvalidRequest(_)));
    }
}
