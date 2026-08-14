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
const SELF_AUDIT_PREDICATE: &str = "MCP remember supports deliberate retractions";
const MIGRATION_CONFLICT_SOURCE_ID: &str = "rich-demo/operations/week-01/conflict-migration_owner";
const DOCUMENTATION_SOURCE_ID: &str = "examples/README.md";
const TOOLS_SOURCE_ID: &str = "src/mcp/tools.rs";
const APPLICATION_SOURCE_ID: &str = "src/application.rs";
const DOCUMENTATION_SOURCE_CONFIG_ID: &str = "rich-demo:docs:v1";
const SELF_AUDIT_SOURCE_CONFIG_ID: &str = "rich-demo:self-audit:v1";
const RETRACTION_SPEC_CLAIM_TEXT: &str = "Repository guidance says MCP remember supports deliberate retractions so their provenance and transaction semantics are exercised.";
const RETRACTION_IMPLEMENTATION_CLAIM_TEXT: &str = "The current MCP remember tool and service implementation support record only; deliberate retraction is outside the implemented vertical slice.";

/// One independently deployable step in the reference fleet scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReferenceAgentStep {
    RecordDecision,
    RecallAndAct,
    RecordConflict,
    RecallConflictAndEscalate,
    RecordRetractionSpecClaim,
    RecordRetractionImplementationClaim,
}

impl ReferenceAgentStep {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RecordDecision => "record_decision",
            Self::RecallAndAct => "recall_and_act",
            Self::RecordConflict => "record_conflict",
            Self::RecallConflictAndEscalate => "recall_conflict_and_escalate",
            Self::RecordRetractionSpecClaim => "record_retraction_spec_claim",
            Self::RecordRetractionImplementationClaim => "record_retraction_implementation_claim",
        }
    }

    #[must_use]
    pub const fn trusted_agent(self) -> &'static str {
        match self {
            Self::RecordDecision | Self::RecordRetractionSpecClaim => "agent-a",
            Self::RecallAndAct | Self::RecallConflictAndEscalate => "agent-b",
            Self::RecordConflict | Self::RecordRetractionImplementationClaim => "agent-c",
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
        ReferenceAgentStep::RecordRetractionSpecClaim => {
            record_retraction_spec_claim(service, scope, run_id).await
        }
        ReferenceAgentStep::RecordRetractionImplementationClaim => {
            record_retraction_implementation_claim(service, scope, run_id).await
        }
    }
}

async fn record_decision(
    service: &dyn FleetMemoryService,
    scope: FleetScope,
    run_id: &str,
) -> ServiceResult<Value> {
    let sources = retrieve_migration_source(service, scope.clone()).await?;
    let key = reference_idempotency_key(&scope, run_id, "migration-decision")?;
    let arguments = decision_arguments(&scope, run_id, false, &sources);
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
    let sources = retrieve_migration_source(service, scope.clone()).await?;
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
                decision_arguments(&scope, run_id, true, &sources),
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExactSourceChunk {
    chunk_id: String,
    source: String,
    source_id: String,
    source_config_id: String,
    text: String,
    content_sha256: String,
}

impl ExactSourceChunk {
    fn support(&self) -> Value {
        json!({
            "source_config_id": self.source_config_id,
            "source": self.source,
            "source_id": self.source_id,
            "chunk_id": self.chunk_id,
            "content_sha256": self.content_sha256,
            "excerpt": self.text,
            "relation": "supports",
        })
    }

    fn coordinate(&self) -> Value {
        json!({
            "source_config_id": self.source_config_id,
            "source": self.source,
            "source_id": self.source_id,
            "chunk_id": self.chunk_id,
            "content_sha256": self.content_sha256,
        })
    }
}

#[derive(Clone, Copy)]
struct ExpectedSourceChunk<'a> {
    source: &'a str,
    source_id: &'a str,
    source_config_id: &'a str,
    markers: &'a [&'a str],
}

async fn record_retraction_spec_claim(
    service: &dyn FleetMemoryService,
    scope: FleetScope,
    run_id: &str,
) -> ServiceResult<Value> {
    record_self_audit_claim(
        service,
        scope,
        run_id,
        SelfAuditClaimSpec {
            step: ReferenceAgentStep::RecordRetractionSpecClaim,
            query: "Use MCP remember for deliberate retractions, provenance, and transaction semantics",
            sources: &[ExpectedSourceChunk {
                source: "markdown",
                source_id: DOCUMENTATION_SOURCE_ID,
                source_config_id: DOCUMENTATION_SOURCE_CONFIG_ID,
                markers: &[
                    "Use MCP `remember` for deliberate claims",
                    "retractions, and conflicts",
                    "provenance and transaction semantics are actually exercised",
                ],
            }],
            text: RETRACTION_SPEC_CLAIM_TEXT,
            value: true,
            operation: "self-audit-retraction-spec",
            allowed_states: &["active", "disputed"],
            require_conflict: false,
        },
    )
    .await
}

async fn record_retraction_implementation_claim(
    service: &dyn FleetMemoryService,
    scope: FleetScope,
    run_id: &str,
) -> ServiceResult<Value> {
    record_self_audit_claim(
        service,
        scope,
        run_id,
        SelfAuditClaimSpec {
            step: ReferenceAgentStep::RecordRetractionImplementationClaim,
            query: "remember action record retract outside hackathon vertical slice",
            sources: &[
                ExpectedSourceChunk {
                    source: "code",
                    source_id: TOOLS_SOURCE_ID,
                    source_config_id: SELF_AUDIT_SOURCE_CONFIG_ID,
                    markers: &["\"action\"", "\"enum\": [\"record\"]"],
                },
                ExpectedSourceChunk {
                    source: "code",
                    source_id: APPLICATION_SOURCE_ID,
                    source_config_id: SELF_AUDIT_SOURCE_CONFIG_ID,
                    markers: &[
                        "RememberAction::Record => self.remember_record",
                        "remember({}) is outside the hackathon vertical slice",
                    ],
                },
            ],
            text: RETRACTION_IMPLEMENTATION_CLAIM_TEXT,
            value: false,
            operation: "self-audit-retraction-implementation",
            allowed_states: &["disputed"],
            require_conflict: true,
        },
    )
    .await
}

struct SelfAuditClaimSpec<'a> {
    step: ReferenceAgentStep,
    query: &'a str,
    sources: &'a [ExpectedSourceChunk<'a>],
    text: &'a str,
    value: bool,
    operation: &'a str,
    allowed_states: &'a [&'a str],
    require_conflict: bool,
}

async fn record_self_audit_claim(
    service: &dyn FleetMemoryService,
    scope: FleetScope,
    run_id: &str,
    spec: SelfAuditClaimSpec<'_>,
) -> ServiceResult<Value> {
    let sources =
        retrieve_exact_source_chunks(service, scope.clone(), spec.query, spec.sources).await?;
    let subject = self_audit_subject(run_id);
    let claim_key = expected_claim_key(&subject, SELF_AUDIT_PREDICATE);
    let mutation = service
        .remember(
            scope.clone(),
            RememberRequest::new(
                RememberAction::Record,
                Some(reference_idempotency_key(&scope, run_id, spec.operation)?),
                object(&json!({
                    "kind": "fact",
                    "text": spec.text,
                    "subject": subject,
                    "predicate": SELF_AUDIT_PREDICATE,
                    "polarity": 1,
                    "value": spec.value,
                    "actor": scope.agent,
                    "support": sources.iter().map(ExactSourceChunk::support).collect::<Vec<_>>(),
                }))?,
            ),
        )
        .await?;
    let claim_id = mutation_claim_id(&mutation.data)?;
    let conflict = spec
        .require_conflict
        .then(|| matching_self_audit_conflict(&mutation.conflicts, &scope.project, &claim_key))
        .transpose()?;
    if conflict
        .as_ref()
        .is_some_and(|conflict| conflict.implementation_claim_id != claim_id)
    {
        return Err(invariant(
            "new implementation claim is not the self-audit conflict's trusted agent-c member",
        ));
    }
    let claim = recall_claim(service, scope.clone(), claim_id).await?;
    validate_self_audit_claim(
        &claim,
        ExpectedSelfAuditClaim {
            id: claim_id,
            project: &scope.project,
            claim_key: &claim_key,
            text: spec.text,
            actor: spec.step.trusted_agent(),
            value: spec.value,
            allowed_states: spec.allowed_states,
            support: &sources,
        },
    )?;

    let mut result = object(&json!({
        "claim_id": claim_id,
        "value": spec.value,
        "retrieval_lanes": ["lexical", "dense"],
        "fusion": "rrf",
        "source_coordinates": sources.iter().map(ExactSourceChunk::coordinate).collect::<Vec<_>>(),
    }))?;
    if let Some(conflict) = conflict {
        result.extend(object(&json!({
            "conflict_id": conflict.id,
            "member_claim_ids": conflict.member_claim_ids,
            "spec_claim_id": conflict.spec_claim_id,
            "implementation_claim_id": conflict.implementation_claim_id,
        }))?);
    }
    Ok(evidence(&scope, spec.step, run_id, &Value::Object(result)))
}

async fn retrieve_exact_source_chunks(
    service: &dyn FleetMemoryService,
    scope: FleetScope,
    query: &str,
    expected_sources: &[ExpectedSourceChunk<'_>],
) -> ServiceResult<Vec<ExactSourceChunk>> {
    let recall = service
        .recall(
            scope.clone(),
            RecallRequest::new(
                RecallAction::Search,
                object(&json!({
                    "query": query,
                    "kind": "chunk",
                    "limit": 100,
                    "max_per_source_id": 8,
                }))?,
            ),
        )
        .await?;
    verify_hybrid_retrieval(&recall.diagnostics)?;
    let hits = recall
        .data
        .get("hits")
        .and_then(Value::as_array)
        .ok_or_else(|| invariant("self-audit semantic recall omitted its hits array"))?;

    let mut sources = Vec::with_capacity(expected_sources.len());
    for expected in expected_sources {
        let mut candidate_ids = Vec::new();
        for hit in hits {
            if hit.get("source").and_then(Value::as_str) == Some(expected.source)
                && hit.get("source_id").and_then(Value::as_str) == Some(expected.source_id)
                && hit.get("project").and_then(Value::as_str) == Some(scope.project.as_str())
            {
                let chunk_id = hit
                    .get("chunk_id")
                    .and_then(Value::as_str)
                    .filter(|id| !id.is_empty() && id.len() <= 256)
                    .ok_or_else(|| invariant("self-audit search hit omitted a bounded chunk id"))?;
                if !candidate_ids.iter().any(|candidate| candidate == chunk_id) {
                    candidate_ids.push(chunk_id.to_owned());
                }
            }
        }
        if candidate_ids.is_empty() {
            return Err(invariant(&format!(
                "semantic recall did not return expected source {:?}",
                expected.source_id
            )));
        }

        let mut matches = Vec::new();
        for chunk_id in candidate_ids {
            let chunk = recall_chunk(service, scope.clone(), &chunk_id).await?;
            if let Some(source) = validate_exact_source_chunk(&chunk, &scope, &chunk_id, *expected)?
            {
                matches.push(source);
            }
        }
        if matches.len() != 1 {
            return Err(invariant(&format!(
                "expected exactly one marker-valid chunk for source {:?}, found {}",
                expected.source_id,
                matches.len()
            )));
        }
        sources.push(matches.remove(0));
    }
    Ok(sources)
}

async fn recall_chunk(
    service: &dyn FleetMemoryService,
    scope: FleetScope,
    chunk_id: &str,
) -> ServiceResult<Value> {
    let result = service
        .recall(
            scope,
            RecallRequest::new(
                RecallAction::Get,
                object(&json!({ "kind": "chunk", "id": chunk_id }))?,
            ),
        )
        .await?;
    result
        .data
        .get("chunk")
        .filter(|chunk| !chunk.is_null())
        .cloned()
        .ok_or_else(|| invariant("recall(get chunk) did not return the selected source chunk"))
}

fn validate_exact_source_chunk(
    chunk: &Value,
    scope: &FleetScope,
    expected_chunk_id: &str,
    expected: ExpectedSourceChunk<'_>,
) -> ServiceResult<Option<ExactSourceChunk>> {
    let chunk_id = chunk.get("chunk_id").and_then(Value::as_str);
    let source = chunk.get("source").and_then(Value::as_str);
    let project = chunk.get("project").and_then(Value::as_str);
    let source_id = chunk.get("source_id").and_then(Value::as_str);
    if chunk_id != Some(expected_chunk_id)
        || source != Some(expected.source)
        || project != Some(scope.project.as_str())
        || source_id != Some(expected.source_id)
    {
        return Err(invariant(
            "exact source lookup changed the selected chunk identity or scope",
        ));
    }
    if chunk.get("source_config_id").and_then(Value::as_str) != Some(expected.source_config_id) {
        return Ok(None);
    }
    let text = chunk
        .get("text")
        .and_then(Value::as_str)
        .ok_or_else(|| invariant("exact source chunk omitted text"))?;
    let content_sha256 = chunk
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| invariant("exact source chunk omitted its content hash"))?;
    let computed_sha256 = hex::encode(Sha256::digest(text.as_bytes()));
    if content_sha256 != computed_sha256 {
        return Err(invariant("exact source chunk content hash did not verify"));
    }
    if !expected.markers.iter().all(|marker| text.contains(marker)) {
        return Ok(None);
    }
    Ok(Some(ExactSourceChunk {
        chunk_id: expected_chunk_id.to_owned(),
        source: expected.source.into(),
        source_id: expected.source_id.into(),
        source_config_id: expected.source_config_id.into(),
        text: text.into(),
        content_sha256: content_sha256.into(),
    }))
}

#[derive(Clone, Copy)]
struct ExpectedSelfAuditClaim<'a> {
    id: i64,
    project: &'a str,
    claim_key: &'a str,
    text: &'a str,
    actor: &'a str,
    value: bool,
    allowed_states: &'a [&'a str],
    support: &'a [ExactSourceChunk],
}

fn validate_self_audit_claim(
    claim: &Value,
    expected: ExpectedSelfAuditClaim<'_>,
) -> ServiceResult<()> {
    let state = claim.get("state").and_then(Value::as_str);
    if claim.get("id").and_then(Value::as_i64) != Some(expected.id)
        || claim.get("project").and_then(Value::as_str) != Some(expected.project)
        || claim.get("claim_key").and_then(Value::as_str) != Some(expected.claim_key)
        || claim.get("kind").and_then(Value::as_str) != Some("fact")
        || claim.get("text").and_then(Value::as_str) != Some(expected.text)
        || !state.is_some_and(|state| expected.allowed_states.contains(&state))
        || claim.get("actor").and_then(Value::as_str) != Some(expected.actor)
        || claim.get("polarity").and_then(Value::as_i64) != Some(1)
        || claim.get("value").and_then(Value::as_bool) != Some(expected.value)
    {
        return Err(invariant(
            "self-audit claim failed exact identity, provenance, Boolean value, or state validation",
        ));
    }
    let support = claim
        .get("support")
        .and_then(Value::as_array)
        .ok_or_else(|| invariant("self-audit claim omitted durable source support"))?;
    if support.len() != expected.support.len()
        || !expected.support.iter().all(|expected_source| {
            support
                .iter()
                .filter(|actual| support_matches(actual, expected_source))
                .count()
                == 1
        })
    {
        return Err(invariant(
            "self-audit claim did not preserve the exact chunk-backed support coordinates",
        ));
    }
    Ok(())
}

fn support_matches(actual: &Value, expected: &ExactSourceChunk) -> bool {
    actual.get("source_config_id").and_then(Value::as_str)
        == Some(expected.source_config_id.as_str())
        && actual.get("source").and_then(Value::as_str) == Some(expected.source.as_str())
        && actual.get("source_id").and_then(Value::as_str) == Some(expected.source_id.as_str())
        && actual.get("chunk_id").and_then(Value::as_str) == Some(expected.chunk_id.as_str())
        && actual.get("content_sha256").and_then(Value::as_str)
            == Some(expected.content_sha256.as_str())
        && actual.get("excerpt").and_then(Value::as_str) == Some(expected.text.as_str())
        && actual.get("relation").and_then(Value::as_str) == Some("supports")
}

#[derive(Debug, PartialEq, Eq)]
struct MatchedSelfAuditConflict {
    id: i64,
    member_claim_ids: Vec<i64>,
    spec_claim_id: i64,
    implementation_claim_id: i64,
}

fn matching_self_audit_conflict(
    conflicts: &[Value],
    expected_project: &str,
    expected_key: &str,
) -> ServiceResult<MatchedSelfAuditConflict> {
    let pair = matching_conflict_pair(
        conflicts,
        expected_project,
        expected_key,
        ExpectedConflictMember {
            kind: "fact",
            actor: "agent-a",
            value: &Value::Bool(true),
            text: Some(RETRACTION_SPEC_CLAIM_TEXT),
        },
        ExpectedConflictMember {
            kind: "fact",
            actor: "agent-c",
            value: &Value::Bool(false),
            text: Some(RETRACTION_IMPLEMENTATION_CLAIM_TEXT),
        },
        "open two-member source-backed retraction-support conflict was not surfaced",
    )?;
    Ok(MatchedSelfAuditConflict {
        id: pair.id,
        member_claim_ids: pair.member_claim_ids,
        spec_claim_id: pair.first_claim_id,
        implementation_claim_id: pair.second_claim_id,
    })
}

#[derive(Clone, Copy)]
struct ExpectedConflictMember<'a> {
    kind: &'a str,
    actor: &'a str,
    value: &'a Value,
    text: Option<&'a str>,
}

struct MatchedConflictPair {
    id: i64,
    member_claim_ids: Vec<i64>,
    first_claim_id: i64,
    second_claim_id: i64,
}

fn matching_conflict_pair(
    conflicts: &[Value],
    expected_project: &str,
    expected_key: &str,
    first: ExpectedConflictMember<'_>,
    second: ExpectedConflictMember<'_>,
    failure: &str,
) -> ServiceResult<MatchedConflictPair> {
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
        let member_ids = members
            .iter()
            .filter_map(|member| member.get("id").and_then(Value::as_i64))
            .collect::<Vec<_>>();
        let first_member = members
            .iter()
            .find(|member| exact_conflict_member(member, expected_project, expected_key, first));
        let second_member = members
            .iter()
            .find(|member| exact_conflict_member(member, expected_project, expected_key, second));
        if member_ids.len() == 2
            && member_ids.iter().all(|member_id| *member_id > 0)
            && member_ids[0] != member_ids[1]
            && first_member.is_some()
            && second_member.is_some()
        {
            let Some(first_claim_id) = first_member
                .and_then(|member| member.get("id"))
                .and_then(Value::as_i64)
            else {
                continue;
            };
            let Some(second_claim_id) = second_member
                .and_then(|member| member.get("id"))
                .and_then(Value::as_i64)
            else {
                continue;
            };
            return Ok(MatchedConflictPair {
                id,
                member_claim_ids: member_ids,
                first_claim_id,
                second_claim_id,
            });
        }
    }
    Err(invariant(failure))
}

fn exact_conflict_member(
    member: &Value,
    expected_project: &str,
    expected_key: &str,
    expected: ExpectedConflictMember<'_>,
) -> bool {
    member
        .get("id")
        .and_then(Value::as_i64)
        .is_some_and(|id| id > 0)
        && member.get("project").and_then(Value::as_str) == Some(expected_project)
        && member.get("claim_key").and_then(Value::as_str) == Some(expected_key)
        && member.get("kind").and_then(Value::as_str) == Some(expected.kind)
        && member.get("state").and_then(Value::as_str) == Some("disputed")
        && member.get("actor").and_then(Value::as_str) == Some(expected.actor)
        && member.get("polarity").and_then(Value::as_i64) == Some(1)
        && member.get("value") == Some(expected.value)
        && expected
            .text
            .is_none_or(|text| member.get("text").and_then(Value::as_str) == Some(text))
}

async fn retrieve_migration_source(
    service: &dyn FleetMemoryService,
    scope: FleetScope,
) -> ServiceResult<Vec<ExactSourceChunk>> {
    retrieve_exact_source_chunks(
        service,
        scope,
        "migration ownership dedicated migrator every worker independently operator review",
        &[ExpectedSourceChunk {
            source: "markdown",
            source_id: MIGRATION_CONFLICT_SOURCE_ID,
            source_config_id: "rich-demo:operations:v1",
            markers: &[
                "one dedicated migrator runs before workers",
                "every worker migrates independently at startup",
                "proposals require operator review",
            ],
        }],
    )
    .await
}

fn decision_arguments(
    scope: &FleetScope,
    run_id: &str,
    incompatible: bool,
    sources: &[ExactSourceChunk],
) -> Map<String, Value> {
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
        "support": sources.iter().map(ExactSourceChunk::support).collect::<Vec<_>>(),
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
    let decision = Value::String(DECISION_VALUE.into());
    let incompatible = Value::String(INCOMPATIBLE_DECISION_VALUE.into());
    let pair = matching_conflict_pair(
        conflicts,
        expected_project,
        expected_key,
        ExpectedConflictMember {
            kind: "decision",
            actor: "agent-a",
            value: &decision,
            text: None,
        },
        ExpectedConflictMember {
            kind: "decision",
            actor: "agent-c",
            value: &incompatible,
            text: None,
        },
        "open two-member migration conflict was not surfaced",
    )?;
    Ok(MatchedConflict {
        id: pair.id,
        member_claim_ids: pair.member_claim_ids,
        decision_claim_id: pair.first_claim_id,
        incompatible_claim_id: pair.second_claim_id,
    })
}

fn mutation_claim_id(data: &Value) -> ServiceResult<i64> {
    data.pointer("/claim/id")
        .and_then(Value::as_i64)
        .filter(|id| *id > 0)
        .ok_or_else(|| invariant("remember result omitted a positive claim id"))
}

fn evidence(scope: &FleetScope, step: ReferenceAgentStep, run_id: &str, result: &Value) -> Value {
    let policy = match step {
        ReferenceAgentStep::RecordRetractionSpecClaim
        | ReferenceAgentStep::RecordRetractionImplementationClaim => {
            "source-backed-mcp-contract-self-audit-v1"
        }
        ReferenceAgentStep::RecordDecision
        | ReferenceAgentStep::RecallAndAct
        | ReferenceAgentStep::RecordConflict
        | ReferenceAgentStep::RecallConflictAndEscalate => "bounded-schema-migration-safety-v1",
    };
    json!({
        "schema": EVIDENCE_SCHEMA,
        "run_id": run_id,
        "step": step.as_str(),
        "agent": scope.agent,
        "project": scope.project,
        "policy": policy,
        "result": result,
    })
}

fn scenario_subject(run_id: &str) -> String {
    format!("fleet deployment {run_id}")
}

fn self_audit_subject(run_id: &str) -> String {
    format!("fleet recall self-audit {run_id}")
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
        MigrationSourceMissing,
        MigrationSourceMarker,
        MigrationSourceHash,
        SelfAuditSourceMissing,
        SelfAuditSourceConfig,
        SelfAuditSourceMarker,
        SelfAuditSourceHash,
        SelfAuditClaimSupport,
        SelfAuditConflictValue,
        SelfAuditConflictText,
    }

    #[derive(Default)]
    struct FakeService {
        decision_calls: AtomicUsize,
        tamper: Tamper,
        recall_actions: Mutex<Vec<RecallAction>>,
        remember_keys: Mutex<Vec<String>>,
        remember_arguments: Mutex<Vec<Map<String, Value>>>,
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

        fn remember_arguments(&self) -> Vec<Map<String, Value>> {
            self.remember_arguments
                .lock()
                .expect("fake remember arguments lock")
                .clone()
        }

        fn search_result(&self, request: &RecallRequest) -> RecallResult {
            let query = request
                .arguments
                .get("query")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let hits = if query.contains("migration ownership dedicated migrator") {
                if self.tamper == Tamper::MigrationSourceMissing {
                    json!([])
                } else {
                    json!([{
                        "chunk_id": "migration-source-chunk",
                        "project": "reference-project",
                        "source": "markdown",
                        "source_id": MIGRATION_CONFLICT_SOURCE_ID,
                        "snippet": MIGRATION_SOURCE_TEXT,
                        "score": 1.0,
                        "links": {},
                    }])
                }
            } else if query.contains("fleet deployment") {
                json!([{
                    "extra": {
                        "claim_id": 101,
                        "claim_key": "fleet-deployment-run-1::migration-strategy",
                    }
                }])
            } else {
                let mut sources = vec![
                    self_audit_source_fixture(DOCUMENTATION_SOURCE_ID),
                    self_audit_source_fixture(TOOLS_SOURCE_ID),
                    self_audit_source_fixture(APPLICATION_SOURCE_ID),
                ];
                if self.tamper == Tamper::SelfAuditSourceMissing {
                    sources.retain(|source| source.source_id != DOCUMENTATION_SOURCE_ID);
                }
                Value::Array(sources.iter().map(self_audit_search_hit).collect())
            };
            let mut result = RecallResult::new(json!({ "hits": hits }));
            result.diagnostics.insert(
                "retrieval".into(),
                json!({ "lanes": ["lexical", "dense"], "fusion": "rrf" }),
            );
            result
        }

        fn get_result(&self, request: &RecallRequest) -> ServiceResult<RecallResult> {
            if request.arguments.get("kind").and_then(Value::as_str) == Some("chunk") {
                let id = request
                    .arguments
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        ServiceError::InvalidRequest("fake chunk get omitted id".into())
                    })?;
                let mut chunk = if id == "migration-source-chunk" {
                    fake_chunk(
                        id,
                        "markdown",
                        MIGRATION_CONFLICT_SOURCE_ID,
                        "rich-demo:operations:v1",
                        MIGRATION_SOURCE_TEXT,
                    )
                } else {
                    [
                        DOCUMENTATION_SOURCE_ID,
                        TOOLS_SOURCE_ID,
                        APPLICATION_SOURCE_ID,
                    ]
                    .into_iter()
                    .map(self_audit_source_fixture)
                    .find(|source| source.chunk_id == id)
                    .as_ref()
                    .map_or(Value::Null, |source| self_audit_chunk(source, self.tamper))
                };
                if self.tamper == Tamper::MigrationSourceMarker {
                    let text = "Synthetic migration narrative without the expected incompatible instructions or operator-review language.";
                    chunk["text"] = json!(text);
                    chunk["sha256"] = json!(hex::encode(Sha256::digest(text.as_bytes())));
                } else if self.tamper == Tamper::MigrationSourceHash {
                    chunk["sha256"] = json!("0".repeat(64));
                }
                return Ok(RecallResult::new(json!({ "chunk": chunk })));
            }
            let id = request
                .arguments
                .get("id")
                .and_then(Value::as_i64)
                .ok_or_else(|| ServiceError::InvalidRequest("fake get omitted id".into()))?;
            let claim = if id >= 400 {
                self_audit_claim(id, self.tamper)
            } else {
                fake_claim(id, self.tamper)
            };
            Ok(RecallResult::new(json!({ "claim": claim })))
        }
    }

    const MIGRATION_SOURCE_TEXT: &str = "Synthetic disagreement: the release agent proposed one dedicated migrator runs before workers, while the worker agent proposed every worker migrates independently at startup. The proposals require operator review because both instructions would contend for schema ownership. Importing this narrative does not create typed claims or conflict state.";

    fn fake_chunk(
        chunk_id: &str,
        source: &str,
        source_id: &str,
        source_config_id: &str,
        text: &str,
    ) -> Value {
        json!({
            "chunk_id": chunk_id,
            "project": "reference-project",
            "source": source,
            "source_id": source_id,
            "source_config_id": source_config_id,
            "chunk_index": 0,
            "text": text,
            "sha256": hex::encode(Sha256::digest(text.as_bytes())),
        })
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
                RecallAction::Search => Ok(self.search_result(&request)),
                RecallAction::Get => self.get_result(&request),
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
            self.remember_arguments
                .lock()
                .expect("fake remember arguments lock")
                .push(request.arguments.clone());
            let (id, kind, claim_key, state, replay, value, conflicts) = if key
                .ends_with("migration-decision")
            {
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
            } else if key.ends_with("self-audit-retraction-spec") {
                (
                    401,
                    "fact",
                    "fleet-recall-self-audit-run-1::mcp-remember-supports-deliberate-retractions",
                    "active",
                    false,
                    request.arguments.get("value").cloned(),
                    Vec::new(),
                )
            } else if key.ends_with("self-audit-retraction-implementation") {
                (
                    402,
                    "fact",
                    "fleet-recall-self-audit-run-1::mcp-remember-supports-deliberate-retractions",
                    "disputed",
                    false,
                    request.arguments.get("value").cloned(),
                    vec![self_audit_conflict(self.tamper)],
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

    const DOCUMENTATION_SOURCE_TEXT: &str = "Source document examples/README.md. Use MCP `remember` for deliberate claims, supersessions, retractions, and conflicts so their provenance and transaction semantics are actually exercised.";
    const TOOLS_SOURCE_TEXT: &str =
        "\"action\": {\n    \"type\": \"string\",\n    \"enum\": [\"record\"]\n},";
    const APPLICATION_SOURCE_TEXT: &str = "match request.action {\n    RememberAction::Record => self.remember_record(&scope, request).await,\n    action => Err(ServiceError::InvalidRequest(format!(\n        \"remember({}) is outside the hackathon vertical slice\",\n        action.as_str()\n    ))),\n}";

    fn self_audit_source_fixture(source_id: &str) -> ExactSourceChunk {
        let (chunk_id, source_config_id, text) = match source_id {
            DOCUMENTATION_SOURCE_ID => (
                "documentation-source-chunk",
                DOCUMENTATION_SOURCE_CONFIG_ID,
                DOCUMENTATION_SOURCE_TEXT,
            ),
            TOOLS_SOURCE_ID => (
                "tools-source-chunk",
                SELF_AUDIT_SOURCE_CONFIG_ID,
                TOOLS_SOURCE_TEXT,
            ),
            APPLICATION_SOURCE_ID => (
                "application-source-chunk",
                SELF_AUDIT_SOURCE_CONFIG_ID,
                APPLICATION_SOURCE_TEXT,
            ),
            _ => panic!("unexpected self-audit source fixture"),
        };
        let source = if source_id == DOCUMENTATION_SOURCE_ID {
            "markdown"
        } else {
            "code"
        };
        ExactSourceChunk {
            chunk_id: chunk_id.into(),
            source: source.into(),
            source_id: source_id.into(),
            source_config_id: source_config_id.into(),
            text: text.into(),
            content_sha256: hex::encode(Sha256::digest(text.as_bytes())),
        }
    }

    fn self_audit_search_hit(source: &ExactSourceChunk) -> Value {
        json!({
            "chunk_id": source.chunk_id,
            "project": "reference-project",
            "source": source.source,
            "source_id": source.source_id,
            "snippet": source.text,
            "score": 1.0,
            "links": {},
        })
    }

    fn self_audit_chunk(source: &ExactSourceChunk, tamper: Tamper) -> Value {
        let mut chunk = fake_chunk(
            &source.chunk_id,
            &source.source,
            &source.source_id,
            &source.source_config_id,
            &source.text,
        );
        if source.source_id == DOCUMENTATION_SOURCE_ID {
            match tamper {
                Tamper::SelfAuditSourceConfig => {
                    chunk["source_config_id"] = json!("rich-demo:wrong:v1");
                }
                Tamper::SelfAuditSourceMarker => {
                    let text = "A publication-safe documentation chunk that does not assert any retraction capability.";
                    chunk["text"] = json!(text);
                    chunk["sha256"] = json!(hex::encode(Sha256::digest(text.as_bytes())));
                }
                Tamper::SelfAuditSourceHash => chunk["sha256"] = json!("0".repeat(64)),
                _ => {}
            }
        }
        chunk
    }

    fn self_audit_claim(id: i64, tamper: Tamper) -> Value {
        let (actor, state, text, value, sources) = match id {
            401 => (
                "agent-a",
                "active",
                RETRACTION_SPEC_CLAIM_TEXT,
                true,
                vec![self_audit_source_fixture(DOCUMENTATION_SOURCE_ID)],
            ),
            402 => (
                "agent-c",
                "disputed",
                RETRACTION_IMPLEMENTATION_CLAIM_TEXT,
                false,
                vec![
                    self_audit_source_fixture(TOOLS_SOURCE_ID),
                    self_audit_source_fixture(APPLICATION_SOURCE_ID),
                ],
            ),
            _ => return Value::Null,
        };
        let mut support = sources
            .iter()
            .map(ExactSourceChunk::support)
            .collect::<Vec<_>>();
        if tamper == Tamper::SelfAuditClaimSupport {
            support[0]["chunk_id"] = json!("tampered-source-chunk");
        }
        json!({
            "id": id,
            "project": "reference-project",
            "kind": "fact",
            "text": text,
            "claim_key": "fleet-recall-self-audit-run-1::mcp-remember-supports-deliberate-retractions",
            "state": state,
            "actor": actor,
            "polarity": 1,
            "value": value,
            "support": support,
        })
    }

    fn self_audit_conflict(tamper: Tamper) -> Value {
        let mut conflict = json!({
            "id": 403,
            "project": "reference-project",
            "claim_key": "fleet-recall-self-audit-run-1::mcp-remember-supports-deliberate-retractions",
            "state": "open",
            "member_count": 2,
            "members_truncated": false,
            "member_values_elided": false,
            "members": [
                {
                    "id": 401,
                    "project": "reference-project",
                    "kind": "fact",
                    "text": RETRACTION_SPEC_CLAIM_TEXT,
                    "claim_key": "fleet-recall-self-audit-run-1::mcp-remember-supports-deliberate-retractions",
                    "state": "disputed",
                    "actor": "agent-a",
                    "polarity": 1,
                    "value": true,
                },
                {
                    "id": 402,
                    "project": "reference-project",
                    "kind": "fact",
                    "text": RETRACTION_IMPLEMENTATION_CLAIM_TEXT,
                    "claim_key": "fleet-recall-self-audit-run-1::mcp-remember-supports-deliberate-retractions",
                    "state": "disputed",
                    "actor": "agent-c",
                    "polarity": 1,
                    "value": false,
                }
            ]
        });
        if tamper == Tamper::SelfAuditConflictValue {
            conflict["members"][1]["value"] = json!(true);
        } else if tamper == Tamper::SelfAuditConflictText {
            conflict["members"][0]["text"] = json!(RETRACTION_IMPLEMENTATION_CLAIM_TEXT);
        }
        conflict
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
        assert_eq!(
            ReferenceAgentStep::RecordRetractionSpecClaim.trusted_agent(),
            "agent-a"
        );
        assert_eq!(
            ReferenceAgentStep::RecordRetractionImplementationClaim.trusted_agent(),
            "agent-c"
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
                RecallAction::Search,
                RecallAction::Get,
                RecallAction::Get,
                RecallAction::Search,
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
        let arguments = service.remember_arguments();
        for index in [0, 1, 3] {
            let support = arguments[index]["support"]
                .as_array()
                .expect("migration claim support");
            assert_eq!(support.len(), 1);
            assert_eq!(
                support[0]["source_id"],
                Value::String(MIGRATION_CONFLICT_SOURCE_ID.into())
            );
            assert_eq!(support[0]["chunk_id"], "migration-source-chunk");
            assert_eq!(
                support[0]["content_sha256"],
                hex::encode(Sha256::digest(MIGRATION_SOURCE_TEXT.as_bytes()))
            );
        }
    }

    #[tokio::test]
    async fn self_audit_records_exact_source_backed_boolean_conflict() {
        let service = FakeService::default();
        let spec = run_reference_agent(
            &service,
            test_scope("agent-a"),
            ReferenceAgentStep::RecordRetractionSpecClaim,
            "run-1",
        )
        .await
        .unwrap();
        assert_eq!(spec["policy"], "source-backed-mcp-contract-self-audit-v1");
        assert_eq!(spec["result"]["claim_id"], 401);
        assert_eq!(spec["result"]["value"], true);
        assert_eq!(
            spec["result"]["source_coordinates"]
                .as_array()
                .unwrap()
                .len(),
            1
        );

        let implementation = run_reference_agent(
            &service,
            test_scope("agent-c"),
            ReferenceAgentStep::RecordRetractionImplementationClaim,
            "run-1",
        )
        .await
        .unwrap();
        assert_eq!(implementation["result"]["claim_id"], 402);
        assert_eq!(implementation["result"]["value"], false);
        assert_eq!(implementation["result"]["conflict_id"], 403);
        assert_eq!(implementation["result"]["spec_claim_id"], 401);
        assert_eq!(implementation["result"]["implementation_claim_id"], 402);
        assert_eq!(
            implementation["result"]["source_coordinates"]
                .as_array()
                .unwrap()
                .len(),
            2
        );

        assert_eq!(
            service.recall_actions(),
            vec![
                RecallAction::Search,
                RecallAction::Get,
                RecallAction::Get,
                RecallAction::Search,
                RecallAction::Get,
                RecallAction::Get,
                RecallAction::Get,
            ]
        );
        let arguments = service.remember_arguments();
        assert_eq!(arguments.len(), 2);
        assert_eq!(arguments[0]["subject"], arguments[1]["subject"]);
        assert_eq!(arguments[0]["predicate"], arguments[1]["predicate"]);
        assert_eq!(arguments[0]["value"], true);
        assert_eq!(arguments[1]["value"], false);
        assert_eq!(arguments[0]["support"].as_array().unwrap().len(), 1);
        assert_eq!(arguments[1]["support"].as_array().unwrap().len(), 2);
        assert_eq!(
            arguments[0]["support"][0]["source_id"],
            DOCUMENTATION_SOURCE_ID
        );
        assert_eq!(arguments[1]["support"][0]["source_id"], TOOLS_SOURCE_ID);
        assert_eq!(
            arguments[1]["support"][1]["source_id"],
            APPLICATION_SOURCE_ID
        );
        assert!(
            service
                .remember_keys()
                .iter()
                .all(|key| key.starts_with("reference-agent/v1/project-"))
        );
    }

    #[tokio::test]
    async fn migration_writers_fail_closed_before_write_without_exact_source() {
        for tamper in [
            Tamper::MigrationSourceMissing,
            Tamper::MigrationSourceMarker,
            Tamper::MigrationSourceHash,
        ] {
            for (step, agent) in [
                (ReferenceAgentStep::RecordDecision, "agent-a"),
                (ReferenceAgentStep::RecordConflict, "agent-c"),
            ] {
                let service = FakeService::with_tamper(tamper);
                let error = run_reference_agent(&service, test_scope(agent), step, "run-1")
                    .await
                    .unwrap_err();
                assert!(
                    matches!(error, ServiceError::Internal(_)),
                    "migration source tamper {tamper:?} must fail as an invariant"
                );
                assert!(service.remember_keys().is_empty());
            }
        }
    }

    #[tokio::test]
    async fn self_audit_source_selection_and_hash_validation_fail_closed_before_write() {
        for tamper in [
            Tamper::SelfAuditSourceMissing,
            Tamper::SelfAuditSourceConfig,
            Tamper::SelfAuditSourceMarker,
            Tamper::SelfAuditSourceHash,
        ] {
            let service = FakeService::with_tamper(tamper);
            let error = run_reference_agent(
                &service,
                test_scope("agent-a"),
                ReferenceAgentStep::RecordRetractionSpecClaim,
                "run-1",
            )
            .await
            .unwrap_err();
            assert!(
                matches!(error, ServiceError::Internal(_)),
                "source tamper {tamper:?} must fail as an invariant"
            );
            assert!(service.remember_keys().is_empty());
        }
    }

    #[tokio::test]
    async fn self_audit_reread_and_conflict_projection_fail_closed() {
        let support_service = FakeService::with_tamper(Tamper::SelfAuditClaimSupport);
        assert!(
            run_reference_agent(
                &support_service,
                test_scope("agent-a"),
                ReferenceAgentStep::RecordRetractionSpecClaim,
                "run-1",
            )
            .await
            .is_err()
        );
        assert_eq!(support_service.remember_keys().len(), 1);

        for tamper in [
            Tamper::SelfAuditConflictValue,
            Tamper::SelfAuditConflictText,
        ] {
            let conflict_service = FakeService::with_tamper(tamper);
            assert!(
                run_reference_agent(
                    &conflict_service,
                    test_scope("agent-c"),
                    ReferenceAgentStep::RecordRetractionImplementationClaim,
                    "run-1",
                )
                .await
                .is_err()
            );
            assert_eq!(conflict_service.remember_keys().len(), 1);
        }
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
