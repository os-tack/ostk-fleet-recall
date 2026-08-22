use std::str::FromStr;

use super::*;
use crate::memory_contracts::{
    bootstrap::PartitionAlgorithm,
    canonical::{decode_strict, require_canonical},
    common::FixedHex32,
};

const SUCCESSOR_LOG_EPOCH: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/ledger-epoch/successor-log-epoch.jsonl");
const EVIDENCE_COMPACTION_CHECKPOINT: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/ledger-epoch/evidence-compaction-checkpoint.jsonl"
);
const PROJECTOR_CHECKPOINT: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/ledger-epoch/projector-checkpoint.jsonl");
const ARCHIVE_MOVE_ADMISSION: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/ledger-epoch/archive-move-admission.jsonl");
const CURSOR_VECTOR_BARRIER: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/ledger-epoch/cursor-vector-barrier.jsonl");
const PROJECTION_GENERATION: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/ledger-epoch/projection-generation.jsonl");
const VECTOR_SUITE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/ledger-epoch/vector-suite.jsonl");
const NEGATIVE_UNSORTED_HEAD_VECTOR: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/ledger-epoch/negative-unsorted-head-vector.jsonl"
);
const NEGATIVE_MISSING_PREDECESSOR: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/ledger-epoch/negative-missing-predecessor.jsonl"
);
const NEGATIVE_SEED_SHAPE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/ledger-epoch/negative-seed-shape.jsonl");
const SUCCESSOR_LOG_EPOCH_ID: &str =
    "1f8c197c5854fed8980db82d88f82f568ba7005da4ed6096a935b6d02e8429c2";
const PROJECTOR_CHECKPOINT_DIGEST: &str =
    "8a44db6d8037225760678ea51a8f55db2fd6be63c0202cead1f2405e39fd333d";
const CURSOR_BARRIER_DIGEST: &str =
    "231b09eb8bb020d4e7fa5fb6d17bac004e67d2d3a7ca912b805f71ec408252c4";
const PROJECTION_GENERATION_ID: &str =
    "5d619c49cfceb87413a7dfb437feb0ab90ed5901918b9afc400b664b442dac82";
/// `ProjectionGenerationV1::record_digest()` of the golden
/// `projection-generation.jsonl` fixture (sequence 0, `supersedes:
/// null`) under the `ostk-projection-generation-record-v1` domain. Added
/// this round to close the residual-review generation-identity fix; see
/// `projection_generation_record_digest_prevents_identity_collision_attacks`.
const PROJECTION_GENERATION_RECORD_DIGEST: &str =
    "0b3fae0fb9fa222294c93316b3975c94745a8f32ecee75fb4954b2b3e5161765";

fn record(artifact: &'static [u8]) -> &'static [u8] {
    let body = artifact
        .strip_suffix(b"\n")
        .expect("contract artifact must have one repository-framing LF");
    assert!(!body.ends_with(b"\n"));
    assert!(!body.contains(&b'\r'));
    body
}

fn digest(value: &str) -> Sha256Digest {
    Sha256Digest::from_str(value).expect("hard-coded digest must be lowercase SHA-256")
}

fn profile() -> ProfileReferenceV1 {
    ProfileReferenceV1 {
        profile_id: ContractId::new("ostk-canonical-json-v1").unwrap(),
        profile_digest: digest("cf22991a86bfc560556c7d04efa4ee6b7b1ee0f49c919b257ea7b4f30f8e4a29"),
        vector_manifest_digest: digest(
            "f984f62866fc769df3a5617a2247e3ade694827c1de69e615a7bda68858b4174",
        ),
    }
}

fn scope() -> AuthenticatedProjectScopeV1 {
    AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.fixture").unwrap(),
        ContractId::new("project.fixture").unwrap(),
    )
}

fn predecessor_epoch_id() -> EpochId {
    EpochId::from_digest(digest(
        "d35655f3297e1c5eb4503443befb956f93dc5210b46cdc1a4d7d9f2746b8fab2",
    ))
}

fn closed_predecessor_head() -> ClosedHeadVectorV1 {
    ClosedHeadVectorV1 {
        schema_version: 1,
        epoch_id: predecessor_epoch_id(),
        heads: vec![
            ClosedShardHeadV1 {
                shard: 0,
                last_committed_offset: CommittedOffsetV1::new(11).unwrap(),
                chain_digest: digest(
                    "1111111111111111111111111111111111111111111111111111111111111111",
                ),
            },
            ClosedShardHeadV1 {
                shard: 5,
                last_committed_offset: CommittedOffsetV1::new(2).unwrap(),
                chain_digest: digest(
                    "2222222222222222222222222222222222222222222222222222222222222222",
                ),
            },
        ],
    }
}

fn successor_partition_recipe() -> PartitionRecipeV1 {
    PartitionRecipeV1 {
        schema_version: 1,
        recipe_id: ContractId::new("ostk.partition.sha256_prefix64_modulo").unwrap(),
        recipe_version: 1,
        algorithm: PartitionAlgorithm::Sha256Prefix64Modulo,
        seed: FixedHex32::from_bytes([9; 32]),
        shard_count: 32,
    }
}

fn successor_epoch() -> SuccessorLogEpochV1 {
    SuccessorLogEpochV1 {
        schema_version: 1,
        profile: profile(),
        scope: scope(),
        partition_recipe: successor_partition_recipe(),
        activation_binding: EpochActivationBindingV1 {
            schema_version: 1,
            predecessor_epoch_id: predecessor_epoch_id(),
            closed_predecessor_head: closed_predecessor_head(),
        },
    }
}

#[test]
fn successor_epoch_matches_golden_bytes_and_id() {
    let epoch = successor_epoch();
    let golden = record(SUCCESSOR_LOG_EPOCH);
    require_canonical(golden).unwrap();
    assert_eq!(encode_canonical(&epoch).unwrap(), golden);

    let decoded: SuccessorLogEpochV1 = decode_strict(golden).unwrap();
    assert_eq!(decoded, epoch);
    decoded.validate().unwrap();
    assert_eq!(
        decoded.epoch_id().unwrap().digest(),
        digest(SUCCESSOR_LOG_EPOCH_ID)
    );

    // The epoch's own identity is deterministic under replay: decoding
    // the same bytes twice reproduces the same ID (REPLAY-01).
    let redecoded: SuccessorLogEpochV1 = decode_strict(golden).unwrap();
    assert_eq!(redecoded.epoch_id().unwrap(), decoded.epoch_id().unwrap());
}

#[test]
fn epoch_missing_predecessor_fails_closed() {
    // The negative fixture is itself canonical JSON (well-formed,
    // sorted, byte-minimal) -- it is `SuccessorLogEpochV1` that rejects
    // it, at the schema boundary, not the canonical-JSON parser.
    require_canonical(record(NEGATIVE_MISSING_PREDECESSOR)).unwrap();
    assert!(decode_strict::<SuccessorLogEpochV1>(record(NEGATIVE_MISSING_PREDECESSOR)).is_err());
}

#[test]
fn seed_shape_fails_closed() {
    // As above: canonical JSON, rejected by `FixedHex32`'s exact-length
    // requirement, not by canonical-form parsing.
    require_canonical(record(NEGATIVE_SEED_SHAPE)).unwrap();
    assert!(decode_strict::<SuccessorLogEpochV1>(record(NEGATIVE_SEED_SHAPE)).is_err());
}

#[test]
fn unsorted_head_vector_fails_closed() {
    // As above: canonical JSON, rejected by `ClosedHeadVectorV1::validate`'s
    // ordering check, not by canonical-form parsing -- `decode_strict`
    // below succeeds precisely because the shape is well-formed.
    require_canonical(record(NEGATIVE_UNSORTED_HEAD_VECTOR)).unwrap();
    let decoded: ClosedHeadVectorV1 = decode_strict(record(NEGATIVE_UNSORTED_HEAD_VECTOR))
        .expect("shape is well-formed JSON; only ordering is invalid");
    assert_eq!(
        decoded.validate(),
        Err(ContractError::NonCanonicalSet { field: "heads" })
    );
}

#[test]
fn shard_count_change_keeps_evidence_ids_unchanged() {
    let epoch = successor_epoch();
    let mut wider = epoch.clone();
    wider.partition_recipe.shard_count = 64;
    // Changing the shard count mints a different log epoch...
    assert_ne!(epoch.epoch_id().unwrap(), wider.epoch_id().unwrap());

    // ...but the very same accepted-event ID validates a retry under
    // either epoch generation: LostFenceRetryV1 has exactly one
    // accepted_event_id field, so nothing about the shard count or
    // epoch identity can ever flow into it.
    let event_id = AcceptedEventId::from_digest(digest(
        "4444444444444444444444444444444444444444444444444444444444444444",
    ));
    for candidate in [epoch, wider] {
        let fence = EpochFenceV1 {
            schema_version: 1,
            successor_epoch: candidate.clone(),
        };
        let key = ConsistencyPartitionKeyV1 {
            family: ContractId::new("evidence.retry").unwrap(),
            key_digest: digest("3333333333333333333333333333333333333333333333333333333333333333"),
        };
        let shard = partition_for_successor_epoch(&candidate, &key).unwrap();
        let retry = LostFenceRetryV1 {
            schema_version: 1,
            accepted_event_id: event_id,
            consistency_partition_key: key,
            losing_position: AppendPositionV1 {
                epoch_id: predecessor_epoch_id(),
                shard: 0,
                committed_offset: CommittedOffsetV1::new(12).unwrap(),
            },
            retry_position: AppendPositionV1 {
                epoch_id: candidate.epoch_id().unwrap(),
                shard,
                committed_offset: CommittedOffsetV1::new(1).unwrap(),
            },
        };
        retry.validate_against(&fence).unwrap();
        assert_eq!(retry.accepted_event_id, event_id);
    }
}

#[test]
fn epoch_fence_rejects_append_at_predecessor_and_admits_retry() {
    let epoch = successor_epoch();
    let successor_id = epoch.epoch_id().unwrap();
    let fence = EpochFenceV1 {
        schema_version: 1,
        successor_epoch: epoch.clone(),
    };
    fence.validate().unwrap();

    let losing_position = AppendPositionV1 {
        epoch_id: predecessor_epoch_id(),
        shard: 0,
        committed_offset: CommittedOffsetV1::new(12).unwrap(),
    };
    assert!(fence.reject_append_after_fence(&losing_position).is_err());

    let key = ConsistencyPartitionKeyV1 {
        family: ContractId::new("evidence.retry").unwrap(),
        key_digest: digest("3333333333333333333333333333333333333333333333333333333333333333"),
    };
    let expected_shard = partition_for_successor_epoch(&epoch, &key).unwrap();
    let retry_position = AppendPositionV1 {
        epoch_id: successor_id,
        shard: expected_shard,
        committed_offset: CommittedOffsetV1::new(1).unwrap(),
    };
    assert!(fence.reject_append_after_fence(&retry_position).is_ok());

    let event_id = AcceptedEventId::from_digest(digest(
        "4444444444444444444444444444444444444444444444444444444444444444",
    ));
    let retry = LostFenceRetryV1 {
        schema_version: 1,
        accepted_event_id: event_id,
        consistency_partition_key: key,
        losing_position,
        retry_position,
    };
    retry.validate_against(&fence).unwrap();
    // The retry keeps exactly one accepted_event_id; before and after
    // retry, the semantic identity is the same struct field.
    assert_eq!(retry.accepted_event_id, event_id);

    // NOTE: this only proves the retry is rejected when its
    // retry_position also names the predecessor epoch — it never
    // reaches the same-physical-position conjunct below, because the
    // earlier "does not target the successor epoch" guard fires first.
    // `lost_fence_retry_rejects_identical_position_but_admits_partial_overlap`
    // isolates that conjunct directly.
    let mut same_position_retry = retry.clone();
    same_position_retry.retry_position = same_position_retry.losing_position;
    assert!(same_position_retry.validate_against(&fence).is_err());

    let mut wrong_predecessor = retry;
    wrong_predecessor.losing_position.epoch_id = successor_id;
    assert!(wrong_predecessor.validate_against(&fence).is_err());
}

#[test]
fn lost_fence_retry_rejects_identical_position_but_admits_partial_overlap() {
    // Isolates the same-physical-position conjunct in
    // `LostFenceRetryV1::validate_against` (the "retry must occupy a
    // different physical position than the losing append" check) from
    // both epoch guards that precede it. Unlike the sibling test above,
    // `losing_position` and `retry_position` here each independently
    // satisfy their own epoch guard (predecessor / successor
    // respectively), so a mutant that deletes or weakens the
    // same-position check is the only way this test can pass.
    let epoch = successor_epoch();
    let successor_id = epoch.epoch_id().unwrap();
    let fence = EpochFenceV1 {
        schema_version: 1,
        successor_epoch: epoch.clone(),
    };
    fence.validate().unwrap();

    let key = ConsistencyPartitionKeyV1 {
        family: ContractId::new("evidence.lost-fence-retry").unwrap(),
        key_digest: digest("6666666666666666666666666666666666666666666666666666666666666666"),
    };
    let shard = partition_for_successor_epoch(&epoch, &key).unwrap();
    let event_id = AcceptedEventId::from_digest(digest(
        "7777777777777777777777777777777777777777777777777777777777777777",
    ));

    let losing_position = AppendPositionV1 {
        epoch_id: predecessor_epoch_id(),
        shard,
        committed_offset: CommittedOffsetV1::new(20).unwrap(),
    };

    // Same (shard, committed_offset) as the losing append, but a
    // successor epoch id -- both epoch guards pass, so only the
    // physical-position conjunct can reject it.
    let identical_position_retry = LostFenceRetryV1 {
        schema_version: 1,
        accepted_event_id: event_id,
        consistency_partition_key: key,
        losing_position,
        retry_position: AppendPositionV1 {
            epoch_id: successor_id,
            shard,
            committed_offset: CommittedOffsetV1::new(20).unwrap(),
        },
    };
    assert_eq!(
        identical_position_retry.validate_against(&fence),
        Err(ContractError::Schema(
            "retry must occupy a different physical position than the losing append".into()
        ))
    );

    // The shape a real cutover actually produces: the retry lands on
    // the SAME shard (its consistency-key hash is unchanged) at a
    // DIFFERENT committed offset. This kills the `&&` -> `||` mutant --
    // under `||` this would already be rejected as "identical".
    let partial_overlap_retry = LostFenceRetryV1 {
        retry_position: AppendPositionV1 {
            epoch_id: successor_id,
            shard,
            committed_offset: CommittedOffsetV1::new(21).unwrap(),
        },
        ..identical_position_retry
    };
    partial_overlap_retry.validate_against(&fence).unwrap();
    assert_eq!(partial_overlap_retry.accepted_event_id, event_id);
}

#[test]
fn epoch_fence_is_an_allow_list_not_a_deny_list() {
    let epoch = successor_epoch();
    let successor_id = epoch.epoch_id().unwrap();
    let fence = EpochFenceV1 {
        schema_version: 1,
        successor_epoch: epoch.clone(),
    };
    fence.validate().unwrap();

    // Attack B: an unknown/fabricated epoch id is not the fenced
    // predecessor, so a deny-list of exactly the predecessor would admit
    // it. The allow-list rejects anything that is not the successor.
    let fabricated = AppendPositionV1 {
        epoch_id: EpochId::from_digest(digest(
            "abababababababababababababababababababababababababababababababab",
        )),
        shard: 0,
        committed_offset: CommittedOffsetV1::new(7).unwrap(),
    };
    assert!(fence.reject_append_after_fence(&fabricated).is_err());

    // A grand-predecessor epoch (two cutovers back) is neither the
    // fenced predecessor nor the successor, and must also be rejected —
    // the "concurrent old-epoch append that loses the fence" case
    // applies to every earlier generation, not only the immediate one.
    let grand_predecessor = AppendPositionV1 {
        epoch_id: EpochId::from_digest(digest(
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        )),
        shard: 0,
        committed_offset: CommittedOffsetV1::new(3).unwrap(),
    };
    assert!(fence.reject_append_after_fence(&grand_predecessor).is_err());

    // The fenced predecessor itself is still rejected.
    let at_predecessor = AppendPositionV1 {
        epoch_id: fence.predecessor_epoch_id(),
        shard: 0,
        committed_offset: CommittedOffsetV1::new(9).unwrap(),
    };
    assert!(fence.reject_append_after_fence(&at_predecessor).is_err());

    // A shard the successor epoch's own partition recipe never assigned
    // (shard_count is 32 here) is rejected even though the epoch id
    // matches.
    let shard_out_of_range = AppendPositionV1 {
        epoch_id: successor_id,
        shard: epoch.partition_recipe.shard_count,
        committed_offset: CommittedOffsetV1::new(1).unwrap(),
    };
    assert!(
        fence
            .reject_append_after_fence(&shard_out_of_range)
            .is_err()
    );

    // Only a position naming exactly the successor epoch and a shard
    // within its recipe is admitted.
    let admitted = AppendPositionV1 {
        epoch_id: successor_id,
        shard: epoch.partition_recipe.shard_count - 1,
        committed_offset: CommittedOffsetV1::new(1).unwrap(),
    };
    assert!(fence.reject_append_after_fence(&admitted).is_ok());
}

#[test]
fn evidence_compaction_and_projector_checkpoints_are_not_interchangeable() {
    let golden = record(EVIDENCE_COMPACTION_CHECKPOINT);
    require_canonical(golden).unwrap();
    let checkpoint: EvidenceCompactionCheckpointV1 = decode_strict(golden).unwrap();
    checkpoint.validate().unwrap();
    assert_eq!(encode_canonical(&checkpoint).unwrap(), golden);

    let anchor = VerifiedReplayAnchorV1::from_checkpoint(&checkpoint).unwrap();
    assert_eq!(anchor.epoch_id(), checkpoint.core.epoch_id);

    let horizon = ReplayHorizonV1::anchored(
        &anchor,
        ReplayFrom::Checkpoint {
            checkpoint_digest: anchor.checkpoint_digest(),
        },
    );
    horizon.validate_semantic_anchor(Some(&anchor)).unwrap();
    assert_eq!(
        horizon.semantic_replay_from,
        ReplayFrom::Checkpoint {
            checkpoint_digest: anchor.checkpoint_digest()
        }
    );

    // A projector checkpoint's canonical bytes cannot decode as an
    // evidence-compaction checkpoint: the field sets are disjoint, so
    // this fails at the schema boundary, not merely by convention.
    let projector_golden = record(PROJECTOR_CHECKPOINT);
    require_canonical(projector_golden).unwrap();
    let projector: ProjectorCheckpointV1 = decode_strict(projector_golden).unwrap();
    projector.validate().unwrap();
    assert_eq!(encode_canonical(&projector).unwrap(), projector_golden);
    assert!(decode_strict::<EvidenceCompactionCheckpointV1>(projector_golden).is_err());
    assert!(decode_strict::<ProjectorCheckpointV1>(golden).is_err());
}

#[test]
fn projector_checkpoint_digest_can_never_satisfy_a_semantic_replay_anchor() {
    // Attack: take a real ProjectorCheckpointV1's checkpoint_digest() and
    // present it as a ReplayHorizonV1's semantic_replay_from, then round
    // trip through the exact wire path a runtime uses (encode -> decode
    // -> validate). The bare digest decodes fine — it is schema-valid
    // bytes — but the type-level guarantee lives in
    // validate_semantic_anchor, not in decode_strict/validate_shape.
    let projector: ProjectorCheckpointV1 = decode_strict(record(PROJECTOR_CHECKPOINT)).unwrap();
    let forged_digest = projector.checkpoint_digest().unwrap();

    let forged_horizon = ReplayHorizonV1 {
        schema_version: LEDGER_EPOCH_SCHEMA_VERSION,
        semantic_replay_from: ReplayFrom::Checkpoint {
            checkpoint_digest: forged_digest,
        },
        historical_content_available_from: ReplayFrom::Genesis {},
    };
    let wire_bytes = encode_canonical(&forged_horizon).unwrap();
    let redecoded: ReplayHorizonV1 = decode_strict(&wire_bytes).unwrap();
    assert_eq!(redecoded, forged_horizon);

    // No anchor at all: rejected, not silently accepted as genesis.
    assert!(redecoded.validate_semantic_anchor(None).is_err());

    // A real anchor, but for a *different* (evidence-compaction)
    // checkpoint: the digests disagree, so this is rejected too. This is
    // the only anchor obtainable from this crate's public API — there is
    // no way to construct a VerifiedReplayAnchorV1 whose
    // checkpoint_digest() equals a ProjectorCheckpointV1's, short of a
    // SHA-256 preimage collision across the two digest domains.
    let checkpoint: EvidenceCompactionCheckpointV1 =
        decode_strict(record(EVIDENCE_COMPACTION_CHECKPOINT)).unwrap();
    let real_anchor = VerifiedReplayAnchorV1::from_checkpoint(&checkpoint).unwrap();
    assert_ne!(real_anchor.checkpoint_digest(), forged_digest);
    assert!(
        redecoded
            .validate_semantic_anchor(Some(&real_anchor))
            .is_err()
    );
}

#[test]
fn replay_from_genesis_unit_variant_rejects_unknown_fields() {
    // Before this fix, serde's `#[serde(deny_unknown_fields)]` had no
    // effect on the unit variant of an internally tagged enum: the
    // variant is deserialized by a `void` visitor that never inspects a
    // payload, so an unknown field smuggled into a `"kind":"genesis"`
    // object decoded successfully and was silently dropped. `Genesis`
    // is now the empty struct variant `Genesis {}`, which goes through
    // serde's normal field-checking machinery -- exactly like
    // `Checkpoint` already did -- so the same attack must now fail
    // closed through the exact runtime decode path (`decode_strict`).
    let honest = br#"{"historical_content_available_from":{"kind":"genesis"},"schema_version":1,"semantic_replay_from":{"kind":"genesis"}}"#;
    let decoded: ReplayHorizonV1 = decode_strict(honest).unwrap();
    assert_eq!(decoded.semantic_replay_from, ReplayFrom::Genesis {});
    assert_eq!(
        decoded.historical_content_available_from,
        ReplayFrom::Genesis {}
    );
    // The wire bytes for the empty struct variant are identical to the
    // unit-variant bytes it replaces: `{"kind":"genesis"}`, no change
    // to any existing fixture.
    assert_eq!(encode_canonical(&decoded).unwrap(), honest);

    let smuggled_semantic = br#"{"historical_content_available_from":{"kind":"genesis"},"schema_version":1,"semantic_replay_from":{"evil":"payload","kind":"genesis"}}"#;
    assert!(decode_strict::<ReplayHorizonV1>(smuggled_semantic).is_err());

    // Both positions a `ReplayFrom::Genesis {}` can appear in are
    // covered, not just `semantic_replay_from`.
    let smuggled_historical = br#"{"historical_content_available_from":{"evil":"payload","kind":"genesis"},"schema_version":1,"semantic_replay_from":{"kind":"genesis"}}"#;
    assert!(decode_strict::<ReplayHorizonV1>(smuggled_historical).is_err());

    // The struct variant `Checkpoint` was already protected; pinned
    // here for parity so both arms of the enum are proven under one
    // test.
    let smuggled_checkpoint = br#"{"historical_content_available_from":{"kind":"genesis"},"schema_version":1,"semantic_replay_from":{"checkpoint_digest":"1111111111111111111111111111111111111111111111111111111111111111","evil":"payload","kind":"checkpoint"}}"#;
    assert!(decode_strict::<ReplayHorizonV1>(smuggled_checkpoint).is_err());
}

#[test]
fn checkpoint_receipt_mismatch_fails_closed() {
    let checkpoint: EvidenceCompactionCheckpointV1 =
        decode_strict(record(EVIDENCE_COMPACTION_CHECKPOINT)).unwrap();
    let mut wrong = checkpoint;
    wrong.replay_verification_receipt.verified_subject_digest =
        digest("5555555555555555555555555555555555555555555555555555555555555555");
    assert!(wrong.validate().is_err());
    assert!(VerifiedReplayAnchorV1::from_checkpoint(&wrong).is_err());
}

#[test]
fn cursor_vector_barrier_is_order_independent() {
    let golden = record(CURSOR_VECTOR_BARRIER);
    require_canonical(golden).unwrap();
    let barrier: CursorVectorBarrierV1 = decode_strict(golden).unwrap();
    barrier.validate().unwrap();
    assert_eq!(encode_canonical(&barrier).unwrap(), golden);
    let first_digest = barrier.barrier_digest().unwrap();

    // Genuinely reversed arrival: feed the same per-shard observations
    // to the normalizing constructor in the opposite order the golden
    // fixture lists them in. Unlike reversing an already-sorted vector
    // and resorting it (which is the identity function on sorted input),
    // this exercises a real different construction order through the
    // one API a projector actually has for turning arrival-order
    // observations into a canonical barrier.
    let mut scrambled_order: Vec<ShardCursorEntryV1> = barrier.cursors.clone();
    scrambled_order.reverse();
    assert_ne!(
        scrambled_order.first().unwrap().shard,
        barrier.cursors.first().unwrap().shard,
        "the golden fixture must have more than one shard for this to be a real reversal"
    );
    let from_scrambled =
        CursorVectorBarrierV1::from_observations(barrier.epoch_id, scrambled_order).unwrap();
    assert_eq!(from_scrambled, barrier);
    assert_eq!(from_scrambled.barrier_digest().unwrap(), first_digest);

    // Duplicate shards can never legitimately arise from one fence.
    let mut duplicated = barrier.cursors.clone();
    duplicated.push(duplicated[0]);
    assert_eq!(
        CursorVectorBarrierV1::from_observations(barrier.epoch_id, duplicated),
        Err(ContractError::NonCanonicalSet { field: "cursors" })
    );

    let generation: ProjectionGenerationV1 = decode_strict(record(PROJECTION_GENERATION)).unwrap();
    generation.validate().unwrap();
    assert_eq!(generation.barrier, barrier);
    let first_generation_id = generation.generation_id().unwrap();
    let first_record_digest = generation.record_digest().unwrap();

    let same_facts_reversed = ProjectionGenerationV1 {
        barrier: from_scrambled,
        ..generation.clone()
    };
    assert_eq!(
        same_facts_reversed.generation_id().unwrap(),
        first_generation_id
    );
    // Byte-identical barrier (reconstructed, not merely relabeled) means
    // a byte-identical record, so the record digest agrees too.
    assert_eq!(
        same_facts_reversed.record_digest().unwrap(),
        first_record_digest
    );

    // Attack J reproduction, now as a passing rejection: a "later"
    // generation over the identical closed barrier — different output,
    // same facts — must be rejected. Late evidence means an advanced
    // cursor vector, never a rewritten output over the same closed one.
    // `supersedes` names the predecessor's `record_digest` (never its
    // `generation_id` — see `validate_supersession`'s docs), so this
    // reaches the barrier check on its own terms rather than failing
    // earlier on a mismatched predecessor reference.
    let mut same_barrier_rewrite = generation.clone();
    same_barrier_rewrite.generation_sequence = 1;
    same_barrier_rewrite.supersedes = Some(first_record_digest);
    same_barrier_rewrite.output_digest =
        digest("7777777777777777777777777777777777777777777777777777777777777777");
    same_barrier_rewrite.validate().unwrap();
    assert_eq!(
        same_barrier_rewrite.validate_supersession(&generation),
        Err(ContractError::Schema(
            "superseding generation must strictly advance the barrier it supersedes; late \
             evidence means an advanced cursor vector, not a rewritten output over the same \
             closed vector"
                .into()
        ))
    );

    // A genuinely advanced barrier — one shard strictly past its
    // predecessor's offset, the other unchanged, same shard set and
    // epoch — is accepted, and the earlier generation's own record and
    // id remain valid and unaffected.
    let mut advanced_cursors = barrier.cursors.clone();
    advanced_cursors[0].last_processed_offset =
        CommittedOffsetV1::new(advanced_cursors[0].last_processed_offset.as_u64() + 1).unwrap();
    let advanced_barrier =
        CursorVectorBarrierV1::from_observations(barrier.epoch_id, advanced_cursors).unwrap();
    let mut later = generation.clone();
    later.generation_sequence = 1;
    later.supersedes = Some(first_record_digest);
    later.barrier = advanced_barrier;
    later.output_digest =
        digest("7777777777777777777777777777777777777777777777777777777777777777");
    later.validate().unwrap();
    later.validate_supersession(&generation).unwrap();
    assert_ne!(later.generation_id().unwrap(), first_generation_id);
    assert_ne!(later.record_digest().unwrap(), first_record_digest);
    // The earlier generation is preserved, not superseded away: its own
    // digest and validation are unaffected by the later record existing.
    assert_eq!(generation.generation_id().unwrap(), first_generation_id);
    assert_eq!(generation.record_digest().unwrap(), first_record_digest);
    generation.validate().unwrap();

    // A barrier that regresses any shard is rejected outright.
    let mut regressed_cursors = barrier.cursors.clone();
    regressed_cursors[0].last_processed_offset = CommittedOffsetV1::new(1).unwrap();
    let regressed_barrier =
        CursorVectorBarrierV1::from_observations(barrier.epoch_id, regressed_cursors).unwrap();
    let mut regressed = generation.clone();
    regressed.generation_sequence = 1;
    regressed.supersedes = Some(first_record_digest);
    regressed.barrier = regressed_barrier;
    regressed.output_digest =
        digest("7777777777777777777777777777777777777777777777777777777777777777");
    regressed.validate().unwrap();
    assert!(regressed.validate_supersession(&generation).is_err());

    let mut inconsistent = generation;
    inconsistent.generation_sequence = 1;
    assert!(inconsistent.validate().is_err());
}

#[test]
fn cursor_vector_barrier_validate_rejects_malformed_shape_directly() {
    // Mirrors `closed_head_vector_validate_rejects_malformed_shape_directly`:
    // `from_observations` sorts and rejects duplicates *before*
    // delegating to `validate()`, so it never exercises `validate()`'s
    // own conjuncts. Construct `CursorVectorBarrierV1` directly -- the
    // shape a `decode_strict` on untrusted wire bytes would actually
    // produce -- to pin each one (REPLAY-01, REPLAY-02).
    let base: CursorVectorBarrierV1 = decode_strict(record(CURSOR_VECTOR_BARRIER)).unwrap();
    base.validate().unwrap();

    let mut wrong_schema_version = base.clone();
    wrong_schema_version.schema_version = LEDGER_EPOCH_SCHEMA_VERSION + 1;
    assert_eq!(
        wrong_schema_version.validate(),
        Err(ContractError::Schema(
            "invalid cursor vector barrier".into()
        ))
    );

    let empty = CursorVectorBarrierV1 {
        schema_version: LEDGER_EPOCH_SCHEMA_VERSION,
        epoch_id: base.epoch_id,
        cursors: Vec::new(),
    };
    assert_eq!(
        empty.validate(),
        Err(ContractError::Schema(
            "invalid cursor vector barrier".into()
        ))
    );

    // Exactly at the boundary (MAX_VECTOR_SHARDS entries) must still be
    // ACCEPTED -- this is what kills a `>` -> `>=` mutant on the length
    // check, which the +1-oversized case alone cannot distinguish.
    let at_boundary_cursors: Vec<ShardCursorEntryV1> = (0..u32::try_from(MAX_VECTOR_SHARDS)
        .unwrap())
        .map(|shard| ShardCursorEntryV1 {
            shard: u16::try_from(shard).unwrap(),
            last_processed_offset: base.cursors[0].last_processed_offset,
        })
        .collect();
    assert_eq!(at_boundary_cursors.len(), MAX_VECTOR_SHARDS);
    CursorVectorBarrierV1 {
        schema_version: LEDGER_EPOCH_SCHEMA_VERSION,
        epoch_id: base.epoch_id,
        cursors: at_boundary_cursors,
    }
    .validate()
    .unwrap();

    let oversized_cursors: Vec<ShardCursorEntryV1> = (0..=u32::try_from(MAX_VECTOR_SHARDS)
        .unwrap())
        .map(|shard| ShardCursorEntryV1 {
            shard: u16::try_from(shard).unwrap(),
            last_processed_offset: base.cursors[0].last_processed_offset,
        })
        .collect();
    assert_eq!(oversized_cursors.len(), MAX_VECTOR_SHARDS + 1);
    let oversized = CursorVectorBarrierV1 {
        schema_version: LEDGER_EPOCH_SCHEMA_VERSION,
        epoch_id: base.epoch_id,
        cursors: oversized_cursors,
    };
    assert_eq!(
        oversized.validate(),
        Err(ContractError::Schema(
            "invalid cursor vector barrier".into()
        ))
    );

    // Duplicate-by-shard, decoded directly: the sorted-strictly-
    // increasing window check, not the constructor's separate equality
    // check, must reject it. Inserted adjacent (not appended at the
    // end) so the duplicate pair is strictly-increasing-adjacent rather
    // than out-of-order -- this is what kills a `<` -> `<=` mutant,
    // which an out-of-order pair alone cannot distinguish.
    let mut duplicate_cursors = base.cursors.clone();
    duplicate_cursors.insert(1, duplicate_cursors[0]);
    let duplicated = CursorVectorBarrierV1 {
        schema_version: LEDGER_EPOCH_SCHEMA_VERSION,
        epoch_id: base.epoch_id,
        cursors: duplicate_cursors,
    };
    assert_eq!(
        duplicated.validate(),
        Err(ContractError::NonCanonicalSet { field: "cursors" })
    );

    // Same shard named twice with a DIFFERENT last_processed_offset:
    // still the same shard twice, and the check compares `shard` alone.
    let mut conflicting_duplicate_cursors = base.cursors.clone();
    let mut conflicting = conflicting_duplicate_cursors[0];
    conflicting.last_processed_offset =
        CommittedOffsetV1::new(conflicting.last_processed_offset.as_u64() + 1).unwrap();
    conflicting_duplicate_cursors.insert(1, conflicting);
    let conflicting_duplicated = CursorVectorBarrierV1 {
        schema_version: LEDGER_EPOCH_SCHEMA_VERSION,
        epoch_id: base.epoch_id,
        cursors: conflicting_duplicate_cursors,
    };
    assert_eq!(
        conflicting_duplicated.validate(),
        Err(ContractError::NonCanonicalSet { field: "cursors" })
    );
}

#[test]
fn projection_generation_supersession_binds_projector_identity_and_sequence() {
    // Attack 1 reproduction, now as a passing rejection: a hostile
    // projector must never be able to supersede another projector's
    // generation, even with a strictly-advanced barrier and the correct
    // predecessor id.
    let g0: ProjectionGenerationV1 = decode_strict(record(PROJECTION_GENERATION)).unwrap();
    // `supersedes` is checked against a predecessor's `record_digest`,
    // never its `generation_id` (see `validate_supersession`'s docs), so
    // every `supersedes` value built in this test below names g0's
    // record digest, not its id.
    let g0_record_digest = g0.record_digest().unwrap();

    let mut advanced_cursors = g0.barrier.cursors.clone();
    advanced_cursors[0].last_processed_offset =
        CommittedOffsetV1::new(advanced_cursors[0].last_processed_offset.as_u64() + 1).unwrap();
    let advanced_barrier =
        CursorVectorBarrierV1::from_observations(g0.barrier.epoch_id, advanced_cursors).unwrap();

    let hostile_projector = ProjectionGenerationV1 {
        projector_id: ContractId::new("projector.hostile.other").unwrap(),
        barrier: advanced_barrier.clone(),
        generation_sequence: 1,
        output_digest: digest("7777777777777777777777777777777777777777777777777777777777777777"),
        supersedes: Some(g0_record_digest),
        ..g0
    };
    hostile_projector.validate().unwrap();
    assert!(
        hostile_projector.validate_supersession(&g0).is_err(),
        "a different projector must never supersede another projector's generation"
    );

    // A projector-version bump is not, by default, an admitted
    // supersession either. If a future workstream wants to allow one, it
    // must be an explicit, separately named and separately tested
    // admission rule, never this default check.
    let hostile_version = ProjectionGenerationV1 {
        projector_version: g0.projector_version + 1,
        barrier: advanced_barrier.clone(),
        generation_sequence: 1,
        output_digest: digest("7777777777777777777777777777777777777777777777777777777777777777"),
        supersedes: Some(g0_record_digest),
        ..g0.clone()
    };
    hostile_version.validate().unwrap();
    assert!(
        hostile_version.validate_supersession(&g0).is_err(),
        "a differing projector_version must never supersede by default"
    );

    // Attack 2 reproduction, now as a passing rejection: build a
    // legitimate predecessor `mid` at a high sequence number, then show
    // a lower, equal, and skipped sequence are all rejected as its
    // successor — not just a same-or-earlier barrier.
    let mid = ProjectionGenerationV1 {
        barrier: advanced_barrier.clone(),
        generation_sequence: 50,
        output_digest: digest("7777777777777777777777777777777777777777777777777777777777777777"),
        supersedes: Some(g0_record_digest),
        ..g0.clone()
    };
    mid.validate().unwrap();
    let mid_record_digest = mid.record_digest().unwrap();

    let mut further_cursors = advanced_barrier.cursors;
    further_cursors[1].last_processed_offset =
        CommittedOffsetV1::new(further_cursors[1].last_processed_offset.as_u64() + 1).unwrap();
    let further_barrier =
        CursorVectorBarrierV1::from_observations(g0.barrier.epoch_id, further_cursors).unwrap();

    let build_successor = |generation_sequence: u64| ProjectionGenerationV1 {
        barrier: further_barrier.clone(),
        generation_sequence,
        output_digest: digest("8888888888888888888888888888888888888888888888888888888888888888"),
        supersedes: Some(mid_record_digest),
        ..g0.clone()
    };

    // Regression: mid's own predecessor sequence (should be 51).
    let regressed_sequence = build_successor(1);
    regressed_sequence.validate().unwrap();
    assert!(
        regressed_sequence.validate_supersession(&mid).is_err(),
        "sequence regression (50 -> 1) must be rejected"
    );

    // Equal: repeating mid's own sequence is not an advance.
    let equal_sequence = build_successor(50);
    equal_sequence.validate().unwrap();
    assert!(
        equal_sequence.validate_supersession(&mid).is_err(),
        "an equal sequence must be rejected"
    );

    // Skipped: 52 instead of the required 51.
    let skipped_sequence = build_successor(52);
    skipped_sequence.validate().unwrap();
    assert!(
        skipped_sequence.validate_supersession(&mid).is_err(),
        "a skipped sequence must be rejected"
    );

    // Exactly one past mid's sequence, correct projector, strictly
    // advanced barrier: accepted.
    let correct_sequence = build_successor(51);
    correct_sequence.validate().unwrap();
    correct_sequence.validate_supersession(&mid).unwrap();
}

/// Residual-review regression: `generation_id()` is deliberately
/// schedule-independent (REPLAY-01), so two records that publish the
/// same total facts under different schedules can — and, in this test,
/// deliberately do — share one `generation_id`. Before this fix
/// `supersedes` was checked against that shared id, so a `supersedes`
/// value could resolve to either record: (ATTACK 1) a record could name
/// its OWN id as its own predecessor, and (ATTACK 2) a rewrite could be
/// admitted against a lower-barrier record sharing the same id as the
/// higher-barrier record it was actually trying to overwrite. This test
/// pins that `record_digest()` — which `supersedes` is now checked
/// against — closes both: (a) it disambiguates records that share a
/// `generation_id`, (b) no record can name itself as its own
/// predecessor, and (c) neither `early` nor `current` below admits a
/// same-barrier rewrite carrying a different `output_digest`.
#[test]
fn projection_generation_record_digest_prevents_identity_collision_attacks() {
    let early: ProjectionGenerationV1 = decode_strict(record(PROJECTION_GENERATION)).unwrap();
    early.validate().unwrap();
    assert_eq!(early.generation_sequence, 0);
    assert_eq!(early.supersedes, None);

    // (a) Two records differing ONLY in barrier share a `generation_id`
    // (identity deliberately excludes `barrier`) but must NOT share a
    // `record_digest` (which deliberately includes it).
    let mut advanced_cursors = early.barrier.cursors.clone();
    advanced_cursors[0].last_processed_offset =
        CommittedOffsetV1::new(advanced_cursors[0].last_processed_offset.as_u64() + 1).unwrap();
    let advanced_barrier =
        CursorVectorBarrierV1::from_observations(early.barrier.epoch_id, advanced_cursors).unwrap();
    let barrier_only_difference = ProjectionGenerationV1 {
        barrier: advanced_barrier.clone(),
        ..early.clone()
    };
    barrier_only_difference.validate().unwrap();
    assert_eq!(
        barrier_only_difference.generation_id().unwrap(),
        early.generation_id().unwrap(),
        "differing only in barrier must not change generation_id"
    );
    assert_ne!(
        barrier_only_difference.record_digest().unwrap(),
        early.record_digest().unwrap(),
        "differing barrier must change record_digest even though generation_id agrees"
    );

    // `current`: a legitimate successor of `early`, over a strictly
    // advanced barrier, publishing the SAME output_digest as `early` —
    // so `current.generation_id() == early.generation_id()` by
    // construction, reproducing the collision the old scheme could not
    // tell apart. `supersedes` correctly names `early`'s record digest.
    let current = ProjectionGenerationV1 {
        barrier: advanced_barrier,
        generation_sequence: 1,
        supersedes: Some(early.record_digest().unwrap()),
        ..early.clone()
    };
    current.validate().unwrap();
    current.validate_supersession(&early).unwrap();
    assert_eq!(
        current.generation_id().unwrap(),
        early.generation_id().unwrap(),
        "current and early must genuinely collide on generation_id for this test to be real"
    );
    assert_ne!(
        current.record_digest().unwrap(),
        early.record_digest().unwrap(),
        "the fix: record_digest disambiguates what generation_id conflates"
    );

    // (b) ATTACK 1 — self-reference. Take `current`, compute the digest
    // it would need to carry in `supersedes` to name itself, and build a
    // record that carries exactly that value. Because `record_digest`
    // hashes a preimage that already contains `supersedes`, changing
    // `supersedes` to the attempted value changes the resulting digest —
    // a record cannot be constructed whose `supersedes` equals its own
    // `record_digest()` by direct assignment, only by finding a SHA-256
    // fixed point. `validate_supersession` independently rejects the
    // attempt: it is checked here treating the record as its own named
    // predecessor.
    let attempted_self_reference = current.record_digest().unwrap();
    let self_ref = ProjectionGenerationV1 {
        supersedes: Some(attempted_self_reference),
        ..current.clone()
    };
    self_ref.validate().unwrap();
    assert_ne!(
        self_ref.record_digest().unwrap(),
        attempted_self_reference,
        "setting supersedes to a guessed self-digest changes the actual digest -- a record \
         cannot name itself by direct construction, only by a SHA-256 preimage attack"
    );
    assert!(
        self_ref.validate_supersession(&self_ref).is_err(),
        "a record naming itself as its own predecessor must be rejected"
    );

    // (c) ATTACK 2 — output rewrite over an already-published barrier via
    // an id-colliding substitute predecessor. `rewrite` claims the exact
    // same barrier `current` already closed, with a DIFFERENT
    // output_digest, and honestly names what it is trying to overwrite:
    // `current`'s own record_digest (the value an attacker rewriting
    // `current` would naturally use).
    let rewrite = ProjectionGenerationV1 {
        barrier: current.barrier.clone(),
        generation_sequence: current.generation_sequence + 1,
        output_digest: digest("7777777777777777777777777777777777777777777777777777777777777777"),
        supersedes: Some(current.record_digest().unwrap()),
        ..current.clone()
    };
    rewrite.validate().unwrap();
    assert_ne!(rewrite.output_digest, current.output_digest);

    // Checked against the record it honestly names (`current`): the
    // supersedes reference matches, but the barrier is byte-identical to
    // `current`'s own, not strictly advanced -- rejected on its own
    // substantive terms.
    assert_eq!(
        rewrite.validate_supersession(&current),
        Err(ContractError::Schema(
            "superseding generation must strictly advance the barrier it supersedes; late \
             evidence means an advanced cursor vector, not a rewritten output over the same \
             closed vector"
                .into()
        ))
    );
    // Checked against `early` -- the record that shares `current`'s
    // generation_id and therefore would have been an admissible
    // substitute under the old generation_id-keyed scheme (early's
    // barrier is strictly dominated by rewrite's, so the barrier check
    // alone would have passed): rejected outright, because `rewrite`'s
    // `supersedes` names `current`'s record_digest, which is NOT equal
    // to `early`'s record_digest even though their generation_ids agree.
    // No single `supersedes` value can any longer satisfy both records.
    assert_ne!(
        current.record_digest().unwrap(),
        early.record_digest().unwrap()
    );
    assert_eq!(
        rewrite.validate_supersession(&early),
        Err(ContractError::Schema(
            "superseding generation does not name its exact predecessor".into()
        )),
        "a different output_digest over a barrier current already closed must not be \
         admissible by substituting a lower-barrier same-output predecessor"
    );
}

#[test]
fn projection_generation_identity_is_independent_of_shard_schedule() {
    // REPLAY-01: "Processing the same facts in a different shard
    // schedule must produce the same generation." A genuine schedule
    // difference is not only a different `barrier`: it can change HOW
    // MANY intermediate generations a schedule needed to publish before
    // reaching the same total facts (a finer-grained shard schedule can
    // require an extra generation a coarser one does not). A test that
    // varies only `barrier` while holding `generation_sequence` and
    // `supersedes` fixed proves barrier-exclusion, which is true by
    // construction and cannot fail — it does not prove
    // schedule-independence. This test varies the publication history
    // itself: a one-generation schedule (sequence 0, no predecessor)
    // and a two-generation schedule's final record (sequence 1,
    // superseding an earlier generation) that reach the identical total
    // facts (`output_digest`) must produce the identical `generation_id`.
    let single_generation_schedule: ProjectionGenerationV1 =
        decode_strict(record(PROJECTION_GENERATION)).unwrap();
    single_generation_schedule.validate().unwrap();
    assert_eq!(
        single_generation_schedule.generation_sequence, 0,
        "the golden fixture must be an unsuperseded first generation"
    );
    assert_eq!(single_generation_schedule.supersedes, None);
    assert_eq!(
        single_generation_schedule.barrier.cursors.len(),
        2,
        "the golden fixture must be a genuine multi-shard barrier"
    );

    // A different shard schedule (different epoch, different shard
    // count/cursor set — a genuinely different barrier, not the same
    // one relabeled) whose SECOND published generation reaches the
    // SAME total facts as the golden schedule's ONLY generation.
    let one_shard_epoch = EpochId::from_digest(digest(
        "1111111111111111111111111111111111111111111111111111111111111111",
    ));
    let one_shard_barrier = CursorVectorBarrierV1::from_observations(
        one_shard_epoch,
        vec![ShardCursorEntryV1 {
            shard: 0,
            last_processed_offset: CommittedOffsetV1::new(14).unwrap(),
        }],
    )
    .unwrap();
    assert_ne!(
        one_shard_barrier.barrier_digest().unwrap(),
        single_generation_schedule.barrier.barrier_digest().unwrap(),
        "the two schedules must be genuinely different barriers, not the same one relabeled"
    );

    // Stand-in for "an earlier generation this schedule published
    // before reaching the golden total facts". Its own identity is
    // irrelevant beyond being distinct from the golden record's, since
    // this test's claim is about the SECOND (final) generation's id.
    let arbitrary_earlier_generation_id =
        digest("6666666666666666666666666666666666666666666666666666666666666666");

    let two_generation_schedule_final_record = ProjectionGenerationV1 {
        barrier: one_shard_barrier,
        generation_sequence: 1,
        supersedes: Some(arbitrary_earlier_generation_id),
        ..single_generation_schedule.clone()
    };
    two_generation_schedule_final_record.validate().unwrap();
    assert_ne!(
        two_generation_schedule_final_record.generation_sequence,
        single_generation_schedule.generation_sequence,
        "the two schedules must genuinely differ in publication history, not just barrier"
    );
    assert_ne!(
        two_generation_schedule_final_record.supersedes,
        single_generation_schedule.supersedes
    );

    assert_eq!(
        two_generation_schedule_final_record
            .generation_id()
            .unwrap(),
        single_generation_schedule.generation_id().unwrap(),
        "same total facts (same output_digest) under a different shard schedule -- including \
         a different number of intermediate generations needed to reach them -- must produce \
         the same generation id"
    );
}

#[test]
fn projection_generation_matches_golden_bytes_and_id() {
    let golden = record(PROJECTION_GENERATION);
    require_canonical(golden).unwrap();
    let generation: ProjectionGenerationV1 = decode_strict(golden).unwrap();
    generation.validate().unwrap();
    assert_eq!(encode_canonical(&generation).unwrap(), golden);
    assert_eq!(
        generation.generation_id().unwrap(),
        digest(PROJECTION_GENERATION_ID)
    );
}

#[test]
fn closed_head_vector_from_heads_normalizes_and_rejects_duplicates() {
    let closed = closed_predecessor_head();
    let mut scrambled = closed.heads.clone();
    scrambled.reverse();
    let from_scrambled = ClosedHeadVectorV1::from_heads(closed.epoch_id, scrambled).unwrap();
    assert_eq!(from_scrambled, closed);

    let mut duplicated = closed.heads.clone();
    duplicated.push(duplicated[0]);
    assert_eq!(
        ClosedHeadVectorV1::from_heads(closed.epoch_id, duplicated),
        Err(ContractError::NonCanonicalSet { field: "heads" })
    );
}

#[test]
fn closed_head_vector_validate_rejects_malformed_shape_directly() {
    // `from_heads` sorts and rejects duplicates *before* delegating to
    // `validate()`, so every prior test that goes through `from_heads`
    // never actually exercises `validate()`'s own conjuncts (schema
    // version, non-empty, bounded length, strictly-sorted-and-unique).
    // These construct `ClosedHeadVectorV1` directly -- its fields are
    // public precisely so decoded, not just constructed, records can be
    // validated -- to pin each conjunct independently (REPLAY-01,
    // PREFLIGHT 2/8: fail closed on malformed decoded input).
    let base = closed_predecessor_head();

    let mut wrong_schema_version = base.clone();
    wrong_schema_version.schema_version = LEDGER_EPOCH_SCHEMA_VERSION + 1;
    assert_eq!(
        wrong_schema_version.validate(),
        Err(ContractError::Schema("invalid closed head vector".into()))
    );

    let empty = ClosedHeadVectorV1 {
        schema_version: LEDGER_EPOCH_SCHEMA_VERSION,
        epoch_id: base.epoch_id,
        heads: Vec::new(),
    };
    assert_eq!(
        empty.validate(),
        Err(ContractError::Schema("invalid closed head vector".into()))
    );

    // Exactly at the boundary (MAX_VECTOR_SHARDS entries) must still be
    // ACCEPTED -- this is what kills a `>` -> `>=` mutant on the length
    // check, which the +1-oversized case alone cannot distinguish.
    let at_boundary_heads: Vec<ClosedShardHeadV1> = (0..u32::try_from(MAX_VECTOR_SHARDS).unwrap())
        .map(|shard| ClosedShardHeadV1 {
            shard: u16::try_from(shard).unwrap(),
            last_committed_offset: CommittedOffsetV1::new(1).unwrap(),
            chain_digest: base.heads[0].chain_digest,
        })
        .collect();
    assert_eq!(at_boundary_heads.len(), MAX_VECTOR_SHARDS);
    ClosedHeadVectorV1 {
        schema_version: LEDGER_EPOCH_SCHEMA_VERSION,
        epoch_id: base.epoch_id,
        heads: at_boundary_heads,
    }
    .validate()
    .unwrap();

    let oversized_heads: Vec<ClosedShardHeadV1> = (0..=u32::try_from(MAX_VECTOR_SHARDS).unwrap())
        .map(|shard| ClosedShardHeadV1 {
            shard: u16::try_from(shard).unwrap(),
            last_committed_offset: CommittedOffsetV1::new(1).unwrap(),
            chain_digest: base.heads[0].chain_digest,
        })
        .collect();
    assert_eq!(oversized_heads.len(), MAX_VECTOR_SHARDS + 1);
    let oversized = ClosedHeadVectorV1 {
        schema_version: LEDGER_EPOCH_SCHEMA_VERSION,
        epoch_id: base.epoch_id,
        heads: oversized_heads,
    };
    assert_eq!(
        oversized.validate(),
        Err(ContractError::Schema("invalid closed head vector".into()))
    );

    // Duplicate-by-shard, decoded directly (not via `from_heads`): the
    // sorted-strictly-increasing window check, not the constructor's
    // separate equality check, must reject it. Inserted adjacent (not
    // appended at the end) so the duplicate pair is
    // strictly-increasing-adjacent rather than out-of-order -- this is
    // what kills a `<` -> `<=` mutant, which an out-of-order pair alone
    // cannot distinguish.
    let mut duplicate_heads = base.heads.clone();
    duplicate_heads.insert(1, duplicate_heads[0]);
    let duplicated = ClosedHeadVectorV1 {
        schema_version: LEDGER_EPOCH_SCHEMA_VERSION,
        epoch_id: base.epoch_id,
        heads: duplicate_heads,
    };
    assert_eq!(
        duplicated.validate(),
        Err(ContractError::NonCanonicalSet { field: "heads" })
    );

    // A shard naming the same value twice with a DIFFERENT
    // last_committed_offset/chain_digest still names the same shard
    // twice -- the ordering/uniqueness check compares `shard` alone, not
    // the whole entry, and must still reject it.
    let mut conflicting_duplicate_heads = base.heads.clone();
    let mut conflicting = conflicting_duplicate_heads[0];
    conflicting.last_committed_offset = CommittedOffsetV1::new(999).unwrap();
    conflicting_duplicate_heads.insert(1, conflicting);
    let conflicting_duplicated = ClosedHeadVectorV1 {
        schema_version: LEDGER_EPOCH_SCHEMA_VERSION,
        epoch_id: base.epoch_id,
        heads: conflicting_duplicate_heads,
    };
    assert_eq!(
        conflicting_duplicated.validate(),
        Err(ContractError::NonCanonicalSet { field: "heads" })
    );

    // The valid base case still passes, proving these rejections are
    // about the specific mutation, not an over-broad check.
    base.validate().unwrap();
}

#[test]
fn closed_head_vector_validate_bounded_by_enforces_the_epoch_shard_count() {
    let base = closed_predecessor_head();
    // `base` closes shards 0 and 5, so shard_count 6 (shards 0..=5) is
    // exactly bounding and must be accepted...
    base.validate_bounded_by(6).unwrap();
    // ...while shard_count 5 (shards 0..=4) excludes shard 5 and must be
    // rejected. This directly exercises `validate_bounded_by`'s own `>=`
    // comparison, which otherwise has no test at all.
    assert!(base.validate_bounded_by(5).is_err());
    // The boundary itself: a shard_count equal to the highest closed
    // shard number is still out of range (shards are 0-indexed).
    assert!(base.validate_bounded_by(5).is_err());
    assert!(base.validate_bounded_by(4).is_err());

    // `validate_bounded_by` must still fail closed on a malformed vector
    // even when every head is within bounds.
    let mut wrong_schema_version = base;
    wrong_schema_version.schema_version = LEDGER_EPOCH_SCHEMA_VERSION + 1;
    assert!(wrong_schema_version.validate_bounded_by(4096).is_err());
}

#[test]
fn checkpoint_plus_tail_replay_reproduces_the_same_closed_vector() {
    let checkpoint: EvidenceCompactionCheckpointV1 =
        decode_strict(record(EVIDENCE_COMPACTION_CHECKPOINT)).unwrap();
    let epoch_id = checkpoint.core.epoch_id;

    // Tail: shard 0 advances past the checkpoint (11 -> 15), shard 5 is
    // untouched, and a shard the checkpoint had not yet closed (7)
    // closes for the first time in the tail.
    let tail = vec![
        ClosedShardHeadV1 {
            shard: 0,
            last_committed_offset: CommittedOffsetV1::new(15).unwrap(),
            chain_digest: digest(
                "3333333333333333333333333333333333333333333333333333333333333333",
            ),
        },
        ClosedShardHeadV1 {
            shard: 7,
            last_committed_offset: CommittedOffsetV1::new(3).unwrap(),
            chain_digest: digest(
                "4444444444444444444444444444444444444444444444444444444444444444",
            ),
        },
    ];
    let replayed = checkpoint.core.replay_tail(&tail).unwrap();

    // A from-genesis full replay reaching the identical final shard
    // state builds the same vector directly.
    let full_replay = ClosedHeadVectorV1::from_heads(
        epoch_id,
        vec![
            ClosedShardHeadV1 {
                shard: 0,
                last_committed_offset: CommittedOffsetV1::new(15).unwrap(),
                chain_digest: digest(
                    "3333333333333333333333333333333333333333333333333333333333333333",
                ),
            },
            ClosedShardHeadV1 {
                shard: 5,
                last_committed_offset: CommittedOffsetV1::new(2).unwrap(),
                chain_digest: digest(
                    "2222222222222222222222222222222222222222222222222222222222222222",
                ),
            },
            ClosedShardHeadV1 {
                shard: 7,
                last_committed_offset: CommittedOffsetV1::new(3).unwrap(),
                chain_digest: digest(
                    "4444444444444444444444444444444444444444444444444444444444444444",
                ),
            },
        ],
    )
    .unwrap();
    assert_eq!(replayed, full_replay);
    assert_eq!(
        encode_canonical(&replayed).unwrap(),
        encode_canonical(&full_replay).unwrap()
    );

    // A tail that regresses a shard the checkpoint already closed fails
    // closed rather than silently rewriting history.
    let regressing_tail = vec![ClosedShardHeadV1 {
        shard: 0,
        last_committed_offset: CommittedOffsetV1::new(1).unwrap(),
        chain_digest: digest("3333333333333333333333333333333333333333333333333333333333333333"),
    }];
    assert!(checkpoint.core.replay_tail(&regressing_tail).is_err());

    // A tail entry naming a shard the checkpoint already closed, at the
    // IDENTICAL offset the checkpoint already recorded, but with a
    // DIFFERENT chain digest, is a forked append chain -- contested
    // input, not an advance -- and must fail closed rather than being
    // silently substituted for the checkpoint's own closed head.
    let honest_shard0 = checkpoint
        .core
        .closed_shard_positions
        .heads
        .iter()
        .find(|head| head.shard == 0)
        .copied()
        .unwrap();
    let forked_tail = vec![ClosedShardHeadV1 {
        shard: 0,
        last_committed_offset: honest_shard0.last_committed_offset,
        chain_digest: digest("dead00000000000000000000000000000000000000000000000000000000beef"),
    }];
    assert_ne!(forked_tail[0].chain_digest, honest_shard0.chain_digest);
    assert!(checkpoint.core.replay_tail(&forked_tail).is_err());

    // Equal offset AND equal chain digest is an idempotent no-op: the
    // checkpoint's own closed head, re-observed, is accepted and leaves
    // the resulting vector unchanged.
    let idempotent_tail = vec![honest_shard0];
    let replayed_noop = checkpoint.core.replay_tail(&idempotent_tail).unwrap();
    assert_eq!(replayed_noop, checkpoint.core.closed_shard_positions);
}

#[test]
fn archive_move_requires_every_admission_binding() {
    let golden = record(ARCHIVE_MOVE_ADMISSION);
    require_canonical(golden).unwrap();
    let admission: ArchiveMoveAdmissionV1 = decode_strict(golden).unwrap();
    admission.validate().unwrap();
    assert_eq!(encode_canonical(&admission).unwrap(), golden);

    let admitted = AdmittedArchiveMoveV1::from_admission(&admission).unwrap();
    assert_eq!(
        admitted.manifest_digest(),
        admission.manifest.manifest_digest().unwrap()
    );

    let mut missing_replay_verification = admission.clone();
    missing_replay_verification
        .replay_verification_receipt
        .verified_subject_digest =
        digest("8888888888888888888888888888888888888888888888888888888888888888");
    assert!(missing_replay_verification.validate().is_err());
    assert!(AdmittedArchiveMoveV1::from_admission(&missing_replay_verification).is_err());

    let mut wrong_copy = admission;
    wrong_copy.durable_copy_receipt.object_digest =
        digest("9999999999999999999999999999999999999999999999999999999999999999");
    assert!(wrong_copy.validate().is_err());
}

#[test]
fn verified_replay_anchor_test_constructor_matches_from_checkpoint() {
    let checkpoint: EvidenceCompactionCheckpointV1 =
        decode_strict(record(EVIDENCE_COMPACTION_CHECKPOINT)).unwrap();
    let anchor = VerifiedReplayAnchorV1::from_checkpoint(&checkpoint).unwrap();
    let rebuilt =
        VerifiedReplayAnchorV1::from_parts_for_test(anchor.checkpoint_digest(), anchor.epoch_id());
    assert_eq!(rebuilt, anchor);
}

#[test]
fn admitted_archive_move_test_constructor_matches_from_admission() {
    let admission: ArchiveMoveAdmissionV1 = decode_strict(record(ARCHIVE_MOVE_ADMISSION)).unwrap();
    let admitted = AdmittedArchiveMoveV1::from_admission(&admission).unwrap();
    let rebuilt = AdmittedArchiveMoveV1::from_parts_for_test(admitted.manifest_digest());
    assert_eq!(rebuilt, admitted);
}

#[test]
fn replay_horizon_states_bounded_replay_explicitly() {
    let genesis_only = ReplayHorizonV1::genesis(ReplayFrom::Genesis {});
    // A genesis semantic bound needs no anchor at all.
    genesis_only.validate_semantic_anchor(None).unwrap();
    assert_eq!(genesis_only.semantic_replay_from, ReplayFrom::Genesis {});
    assert_eq!(
        genesis_only.historical_content_available_from,
        ReplayFrom::Genesis {}
    );

    let checkpoint: EvidenceCompactionCheckpointV1 =
        decode_strict(record(EVIDENCE_COMPACTION_CHECKPOINT)).unwrap();
    let anchor = VerifiedReplayAnchorV1::from_checkpoint(&checkpoint).unwrap();
    let bounded = ReplayHorizonV1::anchored(&anchor, ReplayFrom::Genesis {});
    // A checkpoint semantic bound is rejected without its anchor...
    assert!(bounded.validate_semantic_anchor(None).is_err());
    // ...and accepted with the exact anchor it was built from.
    bounded.validate_semantic_anchor(Some(&anchor)).unwrap();
    assert_ne!(bounded.semantic_replay_from, ReplayFrom::Genesis {});
    assert_eq!(
        bounded.semantic_replay_from,
        ReplayFrom::Checkpoint {
            checkpoint_digest: anchor.checkpoint_digest()
        }
    );
}

/// A record decoded from a `.jsonl` fixture, matching the shape
/// `vector-suite.jsonl` itself advertises. Keys are sorted for the same
/// reason every other fixture's keys are: this is a canonical JSON
/// document like any other, and it is round-tripped through
/// `encode_canonical`/`decode_strict` below.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerEpochVectorSuiteV1 {
    archive_segment_manifest_digest: Sha256Digest,
    cursor_vector_barrier_digest: Sha256Digest,
    evidence_compaction_core_digest: Sha256Digest,
    fixture_authority: String,
    invariants: Vec<String>,
    negative_fixtures: Vec<String>,
    positive_fixtures: Vec<String>,
    projection_generation_id: Sha256Digest,
    projector_checkpoint_digest: Sha256Digest,
    schema_version: u32,
    successor_log_epoch_id: Sha256Digest,
    topic: String,
}

#[test]
fn every_w0_log_digest_domain_is_pinned_by_a_hard_coded_hex_constant() {
    // Every one of the seven digest domains this workstream reserved
    // (LogEpochV2, EvidenceCompactionCheckpointV1, ProjectorCheckpointV1,
    // ArchiveSegmentManifestV1, CursorVectorV1, ProjectionGenerationV1,
    // ProjectionGenerationRecordV1) is exercised here by recomputing its
    // golden fixture's digest and comparing it to a hard-coded hex
    // constant. Renaming any one of the seven `DigestDomain::prefix()`
    // strings changes exactly one of these recomputed digests and fails
    // this test.
    let epoch: SuccessorLogEpochV1 = decode_strict(record(SUCCESSOR_LOG_EPOCH)).unwrap();
    assert_eq!(
        epoch.epoch_id().unwrap().digest(),
        digest(SUCCESSOR_LOG_EPOCH_ID)
    );

    let checkpoint: EvidenceCompactionCheckpointV1 =
        decode_strict(record(EVIDENCE_COMPACTION_CHECKPOINT)).unwrap();
    assert_eq!(
        checkpoint.core.core_digest().unwrap(),
        digest("8db62c9381cc2a2e47855015adfe85baee5ab5a6980d3f7142e2c82499b83eef")
    );

    let projector: ProjectorCheckpointV1 = decode_strict(record(PROJECTOR_CHECKPOINT)).unwrap();
    assert_eq!(
        projector.checkpoint_digest().unwrap(),
        digest(PROJECTOR_CHECKPOINT_DIGEST)
    );

    let admission: ArchiveMoveAdmissionV1 = decode_strict(record(ARCHIVE_MOVE_ADMISSION)).unwrap();
    assert_eq!(
        admission.manifest.manifest_digest().unwrap(),
        digest("13269e974c56de1985af23bf0ce1ab8c048ef676d2ef8eac1182838de0d95086")
    );

    let barrier: CursorVectorBarrierV1 = decode_strict(record(CURSOR_VECTOR_BARRIER)).unwrap();
    assert_eq!(
        barrier.barrier_digest().unwrap(),
        digest(CURSOR_BARRIER_DIGEST)
    );

    let generation: ProjectionGenerationV1 = decode_strict(record(PROJECTION_GENERATION)).unwrap();
    generation.validate().unwrap();
    assert_eq!(
        generation.barrier.barrier_digest().unwrap(),
        digest(CURSOR_BARRIER_DIGEST)
    );
    assert_eq!(
        generation.generation_id().unwrap(),
        digest(PROJECTION_GENERATION_ID)
    );
    assert_eq!(
        generation.record_digest().unwrap(),
        digest(PROJECTION_GENERATION_RECORD_DIGEST)
    );
}

#[test]
fn vector_suite_is_byte_frozen_and_advertises_every_pinned_digest() {
    let golden = record(VECTOR_SUITE);
    require_canonical(golden).unwrap();

    let expected = LedgerEpochVectorSuiteV1 {
        archive_segment_manifest_digest: digest(
            "13269e974c56de1985af23bf0ce1ab8c048ef676d2ef8eac1182838de0d95086",
        ),
        cursor_vector_barrier_digest: digest(CURSOR_BARRIER_DIGEST),
        evidence_compaction_core_digest: digest(
            "8db62c9381cc2a2e47855015adfe85baee5ab5a6980d3f7142e2c82499b83eef",
        ),
        fixture_authority:
            "none; structural fixtures are byte-exact contract vectors, not activated state".into(),
        invariants: ["REPLAY-01", "REPLAY-02", "EVENT-03", "EVID-01"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        negative_fixtures: [
            "negative-unsorted-head-vector.jsonl",
            "negative-missing-predecessor.jsonl",
            "negative-seed-shape.jsonl",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        positive_fixtures: [
            "successor-log-epoch.jsonl",
            "evidence-compaction-checkpoint.jsonl",
            "cursor-vector-barrier.jsonl",
            "projection-generation.jsonl",
            "projector-checkpoint.jsonl",
            "archive-move-admission.jsonl",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        projection_generation_id: digest(PROJECTION_GENERATION_ID),
        projector_checkpoint_digest: digest(PROJECTOR_CHECKPOINT_DIGEST),
        schema_version: 1,
        successor_log_epoch_id: digest(SUCCESSOR_LOG_EPOCH_ID),
        topic: "ledger-epoch".into(),
    };
    assert_eq!(encode_canonical(&expected).unwrap(), golden);

    let suite: LedgerEpochVectorSuiteV1 = decode_strict(golden).unwrap();
    assert_eq!(suite, expected);

    // Every digest the suite advertises is independently re-derived from
    // its own golden fixture (not merely copied) in
    // `every_w0_log_digest_domain_is_pinned_by_a_hard_coded_hex_constant`
    // above; this test additionally proves the suite file itself is
    // exactly reproducible and every field in it agrees with the
    // constants that test uses.
    assert!(
        suite
            .positive_fixtures
            .contains(&"projection-generation.jsonl".to_string())
    );
}
