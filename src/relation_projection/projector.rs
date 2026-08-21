//! Pure re-derivation of one relation fingerprint's current state.
//!
//! # Why this is not a call to `memory_contracts::relation::project_relation`
//!
//! `project_relation` is the canonical, doc-frozen algorithm (REL-01,
//! REPLAY-01) and its output types — [`RelationProjectionV1`] and
//! [`RelationProjectionStateV1`] — are reused verbatim by this module and by
//! [`super::cockroach`]. But `project_relation` takes
//! `&[RelationProjectionInput<'_>]`, and `RelationProjectionInput` can only be
//! built from an `AdmittedRelationAttestation` or a `VerifiedRelationBasis`.
//! Both of those capability types expose a constructor only behind
//! `#[cfg(test)]`, and that constructor is a module-private `fn` (no `pub` at
//! all) reachable solely from `memory_contracts::relation`'s own nested test
//! module. Neither this crate's other modules nor its `tests/` integration
//! binaries — which link the library crate compiled WITHOUT `cfg(test)`, so
//! the item is not even present — can name it.
//!
//! `project_relation` therefore currently has no production caller anywhere
//! in this crate: the general accepted-event ledger's own doc-hidden
//! `AppendableAcceptedEvent::relation_attestation` entry point (the one this
//! module uses to append) sidesteps the capability wrappers entirely by
//! taking the raw, fully public `RelationAttestationEventV1` and proving only
//! structural closure plus the head binding — exactly what a relation
//! *admission* stage would otherwise have proven before minting a capability.
//!
//! Rather than widen scope by adding a production constructor to
//! `memory_contracts::relation` (out of this workstream's owned files), this
//! module ports `project_relation`'s algorithm to operate directly on
//! `&RelationAttestationEventV1` — the freely constructible, publicly
//! deserializable wire type — with the capability's `verified` flag derived
//! from `basis` instead of carried by a wrapper. That derivation is not a
//! free choice: `project_relation`'s own eligibility check enforces exactly
//! the bijection [`basis_is_verified`] encodes (`Declared`/`Inferred` may only
//! ever be admitted unverified; `ProviderAttested`/`VerifierResult` may only
//! ever be admitted verified), so this port and the original accept exactly
//! the same closed input sets and compute exactly the same output for them.
//! See the W1-REL handoff for the request to add a real capability
//! constructor so this port can be deleted in favor of the original.
use std::collections::{BTreeMap, BTreeSet};

use crate::memory_contracts::evidence::AcceptedEventId;
use crate::memory_contracts::relation::{
    RelationAttestationBasisV1, RelationAttestationEventV1, RelationAttestationVerdictV1,
    RelationFingerprint, RelationProjectionStateV1, RelationProjectionV1,
};
use crate::memory_contracts::{ContractError, ContractResult};

/// Whether an attestation counts as `verified` in [`RelationProjectionV1`]
/// terms. See the module documentation for why this is a derivation rather
/// than a free parameter.
#[must_use]
pub const fn basis_is_verified(basis: RelationAttestationBasisV1) -> bool {
    matches!(
        basis,
        RelationAttestationBasisV1::ProviderAttested | RelationAttestationBasisV1::VerifierResult
    )
}

/// Deterministically replay one exact edge from a closed set of admitted
/// attestation events (REPLAY-01: input order and exact retries cannot affect
/// the result).
///
/// A line-for-line port of `memory_contracts::relation::project_relation`; see
/// the module documentation for why this module cannot call that function
/// directly. `events` must be the complete admitted history for
/// `relation_fingerprint` — a missing supersession predecessor fails closed
/// rather than silently treating a partial view as complete.
pub fn project_relation_events(
    relation_fingerprint: RelationFingerprint,
    events: &[&RelationAttestationEventV1],
) -> ContractResult<RelationProjectionV1> {
    let mut records: BTreeMap<AcceptedEventId, (&RelationAttestationEventV1, bool)> =
        BTreeMap::new();

    for event in events {
        event.validate_shape()?;
        if event.relation_fingerprint != relation_fingerprint {
            return Err(ContractError::Schema(
                "relation projection mixed fingerprints".into(),
            ));
        }
        let verified = basis_is_verified(event.basis);
        let event_id = event.accepted_event_id()?;
        match records.get_mut(&event_id) {
            Some((existing, existing_verified)) if *existing == *event => {
                *existing_verified |= verified;
            }
            Some(_) => {
                return Err(ContractError::Schema(
                    "accepted relation event ID collision".into(),
                ));
            }
            None => {
                records.insert(event_id, (*event, verified));
            }
        }
    }

    if records.is_empty() {
        return Err(ContractError::Schema(
            "relation projection requires admitted history".into(),
        ));
    }

    let superseded = collect_superseded(&records)?;

    let mut active_attestation_ids = Vec::new();
    let mut active_unverified_attestation_ids = Vec::new();
    let mut active_verified_support_ids = Vec::new();
    let mut active_verified_refute_ids = Vec::new();
    for (event_id, (event, verified)) in &records {
        if superseded.contains(event_id) {
            continue;
        }
        active_attestation_ids.push(*event_id);
        if *verified {
            match event.verdict {
                RelationAttestationVerdictV1::Supports => {
                    active_verified_support_ids.push(*event_id);
                }
                RelationAttestationVerdictV1::Refutes => {
                    active_verified_refute_ids.push(*event_id);
                }
            }
        } else {
            active_unverified_attestation_ids.push(*event_id);
        }
    }

    let state = match (
        active_verified_support_ids.is_empty(),
        active_verified_refute_ids.is_empty(),
    ) {
        (false, false) => RelationProjectionStateV1::Contested,
        (false, true) => RelationProjectionStateV1::Verified,
        (true, false) => RelationProjectionStateV1::Refuted,
        (true, true) => RelationProjectionStateV1::Declared,
    };

    Ok(RelationProjectionV1 {
        relation_fingerprint,
        state,
        active_attestation_ids,
        superseded_attestation_ids: superseded.into_iter().collect(),
        active_unverified_attestation_ids,
        active_verified_support_ids,
        active_verified_refute_ids,
    })
}

fn collect_superseded(
    records: &BTreeMap<AcceptedEventId, (&RelationAttestationEventV1, bool)>,
) -> ContractResult<BTreeSet<AcceptedEventId>> {
    let mut superseded = BTreeSet::new();
    for (event_id, (event, _)) in records {
        if let Some(predecessor_id) = event.supersedes_attestation_id {
            let Some((predecessor, predecessor_verified)) = records.get(&predecessor_id) else {
                return Err(ContractError::Schema(
                    "invalid or missing same-edge supersession predecessor".into(),
                ));
            };
            let successor_verified = records[event_id].1;
            if predecessor_id == *event_id
                || predecessor.attestor != event.attestor
                || predecessor.basis != event.basis
                || *predecessor_verified != successor_verified
            {
                return Err(ContractError::Schema(
                    "unauthorized or cross-authority relation supersession".into(),
                ));
            }
            superseded.insert(predecessor_id);
        }
    }

    reject_supersession_cycles(records)?;
    Ok(superseded)
}

/// A finite one-predecessor graph must terminate. Detect a forged cycle
/// explicitly rather than letting it deactivate every node.
fn reject_supersession_cycles(
    records: &BTreeMap<AcceptedEventId, (&RelationAttestationEventV1, bool)>,
) -> ContractResult<()> {
    let mut completed = BTreeSet::new();
    for start in records.keys().copied() {
        if completed.contains(&start) {
            continue;
        }
        let mut path = Vec::new();
        let mut path_set = BTreeSet::new();
        let mut cursor = start;
        loop {
            if completed.contains(&cursor) {
                break;
            }
            if !path_set.insert(cursor) {
                return Err(ContractError::Schema(
                    "cyclic relation attestation supersession".into(),
                ));
            }
            path.push(cursor);
            match records[&cursor].0.supersedes_attestation_id {
                Some(predecessor) => cursor = predecessor,
                None => break,
            }
        }
        completed.extend(path);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use super::*;
    use crate::memory_contracts::canonical::decode_strict;
    use crate::memory_contracts::relation::{RelationAttestorIdentityV1, RelationEdgeV1};

    const DECLARED_EVENT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/relation/declared-attestation-event.jsonl"
    );
    const VERIFIED_EVENT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/relation/verifier-support-attestation-event.jsonl"
    );

    fn record(artifact: &'static [u8]) -> &'static [u8] {
        artifact
            .strip_suffix(b"\n")
            .expect("contract artifact must have one repository-framing LF")
    }

    fn declared() -> RelationAttestationEventV1 {
        decode_strict(record(DECLARED_EVENT_FIXTURE)).unwrap()
    }

    fn verified_support() -> RelationAttestationEventV1 {
        decode_strict(record(VERIFIED_EVENT_FIXTURE)).unwrap()
    }

    fn verified_refute() -> RelationAttestationEventV1 {
        let mut event = verified_support();
        event.verdict = RelationAttestationVerdictV1::Refutes;
        event.evidence_event_ids = vec![AcceptedEventId::from_digest(
            crate::memory_contracts::digest::domain_separated_digest(
                crate::memory_contracts::digest::DigestDomain::AcceptedEvent,
                b"refute-evidence",
            ),
        )];
        event
    }

    fn fp() -> RelationFingerprint {
        declared().relation_fingerprint
    }

    // ---------------------------------------------------------------
    // basis_is_verified: exhaustive over the four-variant closed enum.
    // ---------------------------------------------------------------

    #[test]
    fn basis_is_verified_matches_the_project_relation_eligibility_bijection() {
        assert!(!basis_is_verified(RelationAttestationBasisV1::Declared));
        assert!(!basis_is_verified(RelationAttestationBasisV1::Inferred));
        assert!(basis_is_verified(
            RelationAttestationBasisV1::ProviderAttested
        ));
        assert!(basis_is_verified(
            RelationAttestationBasisV1::VerifierResult
        ));
    }

    // ---------------------------------------------------------------
    // Fail-closed shape: empty / mixed-fingerprint / duplicate-id-collision.
    // ---------------------------------------------------------------

    #[test]
    fn empty_history_is_rejected() {
        // Kills a mutant that deletes the `records.is_empty()` guard: without
        // it this call would panic or silently return a vacuous projection
        // instead of failing closed.
        let error = project_relation_events(fp(), &[]).unwrap_err();
        assert!(
            matches!(error, ContractError::Schema(message) if message.contains("admitted history"))
        );
    }

    #[test]
    fn mixed_fingerprints_are_rejected() {
        let declared = declared();
        let mut other_edge_declared = declared.clone();
        // A structurally different edge (different target) fingerprints
        // differently; feed it through under the ORIGINAL fingerprint.
        let mut edge: RelationEdgeV1 = other_edge_declared.edge.clone();
        edge.target =
            crate::memory_contracts::identity::ResourceUri::from_str(
                "urn:ostk:entity:v1:repository:sha256:9999999999999999999999999999999999999999999999999999999999999999",
            )
            .unwrap();
        other_edge_declared.edge = edge;
        other_edge_declared.relation_fingerprint = other_edge_declared.edge.fingerprint().unwrap();
        assert_ne!(
            other_edge_declared.relation_fingerprint,
            declared.relation_fingerprint
        );
        let error = project_relation_events(
            declared.relation_fingerprint,
            &[&declared, &other_edge_declared],
        )
        .unwrap_err();
        assert!(
            matches!(error, ContractError::Schema(message) if message.contains("mixed fingerprints"))
        );
    }

    #[test]
    fn duplicate_identical_event_in_the_input_set_is_idempotent() {
        // Kills a mutant that removes de-duplication by accepted-event ID
        // (e.g. always inserting instead of matching on `records.get_mut`):
        // feeding the exact same admitted event twice (at-least-once delivery
        // replayed into the same input batch) must not double-count it.
        let a = declared();
        let projected = project_relation_events(fp(), &[&a, &a]).unwrap();
        assert_eq!(projected.active_attestation_ids.len(), 1);
        assert_eq!(projected.active_unverified_attestation_ids.len(), 1);
    }

    // ---------------------------------------------------------------
    // State lattice: declared / verified / refuted / contested.
    // ---------------------------------------------------------------

    #[test]
    fn single_declared_attestation_is_declared_and_unverified() {
        let event = declared();
        let projected = project_relation_events(fp(), &[&event]).unwrap();
        assert_eq!(projected.state, RelationProjectionStateV1::Declared);
        assert_eq!(projected.active_unverified_attestation_ids.len(), 1);
        assert!(projected.active_verified_support_ids.is_empty());
        assert!(projected.active_verified_refute_ids.is_empty());
    }

    #[test]
    fn verified_support_is_verified_state() {
        let event = verified_support();
        let projected = project_relation_events(fp(), &[&event]).unwrap();
        assert_eq!(projected.state, RelationProjectionStateV1::Verified);
        assert_eq!(projected.active_verified_support_ids.len(), 1);
    }

    #[test]
    fn verified_refute_is_refuted_state() {
        let event = verified_refute();
        let projected = project_relation_events(fp(), &[&event]).unwrap();
        assert_eq!(projected.state, RelationProjectionStateV1::Refuted);
        assert_eq!(projected.active_verified_refute_ids.len(), 1);
    }

    #[test]
    fn opposing_active_verified_results_are_contested() {
        // Kills a mutant that flips the `(false, false) => Contested` arm to
        // `Verified` or `Refuted`: two independent verified attestations,
        // one support and one refute, on distinct evidence must land here.
        let support = verified_support();
        let refute = verified_refute();
        let projected = project_relation_events(fp(), &[&support, &refute]).unwrap();
        assert_eq!(projected.state, RelationProjectionStateV1::Contested);
        assert_eq!(projected.active_verified_support_ids.len(), 1);
        assert_eq!(projected.active_verified_refute_ids.len(), 1);
    }

    // ---------------------------------------------------------------
    // Supersession: authorized, unauthorized, missing predecessor, cycle,
    // self-reference.
    // ---------------------------------------------------------------

    fn superseding(
        base: &RelationAttestationEventV1,
        mutate: impl FnOnce(&mut RelationAttestationEventV1),
    ) -> RelationAttestationEventV1 {
        let mut event = base.clone();
        event.supersedes_attestation_id = Some(base.accepted_event_id().unwrap());
        mutate(&mut event);
        event
    }

    #[test]
    fn authorized_same_authority_supersession_retires_only_the_predecessor() {
        let old = verified_support();
        let new = superseding(&old, |event| {
            event.effective_at = crate::memory_contracts::common::CanonicalTimestamp::parse(
                "2026-08-15T04:06:00.000000000Z",
            )
            .unwrap();
        });
        let projected = project_relation_events(fp(), &[&old, &new]).unwrap();
        assert_eq!(
            projected.superseded_attestation_ids,
            vec![old.accepted_event_id().unwrap()]
        );
        assert_eq!(
            projected.active_attestation_ids,
            vec![new.accepted_event_id().unwrap()]
        );
        assert_eq!(projected.state, RelationProjectionStateV1::Verified);
    }

    // Note on `predecessor_id == *event_id` (the self-reference disjunct):
    // `AcceptedEventId` is a digest of the event's OWN canonical bytes,
    // including `supersedes_attestation_id` itself, so constructing a genuine
    // self-reference (`accepted_event_id(event) == event.supersedes_attestation_id`)
    // requires a SHA-256 preimage/fixed point — infeasible to build directly,
    // exactly like the multi-node cycle case below. Setting
    // `supersedes_attestation_id` to an event's id BEFORE that assignment
    // changes the event's own bytes (and therefore its own id), so the
    // resulting event's true id never equals its own `supersedes_attestation_id`
    // field; the projector observes this as a MISSING predecessor instead
    // (`missing_supersession_predecessor_fails_closed` below already covers
    // that path). `memory_contracts::relation`'s own test suite has no
    // dedicated self-reference case either, for the same reason. A mutant
    // that deletes this disjunct alone is therefore also an unreachable
    // equivalent mutant (see the W1-REL handoff).

    #[test]
    fn cross_attestor_supersession_is_rejected() {
        // Kills a mutant that drops the `predecessor.attestor != event.attestor`
        // disjunct: a different principal must not be able to retire someone
        // else's attestation.
        let old = declared();
        let new = superseding(&old, |event| {
            event.attestor = RelationAttestorIdentityV1::AuthenticatedActor {
                principal_id: crate::memory_contracts::common::ContractId::new(
                    "principal.someone-else",
                )
                .unwrap(),
            };
        });
        let error = project_relation_events(fp(), &[&old, &new]).unwrap_err();
        assert!(
            matches!(error, ContractError::Schema(message) if message.contains("unauthorized or cross-authority"))
        );
    }

    #[test]
    fn cross_basis_supersession_is_rejected() {
        // Kills a mutant that drops the `predecessor.basis != event.basis`
        // disjunct. The attestor is left byte-identical (same principal, same
        // verifier reference) so `predecessor.attestor != event.attestor`
        // alone cannot explain the rejection; only basis changes on its face.
        //
        // Note for the mutant table: because `basis_matches_attestor` pairs
        // each attestor KIND with exactly two bases whose `verified` flags
        // differ (`Declared`/`ProviderAttested` <-> `AuthenticatedActor`,
        // `Inferred`/`VerifierResult` <-> `RegisteredVerifier`), any basis
        // change that keeps the attestor identical also flips the derived
        // `verified` flag, so the `basis` disjunct is logically redundant
        // with `attestor`+`verified` for every input `validate_shape` admits.
        // A mutant that deletes the `basis` disjunct alone is therefore an
        // equivalent mutant (unkillable by any valid event set); this test
        // still pins the end-to-end rejection.
        let old = verified_support();
        let RelationAttestorIdentityV1::RegisteredVerifier { verifier, .. } = old.attestor.clone()
        else {
            panic!("fixture attestor must be a registered verifier");
        };
        let new = superseding(&old, |event| {
            event.basis = RelationAttestationBasisV1::Inferred;
            event.attestor = RelationAttestorIdentityV1::RegisteredVerifier {
                principal_id: crate::memory_contracts::common::ContractId::new(
                    "principal.projector",
                )
                .unwrap(),
                verifier,
            };
        });
        let error = project_relation_events(fp(), &[&old, &new]).unwrap_err();
        assert!(
            matches!(error, ContractError::Schema(message) if message.contains("unauthorized or cross-authority"))
        );
    }

    // Note on the third `collect_superseded` disjunct,
    // `*predecessor_verified != successor_verified`: given
    // `basis_matches_attestor`'s bijection (proved in the comment on
    // `cross_basis_supersession_is_rejected` above), any event pair that
    // disagrees on the derived `verified` flag while keeping the SAME
    // attestor is exactly the pair `cross_basis_supersession_is_rejected`
    // already builds (attestor fixed, basis changed, verified flips as a
    // consequence). There is no admissible event pair that flips `verified`
    // while holding both `attestor` and `basis` fixed, because `verified` is
    // a pure function of `basis`. A mutant that deletes this disjunct alone
    // is therefore also unkillable by any additional test beyond the one
    // already covering the same input shape.

    #[test]
    fn missing_supersession_predecessor_fails_closed() {
        // Kills a mutant that turns the `records.get(&predecessor_id)` miss
        // into a silent skip instead of a hard error: a partial history must
        // never be treated as complete.
        let mut event = declared();
        event.supersedes_attestation_id = Some(AcceptedEventId::from_digest(
            crate::memory_contracts::digest::domain_separated_digest(
                crate::memory_contracts::digest::DigestDomain::AcceptedEvent,
                b"never-appended",
            ),
        ));
        let error = project_relation_events(fp(), &[&event]).unwrap_err();
        assert!(
            matches!(error, ContractError::Schema(message) if message.contains("missing same-edge supersession predecessor"))
        );
    }

    // Note on `reject_supersession_cycles`: `AcceptedEventId` is a pure digest
    // of an event's own canonical bytes, and `supersedes_attestation_id` can
    // only name an ID computed from bytes fixed BEFORE it (there is no way to
    // mint an event whose id is not yet known and then reference it), so a
    // genuine multi-node supersession cycle cannot be constructed from
    // honestly-computed digests — only a direct self-reference is reachable,
    // and that is caught earlier by `collect_superseded`'s
    // `predecessor_id == *event_id` check (`self_referencing_supersession_is_rejected`
    // above). `reject_supersession_cycles` is therefore defense-in-depth
    // against a future weakening of that earlier check or a hash collision,
    // not something a mutation test can drive through a valid input set; a
    // mutant that disables it survives and is a documented, justified
    // survivor (see the W1-REL handoff).
}
