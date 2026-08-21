#!/usr/bin/env python3
"""Deterministic one-off generator for the W0-OBS contract fixtures.

Not part of the build; run manually to (re)produce
contracts/dynamic-memory/v3/observer/*.jsonl. Every digest is a plain
SHA-256 of a human-readable label so provenance is auditable by inspection.
"""
import hashlib
import json
import os

ROOT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "contracts",
    "dynamic-memory",
    "v3",
    "observer",
)


def d(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


ADMISSION_DIGEST_DOMAIN = "ostk-observer-admission-v2"
RUN_RECEIPT_DIGEST_DOMAIN = "ostk-observer-run-receipt-v1"


def canonical_bytes(obj) -> bytes:
    """Byte-identical to Rust's `encode_canonical` for every shape this suite
    uses (ints, strings, bools, arrays, and objects only -- no floats, no
    non-ASCII): compact separators plus lexicographically sorted object keys,
    exactly what the `ostk-canonical-json-v1` BTreeMap-backed encoder emits.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def domain_digest(prefix: str, obj) -> str:
    """Replicates `domain_separated_digest(domain, encode_canonical(obj))`:
    sha256(prefix || 0x00 || canonical_bytes). Used to chain a result
    fixture's `admission_digest`/`run_receipt_digest` to the *real* digest of
    the sibling fixture object it cites, so the two can never silently drift
    apart the way a `d(f"{label}.admission_digest")` label placeholder would
    let them (PRED-05).
    """
    hasher = hashlib.sha256()
    hasher.update(prefix.encode())
    hasher.update(b"\x00")
    hasher.update(canonical_bytes(obj))
    return hasher.hexdigest()


def uri(kind: str, form: str, seed: int) -> str:
    return f"urn:ostk:{form}:v1:{kind}:sha256:{('%02x' % seed) * 32}"


def write(name: str, obj) -> None:
    path = os.path.join(ROOT, name)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(canonical_bytes(obj).decode("utf-8"))
        handle.write("\n")
    print("wrote", path)


def registry_ref(entry_id: str, label: str, version: int = 1):
    return {"entry_id": entry_id, "version": version, "entry_digest": d(label)}


def toolchain():
    return {
        "language_version": "rust-1.94",
        "schema_version": "schema-v1",
        "compiler_version": "rustc-1.94.0",
        "api_version": "api-v1",
    }


def input_domain(resource_kind="rust.enum"):
    return {
        "closed_input_boundary_id": "boundary.crate-source",
        "supported_source_kinds": ["git.blob"],
        "supported_resource_kinds": [resource_kind],
        "required_applicability_dimensions": ["repository_commit"],
    }


def enumeration_algorithm():
    return {
        "algorithm_id": "algorithm.syn-ast-walk",
        "unsupported_feature_diagnostics": ["macro.unresolved"],
    }


def admission(admission_id, observer_kind, mode, label_ns, resource_kind="rust.enum"):
    dep_one = d(f"{label_ns}.dependency.one")
    dep_two = d(f"{label_ns}.dependency.two")
    dependency_digests = sorted([dep_one, dep_two])
    return {
        "schema_version": 1,
        "admission_id": admission_id,
        "version": 1,
        "identity": {
            "observer_kind": observer_kind,
            "executable_digest": d(f"{label_ns}.executable"),
            "dependency_digests": dependency_digests,
            "version": 1,
        },
        "predicate": registry_ref(
            "predicate.mcp.remember.allowed_actions", f"{label_ns}.predicate"
        ),
        "input_domain": input_domain(resource_kind),
        "configuration_context_digest": d(f"{label_ns}.configuration"),
        "toolchain_versions": toolchain(),
        "mode": mode,
        "enumeration_algorithm": enumeration_algorithm(),
        "declared_outcome_kinds": [
            "success",
            "partial",
            "stale",
            "parse_failure",
            "timeout",
        ],
        "coverage_receipt_recipe": registry_ref(
            "coverage.recipe.default", f"{label_ns}.coverage_recipe"
        ),
        "positive_vector_digest": d(f"{label_ns}.vector.positive"),
        "negative_vector_digest": d(f"{label_ns}.vector.negative"),
        "mutation_vector_digest": d(f"{label_ns}.vector.mutation"),
        "adversarial_vector_digest": d(f"{label_ns}.vector.adversarial"),
    }


def input_tally(total, samples):
    return {"total_count": total, "sample": samples}


def run_receipt(label_ns, admission_id, dep_labels, outcome="success", extra_skipped=False):
    dep_digests = sorted(d(f"{label_ns}.{name}") for name in dep_labels)
    included_samples = sorted(
        [uri("rust.enum", "occurrence", 0x01), uri("rust.enum", "occurrence", 0x02)]
    )
    skipped = input_tally(0, [])
    if extra_skipped:
        skipped = input_tally(1, [uri("rust.enum", "occurrence", 0x09)])
    return {
        "schema_version": 1,
        "admission": registry_ref(admission_id, f"{label_ns}.admission"),
        "executable_identity": {
            "executable_digest": d(f"{label_ns}.executable"),
            "dependency_digests": dep_digests,
        },
        "source_version": uri("repository", "version", 0x20),
        "inputs": {
            "included": input_tally(2, included_samples),
            "excluded": input_tally(0, []),
            "skipped": skipped,
            "failed": input_tally(0, []),
            "unsupported": input_tally(0, []),
            "unknown": input_tally(0, []),
        },
        "applicability": [
            {
                "dimension_id": "repository_commit",
                "resource": uri("commit", "version", 0x10),
            }
        ],
        "configuration_context_digest": d(f"{label_ns}.configuration"),
        "input_digest": d(f"{label_ns}.input_snapshot"),
        "output_digest": d(f"{label_ns}.output_snapshot"),
        "coverage": {
            "coverage_receipt_digest": d(f"{label_ns}.coverage_receipt"),
            "completeness": "complete",
            "freshness": "current",
            "continuity": "contiguous",
        },
        "evidence_event_ids": [d(f"{label_ns}.evidence.one")],
        "outcome": outcome,
        "observed_at": "2026-08-14T12:00:00.000000000Z",
    }


def result(
    label_ns,
    predicate_id,
    claim_shape,
    evaluated_condition,
    verification_outcome,
    admission_obj,
    run_receipt_obj,
):
    return {
        "schema_version": 1,
        "event_kind": "observer.result.accepted",
        "profile": {
            "profile_id": "ostk-canonical-json-v1",
            "profile_digest": "cf22991a86bfc560556c7d04efa4ee6b7b1ee0f49c919b257ea7b4f30f8e4a29",
            "vector_manifest_digest": "f984f62866fc769df3a5617a2247e3ade694827c1de69e615a7bda68858b4174",
        },
        "scope": {
            "tenant_namespace": "tenant.fleet",
            "project_namespace": "project.fleet-recall",
        },
        "predicate": registry_ref(predicate_id, f"{label_ns}.predicate"),
        "applicability": [
            {
                "dimension_id": "repository_commit",
                "resource": uri("commit", "version", 0x10),
            }
        ],
        "admission_digest": domain_digest(ADMISSION_DIGEST_DOMAIN, admission_obj),
        "run_receipt_digest": domain_digest(RUN_RECEIPT_DIGEST_DOMAIN, run_receipt_obj),
        "claim_shape": claim_shape,
        "evaluated_condition": evaluated_condition,
        "verification_outcome": verification_outcome,
        "effective_at": "2026-08-14T12:00:00.000000000Z",
    }


def main():
    os.makedirs(ROOT, exist_ok=True)

    closed_world = admission(
        "observer.ast_schema_enum",
        "ast_schema",
        "closed_world_verified",
        "closed",
    )
    write("observer-admission-closed-world-v1.jsonl", closed_world)
    print("ADMISSION_DIGEST_LABEL closed", "canonical digest computed by cargo test")

    positive_verified = admission(
        "observer.positive_verified_probe",
        "ast_schema",
        "positive_verified",
        "positive",
    )
    write("observer-admission-positive-verified-v1.jsonl", positive_verified)

    candidate_only = admission(
        "observer.llm_candidate_probe",
        "llm",
        "candidate_only",
        "candidate",
    )
    write("observer-admission-candidate-only-v1.jsonl", candidate_only)

    closed_run_receipt = run_receipt(
        "closed", "observer.ast_schema_enum", ["dependency.one", "dependency.two"]
    )
    write("observer-run-receipt-success-v1.jsonl", closed_run_receipt)

    write(
        "observer-result-verified-negative-v1.jsonl",
        result(
            "closed",
            "predicate.mcp.remember.allowed_actions",
            "presence",
            "absent",
            "verified_negative",
            closed_world,
            closed_run_receipt,
        ),
    )

    write(
        "vector-suite.jsonl",
        {
            "schema_version": 1,
            "fixture_authority": "W0-OBS",
            "cases": [
                "observer-admission-closed-world-v1",
                "observer-admission-positive-verified-v1",
                "observer-admission-candidate-only-v1",
                "observer-run-receipt-success-v1",
                "observer-result-verified-negative-v1",
                "negative-llm-closed-world-v1",
                "negative-unknown-field-v1",
                "negative-unsorted-dependency-digests-v1",
            ],
        },
    )

    negative_llm_closed_world = admission(
        "observer.llm_bad_closed_world",
        "llm",
        "closed_world_verified",
        "badllm",
    )
    write("negative-llm-closed-world-v1.jsonl", negative_llm_closed_world)

    negative_unknown_field = dict(closed_world)
    negative_unknown_field["admission_id"] = "observer.unknown_field_probe"
    negative_unknown_field["unexpected_extra_field"] = True
    write("negative-unknown-field-v1.jsonl", negative_unknown_field)

    negative_unsorted = admission(
        "observer.unsorted_probe",
        "ast_schema",
        "closed_world_verified",
        "unsorted",
    )
    negative_unsorted["identity"]["dependency_digests"] = list(
        reversed(negative_unsorted["identity"]["dependency_digests"])
    )
    write("negative-unsorted-dependency-digests-v1.jsonl", negative_unsorted)


if __name__ == "__main__":
    main()
