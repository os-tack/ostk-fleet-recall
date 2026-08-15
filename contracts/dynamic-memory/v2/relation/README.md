# Relation contract vectors

These fixtures freeze the structural Stage 4 relation seam. They carry no runtime authority: the named scope, registry head, actors, verifiers, evidence events, and resource URIs are deterministic test material.

`RelationEdgeV1` is directional and binds the exact ABA-safe registry head, exact relation-proof entry, exact endpoints, and a strictly sorted set of concrete applicability resources. Its fingerprint is `SHA-256("ostk-relation-fingerprint-v1" || 0x00 || canonical_edge_bytes)`.

`RelationAttestationEventV1` is an immutable accepted-event preimage under the existing `ostk-accepted-event-v1` domain. It contains semantic evidence and effective time, but no receipt time or physical append coordinate. Public wire bytes cannot enter the projector. The contract exposes no production constructor for either `AdmittedRelationAttestation` or the stronger `VerifiedRelationBasis` until the repository can supply active-registry, trusted-scope, actor/verifier, evidence, proof, and supersession-authorization witnesses.

The vector suite names the adversarial cases exercised by the Rust contract tests. Supersession is exact and same-edge: it requires the same attestor, basis, and admitted authority class; deactivates only the named predecessor; rejects cycles; and retains independent, forked, and historical evidence. All events for an edge share the logical consistency key `{family: "relation", key_digest: relation_fingerprint}`; epoch/shard mapping remains physical and outside semantic identity.
