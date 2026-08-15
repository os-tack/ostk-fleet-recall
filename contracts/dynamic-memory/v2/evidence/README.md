# Registry-bound evidence v2 contract fixtures

These records freeze the first Stage 4 contract-only seam. Every `.jsonl` file
contains one canonical JSON record followed by exactly one LF. The LF is
repository framing and is excluded from every contract digest.

`connector-schema-v2-entry.jsonl` commits the only admitted v1 logical
consistency recipe: family `source_fact`, key derivation `source_fact_id`. The
recipe derives a logical `ConsistencyPartitionKeyV1`; epoch, shard, offset, and
the key itself remain outside accepted-event identity.

The connector and every representation copy two exact, role-specific identity
recipe references: `provider_instance_identity_recipe` and
`canonical_resource_identity_recipe`. The Git push fixture deliberately uses
distinct recipes. A connector whose two roles genuinely name the same resource
may put the same exact recipe in both explicit fields. The Git provider
instance is an `entity` URI of kind `provider_instance`; its canonical resource
is an `occurrence` URI of kind `provider_event`. Other connectors may use
provider-specific entity kinds, and active-package closure must prove that each
recipe body selects the URI form and resource kind used in that role.

`source-fact-v2.jsonl` is stable across registry activation. Interpretation and
governance live in `representation-origin-v2.jsonl`, which binds the full
structural registry head (activation, package, policy, and effective interval).
The successor fixture proves ABA resistance by returning to the same package
and policy under a new activation ID while explicitly naming its predecessor.
Activation/head and governance changes that leave the exact resource identities
unchanged preserve the source-fact ID and mint an explicitly linked
representation. An identity-recipe revision is not a same-fact
reinterpretation: because the exact recipe reference is part of the resource
locator preimage, runtime rederivation changes the affected URI and therefore
the source-fact ID. Recipe-ref-only candidate mutations are mismatch negatives,
not admissible successor vectors.

These bytes prove only canonical shape and digest closure. They are not an
active-registry witness, trusted ingress context, accepted ledger event, or
runtime authority. Runtime must rederive each resource URI with its matching
role-specific recipe, resolve every registry reference from the active package,
and compare the full head in the same transaction that appends an event.

Changing a canonical record, domain prefix, expected digest, outcome, or
ordering rule is a contract-version change. Cosmetic prose here is not
identity-bearing.
