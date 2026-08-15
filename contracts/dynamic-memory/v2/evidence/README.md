# Registry-bound evidence v2 contract fixtures

These records freeze the first Stage 4 contract-only seam. Every `.jsonl` file
contains one canonical JSON record followed by exactly one LF. The LF is
repository framing and is excluded from every contract digest.

`connector-schema-v2-entry.jsonl` commits the only admitted v1 logical
consistency recipe: family `source_fact`, key derivation `source_fact_id`. The
recipe derives a logical `ConsistencyPartitionKeyV1`; epoch, shard, offset, and
the key itself remain outside accepted-event identity.

`source-fact-v2.jsonl` is stable across registry activation. Interpretation and
governance live in `representation-origin-v2.jsonl`, which binds the full
structural registry head (activation, package, policy, and effective interval).
The successor fixture proves ABA resistance by returning to the same package
and policy under a new activation ID while explicitly naming its predecessor.

These bytes prove only canonical shape and digest closure. They are not an
active-registry witness, trusted ingress context, accepted ledger event, or
runtime authority. Runtime must rederive resource URIs, resolve every registry
reference from the active package, and compare the full head in the same
transaction that appends an event.

Changing a canonical record, domain prefix, expected digest, outcome, or
ordering rule is a contract-version change. Cosmetic prose here is not
identity-bearing.
