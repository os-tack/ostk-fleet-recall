# Dynamic memory contract corpus

`v1/` and `v2/` are append-only: deployed identities derive from the exact
bytes of the files already under those trees, so an existing file must never
be modified or deleted after it lands — a change of meaning is expressed by
cutting a new vector under `v3/` (or a later tier), never by editing frozen
bytes. CI enforces this as a path rule (the `frozen-contracts` job fails any
push or pull request that modifies or deletes an existing file under `v1/`
or `v2/`, while permitting additions). There is no in-repo digest manifest
or byte-pin test duplicating this guarantee: git already controls these
bytes, and the path rule expresses the append-only invariant directly.
Prose inside the frozen trees that still describes the old byte-pin
mechanism is itself frozen and stays as-is.
