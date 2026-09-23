# Dynamic memory contract corpus

The files under `v1/` and `v2/` define deployed identities: registry package,
activation, receipt, and other contract digests are computed over their exact
bytes. Changing or deleting one of those files changes those digests, so a
change of meaning is expressed by adding a new vector under `v3/` (or a later
tier) instead of editing existing `v1/` or `v2/` bytes. The golden identity
tests in `src/memory_contracts` catch accidental byte changes.

Some README prose inside `v1/` and `v2/` still describes byte-pin tests that
have since been removed. Those READMEs carry no identity, but they are left
unchanged along with the rest of those trees.

`v3/` holds the contract vectors for later dynamic-memory stages; see
[`v3/README.md`](v3/README.md).
