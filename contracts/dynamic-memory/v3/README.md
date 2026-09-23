# Dynamic memory v3 contract tiers

v3 holds contract vectors for the dynamic-memory stages described in
[`docs/DYNAMIC_MEMORY_ARCHITECTURE.md`](../../../docs/DYNAMIC_MEMORY_ARCHITECTURE.md):
authority-free structural bytes plus a vector suite per directory. Admission
authority lives only at the repository seam. Each directory's README describes
its records and what each vector proves.

- `action/`: action protocol.
- `bootstrap-manifest/`: legacy rows admitted as one signed bootstrap-manifest
  event.
- `causal/`: causal hypotheses, interventions, and ratification.
- `chunk-identity/`: chunk and embedding identity across parser versions.
- `consolidation/`: derive one durable claim from an explicit set of source
  claims (ADR 0003, CONS-01..10).
- `coverage/`: coverage receipts.
- `discrepancy/`: discrepancy families and episodes.
- `erasure/`: erasure events, tombstones, fences, and receipts.
- `evidence-admission/`: evidence v2 admission.
- `ledger-epoch/`: ledger epochs, checkpoints, archives, and replay barriers.
- `normative/`: normative binding v2.
- `observer/`: observer admission v2, run receipts, and results.
- `quarantine/`: bounded quarantine records for rejected deliveries.
- `registry-gen2/`: generation-2 registry composition.
- `relation-admission/`: provider-attested relation admission v2.
- `successor-generic/`: generic `N -> N+1` successor registry activation.
- `telemetry/`: telemetry receipts and bounded exemplars.

Unless its directory README says otherwise, every fixture file is one
canonical JSONL record plus exactly one repository-framing LF. No fixture
carries runtime authority.
