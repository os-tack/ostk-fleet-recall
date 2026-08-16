# Dynamic memory v3 contract tiers

v3 freezes derivation contracts over admitted v2 memory: deterministic transformations that produce new durable claims from existing ones without mutating their sources. Each tier is authority-free structural bytes plus a frozen vector suite; admission authority lives only at the repository seam.

- `consolidation/` — derive one durable claim from an explicit set of source claims (ADR 0003, CONS-01..10).

Every fixture file is one canonical JSONL record plus exactly one repository-framing LF. No fixture carries runtime authority.
