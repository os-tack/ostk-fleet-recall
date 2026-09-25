# ADR 0008: Collected items from any source

- Status: accepted; D1 and D2 implemented. The generation-3 registry package
  is checked in, the strict witness recognizes it, and
  `ostk-authority-install apply --target generation-3` activates it. No
  collector, sink, or recall surface uses it yet; those land with their own
  decisions.
- Date: 2026-09-25
- Scope: how specs and documents, Slack conversations, Linear tickets,
  Granola meetings, and anything else a collector can read become evidence
  that agents can recall, with provenance, coverage, and conflict awareness
  (docs/DYNAMIC_MEMORY_ARCHITECTURE.md, stage 7 onward). It builds on ADR 0005
  (the writer authority and the installer) and ADR 0006 (the worker and
  evidence recall).

## Context

Generation 2 admits exactly three connectors: git history, transcript
sessions, and CI runs. Its digest is frozen (ADR 0005 D1), because installed
heads name it, so it can never admit a fourth. The owner's direction is one
generic sink with many thin collectors: a normalized "collected item"
envelope with one admission path, fed by worker pulls, signed webhooks, agent
captures, and file imports. Adding a source must not need a new compiled
registry generation.

## D1 — One generic collected-item family, in generation 3

**Decision.** Generation 3 is generation 2 carried forward byte for byte,
plus one provider-parameterized family of 13 entries
(`src/memory_contracts/generation3_registry.rs`):

| Entry kind | Id | Notes |
|---|---|---|
| namespace | `namespace.collected.provider_scope` | keys `[provider_kind, provider_scope_id]`, NFC UTF-8 |
| resource kind | `collected_provider_scope` | entity |
| identity recipe | `identity.collected.provider_scope` | entity; every collected connector's provider-instance recipe |
| namespace | `namespace.collected.item` | key `[immutable_revision]`, hex bytes |
| resource kind | `collected_item_revision` | entity |
| resource kind | `collected_item_version` | version, parent `collected_item_revision` |
| identity recipe | `identity.collected.item_revision` | entity |
| identity recipe | `identity.collected.item_version` | version; the canonical-resource recipe the body plane accepts |
| evidence schema | `evidence.collected.item` | kind `collected.item`, the four carried governance policies, canonical payload required, no private raw default |
| connector schema ×4 | `connector.collected.pull`, `.push`, `.capture`, `.import` | one per trust channel |

- **The provider is data.** `slack`, `linear`, `granola`, `docs`, and any
  later provider are values of the `provider_kind` coordinate, and the
  provider's own scope (a Slack team, a Linear organization, a documents
  root) is the `provider_scope_id` coordinate. Both sit inside one
  provider-scope entity, so a new provider is a collector module and
  configuration, never a registry entry and never a generation 4.
- **The trust channel is governance.** A pulled or pushed item is verified by
  the collector; a captured or imported item is only reported. That
  difference is carried by the connector schema, and so by every
  representation and every URI derived under it, rather than by a field a
  payload could set.
- **The item chain keeps the generation-2 pattern.** Entity and version share
  one coordinate, the source fact's own `immutable_revision`, which admission
  re-checks against the candidate. The entity is honestly named
  `collected_item_revision`: a mutable item has one immutable revision per
  version, part, and channel. Continuity across an item's versions comes from
  the item key the envelope carries, not from a continuing-entity URI, so
  `identity.rs` does not change.
- **Governance is carried, not added.** The evidence schema names generation
  1's redaction, classifier, retention, and publication entries by digest,
  and the connectors reuse generation 1's consistency partition recipe. A
  second classifier would make every admission ambiguous.

Every family entry closes under the generic successor closure: each connector
names an entity-form provider recipe in its own provider namespace, and the
evidence schema names exactly the connector's canonical-resource recipe.

**The bytes are the artifact.** The canonical package is checked in at
`contracts/dynamic-memory/v3/collected-items/registry-package.jsonl` (digest
`b5103302073c26cd42d727e1f907acecb9803d7f3da7166dd0f98d29255ac54b`).
`KNOWN_PACKAGES` gains a third row, `KnownRegistryPackage::CollectedItemsGeneration3`,
that closes those compiled-in bytes, as generation 1's row does. A test
proves the composition reproduces them from the compiled generation-2
package, so the composition can never drift from what heads name.

**What would need a generation 4.** A new trust channel, per-connector
governance, an identity change that allows continuing-entity URIs, or a
change to any carried entry. Nothing a new provider needs.

## D2 — Generation 3 is opt-in, and the rollout order is fixed

**Decision.** The installer's default target stays generation 2.
`ostk-authority-install apply --target generation-3` walks the same lineage one
generation further: `0 -> 1 -> 2 -> 3` on a fresh scope, or `2 -> 3` on an
installed one, with the same fixture signers, proposer, and author, and a
conformance result minted with its own fixed completion instant. It never
moves a head backwards: a head at or past a step's package reports that step
`already_present`, so the default target over a generation-3 head changes
nothing. A package at a generation the installer's own lineage would not have
put it at, such as generation 2 re-activated as generation 4 by a hand-run
revert, is refused rather than driven forward.

Rollout order, for every physical scope that is to collect items:

1. Ship binaries that recognize generation 3 to every process that verifies
   a head: every event-first writer, every `serve`, the worker on its ingest
   host, and the projector container (ADR 0006 D1). A binary without the
   generation-3 row refuses a generation-3 head as `UnknownActivePackage`.
2. Apply the release's migrations and re-apply the grant files. This release
   adds none.
3. Run `ostk-authority-install apply --target generation-3`. The pins do not
   change, so no writer is reconfigured.
4. Only then configure collectors, agent capture, or webhook ingress.

**Consequences an operator sees after the move.**

- **Representations are re-keyed.** `RepresentationIdentityV2` binds the
  registry head, so a source fact read again after the move is admitted as a
  second representation: a new accepted event beside the one generation 2
  accepted. Nothing already admitted is rewritten, body bytes are stored
  once by content, and the worker's cursors mean a source is read again only
  when it moves (for example, a git scan after a new commit walks the
  history behind it).
- **Claims keep their keys.** Every recipe an asserted claim key is derived
  under is carried byte for byte, so the same assertion keys identically
  under generation 2 and 3 and the conflict lifecycle is unchanged.
- **Spec families strand.** A binding family last advanced under the
  generation-2 package loses every compare-and-set after the move, exactly as
  ADR 0007 D11 describes for `1 -> 2`. Until a normative rebase exists, move a
  scope before activating any spec in it, or accept that its families can
  only be checked, not superseded.
