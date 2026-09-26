# Collected-item fixtures

Synthetic, recorded-shape fixtures for the collected-item sink (ADR 0008). No
test reaches a provider: these files and local fake servers stand in for Slack,
Linear, and Granola.

- `items-docs.jsonl`, `items-slack.jsonl`, `items-linear.jsonl`,
  `items-granola.jsonl`: one `CollectedItemInputV1` per line (the JSONL import
  and capture input, `src/memory_contracts/collected_item.rs`), one provider
  scope per file. They tell one story across four sources, the ingest worker's
  retry budget (3 or 5, with jitter), so a query can find it everywhere and a
  claim can be contested between sources. Each file is also a valid
  `ostk-fleet-recall collect import --format items-jsonl` input for its
  provider scope (ADR 0008 D9).
- `src/collectors/{slack,linear,granola}/fixtures/*.json`: provider API pages
  and signed webhook deliveries in each provider's documented shape, for the
  provider collectors. Every signing secret in them is an obvious placeholder
  (`EXAMPLE-NOT-A-SIGNING-SECRET`, `lin_wh_EXAMPLENOTASIGNINGSECRET`,
  `whsec_EXAMPLEEXAMPLEEXAMPLEEXAMPLE`), never a real credential or one with a
  realistic shape, and each delivery's signature header is computed from it;
  the Granola desktop cache is deliberately absent, because the collectors
  never read it.
- `tests/common/fake_provider.rs`: a local HTTP server on `127.0.0.1:0` that
  serves a provider's API pages to a collector under test, with scripted rate
  limits and failures, and records every request so a test can prove the
  credential travels only in the `Authorization` header
  (`tests/slack_collector_live.rs` serves a Slack workspace through it, and
  `tests/linear_collector_live.rs` a Linear organization's GraphQL API).
