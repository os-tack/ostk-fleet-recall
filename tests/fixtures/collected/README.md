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
  provider collectors. Every signing secret in them is a fixture value, never a
  real credential; the Granola desktop cache is deliberately absent, because
  the collectors never read it.
