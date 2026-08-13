# Security and supply-chain policy

Fleet Recall binds tenant, project, and agent identity from deployment
configuration. MCP callers may select a session subdivision, but neither
session nor the currently fixed project privacy tier is an authorization
principal. Privacy refinement is deliberately rejected until owner/tier
visibility is persisted and enforced. Every repository reapplies the trusted
tenant/project coordinates at SQL execution.

Mutations require bounded idempotency keys. Compound claim, support, conflict,
event, and receipt writes execute in one serializable transaction; only
CockroachDB SQLSTATE `40001` is retried.

## Dependency audit exception

`RUSTSEC-2023-0071` affects `rsa 0.9`, which appears in Cargo's lockfile through
SQLx's optional MySQL driver. This application enables only SQLx PostgreSQL;
`cargo tree --target <deployment-target> -i rsa` and `-i sqlx-mysql` must both
remain empty in CI. There is no fixed `rsa` release listed by the advisory.
The exception is therefore confined to an inactive optional package, not a
linked runtime dependency, and should be removed as soon as SQLx's graph no
longer records it.

Warnings for unmaintained `number_prefix` and `paste` currently arrive through
the disclosed upstream model2vec embedding stack. They contain no published
vulnerability; upgrades remain tracked upstream.
