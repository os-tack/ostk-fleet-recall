# Operator glossary

[Documentation index](../README.md) · [Operating guide](../guides/OPERATING.md)

| Term | Meaning in Fleet Recall |
| --- | --- |
| Tenant / project | The physical data scope. A tenant is a UUID; projects live inside it. Requests cannot choose arbitrary scope by changing tool arguments. |
| Agent | The attributed writer identity within a scope. Stdio gets it from trusted process configuration; HTTP derives it from an enrolled identity or a scoped grant. |
| Session | A subdivision of an agent's activity, not a separate authorization principal. |
| Identity anchor | A configured verification mechanism: an OIDC issuer, local Ed25519 key map, or AWS STS proof policy. Verifying an identity does not enroll it. |
| Principal / enrollment | A registry entry mapping a verified external subject to a role, tenant/project, agent pattern and visibility ceiling. Managed with the separate enrollment credential. |
| Operator / launcher / shipper | Remote application roles. An operator can use its enrolled Recall scope; a launcher issues scoped sandbox grants; a shipper uploads transcripts. None of these names means SQL administrator. |
| Grant | A revocable, bounded delegation to one sandbox agent or shipper. The launcher obtains separate grants and revokes them during teardown. |
| Writer SQL login | The database credential used by the private runtime and worker. It is distinct from migrator, publication-reader, ingress and enrollment logins. |
| Writer authority | Installed, pinned application authority for event-first writes under a registry generation. It is separate from a user's OAuth login, sandbox grant and SQL role. |
| Authority pins | Semantic tenant/project namespaces plus the bootstrap receipt digest, optionally an exact activation ID. They bind runtime configuration to an installed authority. |
| Semantic namespace | The contract-level scope used by writer authority. It is not interchangeable with the physical tenant UUID/project string. |
| Claim | A deliberate statement recorded with an author, provenance and lifecycle. Typed claims on the same functional key can be checked for conflicts. |
| Conflict | An episode grouping incompatible lifecycle-current typed claims; it may have more than two members. Detection compares typed propositions, not arbitrary natural-language disagreement. |
| Evidence | Source material admitted and projected by the worker, such as git facts, transcript turns or collected item bodies. Retrieved content is data, not instructions. |
| Collected item | A versioned provider object with provenance and visibility, such as a document or Slack message. Verified pulls/pushes and reported captures/imports have different trust. |
| Projection | A derived read representation of accepted data: bodies, lexical search or dense vectors. An accepted write and fully current search indexes are different checkpoints. |
| Worker tick | One `worker --once` run. Scheduling and exclusion are deployment responsibilities; the local reference uses a five-minute CronJob. |
| Sources file | Worker JSON declaring git, transcript, CI and collector inputs, with references to credential variable names. It is not a set of credentials. |
| Transcript spool | Durable receiver files read by the worker. A server acknowledgement is the upload durability boundary; unshipped sandbox bytes are outside it. |
| Content KEK | The retained key-encryption key for governed content. It is not the grant key, TLS key or SQL password; replacing it does not recover old content. |
| Resource URL | Canonical external MCP audience, including `/mcp`. A reachable internal address is not automatically an equivalent identity. |
| Issuer URL | Exact OIDC issuer identity used in discovery and token verification. DNS/routing should make it reachable without changing the issuer string. |
| Liveness / readiness / status | `/healthz` says the process runs; private `/readyz` says the cached core database/capability check is fresh and successful; authenticated `recall(status)` explains scope and dependency state. |
| Publication demo | Read-only HTTP demonstration using a restricted SQL login. It is a separate surface from authenticated HTTP MCP. |
| Checkpoint / restore / rollback | A checkpoint retains recovery inputs; an isolated restore proves those inputs can reconstruct a service; image rollback changes software while retaining current authorization data. They are not interchangeable. |
| Local `.state` | Private installation state, credentials and evidence under the original deployment directory. It is gitignored and does not appear automatically in another worktree. |

## Numbers that name different things

| Number or label | What it tracks |
| --- | --- |
| Schema 39 | Database migration/capability baseline. It is not registry generation 39. |
| Registry generation 3 | Installed application authority/package baseline. It is not the third database migration. |
| M1–M4 / M4.1–M4.5 | Delivery milestones and their slices, not protocol or schema versions. Local M4.3 is qualified; M4.4 cloud work is on hold. |
| Stage numbers in older ADRs | Architectural implementation stages. Read their status and current runbooks before treating them as operator steps. |

For exact behavior, use [MCP semantics](MCP.md), [configuration](CONFIGURATION.md),
[CLI roles](CLI.md), and [deployment status](STATUS.md).
