# Deployment profiles

Choose the profile before copying commands. These paths share a codebase but
have different identity, persistence and qualification boundaries. As of the
M4.3 checkpoint, the existing supported pilot is one Mac running the private-CA
HTTPS deployment. M4.4 is deferred while documentation is improved.

| Profile | Use and entry point | Identity and storage | Status / boundary |
| --- | --- | --- | --- |
| Disposable developer stdio/demo | Build, test, and explore the local binary; [local development tutorial](../tutorials/LOCAL_DEVELOPMENT.md). | Direct deployment identity and a developer-selected CockroachDB/model. Stdio is a child process, not a shared OAuth endpoint. | Development path; do not point migration/live-test examples at the retained installation. |
| Legacy Lima/k0s HTTP bootstrap (M1–M3) | Earlier infrastructure/bootstrap and remote-plane checkpoints; [local bootstrap archive](../../deploy/local/README.md). | Secure SQL, Ory with loopback HTTP identity, optional LocalStack; M3 adds embedding, sandbox grants and transcript spool. | Retained for development/history. `bootstrap.sh up`, `serve-remote.sh` without enrollment arguments, and M3 deployment commands are not HTTPS reconciliation tools. |
| Single-Mac HTTPS (M4.2–M4.3) | Operate the existing upgraded cluster; [operator guide](../guides/OPERATING.md), [cutover](../../deploy/local/https/README.md). | Three canonical names, private CA, existing principals/keys/pins, singleton receiver, retained VM database and spool. | Locally qualified for documented lifecycle/recovery checks; awake Mac and running VM required. No HA or boot autostart service. |
| Second-machine LAN/VPN HTTPS | Reach the same private-CA identities from another workstation. [M4 plan](../M4_REMOTE_ACCESS_PLAN.md). | Same issuer/resource names, caller trust and routing must work from every machine. | Deferred: no second-machine qualification. Current Mac forwarding binds loopback; a hosts-file entry on another laptop alone does not make the service reachable. |
| Existing AWS publication demo | Deploy the read-only public corpus viewer; [AWS runbook](../../deploy/aws/README.md). | ECS/Fargate, CockroachDB Cloud, externally managed SQL/Secrets Manager credentials, pinned S3 model bundle; read-only publication identity. | Existing implementation, distinct from authenticated remote Recall. Its runbook and Terraform tests do not constitute an M4.4 cloud apply or qualification. |
| Planned AWS remote plane (M4.4) | Future deployment of authenticated Recall/Ory, embedding and sandbox/transcript services. [M4 plan](../M4_REMOTE_ACCESS_PLAN.md), [profile examples](../../deploy/remote/profiles/README.md). | Public canonical HTTPS and cloud identity/storage boundaries to be implemented and qualified. | Configuration examples and plan exist; no implemented/qualified M4.4 remote stack is claimed. Work is on hold. |

## Canonical addresses for the current local pilot

| Purpose | Address |
| --- | --- |
| Recall MCP resource and audience | `https://recall.fleet.test:8443/mcp` |
| Human OIDC issuer | `https://auth.fleet.test:8443/` |
| Browser login / Kratos public API | `https://login.fleet.test:8443` |

The Mac maps these names to loopback; Lima forwards 8443 to the edge NodePort.
Docker maps the MCP hostname to its host gateway only when the launcher uses
`--docker-host-gateway`. Kubernetes resolves the canonical names to the edge
Service through its managed CoreDNS block. Each route preserves TLS SNI,
certificate verification and OAuth identity. An internal Service URL is not a
replacement issuer or audience.

Native clients use the public root installed through
[trust setup](../../deploy/local/https/README.md#name-resolution-and-the-mac-boundary).
Fleet clients use `FLEET_RECALL_CA_PATH`; native Codex also uses its documented
`CODEX_CA_CERTIFICATE` process setting. Keep HTTP opt-in false for HTTPS.

## What the operator must retain

| Material | Why it matters |
| --- | --- |
| Original private `.state` directory and kubeconfig | Connects any worktree to the intended installation and retains authority, trust, launch and maintenance records. |
| Lima VM disk | Holds SQL, acknowledged transcript spool and local observability data. Pod replacement is not VM deletion. |
| Encrypted checkpoint, recovery key and source cluster UID | Authenticates an isolated restoration. Keep separately protected recovery material and an off-device copy. |
| Public CA and private CA/application keys | Public roots go to clients; private keys remain protected. Replacing them changes recovery and authority assumptions. |
| Model bundle, release image versions and source commit | Restored application proof and reproducible deployment require more than a SQL backup. |

LocalStack supplies optional AWS-emulation checks. It is not required for
mounted-model embedding, Ory OAuth, the HTTPS edge, native clients, or sandbox
transcript shipping. A valid LocalStack license/token is needed only when
selecting its licensed AWS-emulation path.

The [M4.2](../../deploy/local/https/QUALIFICATION.md) and
[M4.3](../../deploy/local/https/LIFECYCLE_QUALIFICATION.md) records distinguish
implemented checks from remaining work. Local restore timings do not qualify
offsite retrieval, public promotion, a second machine, cloud storage, root/key
rotation or the later 24-hour soak.
