# Ory HTTPS cutover

These are overrides for the **existing** `ory` releases, pinned to chart
`0.64.0` and application images `v26.2.0`. Apply with `--reuse-values` after
the private backup and cutover checks. Render `__TRUSTED_PROXY_CIDR__` in
`hydra-values.yaml.in` from the actual edge Pod CIDR; the current single-node
k0s allocation is `10.244.0.0/24`. A network policy must also limit access to
Hydra's public port to the edge and explicitly needed internal clients.
The edge must replace forwarded headers, preserve the external Host including
`:8443`, and set `X-Forwarded-Proto: https`.

The overrides retain the original identity schema, public subject IDs, DSNs,
Hydra signing keys and cookie secrets. They disable migration hooks because
the application versions and schema are unchanged. Hydra/Kratos continue to
reference `hydra-secrets` and `kratos-secrets`. The UI references the existing
`kratos-ui-kratos-selfservice-ui-node` Secret with generation and checksum
rendering disabled: chart 0.64.0's pre-upgrade hook otherwise generates new
keys. Verify that this existing Secret has `helm.sh/resource-policy: keep`
before upgrade. Do not copy secret contents into values or renderer output.

All development flags are disabled. Kratos session/CSRF cookies and Hydra
cookies are Secure with SameSite=Lax, with no broad cookie Domain. The UI uses
`__Host-fleet-recall-csrf`; its old insecure-cookie environment variable is
**removed**, because even setting its value to `"false"` activates the bypass.
Kratos v26.2.0 does not support Hydra's `allow_termination_from` setting; its
HTTPS public base URL, explicit secure cookies, and restricted private service
reachability provide the corresponding boundary.

## Routes without rewriting

| Public host | Paths | Private Service |
| --- | --- | --- |
| `auth.fleet.test:8443` | Exact `/.well-known/openid-configuration`, `/.well-known/jwks.json`, `/oauth2/auth`, `/oauth2/token`, `/oauth2/revoke`, `/oauth2/register`, `/oauth2/sessions/logout`, `/userinfo`, `/oauth2/fallbacks/consent`, `/oauth2/fallbacks/error` | `hydra-public.ory.svc:4444` |
| `login.fleet.test:8443` | Prefix `/self-service/`, exact `/sessions/whoami` | `kratos-public.ory.svc:80` |
| `login.fleet.test:8443` | Exact `/`, `/login`, `/registration`, `/consent`, `/logout`, `/settings`, `/sessions`, `/welcome`, `/error` | `kratos-ui-kratos-selfservice-ui-node.ory.svc:80` |
| `login.fleet.test:8443` | Prefix `/assets/`; exact `/theme.css`, `/style.css`, `/main.css`, `/auth-layout.css`, `/content-layout.css`, `/favico.png`, `/ory-logo.svg`, `/ory-small.svg` | Same UI Service |

The pinned UI distinguishes `KRATOS_PUBLIC_URL` (private SDK calls) from
`KRATOS_BROWSER_URL` (browser redirects). Its browser flow URLs append
`/self-service/{flow}/browser`; Kratos form actions use its public base URL.
Both therefore use the root of `https://login.fleet.test:8443`, with no
`/kratos` prefix or rewriting. `/sessions` is a UI page; `/sessions/whoami`
belongs to Kratos. Recovery, verification and WebAuthn remain disabled.
Administrative APIs and health endpoints are never public gateway routes.
Self-registration is retained for this local profile; the cloud profile must
make its own explicit registration-policy choice.

Changing the issuer invalidates the old issuer contract even though subjects
and databases are retained. Update the issuer under the existing `hydra`
anchor ID and acquire fresh client credentials/tokens; existing enrolled
subjects remain mapped to their original principals. Do not rewrite claims. A successful cutover
must prove an existing account retains its subject, fresh password login and
consent work, session and CSRF cookies are Secure/host-only/appropriate
SameSite, native OAuth works, and old issuer/resource tokens are rejected.

## Operator proof helpers

`deploy/local/bin/oauth-headless-smoke.py --profile https --ca-path CA.pem
--state PRIVATE_STATE` exercises registration, a fresh password login, consent,
PKCE, nonce and refresh-token issuance. It checks canonical discovery endpoints,
requires an explicit Kratos `security_csrf_violation` rejection before submitting
the valid login form, and records only cookie **attributes** in the summary.
All live cookies must be Secure, HttpOnly, host-only, Path=/ and SameSite=Lax.
The pinned UI masks invalid consent CSRF errors as generic HTTP 500; that
ambiguous response is deliberately not used as a security acceptance signal.
To prove an existing identity was preserved, add `--account-file
OLD_PRIVATE_ACCOUNT.json --expected-subject UUID`; that skips registration and
compares `/sessions/whoami` and token subjects to the recorded UUID. JWT payload
checks here are consistency checks on the TLS token response; Recall's verifier
separately proves cryptographic acceptance.

After saving the issued OAuth credentials privately, the helper performs the
Kratos browser logout flow, verifies the canonical login redirect, and requires
`/sessions/whoami` to return 401. This clears that Kratos session; it is not
Hydra SSO logout, client credential deletion, refresh-token revocation, or
instant invalidation of offline-verified access tokens. Those are separate
lifecycle actions with separate acceptance checks.

`deploy/local/bin/register-mcp-client.py --profile https --ca-path CA.pem
--state PRIVATE_STATE --client-name NAME --redirect-uri LOOPBACK_CALLBACK`
registers a public native client and prints only its public client ID.
Registration tokens remain in private state. Repeat `--redirect-uri` for
multiple callbacks. Both helpers retain their original loopback defaults for
existing callers, and accept explicit public URL overrides plus
`FLEET_RECALL_CA_PATH` as a CA default. The shared helper reuses the sandbox
proof's bounded, additive PEM trust loader; it never disables hostname or
certificate verification. Run its offline boundary tests with
`python3 deploy/local/https/ory/test_http_client.py`.

## Pinned references

- [UI flow URL construction](https://github.com/ory/kratos-selfservice-ui-node/blob/v26.2.0/src/pkg/index.ts), [SDK origins](https://github.com/ory/kratos-selfservice-ui-node/blob/v26.2.0/src/pkg/sdk/index.ts), [cookie setup](https://github.com/ory/kratos-selfservice-ui-node/blob/v26.2.0/src/index.ts).
- [UI static routes](https://github.com/ory/kratos-selfservice-ui-node/blob/v26.2.0/src/routes/static.ts) and [HTML asset references](https://github.com/ory/kratos-selfservice-ui-node/blob/v26.2.0/views/partials/standard_headers.hbs).
- [UI chart Secret hook](https://github.com/ory/k8s/blob/v0.64.0/helm/charts/kratos-selfservice-ui-node/templates/secret.yaml).
- [Hydra schema](https://github.com/ory/hydra/blob/v26.2.0/.schema/config.schema.json), [TLS termination schema](https://github.com/ory/hydra/blob/v26.2.0/oryx/configx/tls.schema.json), [Kratos schema](https://github.com/ory/kratos/blob/v26.2.0/.schemastore/config.schema.json).
- [Ory production proxy guidance](https://www.ory.com/docs/hydra/self-hosted/production).
