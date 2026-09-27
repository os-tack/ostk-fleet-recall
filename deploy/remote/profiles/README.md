# Remote HTTPS configuration profiles

These non-secret examples describe the shared M4.1 client/discovery contract.
They are inputs for later deployment slices, not installers or live endpoints.
Select names before registration/enrollment, and set server variables in the
server environment and client variables in the launcher/shim/shipper environment.
No database URL, signing seed, content key, OAuth token, or provider credential
belongs in a checked-in profile.

- [Local private-CA profile](local-https.env.example): the Mac, sandbox, pods,
  and LAN/VPN workstation must resolve the same names and port 8443. Install
  the public root in browser trust and configure the native Codex process with
  `CODEX_CA_CERTIFICATE`; Fleet clients use `FLEET_RECALL_CA_PATH`. The server's
  OIDC bundle must also trust its separate Kubernetes issuer when enabled.
- [Cloud public-CA profile](cloud-https.env.example): substitute an owned DNS
  zone and reachable issuer. Ordinary public certificates need no extra Fleet
  CA bundle. Configure the server's enrolled local-key public-key map separately
  to support an existing workstation launcher.

Keep `FLEET_RECALL_ALLOW_HTTP` unset or false for these profiles. Clear an old
development opt-in when changing environments. For explicit HTTP development,
pass `--allow-http`; the launcher carries that decision into both runtimes.
Do not use a different internal issuer/resource string to work around DNS.

CA bundles contain certificate PEM blocks only, up to 256 KiB/256 certificates.
They add trust without replacing built-in roots. The launcher snapshots the
bundle for runtime mounts and later cleanup; client processes must restart to
load a changed bundle. Native Codex's provider trust remains separate from the
Recall shim in a sandbox.

Load runtime secrets through the deployment's private secret store. Apply
principal enrollment from its separate workstation environment, then use the
existing launch commands in [REMOTE_PLANE.md](../../../docs/REMOTE_PLANE.md).
Full local DNS/edge/Ory deployment is M4.2; the AWS remote stack is M4.4.
