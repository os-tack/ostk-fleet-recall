# Local HTTPS lifecycle operations

The local deployment has one receiver and one scheduled worker for its pinned
scope. It accepts bounded maintenance interruptions. A sleeping Mac, stopped
Lima VM, unavailable disk or disconnected network makes the service unavailable;
this profile has no HA or always-on guarantee. LocalStack remains optional.

## Health and dependency behavior

`/healthz` reports process liveness. Private `/readyz` reports the last core
database/schema/grant-capability check: one check every five seconds, a
three-second deadline, and a ten-second maximum observation age. Startup,
failure, shutdown and stale observations are unready. Kubernetes probes every
five seconds and withdraws the receiver on the first failure. Probe requests
do not acquire database connections or compete with MCP request admission.

Embedding and issuer availability do not gate core readiness. An embedding
outage still permits existing claim reads and lexical search, including after
restarting Recall; embedding-dependent operations report unavailable. OIDC
keys are cached for at most 600 seconds with a 60-second refresh cooldown.
An already cached key can verify during an issuer outage; a cold or expired
cache fails closed. Neither policy permits using an unverified certificate.
See [telemetry](../../../docs/TELEMETRY.md) for separate dependency observation.

## Rehearsal and deployment

Use Python with `cryptography` and `PyYAML`, the original private state
directory, a current authenticated encrypted
checkpoint, and a fresh enrolled user's OAuth `token.json`. The helper requires
at least fifteen minutes of token lifetime and verifies it against Recall.
Choose an existing claim and words that match indexed content; no token value
belongs in a command line. Stop existing sandboxes with `launch down` first.

```sh
python3 deploy/local/bin/lifecycle-smoke.py \
  --state "$FLEET_LOCAL_STATE" --backup /absolute/current/checkpoint \
  --ca-path "$FLEET_LOCAL_STATE/https-edge/pki/root.pem" \
  --token-file /absolute/private/oauth/token.json \
  --claim-id EXISTING_ID --query 'known indexed words' --mode restart
```

Modes `db-outage`, `embed-outage`, `issuer-outage` and `vm-restart` deliberately
disrupt the named dependency. Run them sequentially during maintenance. Each
run locks the same workstation worker lock used by sandbox smoke, suspends and
drains scheduled/manual workers, and verifies no live grants or sandboxes.
It compares protected Secret/local-key hashes, transcript bytes, split DNS,
cluster identity and an existing claim before/after. Revocation preservation
compares the count and hash of ordered grant identities, revocation timestamps
and revoking actors; matching counts alone are insufficient. It restores
dependencies even after a failed assertion. The original worker schedule resumes
only after the recovery gates pass; otherwise inspect the private result and
saved worker state before changing suspension. Do not launch another maintenance
helper while one is running.

Use the same arguments with `--mode worker-exclusion` to prove scheduled-worker
overlap prevention. Allow several minutes: the helper temporarily schedules
the original `Forbid` CronJob every minute and holds its first Job in a
150-second init container. It requires the controller to refuse two later
scheduled ticks while tracking exactly one active Job. It then restores the
original schedule and template while suspended, lets the unmodified worker
finish successfully, and applies the same recovery gates before restoring the
original suspension state. Worker images, commands and environment are unchanged.

For a service-only upgrade, import a uniquely tagged tested image into k0s,
then use `--mode deploy --image ostk-fleet-recall:YOUR_TAG`. The helper retains
the previous Deployment for rollback, changes only the image/readiness probe,
and keeps the new image only after acceptance. It does not migrate SQL or
replace identity configuration. Existing embed/worker/sandbox images need not
change for an HTTP-only fix; record their versions separately.

Rehearse rollback with `--mode rollback --rollback-deployment-file` pointing
to the retained private `deployment-before.json`. This switches the previous
image/probe into service, verifies authenticated reads, and returns to the
current image. It preserves the canonical URL set, current authorization
database, revoked grants and keys. Restoring an older SQL snapshot is not an
authorization-safe deployment rollback. Use fresh OAuth/grants after recovery.

## Leaf renewal

cert-manager renews the 90-day leaf thirty days before expiry. A manual
rehearsal uses its [supported renewal command](https://cert-manager.io/docs/reference/cmctl/#renew),
then verifies the new leaf over trusted TLS on all three names. It also checks
that the CA, content KEK, grant key and Ory Secrets remain unchanged. The
gateway may briefly serve old/new leaves during hot reload; success requires
every name to serve the same new leaf.

The helper pins cmctl v2.6.1 for this qualification host (Darwin arm64):

```sh
curl -fL --max-time 120 -o /private/tmp/cmctl-v2.6.1-darwin-arm64 \
  https://github.com/cert-manager/cmctl/releases/download/v2.6.1/cmctl_darwin_arm64
shasum -a 256 /private/tmp/cmctl-v2.6.1-darwin-arm64
# Expected: 158413ab2f8466c2680317a9618396ed206f4207451d6c24f6f14ccdc6788d4e
chmod 755 /private/tmp/cmctl-v2.6.1-darwin-arm64
python3 deploy/local/bin/renew-https-certificate.py \
  --state "$FLEET_LOCAL_STATE" --backup /absolute/current/checkpoint \
  --cmctl /private/tmp/cmctl-v2.6.1-darwin-arm64 --apply
```

The helper verifies the executable checksum itself before invoking it. It
never deletes a Secret or disables verification. Root/intermediate rotation,
Ory signing-key rotation and Recall grant-key rotation are separate ceremonies.
Root rotation needs an overlap trust bundle and client rollout; grant-key
rotation needs a drain and fresh grants. These are not established by renewing
the leaf. Keep the root private key outside Kubernetes.

## Mac and VM recovery

Keep the Lima disk and its mounted state directory. Start the existing VM with
`limactl start k0s --tty=false`, then run the HTTPS verifier and authenticated
Recall checks before allowing launches. Do not recreate the VM as a restart
procedure. Check CoreDNS's managed Fleet block and the loopback 8443 forward
if canonical access fails. `configure-https-dns.py --apply` can reconcile the
block against the current edge Service without changing issuer names.

Mac boot/login autostart is not installed by these helpers. Start Lima manually
after reboot; verify Docker is available before using Docker sandboxes. Mac
sleep suspends availability. A user launch environment set through
`launchctl setenv CODEX_CA_CERTIFICATE ...` is not a persistent reboot setup:
repeat it before starting a new GUI harness, or use the installed macOS trust
and verify the actual harness connection. Existing terminal shells need the
documented export. The previous restarted harness was tested; future startup
checks still matter.

## Backup, restore and limits

See [isolated recovery](RECOVERY.md) for authenticated backup inputs, preserved
authority, revocation quarantine, and fresh OAuth/Recall/pending-work replay.
Keep an encrypted copy and recovery key off the machine as well as off the VM.
A local checkpoint on the same Mac does not protect against loss of that Mac.
The pilot targets are backup age at most 24 hours and restore within four hours;
measure both and retain evidence. Quiesce the receiver/worker for a consistent
checkpoint when qualifying acknowledged upload recovery.

The receiver's acknowledgement is the durability boundary. Unshipped sandbox
bytes remain vulnerable to container/node failure. Preserve final flushing
and grant revocation during normal teardown. Local lifecycle evidence does
not qualify a second machine, cloud storage, root/key rotation, or a 24-hour
soak. The LAN/VPN second-machine test remains explicitly deferred until hardware
is available; cloud deployment and release soak remain later M4 slices.
