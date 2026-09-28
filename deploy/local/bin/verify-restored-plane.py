#!/usr/bin/env python3
"""Rehearse fresh Ory OAuth, Recall and spool replay inside a restored namespace.

Requires a completed restore-https-checkpoint.py directory. Every new container
shares that SQL container's network=none namespace; no port is published. The
source installation is never contacted. All containers are stopped afterward.
"""

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import secrets
import shutil
import subprocess
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit, urlunsplit

import yaml

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("checkpoint_restore", HERE / "restore-https-checkpoint.py")
RECOVERY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECOVERY)
require = RECOVERY.require


def deployment(items, name):
    return RECOVERY.resource(items, "Deployment", name, "ory" if name in
                             ("hydra", "kratos", "kratos-ui-kratos-selfservice-ui-node") else "fleet-recall")


def environment(container, items, namespace):
    result = {}
    for reference in container.get("envFrom", []):
        if "secretRef" in reference:
            result.update(RECOVERY.secret_data(RECOVERY.resource(items, "Secret", reference["secretRef"]["name"], namespace)))
        elif "configMapRef" in reference:
            result.update(RECOVERY.resource(items, "ConfigMap", reference["configMapRef"]["name"], namespace)["data"])
        else:
            raise RuntimeError("unsupported recovery environment source")
    for entry in container.get("env", []):
        if "valueFrom" not in entry:
            result[entry["name"]] = entry.get("value", "")
        else:
            ref = entry["valueFrom"].get("secretKeyRef")
            require(ref is not None, "unsupported recovery environment reference")
            result[entry["name"]] = RECOVERY.secret_data(RECOVERY.resource(items, "Secret", ref["name"], namespace))[ref["key"]]
    return result


def isolated_dsn(value):
    parsed = urlsplit(value)
    require(parsed.scheme in ("postgresql", "postgres", "cockroach")
            and parsed.hostname == "cockroach.fleet-recall.svc.cluster.local"
            and parsed.port == 26257 and parse_qs(parsed.query).get("sslmode") == ["verify-full"],
            "unexpected source SQL endpoint or TLS mode")
    credentials = parsed.netloc.rsplit("@", 1)[0]
    return urlunsplit(parsed._replace(netloc=credentials + "@127.0.0.1:26257"))


def verify_preserved_files(restored, baseline):
    for group, subdirectory in (("spool_file_sha256", "spool"), ("workstation_file_sha256", "workstation"),
                                ("resource_artifact_sha256", "resources")):
        require(isinstance(baseline.get(group), dict), "completed restoration lacks an authenticated input inventory")
        root = restored / subdirectory
        require(root.is_dir() and not root.is_symlink(), "recovered input directory is missing or replaced")
        actual = set()
        for path in root.rglob("*"):
            require(not path.is_symlink() and (path.is_dir() or path.is_file()), "recovered input contains a link or special file")
            if path.is_file():
                actual.add(str(path.relative_to(root)))
        require(actual == set(baseline[group]), "recovered input inventory differs from authenticated files")
        for relative, digest in baseline[group].items():
            path = Path(relative)
            require(not path.is_absolute() and ".." not in path.parts, "invalid recovered file inventory path")
            content = RECOVERY.regular_bytes(restored / subdirectory / path, RECOVERY.MAX_ARTIFACT)
            require(hashlib.sha256(content).hexdigest() == digest, "authenticated recovered input changed after SQL restoration")


def verify_application_container(item, identity, database_id, directory, mounts):
    require(item.get("Id") == identity and item["HostConfig"]["NetworkMode"] == "container:" + database_id
            and not item["HostConfig"].get("PortBindings") and not item["HostConfig"].get("Privileged")
            and item["Config"].get("Labels", {}).get("fleet-recall.dev/recovery") == directory.name,
            "isolated application container has wrong network or ownership boundary")
    expected = {target: (source, writable) for source, target, writable in mounts}
    actual = {mount["Destination"]: mount for mount in item.get("Mounts", [])}
    require(len(actual) == len(item.get("Mounts", [])) and set(actual) == set(expected),
            "isolated application has unexpected mounts")
    for target, (source, writable) in expected.items():
        mount = actual[target]
        require(mount.get("Type") == "bind" and Path(mount["Source"]).resolve() == source.resolve()
                and mount["RW"] is writable, "isolated application mount differs from intended recovery path")


def stop_owned_containers(run, containers, database_id=None):
    """A diagnostic failure must never skip the mandatory stop attempt."""
    failures, log_failures = 0, 0
    with RECOVERY.cleanup_signals():
        for identity in reversed(containers):
            try:
                run(["docker", "logs", identity], check=False)
            except (OSError, RuntimeError, subprocess.TimeoutExpired):
                log_failures += 1
            try:
                run(["docker", "stop", "--timeout=20", identity], timeout=35)
            except (OSError, RuntimeError, subprocess.TimeoutExpired):
                failures += 1
        if database_id is not None:
            try:
                run(["docker", "stop", "--timeout=30", database_id], timeout=45)
            except (OSError, RuntimeError, subprocess.TimeoutExpired):
                failures += 1
    return failures, log_failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--restore", type=Path, required=True)
    parser.add_argument("--account-file", type=Path, required=True)
    parser.add_argument("--expected-subject", required=True)
    parser.add_argument("--known-claim-id", type=int, default=13, help="known pre-backup claim whose body must decrypt")
    parser.add_argument("--image", required=True)
    parser.add_argument("--client-image", default="ostk-sandbox:m4-20260927b")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    restored = args.restore.resolve(strict=True)
    baseline = json.loads((restored / "result.json").read_text())
    require(baseline.get("complete") and baseline.get("container_stopped")
            and baseline.get("schema_version") == 39 and baseline.get("generation") == 3,
            "completed generation-3/schema-39 isolated restoration required")
    container_id = baseline["container_id"]
    require(re.fullmatch(r"[0-9a-f]{64}", container_id), "invalid restore container identity")
    require(args.known_claim_id > 0, "known pre-backup claim ID must be positive")
    require(re.fullmatch(r"ostk-fleet-recall:[A-Za-z0-9_.-]+", args.image)
            and re.fullmatch(r"ostk-sandbox:[A-Za-z0-9_.-]+", args.client_image), "unexpected proof image")
    # This is an operator's password file, not a copied OAuth session/token.
    account = json.loads(RECOVERY.regular_bytes(args.account_file, 16384))
    require(set(("email", "password")) <= account.keys(), "account file lacks login credentials")
    if not args.apply:
        print("Plan: isolated SQL network namespace; restored Ory/key state; fresh HTTPS OAuth; Recall scope check; two worker replay ticks; stop all.")
        return
    directory = restored / ("application-" + time.strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(4))
    directory.mkdir(mode=0o700)
    print("Private restored application proof: " + str(directory), flush=True)
    result = {"version": 1, "complete": False, "network": "container:" + container_id,
              "published_ports": [], "containers": [], "phase": "prepare"}
    commands = 0
    running = []
    owns_database_start = False
    started = time.monotonic()

    def run(argv, *, data=None, timeout=120, check=True):
        nonlocal commands
        commands += 1
        response = subprocess.run(argv, input=data, capture_output=True, timeout=timeout, check=False)
        (directory / f"command-{commands:03d}.log").write_bytes(response.stdout + response.stderr)
        require(not check or response.returncode == 0, "isolated application command failed; inspect private command logs")
        return response

    def inspect_base():
        item = json.loads(run(["docker", "inspect", container_id]).stdout)[0]
        RECOVERY.verify_isolation(item, container_id, restored)
        return item

    def launch(label, image, command, env=None, mounts=(), entrypoint=None):
        name = "fleet-recovery-" + directory.name[-8:] + "-" + label
        envfile = directory / (label + ".env")
        values = env or {}
        require(all(re.fullmatch(r"[A-Z][A-Z0-9_]*", key) and "\n" not in value and "\r" not in value
                    for key, value in values.items()), "invalid environment-file value")
        envfile.write_text("".join(key + "=" + value + "\n" for key, value in sorted(values.items())))
        all_mounts = [(directory / "hosts", "/etc/hosts", False)] + list(mounts)
        argv = ["docker", "create", "--pull=never", "--name", name, "--user=0:0", "--network=container:" + container_id,
                "--restart=no", "--env-file", str(envfile), "--label", "fleet-recall.dev/recovery=" + directory.name,
                ]
        for source, target, writable in all_mounts:
            argv += ["--mount", f"type=bind,src={source},dst={target}" + ("" if writable else ",readonly")]
        if entrypoint:
            argv += ["--entrypoint", entrypoint]
        argv += [image] + command
        identity = run(argv).stdout.decode().strip()
        require(re.fullmatch(r"[0-9a-f]{64}", identity), "invalid isolated application identity")
        running.append(identity)
        item = json.loads(run(["docker", "inspect", identity]).stdout)[0]
        result["containers"].append({"role": label, "id": identity, "image": image, "image_id": item["Image"]})
        verify_application_container(item, identity, container_id, directory, all_mounts)
        run(["docker", "start", identity])
        return identity

    def finished(identity, timeout=240):
        response = run(["docker", "wait", identity], timeout=timeout)
        logs = run(["docker", "logs", identity], check=False)
        require(response.stdout.decode().strip() == "0", "isolated proof process failed; inspect private container logs")
        return logs.stdout

    try:
        require(inspect_base()["State"]["Running"] is False, "restore container is already running")
        verify_preserved_files(restored, baseline)
        (directory / "hosts").write_text("127.0.0.1 localhost recall.fleet.test auth.fleet.test login.fleet.test\n::1 localhost\n")
        ory = json.loads((restored / "resources/ory-resources.json").read_text())["items"]
        fleet = json.loads((restored / "resources/fleet-recall-resources.json").read_text())["items"]
        for label, source in (("hydra", "hydra"), ("kratos", "kratos-config")):
            target = directory / label
            target.mkdir(mode=0o700)
            for filename, content in RECOVERY.resource(ory, "ConfigMap", source, "ory")["data"].items():
                require(re.fullmatch(r"[A-Za-z0-9_.-]+", filename), "invalid configuration filename")
                (target / filename).write_text(content)
        hydra_path = directory / "hydra/hydra.yaml"
        hydra = yaml.safe_load(hydra_path.read_text())
        hydra["serve"]["tls"]["allow_termination_from"] = ["127.0.0.1/32"]
        hydra["urls"]["identity_provider"]["url"] = "http://127.0.0.1:4434"
        hydra["urls"]["self"]["admin"] = "http://127.0.0.1:4445/"
        hydra_path.write_text(yaml.safe_dump(hydra))
        kratos_path = directory / "kratos/kratos.yaml"
        kratos = yaml.safe_load(kratos_path.read_text())
        kratos["oauth2_provider"]["url"] = "http://127.0.0.1:4445"
        kratos["serve"]["admin"]["base_url"] = "http://127.0.0.1:4434/"
        kratos_path.write_text(yaml.safe_dump(kratos))
        tls = directory / "tls"
        tls.mkdir(mode=0o700)
        pki = restored / "workstation/https-edge/pki"
        # New isolated leaf only. Neither the copied nor source CA/key changes.
        run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(tls / "leaf.key"),
             "-out", str(tls / "leaf.csr"), "-subj", "/CN=recall.fleet.test"], timeout=30)
        (tls / "leaf.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                                      "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:recall.fleet.test,DNS:auth.fleet.test,DNS:login.fleet.test\n")
        run(["openssl", "x509", "-req", "-in", str(tls / "leaf.csr"), "-CA", str(pki / "intermediate.pem"),
             "-CAkey", str(pki / "intermediate-key.pem"), "-set_serial", "0x" + secrets.token_hex(16),
             "-days", "7", "-sha256", "-extfile", str(tls / "leaf.ext"), "-out", str(tls / "leaf.pem")])
        (tls / "chain.pem").write_bytes((tls / "leaf.pem").read_bytes() + (pki / "intermediate.pem").read_bytes())
        shutil.copyfile(pki / "root.pem", tls / "root.pem")
        helpers = directory / "helpers"
        (helpers / "bin").mkdir(parents=True, mode=0o700)
        (helpers / "https/ory").mkdir(parents=True, mode=0o700)
        for filename in ("oauth-headless-smoke.py", "sandbox-smoke.py"):
            shutil.copyfile(HERE / filename, helpers / "bin" / filename)
        shutil.copyfile(HERE.parent / "https/ory/http_client.py", helpers / "https/ory/http_client.py")
        shutil.copyfile(HERE.parent / "https/recovery/proxy.py", directory / "proxy.py")
        shutil.copyfile(HERE.parent / "https/recovery/client.py", directory / "client.py")
        (directory / "account.json").write_text(json.dumps(account))
        shutil.copytree(restored / "spool", directory / "spool")
        model_spec = deployment(fleet, "embed")["spec"]["template"]["spec"]
        model = Path(next(volume["hostPath"]["path"] for volume in model_spec["volumes"] if volume["name"] == "model")).resolve(strict=True)
        shared_ca = [(restored / "workstation/certs/ca.crt", "/etc/crdb/ca.crt", False)]
        owns_database_start = True
        run(["docker", "start", container_id])
        result["phase"] = "start"
        for label in ("hydra", "kratos"):
            spec = deployment(ory, label)["spec"]["template"]["spec"]["containers"][0]
            env = environment(spec, ory, "ory")
            env["DSN"] = isolated_dsn(env["DSN"])
            mounts = [(directory / label, "/etc/config", False)] + shared_ca
            if label == "kratos":
                # Override the image's two implicit VOLUMEs with fresh private
                # paths; no unverified anonymous/shared volume enters recovery.
                for name, target in (("kratos-sqlite", "/var/lib/sqlite"), ("kratos-home", "/home/ory")):
                    (directory / name).mkdir(mode=0o700)
                    mounts.append((directory / name, target, True))
            launch(label, spec["image"], spec["args"], env, mounts, entrypoint=label)
        ui = deployment(ory, "kratos-ui-kratos-selfservice-ui-node")["spec"]["template"]["spec"]["containers"][0]
        ui_env = environment(ui, ory, "ory")
        ui_env.update(KRATOS_PUBLIC_URL="http://127.0.0.1:4433", KRATOS_ADMIN_URL="http://127.0.0.1:4434", HYDRA_ADMIN_URL="http://127.0.0.1:4445")
        launch("ui", ui["image"], [], ui_env)
        launch("proxy", args.client_image, ["/proof/proxy.py"], mounts=[(directory, "/proof", False)], entrypoint="python3")
        embed_env = environment(model_spec["containers"][0], fleet, "fleet-recall")
        embed_env.pop("FLEET_RECALL_METRICS_LISTEN", None)
        embed_env.pop("FLEET_RECALL_METRICS_ALLOW_NON_LOOPBACK", None)
        launch("embed", args.image, ["embed", "serve", "127.0.0.1:8090"], embed_env,
               [(model, "/opt/ostk/models/potion-retrieval-32M", False)])
        recall_spec = deployment(fleet, "recall")["spec"]["template"]["spec"]["containers"][0]
        recall_env = environment(recall_spec, fleet, "fleet-recall")
        recall_env["FLEET_RECALL_DATABASE_URL"] = isolated_dsn(recall_env["FLEET_RECALL_DATABASE_URL"])
        recall_env.update(FLEET_RECALL_OIDC_ISSUERS="hydra=https://auth.fleet.test:8443/",
                          FLEET_RECALL_OIDC_CA_PATH="/proof/tls/root.pem", FLEET_RECALL_EMBEDDING_TIER_URL="http://127.0.0.1:8090",
                          FLEET_RECALL_TRANSCRIPT_SPOOL_DIR="/proof/spool/transcripts",
                          FLEET_RECALL_LOCAL_KEY_ANCHOR_PATH="/proof/launcher-keys.json")
        for name in ("FLEET_RECALL_METRICS_LISTEN", "FLEET_RECALL_METRICS_ALLOW_NON_LOOPBACK", "FLEET_RECALL_OIDC_DISCOVERY_TOKEN_PATHS"):
            recall_env.pop(name, None)
        shutil.copyfile(restored / "workstation/launcher-keys.json", directory / "launcher-keys.json")
        shutil.copyfile(restored / "workstation/authority.json", directory / "authority.json")
        recall_id = launch("recall", args.image, ["serve", "--http", "127.0.0.1:8081"], recall_env,
                           shared_ca + [(directory, "/proof", True)])
        result["phase"] = "oauth-recall"
        client_args = ["/proof/client.py", "oauth", args.expected_subject, str(args.known_claim_id)]
        finished(launch("client", args.client_image, client_args, mounts=[(directory, "/proof", True)], entrypoint="python3"), timeout=300)
        first = json.loads((directory / "client-oauth.json").read_text())
        result["oauth"] = first
        result["phase"] = "worker-replay"
        worker = RECOVERY.resource(fleet, "CronJob", "worker", "fleet-recall")["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"][0]
        worker_env = environment(worker, fleet, "fleet-recall")
        worker_env["FLEET_RECALL_DATABASE_URL"] = isolated_dsn(worker_env["FLEET_RECALL_DATABASE_URL"])
        worker_env.update(FLEET_RECALL_EMBEDDING_TIER_URL="http://127.0.0.1:8090", FLEET_RECALL_TRANSCRIPT_SPOOL_DIR="/proof/spool/transcripts")
        worker_env.pop("FLEET_RECALL_METRICS_TEXTFILE", None)
        (directory / "worker-sources.json").write_text(RECOVERY.resource(fleet, "ConfigMap", "fleet-sources", "fleet-recall")["data"]["worker-sources.json"])
        for tick in (1, 2):
            finished(launch("worker" + str(tick), args.image, ["worker", "--once", "--sources", "/proof/worker-sources.json", "--steps", "ingest,project,embed"],
                            worker_env, shared_ca + [(directory, "/proof", True)]), timeout=300)
        finished(launch("verify", args.client_image, ["/proof/client.py", "verify"], mounts=[(directory, "/proof", True)], entrypoint="python3"))
        result["replay"] = json.loads((directory / "client-verify.json").read_text())
        inspect_base()
        verify_preserved_files(restored, baseline)
        result["original_recovery_inputs_preserved"] = True
        result.update(complete=True, phase="complete")
    except (Exception, KeyboardInterrupt) as error:
        result["complete"] = False
        result["interrupted"] = isinstance(error, KeyboardInterrupt)
        (directory / "failure.json").write_text(json.dumps({"error_type": type(error).__name__, "detail": str(error)}))
        raise
    finally:
        with RECOVERY.cleanup_signals():
            failures, log_failures = stop_owned_containers(run, running, container_id if owns_database_start else None)
            result["cleanup_failures"] = failures
            result["cleanup_log_failures"] = log_failures
            result["complete"] = result["complete"] and failures == 0
            result["elapsed_seconds"] = round(time.monotonic() - started, 2)
            (directory / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    require(result["complete"], "isolated application proof incomplete")
    print("PASS restored fresh HTTPS OAuth, Recall scope enforcement and pending transcript replay; all containers stopped.")


if __name__ == "__main__":
    try:
        with RECOVERY.interruption_signals():
            main()
    except (Exception, KeyboardInterrupt):
        raise SystemExit("FAIL isolated restored application proof; inspect private result and logs") from None
