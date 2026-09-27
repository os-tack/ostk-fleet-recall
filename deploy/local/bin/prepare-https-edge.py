#!/usr/bin/env python3
"""Prepare pinned local HTTPS assets; apply only on an explicit second invocation.

The root key stays on the workstation. Partial/mismatched PKI is never replaced.
Command output is retained in a private run directory, not echoed to terminals.
"""

import argparse
import base64
import fcntl
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "https" / "gateway"
PROFILE = ["auth.fleet.test", "login.fleet.test", "recall.fleet.test"]
PKI_FILES = ("root-key.pem", "root.pem", "intermediate-key.pem", "intermediate.pem", "pins.json")
MANIFESTS = ("namespaces.yaml", "rbac.yaml", "admission.yaml", "pki.yaml", "gateway.yaml", "routes.yaml")
VALUES = ("traefik-values.yaml", "cert-manager-values.yaml", "versions.json")


class Failure(Exception):
    """A bounded, credential-free diagnostic."""


def private_dir(directory):
    if directory.is_symlink():
        raise Failure(f"refusing symlink directory: {directory}")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not directory.is_dir() or directory.stat().st_mode & 0o077:
        raise Failure(f"directory must be private (0700): {directory}")


def regular_file(filename, *, private=False):
    if filename.is_symlink() or not filename.is_file():
        raise Failure(f"expected a regular file: {filename}")
    if private and filename.stat().st_mode & 0o077:
        raise Failure(f"private key must have mode 0600: {filename}")


def digest(filename):
    regular_file(filename)
    return hashlib.sha256(filename.read_bytes()).hexdigest()


def write_new(filename, content):
    with filename.open("xb") as stream:
        stream.write(content if isinstance(content, bytes) else content.encode())


class Runner:
    def __init__(self, directory):
        self.directory = directory
        self.count = 0

    def run(self, argv, *, data=None, timeout=300, allow_denied=False):
        self.count += 1
        stem = self.directory / f"command-{self.count:03d}"
        # argv contain only operator paths/options, never key contents or tokens.
        write_new(stem.with_suffix(".argv.json"), json.dumps(argv))
        try:
            result = subprocess.run(argv, input=data, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, check=False, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise Failure(f"{argv[0]} exceeded its timeout; inspect {self.directory}") from error
        write_new(stem.with_suffix(".stdout"), result.stdout)
        write_new(stem.with_suffix(".stderr"), result.stderr)
        denied = allow_denied and result.returncode == 1 and result.stdout.strip() == b"no"
        if result.returncode and not denied:
            raise Failure(f"{argv[0]} failed ({result.returncode}); inspect {self.directory}")
        return result.stdout


def ca_pins(directory):
    return {"profile": PROFILE, "root_sha256": digest(directory / "root.pem"),
            "intermediate_sha256": digest(directory / "intermediate.pem")}


def validate_pki(directory, runner):
    for name in PKI_FILES:
        regular_file(directory / name, private=name.endswith("-key.pem"))
    if json.loads((directory / "pins.json").read_text()) != ca_pins(directory):
        raise Failure("CA pins/profile mismatch; refusing to replace trust")
    for name in ("root", "intermediate"):
        cert = str(directory / f"{name}.pem")
        key = str(directory / f"{name}-key.pem")
        public_cert = runner.run(["openssl", "x509", "-in", cert, "-pubkey", "-noout"])
        public_key = runner.run(["openssl", "pkey", "-in", key, "-pubout"])
        if public_cert != public_key:
            raise Failure(f"{name} certificate does not match its existing private key")
        # Never issue a 90-day leaf near intermediate/root expiry. Rotation is manual.
        runner.run(["openssl", "x509", "-in", cert, "-noout", "-checkend", "15552000"])
    runner.run(["openssl", "verify", "-check_ss_sig", "-CAfile", str(directory / "root.pem"),
                str(directory / "root.pem"), str(directory / "intermediate.pem")])


def ensure_pki(directory, initialize, runner):
    private_dir(directory)
    existing = any(directory.iterdir())
    if existing:
        # Even a previous interrupted initialization requires operator inspection.
        validate_pki(directory, runner)
        return
    if not initialize:
        raise Failure("CA is absent; prepare once with --initialize-ca to create workstation trust")
    root_key, root_cert = directory / "root-key.pem", directory / "root.pem"
    intermediate_key, intermediate_cert = directory / "intermediate-key.pem", directory / "intermediate.pem"
    for key in (root_key, intermediate_key):
        runner.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384",
                    "-out", str(key)])
    runner.run(["openssl", "req", "-new", "-x509", "-sha384", "-days", "3650",
                "-key", str(root_key), "-out", str(root_cert), "-subj", "/CN=Fleet local development root",
                "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-addext", "subjectKeyIdentifier=hash"])
    csr = directory / "intermediate.csr"
    extensions = directory / "intermediate.ext"
    write_new(extensions, "basicConstraints=critical,CA:TRUE,pathlen:0\n"
              "keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n"
              "authorityKeyIdentifier=keyid:always\n"
              "nameConstraints=critical,permitted;DNS:.fleet.test\n")
    runner.run(["openssl", "req", "-new", "-sha384", "-key", str(intermediate_key),
                "-out", str(csr), "-subj", "/CN=Fleet fleet.test issuing CA"])
    runner.run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(root_cert),
                "-CAkey", str(root_key), "-set_serial", "0x" + secrets.token_hex(16),
                "-out", str(intermediate_cert), "-days", "825", "-sha384", "-extfile", str(extensions)])
    write_new(directory / "pins.json", json.dumps(ca_pins(directory), indent=2) + "\n")
    validate_pki(directory, runner)


def obtain_assets(cache, versions, runner):
    private_dir(cache)
    for name, pin in versions.items():
        archive = cache / pin["archive"]
        if not archive.exists():
            if name == "gateway_api":
                with urllib.request.urlopen(pin["url"], timeout=60) as response:
                    if not response.url.startswith("https://"):
                        raise Failure("Gateway API download redirected outside HTTPS")
                    content = response.read(16 * 1024 * 1024 + 1)
                if len(content) > 16 * 1024 * 1024:
                    raise Failure("Gateway API manifest exceeds 16 MiB")
                write_new(archive, content)
            else:
                command = ["helm", "pull", pin["chart"], "--version", pin["version"],
                           "--destination", str(cache)]
                if "repository" in pin:
                    command += ["--repo", pin["repository"]]
                runner.run(command)
        if digest(archive) != pin["sha256"]:
            raise Failure(f"pinned archive checksum mismatch: {archive.name}; retained for inspection")


def prepare(edge, source, initialize, runner):
    pki = edge / "pki"
    ensure_pki(pki, initialize, runner)
    versions = json.loads((source / "versions.json").read_text())
    obtain_assets(edge / "downloads", versions, runner)
    prepared = runner.directory / "prepared"
    private_dir(prepared)
    hashes = {}
    for name in MANIFESTS + VALUES:
        content = (source / name).read_bytes()
        write_new(prepared / name, content)
        hashes[name] = hashlib.sha256(content).hexdigest()
    for pin_name, release, namespace, values in (
        ("traefik", "fleet-edge", "fleet-edge", "traefik-values.yaml"),
        ("cert_manager", "cert-manager", "fleet-pki", "cert-manager-values.yaml"),
    ):
        archive = edge / "downloads" / versions[pin_name]["archive"]
        command = ["helm", "template", release, str(archive), "--namespace", namespace,
                   "--kube-version", "1.35.8", "-f", str(prepared / values)]
        if pin_name == "cert_manager":
            command.append("--include-crds")
        rendered = runner.run(command)
        write_new(prepared / f"{release}-rendered.yaml", rendered)
    record = {"prepared": str(prepared), "hashes": hashes, "pki": ca_pins(pki)}
    # A public pointer only; immutable run directories preserve every preparation.
    (edge / "prepared.json").write_text(json.dumps(record, indent=2) + "\n")
    return prepared


def prepared_assets(edge, source, runner):
    regular_file(edge / "prepared.json")
    record = json.loads((edge / "prepared.json").read_text())
    prepared = Path(record["prepared"])
    if not prepared.resolve().is_relative_to(edge) or prepared.is_symlink():
        raise Failure("prepared snapshot is outside the protected edge state")
    for name in MANIFESTS + VALUES:
        if digest(prepared / name) != record["hashes"][name] or digest(source / name) != record["hashes"][name]:
            raise Failure("edge source/snapshot changed; rerun prepare before apply")
    validate_pki(edge / "pki", runner)
    if record["pki"] != ca_pins(edge / "pki"):
        raise Failure("prepared trust differs from current trust")
    versions = json.loads((prepared / "versions.json").read_text())
    for pin in versions.values():
        if digest(edge / "downloads" / pin["archive"]) != pin["sha256"]:
            raise Failure("prepared dependency checksum changed")
    return prepared, versions


def intermediate_secret(pki):
    # Deliberately no path to root-key.pem here or in any cluster manifest.
    chain = (pki / "intermediate.pem").read_bytes() + (pki / "root.pem").read_bytes()
    return {"apiVersion": "v1", "kind": "Secret", "type": "kubernetes.io/tls", "immutable": True,
            "metadata": {"name": "fleet-intermediate-ca", "namespace": "fleet-pki"},
            "data": {"tls.crt": base64.b64encode(chain).decode(),
                     "tls.key": base64.b64encode((pki / "intermediate-key.pem").read_bytes()).decode()}}


def current_conditions(conditions, required, generation):
    return all(any(condition.get("type") == name and condition.get("status") == "True"
                   and condition.get("observedGeneration") == generation
                   for condition in conditions) for name in required)


def routing_ready(inventory):
    objects = {(item["kind"], item["metadata"]["name"]): item
               for item in inventory.get("items", [])}
    gateway = objects.get(("Gateway", "fleet-edge"))
    if gateway is None:
        return False
    generation = gateway["metadata"]["generation"]
    status = gateway.get("status", {})
    if not current_conditions(status.get("conditions", []), ("Accepted", "Programmed"), generation):
        return False
    listener = next((item for item in status.get("listeners", []) if item.get("name") == "https"), {})
    if not current_conditions(listener.get("conditions", []),
                              ("Accepted", "Programmed", "ResolvedRefs"), generation):
        return False
    for name in ("fleet-recall", "fleet-auth", "fleet-login-kratos", "fleet-login-ui"):
        route = objects.get(("HTTPRoute", name))
        if route is None:
            return False
        parents = [item for item in route.get("status", {}).get("parents", [])
                   if item.get("controllerName") == "traefik.io/gateway-controller"
                   and item.get("parentRef", {}).get("name") == "fleet-edge"
                   and item.get("parentRef", {}).get("namespace", "fleet-edge") == "fleet-edge"]
        if len(parents) != 1 or not current_conditions(parents[0].get("conditions", []),
                                                       ("Accepted", "ResolvedRefs"),
                                                       route["metadata"]["generation"]):
            return False
    return True


def wait_routing(kube, runner):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        inventory = json.loads(runner.run(kube + ["get", "gateway,httproute", "-n", "fleet-edge", "-o", "json"]))
        if routing_ready(inventory):
            return
        time.sleep(2)
    raise Failure("Gateway/routes did not accept and resolve the applied generations within 90 seconds")


def apply(edge, source, kubeconfig, runner):
    prepared, versions = prepared_assets(edge, source, runner)
    kube = ["kubectl", "--kubeconfig", str(kubeconfig), "--request-timeout=30s"]
    secret = intermediate_secret(edge / "pki")
    existing = runner.run(kube + ["get", "secret", "fleet-intermediate-ca", "-n", "fleet-pki",
                                  "--ignore-not-found", "-o", "json"])
    if existing and json.loads(existing).get("data") != secret["data"]:
        raise Failure("cluster intermediate differs from workstation trust; refusing replacement")
    # Reject an unrelated installation before any mutation. Upgrades need a reviewed pin update.
    releases = json.loads(runner.run(["helm", "list", "--kubeconfig", str(kubeconfig), "-A",
                                     "--deployed", "--failed", "--pending", "--uninstalled",
                                     "--superseded", "--uninstalling", "--max", "10000", "-o", "json"]))
    if len(releases) >= 10000:
        raise Failure("Helm release inventory exceeded its safe limit")
    expected = {"fleet-edge": ("fleet-edge", "traefik-" + versions["traefik"]["version"]),
                "cert-manager": ("fleet-pki", "cert-manager-" + versions["cert_manager"]["version"])}
    for release in releases:
        if release.get("status") == "uninstalled":
            # Retained Helm history is evidence, not an active conflicting release.
            continue
        if release["name"] in expected and (release["namespace"], release["chart"]) != expected[release["name"]]:
            raise Failure("existing Helm release differs from the reviewed edge profile")
        if release["chart"].startswith("cert-manager-") and release["name"] != "cert-manager":
            raise Failure("another cert-manager installation already exists")
    runner.run(kube + ["apply", "-f", str(prepared / "namespaces.yaml")])
    runner.run(kube + ["apply", "--server-side", "--field-manager=fleet-https-edge", "-f",
                       str(edge / "downloads" / versions["gateway_api"]["archive"])])
    runner.run(kube + ["wait", "--for=condition=Established", "--timeout=90s", "crd",
                       "gateways.gateway.networking.k8s.io", "httproutes.gateway.networking.k8s.io",
                       "tlsroutes.gateway.networking.k8s.io", "backendtlspolicies.gateway.networking.k8s.io"])
    for pin_name, release, namespace, values in (
        ("cert_manager", "cert-manager", "fleet-pki", "cert-manager-values.yaml"),
        ("traefik", "fleet-edge", "fleet-edge", "traefik-values.yaml"),
    ):
        if pin_name == "traefik":
            # Deny issuance outside fleet-edge before installing the signer.
            runner.run(kube + ["apply", "-f", str(prepared / "admission.yaml")])
            if not existing:
                runner.run(kube + ["create", "-f", "-"], data=json.dumps(secret).encode())
            runner.run(kube + ["apply", "-f", str(prepared / "pki.yaml")])
            runner.run(kube + ["wait", "--for=condition=Ready", "--timeout=120s",
                               "certificate/fleet-edge", "-n", "fleet-edge"], timeout=150)
            runner.run(kube + ["apply", "-f", str(prepared / "rbac.yaml")])
            for private_namespace in ("ory", "fleet-recall", "fleet-pki"):
                for verb in ("get", "list", "watch"):
                    answer = runner.run(kube + ["auth", "can-i", verb, "secrets", "-n", private_namespace,
                                                "--as=system:serviceaccount:fleet-edge:fleet-edge",
                                                "--as-group=system:serviceaccounts",
                                                "--as-group=system:serviceaccounts:fleet-edge",
                                                "--as-group=system:authenticated"],
                                        allow_denied=True)
                    if answer.strip() != b"no":
                        raise Failure("edge ServiceAccount has forbidden application/CA Secret access")
            runner.run(kube + ["apply", "-f", str(prepared / "gateway.yaml")])
        command = ["helm", "upgrade", "--install", release,
                   str(edge / "downloads" / versions[pin_name]["archive"]),
                   "--kubeconfig", str(kubeconfig), "--namespace", namespace,
                   "--wait", "--timeout", "240s", "-f", str(prepared / values)]
        if pin_name == "traefik":
            command.append("--skip-crds")
        runner.run(command, timeout=270)
    runner.run(kube + ["apply", "-f", str(prepared / "routes.yaml")])
    wait_routing(kube, runner)
    return runner.run(kube + ["get", "service", "fleet-edge", "-n", "fleet-edge",
                              "-o", "jsonpath={.spec.clusterIP}"]).decode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "apply"))
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--kubeconfig", type=Path)
    parser.add_argument("--initialize-ca", action="store_true")
    args = parser.parse_args()
    if args.initialize_ca and args.phase != "prepare":
        parser.error("--initialize-ca is valid only for prepare")
    os.umask(0o077)
    edge = args.state.resolve() / "https-edge"
    private_dir(edge)
    lock = (edge / "operation.lock").open("a")
    try:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        raise Failure("another edge preparation/apply operation holds the state lock") from error
    run_dir = edge / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3))
    private_dir(run_dir)
    runner = Runner(run_dir)
    if args.phase == "prepare":
        prepared = prepare(edge, SOURCE, args.initialize_ca, runner)
        result = {"phase": "prepared", "snapshot": str(prepared)}
    else:
        kubeconfig = args.kubeconfig or args.state / "kubeconfig"
        regular_file(kubeconfig, private=True)
        result = {"phase": "applied", "service_ip": apply(edge, SOURCE, kubeconfig, runner)}
    result.update(root_ca=str(edge / "pki" / "root.pem"), evidence=str(run_dir))
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except (Failure, OSError, ValueError, KeyError) as error:
        print(f"HTTPS edge failed: {error}", file=sys.stderr)
        sys.exit(1)
