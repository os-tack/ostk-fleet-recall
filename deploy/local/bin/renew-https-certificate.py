#!/usr/bin/env python3
"""Rehearse leaf renewal without changing CA, content or grant signing keys.

Authenticates a current recovery checkpoint and verifies all canonical TLS
names before mutation. --apply uses the pinned official cmctl binary to request
renewal, then waits for a different leaf on all three names. No Secret is deleted.
All diagnostics stay in private state. A failed renewal never weakens TLS.
"""

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import secrets
import socket
import ssl
import subprocess
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

CMCTL_SHA256 = "158413ab2f8466c2680317a9618396ed206f4207451d6c24f6f14ccdc6788d4e"
CMCTL_URL = "https://github.com/cert-manager/cmctl/releases/download/v2.6.1/cmctl_darwin_arm64"
NAMES = ("recall.fleet.test", "auth.fleet.test", "login.fleet.test")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def leaf_info(der):
    certificate = x509.load_der_x509_certificate(der)
    names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    require(set(names.get_values_for_type(x509.DNSName)) == set(NAMES), "leaf SAN set differs")
    public_key = certificate.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return {"sha256": certificate.fingerprint(hashes.SHA256()).hex(),
            "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
            "not_after": certificate.not_valid_after_utc.isoformat(),
            "expires_at": certificate.not_valid_after_utc.timestamp()}


def validate_renewal(before, after):
    require(after["sha256"] != before["sha256"], "leaf did not change")
    require(after["public_key_sha256"] != before["public_key_sha256"], "Always policy did not rotate leaf key")
    require(after["expires_at"] > before["expires_at"] and after["expires_at"] > time.time() + 60 * 86400,
            "renewed leaf does not extend the validity window")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--backup", required=True, type=Path)
    parser.add_argument("--cmctl", type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    state = args.state.resolve(strict=True)
    directory = state / ("https-renewal-" + time.strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(4))
    directory.mkdir(mode=0o700)
    result = {"complete": False, "phase": "preflight"}
    print("Private renewal evidence: " + str(directory), flush=True)
    kube = ["kubectl", "--kubeconfig", str(state / "kubeconfig"), "--request-timeout=30s"]
    sequence = 0

    def run(argv, timeout=40):
        nonlocal sequence
        sequence += 1
        response = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
        (directory / f"command-{sequence:03d}.log").write_bytes(response.stdout + response.stderr)
        require(response.returncode == 0, "command failed; inspect private log")
        return response.stdout

    def obj(namespace, kind, name):
        return json.loads(run(kube + ["-n", namespace, "get", kind, name, "-o", "json"]))

    spec = importlib.util.spec_from_file_location("cutover", Path(__file__).with_name("deploy-https-plane.py"))
    cutover = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cutover)

    def protected():
        fingerprints = {namespace + "/" + name: cutover.secret_fingerprint(obj(namespace, "secret", name)["data"])
                        for namespace, names in cutover.PROTECTED_SECRETS.items() for name in names}
        return fingerprints

    def authority():
        values = {"intermediate_secret": cutover.secret_fingerprint(
            obj("fleet-pki", "secret", "fleet-intermediate-ca")["data"])}
        for name in ("root.pem", "root-key.pem", "intermediate.pem", "intermediate-key.pem", "pins.json"):
            path = state / "https-edge/pki" / name
            require(path.is_file() and not path.is_symlink(), "missing retained PKI file")
            values[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        return values

    try:
        cluster = obj("", "namespace", "kube-system")["metadata"]["uid"]
        expected = cutover.verify_backup(args.backup, state, cluster)
        require(protected() == expected, "protected keys differ from authenticated checkpoint")
        before_authority = authority()
        certificate = obj("fleet-edge", "certificate", "fleet-edge")
        require(certificate["spec"]["secretName"] == "fleet-edge-tls"
                and certificate["spec"]["privateKey"]["rotationPolicy"] == "Always"
                and certificate["spec"]["issuerRef"]["name"] == "fleet-local-ca", "unexpected certificate policy")
        tls = ssl.create_default_context(cafile=str(state / "https-edge/pki/root.pem"))

        def served():
            leaves = {}
            for name in NAMES:
                with socket.create_connection((name, 8443), timeout=10) as raw, \
                        tls.wrap_socket(raw, server_hostname=name) as connection:
                    leaves[name] = leaf_info(connection.getpeercert(binary_form=True))
            return leaves

        before = served()
        require(len({leaf["sha256"] for leaf in before.values()}) == 1, "canonical names serve different leaves before renewal")
        result["before"] = before
        result["authority_sha256"] = before_authority
        if not args.apply:
            result["phase"] = "prepared"
            print("PASS checkpoint, canonical TLS names and key inventory; use --apply for renewal")
            return
        require(args.cmctl is not None, "--apply requires pinned --cmctl (see script CMCTL_URL)")
        binary = args.cmctl.resolve(strict=True)
        require(hashlib.sha256(binary.read_bytes()).hexdigest() == CMCTL_SHA256, "cmctl binary checksum differs")
        result["phase"] = "renew"
        run([str(binary), "--kubeconfig", str(state / "kubeconfig"), "renew", "-n", "fleet-edge", "fleet-edge"], timeout=60)
        deadline = time.monotonic() + 300
        while True:
            current = obj("fleet-edge", "certificate", "fleet-edge")
            ready = any(item.get("type") == "Ready" and item.get("status") == "True"
                        for item in current.get("status", {}).get("conditions", []))
            secret = obj("fleet-edge", "secret", "fleet-edge-tls")
            pem = base64.b64decode(secret["data"]["tls.crt"], validate=True)
            leaf = x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER)
            after = leaf_info(leaf)
            if ready and after["sha256"] != before[NAMES[0]]["sha256"]:
                observed = served()
                # The gateway can hot-reload between the three TLS handshakes.
                # Retry that bounded transition; only a uniform new leaf passes.
                if {leaf["sha256"] for leaf in observed.values()} == {after["sha256"]}:
                    for name in NAMES:
                        validate_renewal(before[name], observed[name])
                    result["after"] = observed
                    break
            require(time.monotonic() < deadline, "renewed leaf was not served within five minutes")
            time.sleep(3)
        require(protected() == expected and authority() == before_authority, "renewal changed protected keys or CA authority")
        result.update(complete=True, phase="passed", protected_keys_preserved=True, ca_preserved=True)
        print("PASS renewed leaf served over trusted TLS on all three names; CA and application keys preserved")
    except Exception as error:
        result["failure_type"] = type(error).__name__
        result["failure"] = str(error)
        raise
    finally:
        (directory / "result.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("FAIL renewal rehearsal; inspect private result and command logs")
        raise SystemExit(1) from None
