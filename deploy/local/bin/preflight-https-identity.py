#!/usr/bin/env python3
"""Prepare or deploy an isolated HTTPS identity preflight; never touch old Ory.

Fresh roles own only fresh databases on the existing verified-TLS CockroachDB.
The fixed preflight namespace and database names must not already exist.
All credentials and command output are retained in private state. Nothing is
deleted, including after failure. The operator controls the edge backend switch.
"""

import argparse
import csv
import io
import ipaddress
import json
import os
import secrets
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

NAMESPACE = "fleet-https-preflight"
DATABASES = ("hydra_https_preflight", "kratos_https_preflight")
CHART_VERSION = "0.64.0"
IMAGE = "cockroachdb/cockroach:v26.2.3"


def private_json(path, value):
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(value, output, indent=2)
        output.write("\n")


def sql_statements(passwords):
    statements = []
    for database in DATABASES:
        password = passwords[database]
        if len(password) != 64 or any(c not in "0123456789abcdef" for c in password):
            raise ValueError("password must be locally generated hex")
        statements.extend([
            f"CREATE ROLE {database} WITH LOGIN NOCREATEDB NOCREATEROLE PASSWORD '{password}';",
            f"CREATE DATABASE {database};",
            f"ALTER DATABASE {database} OWNER TO {database};",
            f"ALTER SCHEMA {database}.public OWNER TO {database};",
            f"REVOKE ALL ON DATABASE {database} FROM public;",
            f"REVOKE ALL ON SCHEMA {database}.public FROM public;",
        ])
    return statements


def namespace_secrets(passwords, ca):
    resources = []

    def add(name, data):
        resources.append({"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
                          "metadata": {"name": name, "namespace": NAMESPACE}, "stringData": data})

    add("crdb-ca", {"ca.crt": ca})
    for service, database in zip(("hydra", "kratos"), DATABASES):
        dsn = (f"cockroach://{database}:{passwords[database]}@"
               f"cockroach.fleet-recall.svc.cluster.local:26257/{database}"
               "?sslmode=verify-full&sslrootcert=/etc/crdb/ca.crt")
        data = {"dsn": dsn, "secretsCookie": secrets.token_hex(32)}
        if service == "hydra":
            data["secretsSystem"] = secrets.token_hex(32)
        else:
            data.update(secretsDefault=secrets.token_hex(32), secretsCipher=secrets.token_hex(16),
                        smtpConnectionURI="smtps://unused:unused@mail.invalid:1025/")
        add(service + "-secrets", data)
    add("kratos-ui-kratos-selfservice-ui-node",
        {"secretsCookie": secrets.token_hex(32), "secretsCSRFCookie": secrets.token_hex(32)})
    return {"apiVersion": "v1", "kind": "List", "items": resources}


def password_check_policy(addresses):
    # Kubernetes NetworkPolicy has no FQDN matcher. Pin the external validator's
    # current public addresses for this short preflight; TLS still checks its name.
    peers = []
    for value in sorted(set(addresses)):
        address = ipaddress.ip_address(value)
        if not address.is_global:
            raise ValueError("password validator resolved to a nonpublic address")
        peers.append({"ipBlock": {"cidr": f"{address}/{address.max_prefixlen}"}})
    if not peers:
        raise ValueError("password validator had no public DNS addresses")
    return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {
        "name": "password-breach-lookup", "namespace": NAMESPACE}, "spec": {
        "podSelector": {"matchLabels": {"app.kubernetes.io/name": "kratos",
                                         "app.kubernetes.io/instance": "kratos"}},
        "policyTypes": ["Egress"], "egress": [{"to": peers, "ports": [{"port": 443, "protocol": "TCP"}]}]}}


def validate_inherited_privileges(grants, system_grants):
    """An otherwise unprivileged LOGIN still inherits every PUBLIC grant."""
    for grant in grants:
        if (grant.get("database_name") not in DATABASES
                and grant.get("privilege_type") not in {"CONNECT", "USAGE"}):
            raise RuntimeError("PUBLIC grants allow preflight roles to modify or read outside their databases; "
                               "use a separately isolated cluster or coordinate existing-grant hardening")
    if system_grants:
        raise RuntimeError("PUBLIC system grants prevent a least-privileged identity preflight")


def verify_inherited_privileges(run, sql):
    """Inventory each database explicitly; SHOW GRANTS uses the current database."""
    def read(query, columns, database=None):
        argv = [*sql, "--database=" + database] if database is not None else sql
        run(argv, data=("EXPLAIN " + query).encode())
        result = run(argv, data=query.encode()).stdout.decode()
        rows = csv.DictReader(io.StringIO(result), delimiter="\t")
        if not rows.fieldnames or not columns.issubset(rows.fieldnames):
            raise RuntimeError("could not verify inherited PUBLIC privileges")
        return list(rows)

    databases = read("SELECT database_name FROM [SHOW DATABASES] ORDER BY database_name;",
                     {"database_name"})
    if not databases or any(not row.get("database_name") for row in databases):
        raise RuntimeError("could not enumerate databases for inherited PUBLIC privileges")
    grants = []
    for database in databases:
        grants.extend(read("SELECT database_name, privilege_type FROM [SHOW GRANTS FOR public];",
                           {"database_name", "privilege_type"}, database["database_name"]))
    system_grants = read("SELECT privilege_type FROM [SHOW SYSTEM GRANTS] WHERE grantee = 'public';",
                         {"privilege_type"})
    validate_inherited_privileges(grants, system_grants)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--trusted-proxy-cidr", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    network = ipaddress.ip_network(args.trusted_proxy_cidr, strict=True)
    if network.prefixlen == 0 or not network.is_private:
        parser.error("trusted proxy CIDR must be an explicit private Pod range")
    os.umask(0o077)
    state = args.state.resolve()
    local = Path(__file__).resolve().parents[1]
    directory = state / "https-preflight" / (time.strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(4))
    directory.mkdir(parents=True, mode=0o700)
    environment = dict(os.environ, KUBECONFIG=str(state / "kubeconfig"))
    count = 0

    def run(argv, *, data=None, timeout=60, check=True):
        nonlocal count
        count += 1
        result = subprocess.run(argv, input=data, env=environment, capture_output=True,
                                timeout=timeout, check=False)
        (directory / f"command-{count:03d}.stdout").write_bytes(result.stdout)
        (directory / f"command-{count:03d}.stderr").write_bytes(result.stderr)
        if check and result.returncode:
            raise RuntimeError(f"command {count} failed; inspect private diagnostics")
        return result

    try:
        passwords = {name: secrets.token_hex(32) for name in DATABASES}
        private_json(directory / "database-passwords.json", passwords)
        resources = namespace_secrets(passwords, (state / "certs/ca.crt").read_text())
        private_json(directory / "secrets.json", resources)
        password_policy = password_check_policy({row[4][0] for row in socket.getaddrinfo(
            "api.pwnedpasswords.com", 443, type=socket.SOCK_STREAM)})
        private_json(directory / "password-check-network.json", password_policy)
        statements = sql_statements(passwords)
        (directory / "bootstrap.sql").write_text("\n".join(statements) + "\n")
        hydra_values = directory / "hydra-https-values.yaml"
        hydra_values.write_text((local / "https/ory/hydra-values.yaml.in").read_text().replace(
            "__TRUSTED_PROXY_CIDR__", str(network)))
        values = {}
        for release, chart in (("hydra", "hydra"), ("kratos", "kratos"),
                               ("kratos-ui", "kratos-selfservice-ui-node")):
            override = hydra_values if release == "hydra" else local / f"https/ory/{release}-values.yaml"
            flags = ["-f", str(local / f"helm/{release}-values.yaml"), "-f", str(override),
                     "-f", str(local / f"https/preflight/{release}-values.yaml")]
            values[release] = (chart, flags)
            rendered = run(["helm", "template", release, "ory/" + chart, "-n", NAMESPACE,
                            "--version", CHART_VERSION, *flags]).stdout
            if any(marker in rendered for marker in
                   (b".ory.svc", b"--dev", b"DANGEROUSLY_DISABLE_SECURE_CSRF_COOKIES")):
                raise RuntimeError("preflight render references old Ory or enables a development bypass")
            (directory / (release + "-rendered.yaml")).write_bytes(rendered)
        print("Prepared isolated identity preflight: " + str(directory), flush=True)
        if not args.apply:
            return 0
        existing = run(["kubectl", "--request-timeout=20s", "get", "namespace", NAMESPACE,
                        "--ignore-not-found", "-o", "name"]).stdout.strip()
        if existing:
            raise RuntimeError("preflight namespace already exists; refusing to overwrite it")
        sql = ["docker", "run", "--rm", "-i", "--network", "host", "-v", f"{state}/certs:/certs:ro",
               IMAGE, "sql", "--certs-dir=/certs", "--host=127.0.0.1:26258", "--format=tsv"]
        # This must precede every role/database/namespace mutation. A role cannot
        # opt out of PUBLIC membership, so revoking its direct grants is not a fix.
        verify_inherited_privileges(run, sql)
        inventory = ("SELECT count(*) FROM [SHOW DATABASES] WHERE database_name IN "
                     "('hydra_https_preflight','kratos_https_preflight'); "
                     "SELECT count(*) FROM [SHOW ROLES] WHERE username IN "
                     "('hydra_https_preflight','kratos_https_preflight');")
        for query in inventory.split("; "):
            run(sql, data=("EXPLAIN " + query.rstrip(";") + ";").encode())
        rows = run(sql, data=inventory.encode()).stdout.decode().splitlines()
        if [line for line in rows if line.isdigit()] != ["0", "0"]:
            raise RuntimeError("preflight databases/roles already exist; refusing to reuse them")
        print("Creating fresh preflight database owners and databases", flush=True)
        # Administrative DDL may not support EXPLAIN; keep its diagnostic separate
        # from execution. Every name is fixed and every password is generated hex.
        for statement in statements:
            run(sql, data=("EXPLAIN " + statement).encode(), check=False)
            run(sql, data=statement.encode())
        namespace = {"apiVersion": "v1", "kind": "Namespace", "metadata": {
            "name": NAMESPACE, "labels": {"fleet-recall.dev/preflight-id": str(uuid.uuid4())}}}
        run(["kubectl", "create", "-f", "-"], data=json.dumps(namespace).encode())
        run(["kubectl", "create", "-f", "-"], data=json.dumps(resources).encode())
        run(["kubectl", "create", "-f", str(local / "https/preflight/network.yaml")])
        run(["kubectl", "create", "-f", "-"], data=json.dumps(password_policy).encode())
        for release, (chart, flags) in values.items():
            print("Installing isolated " + release, flush=True)
            run(["helm", "install", release, "ory/" + chart, "-n", NAMESPACE,
                 "--version", CHART_VERSION, "--wait", "--timeout", "8m", *flags], timeout=510)
        private_json(directory / "ready.json", {"namespace": NAMESPACE, "databases": DATABASES,
                                                "ready": True, "existing_ory_modified": False})
        print("PASS isolated Ory preflight ready; operator may switch the edge backends", flush=True)
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        private_json(directory / "failure.json", {"type": type(error).__name__, "detail": str(error)})
        print("FAIL preflight setup; protected diagnostics: " + str(directory), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
