"""Offline safety bounds for a helper permitted to create isolated SQL owners."""

import importlib.util
import subprocess
import unittest
from pathlib import Path

path = Path(__file__).resolve().parents[2] / "bin" / "preflight-https-identity.py"
spec = importlib.util.spec_from_file_location("identity_preflight_test", path)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


class IsolationTests(unittest.TestCase):
    def test_safe_default_database_cannot_hide_privileges_on_another_database(self):
        visited = []

        def run(argv, *, data):
            query = data.decode()
            if query.startswith("EXPLAIN "):
                return subprocess.CompletedProcess(argv, 0, stdout=b"plan\n")
            if "SHOW DATABASES" in query:
                output = "database_name\ndefaultdb\nhydra\nkratos\n"
            elif "SHOW SYSTEM GRANTS" in query:
                output = "privilege_type\n"
            else:
                database_flags = [arg for arg in argv if arg.startswith("--database=")]
                self.assertEqual(len(database_flags), 1)
                database = database_flags[0].split("=", 1)[1]
                visited.append(database)
                privilege = "CREATE" if database == "hydra" else "CONNECT"
                output = f"database_name\tprivilege_type\n{database}\t{privilege}\n"
            return subprocess.CompletedProcess(argv, 0, stdout=output.encode())

        with self.assertRaisesRegex(RuntimeError, "PUBLIC grants"):
            preflight.verify_inherited_privileges(run, ["sql"])
        self.assertEqual(visited, ["defaultdb", "hydra", "kratos"])

    def test_inherited_public_privileges_must_be_safe_before_creating_any_role(self):
        preflight.validate_inherited_privileges(
            [{"database_name": "hydra", "privilege_type": "CONNECT"},
             {"database_name": "kratos", "privilege_type": "USAGE"}], [])
        for privilege in ("CREATE", "TEMPORARY", "SELECT", "INSERT", "UPDATE", "DELETE", "EXECUTE"):
            with self.subTest(privilege=privilege), self.assertRaisesRegex(RuntimeError, "PUBLIC grants"):
                preflight.validate_inherited_privileges(
                    [{"database_name": "hydra", "privilege_type": privilege}], [])
        with self.assertRaisesRegex(RuntimeError, "PUBLIC system grants"):
            preflight.validate_inherited_privileges([], [{"privilege_type": "CREATEROLE"}])
        with self.assertRaisesRegex(RuntimeError, "PUBLIC grants"):
            preflight.validate_inherited_privileges([{}], [])

    def test_bootstrap_cannot_adopt_existing_users_or_grant_global_privileges(self):
        passwords = {name: "a" * 64 for name in preflight.DATABASES}
        statements = preflight.sql_statements(passwords)
        self.assertTrue(all("https_preflight" in statement for statement in statements))
        for statement in statements:
            self.assertNotIn("IF NOT EXISTS", statement)
            self.assertNotIn("GRANT ", statement)
            self.assertNotIn("ALTER USER", statement)
            self.assertNotIn("DROP ", statement)
            self.assertNotIn("TRUNCATE ", statement)
        passwords[preflight.DATABASES[0]] = "'; GRANT admin TO attacker; --"
        with self.assertRaises(ValueError):
            preflight.sql_statements(passwords)

    def test_secrets_use_only_isolated_verified_tls_database_credentials(self):
        passwords = {name: "b" * 64 for name in preflight.DATABASES}
        resources = preflight.namespace_secrets(passwords, "public-ca-fixture")
        for resource in resources["items"]:
            self.assertEqual(resource["metadata"]["namespace"], "fleet-https-preflight")
            dsn = resource["stringData"].get("dsn")
            if dsn:
                self.assertIn("_https_preflight:", dsn)
                self.assertIn("sslmode=verify-full&sslrootcert=/etc/crdb/ca.crt", dsn)
                self.assertNotIn("root@", dsn)
        self.assertEqual(len(resources["items"]), 4)

    def test_password_validator_egress_never_accepts_private_or_broad_ranges(self):
        for addresses in ([], ["127.0.0.1"], ["10.0.0.1"], ["169.254.169.254"], ["::1"]):
            with self.subTest(addresses=addresses), self.assertRaises(ValueError):
                preflight.password_check_policy(addresses)
        policy = preflight.password_check_policy(["1.1.1.1", "1.1.1.1"])
        self.assertEqual(policy["spec"]["egress"], [{"to": [{"ipBlock": {"cidr": "1.1.1.1/32"}}],
                                                   "ports": [{"port": 443, "protocol": "TCP"}]}])


if __name__ == "__main__":
    unittest.main()
