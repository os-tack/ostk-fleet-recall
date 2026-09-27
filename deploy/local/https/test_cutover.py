"""Regression checks for authenticated recovery gates and cutover sequencing.

Run with the repository Python 3.12 environment (cryptography is required).
Every subprocess and network operation in orchestration tests is mocked.
"""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BIN = Path(__file__).resolve().parents[1] / "bin"


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), BIN / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CUTOVER = load("deploy-https-plane")
LIMA = load("reconcile-https-lima")
ARTIFACTS = ("database.tar", "database-location.json", "database-backup.tsv", "database-check-files.tsv",
             "spool.tar", "workstation-state.tar.gz", "fleet-recall-resources.json", "ory-resources.json",
             "hydra-helm-values.yaml", "kratos-helm-values.yaml", "kratos-ui-helm-values.yaml", "lima.json")


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.state = Path(self.temporary.name).resolve()
        self.backup = self.state / "backup"
        self.backup.mkdir()
        key = AESGCM.generate_key(bit_length=256)
        self.cipher = AESGCM(key)
        (self.backup / "recovery-key.hex").write_text(key.hex())
        self.manifest = {"version": 1, "complete": True, "state": str(self.state),
                         "cluster_uid": "fixture-cluster", "created_at": time.time(), "artifacts": []}
        for number, name in enumerate(ARTIFACTS):
            plaintext = b"non-sensitive test recovery input: " + name.encode()
            for namespace, names in CUTOVER.PROTECTED_SECRETS.items():
                if name == namespace + "-resources.json":
                    plaintext = json.dumps({"items": [
                        {"kind": "Secret", "metadata": {"name": secret, "namespace": namespace},
                         "data": {"fixture-key": "unchanged"}} for secret in names
                    ]}).encode()
            nonce = number.to_bytes(12, "big")
            encrypted = nonce + self.cipher.encrypt(nonce, plaintext, name.encode())
            (self.backup / (name + ".aesgcm")).write_bytes(encrypted)
            self.manifest["artifacts"].append({"name": name, "bytes": len(plaintext),
                                                "sha256": hashlib.sha256(encrypted).hexdigest()})
        self.save_manifest()

    def save_manifest(self):
        (self.backup / "manifest.json").write_text(json.dumps(self.manifest))

    def verify(self, *, state=None, cluster="fixture-cluster"):
        CUTOVER.verify_backup(self.backup, state or self.state, cluster)

    def test_genuine_authenticated_checkpoint_is_accepted(self):
        hashes = CUTOVER.verify_backup(self.backup, self.state, "fixture-cluster")
        expected = hashlib.sha256(json.dumps({"fixture-key": "unchanged"}, sort_keys=True).encode()).hexdigest()
        self.assertEqual(hashes, {namespace + "/" + name: expected
                                  for namespace, names in CUTOVER.PROTECTED_SECRETS.items() for name in names})

    def test_authenticated_resource_export_must_contain_every_protected_secret(self):
        artifact = next(item for item in self.manifest["artifacts"] if item["name"] == "ory-resources.json")
        plaintext = json.dumps({"items": []}).encode()
        nonce = os.urandom(12)
        encrypted = nonce + self.cipher.encrypt(nonce, plaintext, artifact["name"].encode())
        (self.backup / (artifact["name"] + ".aesgcm")).write_bytes(encrypted)
        artifact.update(bytes=len(plaintext), sha256=hashlib.sha256(encrypted).hexdigest())
        self.save_manifest()
        with self.assertRaisesRegex(RuntimeError, "missing protected Secrets"):
            self.verify()

    def test_corruption_fails_checksum_and_cannot_be_hidden_by_rehashing(self):
        artifact = self.manifest["artifacts"][0]
        path = self.backup / (artifact["name"] + ".aesgcm")
        corrupted = bytearray(path.read_bytes())
        corrupted[-1] ^= 1
        path.write_bytes(corrupted)
        with self.assertRaisesRegex(RuntimeError, "checksum"):
            self.verify()
        artifact["sha256"] = hashlib.sha256(corrupted).hexdigest()
        self.save_manifest()
        with self.assertRaises(InvalidTag):
            self.verify()

    def test_other_state_or_cluster_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "cluster/state"):
            self.verify(state=self.state / "different-state")
        with self.assertRaisesRegex(RuntimeError, "cluster/state"):
            self.verify(cluster="different-cluster")

    def test_missing_artifact_manifest_entry_or_file_is_rejected(self):
        removed = self.manifest["artifacts"].pop()
        self.save_manifest()
        with self.assertRaisesRegex(RuntimeError, "missing required artifacts"):
            self.verify()
        # Keep files intact: a declared extra artifact without a file must fail too.
        self.manifest["artifacts"].append(removed)
        self.manifest["artifacts"].append(dict(removed, name="missing-file"))
        self.save_manifest()
        with self.assertRaises(FileNotFoundError):
            self.verify()

    def test_expired_future_or_incomplete_checkpoint_is_rejected(self):
        for changes in ({"created_at": time.time() - 86401},
                        {"created_at": time.time() + 3600}, {"complete": False}):
            with self.subTest(changes=changes):
                original = dict(self.manifest)
                self.manifest.update(changes)
                self.save_manifest()
                with self.assertRaisesRegex(RuntimeError, "less than a day old"):
                    self.verify()
                self.manifest = original

    def test_duplicate_or_path_traversal_artifacts_are_rejected(self):
        original = list(self.manifest["artifacts"])
        for name in (ARTIFACTS[0], "../outside"):
            self.manifest["artifacts"] = original + [dict(original[0], name=name)]
            self.save_manifest()
            with self.assertRaisesRegex(RuntimeError, "invalid recovery artifact name"):
                self.verify()

    def test_authenticated_size_must_match_manifest(self):
        self.manifest["artifacts"][0]["bytes"] += 1
        self.save_manifest()
        with self.assertRaisesRegex(RuntimeError, "size changed"):
            self.verify()


class LimaTests(unittest.TestCase):
    def invoke(self, forwards):
        record = {"name": "k0s", "status": "Running", "config": {"portForwards": forwards}}
        with mock.patch.object(sys, "argv",
                               ["reconcile-https-lima.py", "--state", "/unused", "--apply"]), \
                mock.patch.object(LIMA.subprocess, "check_output", return_value=json.dumps(record)), \
                mock.patch.object(LIMA.subprocess, "run") as run, \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            try:
                LIMA.main()
            finally:
                run.assert_not_called()

    def test_existing_https_mapping_does_not_skip_later_conflicts(self):
        correct = {"hostIP": "127.0.0.1", "hostPort": 8443, "guestPort": 30443, "static": True}
        self.invoke([correct, {"hostPort": 6443, "guestPort": 6443}])
        for later in ({"hostIP": "0.0.0.0", "hostPort": 6443, "guestPort": 6443},
                      {"hostPort": 8443, "guestPort": 30444, "static": True},
                      {"hostPort": 9001, "guestPort": 30443, "static": True}, correct):
            with self.subTest(later=later), self.assertRaises(SystemExit) as error:
                self.invoke([correct, later])
            self.assertEqual(error.exception.code, 2)


class DrainTests(unittest.TestCase):
    def test_grant_minted_during_drain_restores_old_endpoint_before_identity_changes(self):
        calls = []
        grant_checks = 0

        def command(argv, *, input=None, **_kwargs):
            nonlocal grant_checks
            calls.append((list(argv), input))
            output = b""
            if argv[0] == "helm":
                self.fail("issuer configuration must not change when drain finds a live grant")
            if argv[:2] == ["kubectl", "kustomize"]:
                output = b"# synthetic rendered manifest\n"
            elif argv[:2] == ["docker", "ps"]:
                pass
            elif argv[:2] == ["docker", "run"]:
                self.assertIn(b"memory_session_grants_v1", input)
                grant_checks += 1
                output = b"count\n0\n" if grant_checks == 1 else b"count\n1\n"
            elif "get" in argv:
                resource = argv[argv.index("get") + 1]
                if resource == "secret":
                    value = {"data": {"fixture-key": "unchanged"}}
                elif resource == "namespace":
                    value = {"metadata": {"uid": "fixture-cluster"}}
                elif resource == "nodes":
                    value = {"items": [{"spec": {"podCIDR": "10.244.0.0/24"},
                                        "status": {"images": [{"names": ["docker.io/library/ostk-fleet-recall:fixture"]}]}}]}
                elif resource in ("pods", "jobs", "jobs,pods"):
                    value = {"items": []}
                elif resource == "cronjob":
                    value = {"metadata": {"uid": "fixture-worker"}, "spec": {"suspend": False}}
                elif resource == "deployment":
                    value = {"spec": {"replicas": 1}}
                else:
                    self.fail("unexpected get during grant race: " + resource)
                output = json.dumps(value).encode()
            elif "apply" in argv:
                self.assertIn("--dry-run=server", argv, "only preflight dry-run may happen before the grant gate")
            else:
                self.assertTrue(any(operation in argv for operation in ("patch", "scale", "wait", "rollout")))
            return subprocess.CompletedProcess(argv, 0, output, b"")

        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary).resolve()
            (state / "model.sha256").write_text("a" * 64)
            ca = state / "root.pem"
            ca.write_text("test fixture; TLS itself is mocked in orchestration test")
            argv = ["deploy-https-plane.py", "--state", str(state), "--image-tag", "fixture",
                    "--ca-path", str(ca), "--trusted-proxy-cidr", "10.244.0.0/24",
                    "--backup", str(state / "backup"), "--apply"]
            original_umask = os.umask(0o077)
            try:
                baseline = {namespace + "/" + name: CUTOVER.secret_fingerprint({"fixture-key": "unchanged"})
                            for namespace, names in CUTOVER.PROTECTED_SECRETS.items() for name in names}
                with mock.patch("sys.argv", argv), mock.patch.object(CUTOVER.subprocess, "run", side_effect=command), \
                        mock.patch.object(CUTOVER, "verify_backup", return_value=baseline), \
                        mock.patch.object(CUTOVER.time, "sleep"), \
                        mock.patch.object(CUTOVER.ssl, "create_default_context"), \
                        mock.patch.object(CUTOVER.socket, "create_connection"), \
                        self.assertRaisesRegex(RuntimeError, "old endpoint restored"):
                    CUTOVER.main()
            finally:
                os.umask(original_umask)
        queries = [index for index, (argv, _) in enumerate(calls) if argv[:2] == ["docker", "run"]]
        scale_zero = next(index for index, (argv, _) in enumerate(calls) if "--replicas=0" in argv)
        wait_deleted = next(index for index, (argv, _) in enumerate(calls) if "--for=delete" in argv)
        restored = next(index for index, (argv, _) in enumerate(calls) if "--replicas=1" in argv)
        self.assertEqual(len(queries), 2)
        self.assertLess(queries[0], scale_zero)
        self.assertLess(scale_zero, wait_deleted)
        self.assertLess(wait_deleted, queries[1])
        self.assertLess(queries[1], restored)
        self.assertEqual(json.loads(calls[-1][0][-1]), {"spec": {"suspend": False}})

    def test_retry_rejects_changed_keys_before_quiescing_or_identity_changes(self):
        calls = []

        def command(argv, *, input=None, **_kwargs):
            calls.append(list(argv))
            if argv[:2] == ["kubectl", "kustomize"]:
                output = b"# synthetic rendered manifest\n"
            elif "get" in argv and "secret" in argv:
                output = json.dumps({"data": {"fixture-key": "changed-in-prior-attempt"}}).encode()
            elif "get" in argv and "namespace" in argv:
                output = json.dumps({"metadata": {"uid": "fixture-cluster"}}).encode()
            elif "apply" in argv and "--dry-run=server" in argv:
                output = b""
            else:
                self.fail("no mutation or dependent work may happen after a changed-key retry: " + argv[0])
            return subprocess.CompletedProcess(argv, 0, output, b"")

        baseline = {namespace + "/" + name: CUTOVER.secret_fingerprint({"fixture-key": "unchanged"})
                    for namespace, names in CUTOVER.PROTECTED_SECRETS.items() for name in names}
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary).resolve()
            (state / "model.sha256").write_text("a" * 64)
            argv = ["deploy-https-plane.py", "--state", str(state), "--image-tag", "fixture",
                    "--ca-path", str(state / "root.pem"), "--trusted-proxy-cidr", "10.244.0.0/24",
                    "--backup", str(state / "backup"), "--apply"]
            original_umask = os.umask(0o077)
            try:
                with mock.patch("sys.argv", argv), mock.patch.object(CUTOVER.subprocess, "run", side_effect=command), \
                        mock.patch.object(CUTOVER, "verify_backup", return_value=baseline), \
                        self.assertRaisesRegex(RuntimeError, "refusing a new retry baseline"):
                    CUTOVER.main()
            finally:
                os.umask(original_umask)
        self.assertFalse(any(operation in argv for argv in calls for operation in ("scale", "patch", "upgrade")))


class WorkerDrainTests(unittest.TestCase):
    @staticmethod
    def job(conditions=(), *, active=0):
        return {"kind": "Job", "metadata": {"name": "verify-worker-unowned"},
                "spec": {"template": {"metadata": {"labels": {"app": "worker"}}}},
                "status": {"active": active, "conditions": [
                    {"type": name, "status": "True"} for name in conditions]}}

    @staticmethod
    def pod(phase):
        return {"kind": "Pod", "metadata": {"name": "orphan-worker", "labels": {"app": "worker"}},
                "status": {"phase": phase}}

    def drain(self, observations, *, clock=None):
        calls = []
        snapshots = iter(observations)

        def run(argv, **_kwargs):
            self.assertIn("jobs,pods", argv)
            calls.append(argv)
            return json.dumps({"items": next(snapshots)}).encode()

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(CUTOVER.time, "sleep"):
            if clock is None:
                CUTOVER.drain_workers(["kubectl"], run, "scheduled-cron-uid", Path(temporary))
            else:
                with mock.patch.object(CUTOVER.time, "monotonic", side_effect=clock):
                    CUTOVER.drain_workers(["kubectl"], run, "scheduled-cron-uid", Path(temporary))
        return len(calls)

    def test_manual_job_without_owner_or_pod_must_finish(self):
        completed = self.job(("Complete",))
        self.assertEqual(self.drain([[self.job()], [completed], [completed]]), 3)

    def test_worker_pod_without_job_must_be_terminal(self):
        self.assertEqual(self.drain([[self.pod("Pending")], [self.pod("Succeeded")],
                                     [self.pod("Succeeded")]]), 3)

    def test_late_worker_after_first_idle_observation_is_drained(self):
        completed = self.job(("Complete",))
        self.assertEqual(self.drain([[], [self.job(active=1)], [completed], [completed]]), 4)

    def test_new_job_failure_aborts_but_old_retained_failure_is_not_active(self):
        failed = self.job(("Failed",))
        self.assertEqual(self.drain([[failed], [failed]]), 2)
        with self.assertRaisesRegex(RuntimeError, "failed while draining"):
            self.drain([[self.job(active=1)], [failed]])

    def test_unfinished_worker_has_bounded_drain(self):
        with self.assertRaisesRegex(RuntimeError, "exceeded 300 seconds"):
            self.drain([[self.pod("Unknown")]], clock=[0, 1, 301])


if __name__ == "__main__":
    unittest.main()
