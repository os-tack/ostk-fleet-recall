"""Restore safety boundaries; no Docker, network, or live SQL is used."""

import base64
import hashlib
import importlib.util
import io
import json
import os
import signal
import subprocess
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SPEC = importlib.util.spec_from_file_location("restore_checkpoint", Path(__file__).resolve().parents[1] / "bin/restore-https-checkpoint.py")
RESTORE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RESTORE)
APP_SPEC = importlib.util.spec_from_file_location("restored_plane", Path(__file__).resolve().parents[1] / "bin/verify-restored-plane.py")
APP = importlib.util.module_from_spec(APP_SPEC)
APP_SPEC.loader.exec_module(APP)


def archive(entries):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as handle:
        for name, kind in entries:
            info = tarfile.TarInfo(name)
            info.type = kind
            if kind == tarfile.REGTYPE:
                info.size = 4
                handle.addfile(info, io.BytesIO(b"test"))
            else:
                info.linkname = "../escape"
                handle.addfile(info)
    return buffer.getvalue()


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name).resolve()
        self.key = AESGCM.generate_key(bit_length=256)
        (self.path / "recovery-key.hex").write_text(self.key.hex())
        self.cipher = AESGCM(self.key)
        self.manifest = {"version": 1, "complete": True, "state": str(self.path), "cluster_uid": "fixture",
                         "created_at": time.time(), "artifacts": []}
        for name in sorted(RESTORE.REQUIRED):
            plain = name.encode()
            nonce = os.urandom(12)
            encrypted = nonce + self.cipher.encrypt(nonce, plain, name.encode())
            (self.path / (name + ".aesgcm")).write_bytes(encrypted)
            self.manifest["artifacts"].append({"name": name, "bytes": len(plain), "sha256": hashlib.sha256(encrypted).hexdigest()})
        self.save()

    def save(self):
        (self.path / "manifest.json").write_text(json.dumps(self.manifest))

    def verify(self):
        return RESTORE.authenticate(self.path, self.path, "fixture")

    def test_checkpoint_authenticates_every_artifact(self):
        _, plaintext = self.verify()
        self.assertEqual(set(plaintext), RESTORE.REQUIRED)

    def test_checksum_rewrite_cannot_hide_ciphertext_tampering(self):
        entry = self.manifest["artifacts"][-1]
        path = self.path / (entry["name"] + ".aesgcm")
        encrypted = bytearray(path.read_bytes())
        encrypted[-1] ^= 1
        path.write_bytes(encrypted)
        entry["sha256"] = hashlib.sha256(encrypted).hexdigest()
        self.save()
        with self.assertRaises(InvalidTag):
            self.verify()

    def test_file_swap_is_bound_to_artifact_filename(self):
        first, second = self.manifest["artifacts"][:2]
        data = (self.path / (first["name"] + ".aesgcm")).read_bytes()
        (self.path / (second["name"] + ".aesgcm")).write_bytes(data)
        second.update(bytes=first["bytes"], sha256=first["sha256"])
        self.save()
        with self.assertRaises(InvalidTag):
            self.verify()

    def test_source_binding_age_completeness_and_required_files(self):
        baseline = dict(self.manifest)
        for change in ({"state": "/wrong"}, {"cluster_uid": "wrong"}, {"complete": False},
                       {"created_at": time.time() - 86401}, {"created_at": time.time() + 3600},
                       {"artifacts": self.manifest["artifacts"][:-1]}):
            with self.subTest(change=change):
                self.manifest = dict(baseline, **change)
                self.save()
                with self.assertRaises(RuntimeError):
                    self.verify()

    def test_duplicate_path_and_size_bomb_fail_before_decryption(self):
        for change in ({"name": "../escape"}, {"bytes": RESTORE.MAX_ARTIFACT + 1},
                       {"name": self.manifest["artifacts"][1]["name"]}):
            original = dict(self.manifest["artifacts"][0])
            self.manifest["artifacts"][0].update(change)
            self.save()
            with self.assertRaises(RuntimeError):
                self.verify()
            self.manifest["artifacts"][0] = original

    def test_symlink_input_is_rejected(self):
        link = self.path / "symlink"
        link.symlink_to(self.path / "manifest.json")
        with self.assertRaisesRegex(RuntimeError, "regular file"):
            RESTORE.regular_bytes(link, 100000)


class ArchiveTests(unittest.TestCase):
    def test_traversal_absolute_paths_links_devices_and_duplicates_rejected(self):
        examples = [([("../escape", tarfile.REGTYPE)]), ([('/escape', tarfile.REGTYPE)]),
                    ([("root/link", tarfile.SYMTYPE)]), ([("root/link", tarfile.LNKTYPE)]),
                    ([("root/device", tarfile.CHRTYPE)]), ([("root/fifo", tarfile.FIFOTYPE)]),
                    ([("root/a", tarfile.REGTYPE), ("root/a", tarfile.REGTYPE)]),
                    ([("root/a", tarfile.REGTYPE), ("root/a/b", tarfile.REGTYPE)]),
                    ([("root\\evil", tarfile.REGTYPE)])]
        for entries in examples:
            with self.subTest(entries=entries), self.assertRaises(RuntimeError):
                RESTORE.archive_members(archive(entries))

    def test_wrong_root_or_oversized_uncompressed_data_rejected(self):
        data = archive([("other/file", tarfile.REGTYPE)])
        with self.assertRaisesRegex(RuntimeError, "root"):
            RESTORE.archive_members(data, required_root="transcripts")
        with mock.patch.object(RESTORE, "MAX_TOTAL", 3), self.assertRaisesRegex(RuntimeError, "size"):
            RESTORE.archive_members(data)

    def test_all_entries_validated_before_any_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "new"
            data = archive([("root/good", tarfile.REGTYPE), ("../escape", tarfile.REGTYPE)])
            with self.assertRaises(RuntimeError):
                RESTORE.extract_private(data, destination)
            self.assertFalse(destination.exists())

    def test_extraction_is_private_hash_verified_and_refuses_existing_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "new"
            data = archive([("transcripts", tarfile.DIRTYPE), ("transcripts/file", tarfile.REGTYPE)])
            hashes = RESTORE.extract_private(data, destination, required_root="transcripts")
            self.assertEqual(hashes, {"transcripts/file": hashlib.sha256(b"test").hexdigest()})
            self.assertEqual((destination / "transcripts/file").stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                RESTORE.extract_private(data, destination)


class IsolationTests(unittest.TestCase):
    def fixture(self, directory):
        return {"Id": "test", "HostConfig": {"NetworkMode": "none", "PortBindings": {}, "Privileged": False},
                "Config": {"Labels": {"fleet-recall.dev/recovery": directory.name}},
                "Mounts": [{"Source": str(directory / source), "Destination": target, "RW": writable}
                           for source, target, writable in (("crdb", "/store", True), ("workstation/certs", "/certs", False),
                                                            ("database", "/recovery", False))]}

    def test_network_port_or_wrong_mount_fails_closed(self):
        directory = Path("/private/recovery")
        good = self.fixture(directory)
        RESTORE.verify_isolation(good, "test", directory)
        for field, value in (("NetworkMode", "host"), ("PortBindings", {"26257/tcp": [{"HostPort": "26257"}]}),
                             ("Privileged", True)):
            with self.subTest(field=field):
                changed = self.fixture(directory)
                changed["HostConfig"][field] = value
                with self.assertRaises(RuntimeError):
                    RESTORE.verify_isolation(changed, "test", directory)
        changed = self.fixture(directory)
        changed["Mounts"][0]["Source"] = "/daily/database"
        with self.assertRaises(RuntimeError):
            RESTORE.verify_isolation(changed, "test", directory)

    def test_invalid_archive_never_starts_a_container(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            # Exercise cleanup using an extraction failure: no Docker command is
            # permissible before all keys/archives have validated.
            with mock.patch.object(RESTORE.subprocess, "run") as run:
                with self.assertRaises(Exception):
                    RESTORE.restore(directory, {"spool.tar": b"invalid archive"}, ({}, {}, {}, {}))
                run.assert_not_called()
            self.assertFalse(json.loads((directory / "result.json").read_text())["complete"])

    def test_sql_failure_stops_only_new_container_and_keeps_passphrase_out_of_arguments(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            container_id = "a" * 64
            passphrase = "b" * 64
            signing_key = "c" * 64
            calls = []

            def extract(_data, destination, **_kwargs):
                destination.mkdir()
                if destination.name == "workstation":
                    (destination / "authority.json").write_text(json.dumps({"generation": 3, "activation_id": "d" * 64, "pins": {}}))
                    (destination / "remote-grant-signing-key.hex").write_text(signing_key)
                    (destination / "certs").mkdir()
                    for name in ("ca.crt", "node.crt", "node.key", "client.root.crt", "client.root.key"):
                        (destination / "certs" / name).write_text("mocked certificate fixture")
                return {}

            def command(argv, *, input=None, **_kwargs):
                calls.append((argv, input))
                self.assertFalse(any(passphrase in arg or signing_key in arg for arg in argv))
                output = b""
                code = 0
                if argv[:2] == ["docker", "create"]:
                    self.assertIn("--network=none", argv)
                    self.assertFalse(any(arg in argv for arg in ("-p", "--publish", "--privileged")))
                    output = (container_id + "\n").encode()
                elif argv[:2] == ["docker", "inspect"]:
                    item = self.fixture(directory)
                    item["Id"] = container_id
                    output = json.dumps([item]).encode()
                elif input and input.startswith(b"SELECT database_name"):
                    output = b"database_name\ndefaultdb\npostgres\nsystem\n"
                elif input and input.startswith(b"SHOW BACKUP"):
                    # Simulate a SQL error containing sensitive query text. The
                    # caller must retain it only in private logs, then stop.
                    output = passphrase.encode()
                    code = 1
                return subprocess.CompletedProcess(argv, code, output, b"")

            plaintext = {"spool.tar": b"mock", "workstation-state.tar.gz": b"mock", "database.tar": b"mock",
                         "fleet-recall-resources.json": json.dumps({"items": [{"kind": "Secret",
                             "metadata": {"name": "fleet-remote", "namespace": "fleet-recall"},
                             "data": {"FLEET_RECALL_GRANT_SIGNING_KEY_HEX": base64.b64encode(signing_key.encode()).decode()}}]}).encode()}
            inputs = ({"uri": "nodelocal://1/https-backup-fixture", "encryption_passphrase": passphrase}, {}, {}, {})
            with mock.patch.object(RESTORE, "extract_private", side_effect=extract), \
                    mock.patch.object(RESTORE.subprocess, "run", side_effect=command), self.assertRaises(RuntimeError):
                RESTORE.restore(directory, plaintext, inputs)
            result = json.loads((directory / "result.json").read_text())
            self.assertFalse(result["complete"])
            self.assertTrue(result["container_stopped"])
            self.assertEqual(result["phase"], "restore")
            self.assertEqual(calls[-1][0], ["docker", "stop", "--time=30", container_id])

    def test_sigterm_after_sql_container_creation_records_interruption_and_stops(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            identity = "a" * 64
            key = "c" * 64
            calls = []

            def extract(_data, destination, **_kwargs):
                destination.mkdir()
                if destination.name == "workstation":
                    (destination / "authority.json").write_text(json.dumps({"generation": 3, "activation_id": "d" * 64, "pins": {}}))
                    (destination / "remote-grant-signing-key.hex").write_text(key)
                    (destination / "certs").mkdir()
                    for name in ("ca.crt", "node.crt", "node.key", "client.root.crt", "client.root.key"):
                        (destination / "certs" / name).write_text("mock certificate")
                return {}

            def command(argv, **_kwargs):
                calls.append(argv)
                output = b""
                if argv[:2] == ["docker", "create"]:
                    output = identity.encode()
                elif argv[:2] == ["docker", "inspect"]:
                    item = self.fixture(directory)
                    item["Id"] = identity
                    output = json.dumps([item]).encode()
                elif argv[:2] == ["docker", "start"]:
                    signal.raise_signal(signal.SIGTERM)
                elif argv[:2] == ["docker", "stop"]:
                    self.assertEqual(signal.getsignal(signal.SIGTERM), signal.SIG_IGN)
                    signal.raise_signal(signal.SIGTERM)
                return subprocess.CompletedProcess(argv, 0, output, b"")

            plaintext = {"spool.tar": b"fixture", "workstation-state.tar.gz": b"fixture", "database.tar": b"fixture",
                         "fleet-recall-resources.json": json.dumps({"items": [{"kind": "Secret",
                         "metadata": {"name": "fleet-remote", "namespace": "fleet-recall"},
                         "data": {"FLEET_RECALL_GRANT_SIGNING_KEY_HEX": base64.b64encode(key.encode()).decode()}}]}).encode()}
            inputs = ({"uri": "nodelocal://1/https-backup-fixture"}, {}, {}, {})
            with RESTORE.interruption_signals(), mock.patch.object(RESTORE, "extract_private", side_effect=extract), \
                    mock.patch.object(RESTORE.subprocess, "run", side_effect=command), self.assertRaises(KeyboardInterrupt):
                RESTORE.restore(directory, plaintext, inputs)
            result = json.loads((directory / "result.json").read_text())
            self.assertTrue(result["interrupted"])
            self.assertTrue(result["container_stopped"])
            self.assertFalse(result["complete"])
            self.assertEqual(calls[-1], ["docker", "stop", "--time=30", identity])


class ApplicationRecoveryTests(unittest.TestCase):
    def test_only_verified_source_dsn_is_rewritten_and_credentials_remain_literal(self):
        source = "postgresql://role:encoded%40password@cockroach.fleet-recall.svc.cluster.local:26257/fleet_recall?sslmode=verify-full&sslrootcert=/etc/crdb/ca.crt"
        changed = APP.isolated_dsn(source)
        self.assertEqual(changed, source.replace("cockroach.fleet-recall.svc.cluster.local", "127.0.0.1"))
        for unsafe in (source.replace("verify-full", "disable"), source.replace("verify-full", "verify-full-invalid"),
                       source + "&sslmode=disable", source.replace("cockroach.fleet-recall.svc.cluster.local", "production.example.test"),
                       source.replace(":26257", ":26258")):
            with self.subTest(unsafe=unsafe), self.assertRaises(RuntimeError):
                APP.isolated_dsn(unsafe)

    def test_empty_kubernetes_environment_value_is_preserved_without_missing_reference(self):
        self.assertEqual(APP.environment({"env": [{"name": "BASE_PATH"}, {"name": "SECURITY_MODE", "value": ""}]}, [], "ory"),
                         {"BASE_PATH": "", "SECURITY_MODE": ""})

    def test_environment_secret_reference_must_name_exact_namespace_and_key(self):
        secret = {"kind": "Secret", "metadata": {"name": "example", "namespace": "ory"},
                  "data": {"key": base64.b64encode(b"non-sensitive fixture").decode()}}
        container = {"env": [{"name": "VALUE", "valueFrom": {"secretKeyRef": {"name": "example", "key": "key"}}}]}
        self.assertEqual(APP.environment(container, [secret], "ory"), {"VALUE": "non-sensitive fixture"})
        with self.assertRaises(RuntimeError):
            APP.environment(container, [secret], "other")

    def test_recovery_files_must_match_original_authenticated_hash_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "spool").mkdir()
            (directory / "workstation").mkdir()
            (directory / "resources").mkdir()
            (directory / "spool/file").write_bytes(b"fixture")
            baseline = {"spool_file_sha256": {"file": hashlib.sha256(b"fixture").hexdigest()}, "workstation_file_sha256": {},
                        "resource_artifact_sha256": {}}
            APP.verify_preserved_files(directory, baseline)
            (directory / "spool/file").write_bytes(b"changed")
            with self.assertRaisesRegex(RuntimeError, "changed"):
                APP.verify_preserved_files(directory, baseline)
            baseline["spool_file_sha256"] = {"../outside": "unused"}
            with self.assertRaisesRegex(RuntimeError, "inventory"):
                APP.verify_preserved_files(directory, baseline)

    def test_modified_ory_or_recall_resources_are_rejected_before_container_start(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name in ("spool", "workstation", "resources"):
                (directory / name).mkdir()
            resource = directory / "resources/fleet-recall-resources.json"
            original = b'{"data":"authenticated fixture"}'
            resource.write_bytes(original)
            baseline = {"spool_file_sha256": {}, "workstation_file_sha256": {},
                        "resource_artifact_sha256": {resource.name: hashlib.sha256(original).hexdigest()}}
            APP.verify_preserved_files(directory, baseline)
            resource.write_bytes(b'{"data":"changed signing-key fixture"}')
            with mock.patch.object(APP.subprocess, "run") as run, self.assertRaisesRegex(RuntimeError, "changed"):
                APP.verify_preserved_files(directory, baseline)
            run.assert_not_called()

    def test_added_resource_file_is_rejected_even_when_known_hashes_match(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name in ("spool", "workstation", "resources"):
                (directory / name).mkdir()
            (directory / "resources/unexpected.json").write_text("fixture")
            with self.assertRaisesRegex(RuntimeError, "inventory"):
                APP.verify_preserved_files(directory, {"spool_file_sha256": {}, "workstation_file_sha256": {}, "resource_artifact_sha256": {}})

    def test_application_mounts_reject_extra_writable_or_wrong_source(self):
        directory = Path("/private/recovery/application")
        mounts = [(directory / "hosts", "/etc/hosts", False), (directory, "/proof", True)]

        def fixture():
            return {"Id": "application", "HostConfig": {"NetworkMode": "container:database", "PortBindings": {}, "Privileged": False},
                    "Config": {"Labels": {"fleet-recall.dev/recovery": directory.name}},
                    "Mounts": [{"Type": "bind", "Source": str(source), "Destination": target, "RW": writable}
                               for source, target, writable in mounts]}

        APP.verify_application_container(fixture(), "application", "database", directory, mounts)
        for mutate in (lambda item: item["Mounts"][0].update(Source="/daily/production"),
                       lambda item: item["Mounts"][0].update(RW=True),
                       lambda item: item["Mounts"].append({"Type": "volume", "Destination": "/extra", "RW": True})):
            item = fixture()
            mutate(item)
            with self.assertRaises(RuntimeError):
                APP.verify_application_container(item, "application", "database", directory, mounts)

    def test_log_timeout_does_not_skip_any_container_stop(self):
        calls = []

        def run(argv, **_kwargs):
            calls.append(argv)
            if argv[:2] == ["docker", "logs"]:
                raise subprocess.TimeoutExpired(argv, 1)

        self.assertEqual(APP.stop_owned_containers(run, ["first", "second"], "database"), (0, 2))
        self.assertEqual([argv[-1] for argv in calls if argv[1] == "stop"], ["second", "first", "database"])

    def test_sigterm_unwinds_and_repeated_signals_do_not_interrupt_stops(self):
        calls = []
        previous = signal.getsignal(signal.SIGTERM)

        def run(argv, **_kwargs):
            calls.append(argv)
            self.assertEqual(signal.getsignal(signal.SIGTERM), signal.SIG_IGN)
            signal.raise_signal(signal.SIGTERM)

        with self.assertRaises(KeyboardInterrupt):
            with RESTORE.interruption_signals():
                try:
                    signal.raise_signal(signal.SIGTERM)
                finally:
                    APP.stop_owned_containers(run, ["owned"], "database")
        self.assertEqual([argv[-1] for argv in calls if argv[1] == "stop"], ["owned", "database"])
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous)

    def test_sigint_during_normal_cleanup_is_ignored_until_cleanup_finishes(self):
        previous = signal.getsignal(signal.SIGINT)
        with RESTORE.interruption_signals():
            with RESTORE.cleanup_signals():
                signal.raise_signal(signal.SIGINT)
                self.assertEqual(signal.getsignal(signal.SIGINT), signal.SIG_IGN)
        self.assertEqual(signal.getsignal(signal.SIGINT), previous)


if __name__ == "__main__":
    unittest.main()
