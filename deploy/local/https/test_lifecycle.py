"""Lifecycle orchestration regressions; no subprocess or live-cluster mutations."""

import base64
import contextlib
import copy
import importlib.util
import io
import json
import tempfile
import tarfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


spec = importlib.util.spec_from_file_location("lifecycle", Path(__file__).resolve().parents[1] / "bin/lifecycle-smoke.py")
LIFECYCLE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(LIFECYCLE)


def archive(entries):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as output:
        for name, body, kind in entries:
            info = tarfile.TarInfo(name)
            info.type = kind
            if kind == tarfile.REGTYPE:
                info.size = len(body)
                output.addfile(info, io.BytesIO(body))
            else:
                info.linkname = body.decode()
                output.addfile(info)
    return buffer.getvalue()


def deployment(image="new", uid="installed", path="/readyz"):
    return {"metadata": {"name": "recall", "namespace": "fleet-recall", "uid": uid, "resourceVersion": "1"},
            "spec": {"replicas": 1, "strategy": {"type": "Recreate"}, "template": {"spec": {"containers": [{
                "name": "recall", "image": image, "readinessProbe": {"httpGet": {"path": path, "port": "mcp"}},
                "env": [{"name": "FLEET_RECALL_RESOURCE_URL", "value": "https://recall.fleet.test:8443/mcp"},
                        {"name": "FLEET_RECALL_OIDC_ISSUERS", "value": "hydra=https://auth.fleet.test:8443/,k8s=https://kubernetes.default.svc"}]
            }]}}}}


def stub(mode="restart"):
    smoke = LIFECYCLE.Lifecycle.__new__(LIFECYCLE.Lifecycle)
    smoke.args = SimpleNamespace(mode=mode, claim_id=13, query="known fixture", vm="k0s",
                                 state=Path("/private/fixture"), backup=Path("/private/fixture/checkpoint"),
                                 url="https://recall.fleet.test:8443/mcp")
    smoke.cron = {"metadata": {"uid": "worker", "resourceVersion": "1"},
                  "spec": {"suspend": False, "concurrencyPolicy": "Forbid"}}
    smoke.suspended = True
    smoke.scaled = []
    smoke.vm_restart_pending = False
    smoke.rollback_restore = None
    smoke.worker_restore_spec = None
    smoke.deploy_values = None
    smoke.deployment_before = None
    smoke.ready_path = "/readyz"
    smoke.baseline = {"secrets": {"key": "old"}, "spool": {"file": "unchanged"}}
    smoke.claim_hash = None
    smoke.events = []
    smoke.save = mock.Mock()
    smoke.command = mock.Mock(return_value=b"")
    smoke.kubectl = mock.Mock(return_value=b"{}")
    smoke.obj = mock.Mock(return_value=smoke.cron)
    smoke.healthy = mock.Mock(return_value=True)
    smoke.fingerprint = mock.Mock(side_effect=lambda: copy.deepcopy(smoke.baseline))
    smoke.wait = lambda check, _message, seconds=0: LIFECYCLE.require(check(), "wait failed")
    return smoke


class RevocationTests(unittest.TestCase):
    def test_private_ordered_rows_preserve_revocation_time_and_actor(self):
        first = b"jti,revoked_at,revoked_by\ngrant,2026-09-27 12:00:00+00,operator\n"
        self.assertEqual(LIFECYCLE.revoked_rows(first)["count"], 1)
        self.assertNotEqual(LIFECYCLE.revoked_rows(first), LIFECYCLE.revoked_rows(first.replace(b"12:00", b"13:00")))
        self.assertNotEqual(LIFECYCLE.revoked_rows(first), LIFECYCLE.revoked_rows(first.replace(b"operator", b"another")))
        self.assertEqual(LIFECYCLE.revoked_rows(b"jti,revoked_at,revoked_by\n")["count"], 0)
        for raw in (b"jti,revoked_at\n", first + first.splitlines(keepends=True)[1], b"jti,revoked_at,revoked_by\na,,actor\n"):
            with self.assertRaises(LIFECYCLE.LifecycleFailure):
                LIFECYCLE.revoked_rows(raw)

    def test_explain_precedes_read_only_query_and_only_digest_is_returned(self):
        smoke = stub()
        smoke.command.side_effect = [b"plan", b"jti,revoked_at,revoked_by\ngrant,timestamp,actor\n"]
        value = smoke.revocation_fingerprint()
        self.assertEqual(set(value), {"count", "sha256"})
        self.assertEqual(value["count"], 1)
        self.assertEqual(smoke.command.call_args_list[0].args[1], ("EXPLAIN " + LIFECYCLE.REVOCATIONS_SQL).encode())
        self.assertEqual(smoke.command.call_args_list[1].args[1], LIFECYCLE.REVOCATIONS_SQL.encode())
        self.assertTrue(LIFECYCLE.REVOCATIONS_SQL.startswith("SELECT "))


class WorkerExclusionTests(unittest.TestCase):
    def fixture(self):
        smoke = stub("worker-exclusion")
        smoke.kube, smoke.directory = ["kubectl"], Path("/private/evidence")
        smoke.no_sandboxes = mock.Mock()
        smoke.cron["spec"].update(schedule="*/5 * * * *", jobTemplate={"spec": {"backoffLimit": 0, "template": {
            "metadata": {"labels": {"app": "worker"}}, "spec": {"restartPolicy": "Never",
            "initContainers": [{"name": "prepare-metrics", "image": "busybox:1.37.0"}],
            "containers": [{"name": "worker", "image": "original-worker", "args": ["worker", "--once"],
                            "env": [{"name": "UNCHANGED", "value": "original"}]}]}}}})
        current = copy.deepcopy(smoke.cron)
        current["spec"]["suspend"] = True
        current["status"] = {"active": [{"uid": "job-id"}]}
        job = {"kind": "Job", "metadata": {"name": "worker-proof", "uid": "job-id", "ownerReferences": [
            {"kind": "CronJob", "uid": "worker", "controller": True}]},
            "spec": copy.deepcopy(current["spec"]["jobTemplate"]["spec"]), "status": {"active": 1}}
        pod = {"kind": "Pod", "metadata": {"name": "worker-proof-pod", "uid": "pod-id", "labels": {"app": "worker"},
            "ownerReferences": [{"kind": "Job", "uid": "job-id", "controller": True}]}, "status": {
            "phase": "Running", "initContainerStatuses": [{"name": "lifecycle-hold", "state": {"running": {
                "startedAt": "2026-09-27T12:00:01Z"}}}], "containerStatuses": [{"name": "worker", "state": {"waiting": {}}, "restartCount": 0}]}}
        complete = copy.deepcopy(job)
        complete["status"] = {"succeeded": 1, "conditions": [{"type": "Complete", "status": "True"}]}
        smoke.obj.side_effect = lambda _namespace, kind, _name: complete if kind == "job" else copy.deepcopy(current)
        smoke.worker_snapshot = mock.Mock(side_effect=[([], [], [])] + [([job], [job], [pod])] * 3)
        smoke.exclusion_events = mock.Mock(side_effect=[{}, {"event": {"count": 1, "last": LIFECYCLE.timestamp("2026-09-27T12:01:00Z")}},
                                                       {"event": {"count": 2, "last": LIFECYCLE.timestamp("2026-09-27T12:02:00Z")}}])
        return smoke, current, job, pod

    def test_two_controller_refusals_then_original_template_restored_before_real_tick_drains(self):
        smoke, original, _job, _pod = self.fixture()
        with mock.patch.object(LIFECYCLE.CUTOVER, "drain_workers") as drain:
            smoke.exercise()
        mutations = [json.loads(call.args[-1]) for call in smoke.kubectl.call_args_list]
        self.assertEqual(mutations[0][1]["value"], "* * * * *")
        changed = mutations[0][2]["value"]["spec"]["template"]["spec"]
        self.assertEqual(changed["containers"], original["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"])
        self.assertEqual(changed["initContainers"][0]["command"], ["sleep", "150"])
        self.assertEqual(mutations[1][1], {"op": "add", "path": "/spec/suspend", "value": True})
        self.assertEqual(mutations[1][2]["value"], "*/5 * * * *")
        self.assertEqual(mutations[1][3]["value"], original["spec"]["jobTemplate"])
        drain.assert_called_once()
        self.assertIsNone(smoke.worker_restore_spec)
        self.assertEqual(smoke.events[-1]["worker_exclusion"], "two_scheduled_ticks_refused_then_worker_succeeded")
        smoke.no_sandboxes.assert_called_once()

    def test_mutation_timeout_or_failed_proof_still_restores_original_schedule_before_drain(self):
        for failure in ("mutation", "proof", "drain"):
            smoke, original, _job, _pod = self.fixture()
            if failure == "mutation":
                smoke.kubectl.side_effect = LIFECYCLE.LifecycleFailure("ambiguous timeout")
            elif failure == "proof":
                smoke.wait = mock.Mock(side_effect=LIFECYCLE.LifecycleFailure("proof failed"))
            with mock.patch.object(LIFECYCLE.CUTOVER, "drain_workers", side_effect=
                                   LIFECYCLE.LifecycleFailure("drain failed") if failure == "drain" else None):
                with self.assertRaises(LIFECYCLE.LifecycleFailure):
                    smoke.exercise()
            self.assertIsNotNone(smoke.worker_restore_spec)
            smoke.kubectl.side_effect = None
            with mock.patch.object(LIFECYCLE.CUTOVER, "drain_workers") as drain:
                smoke.restore_dependencies()
            patch = json.loads(smoke.kubectl.call_args.args[-1])
            self.assertEqual(patch[1]["value"], True)
            self.assertEqual(patch[2]["value"], original["spec"]["schedule"])
            self.assertEqual(patch[3]["value"], original["spec"]["jobTemplate"])
            drain.assert_called_once()
            self.assertIsNone(smoke.worker_restore_spec)

    def test_controller_missing_second_tick_overlap_or_process_start_cannot_pass(self):
        for failure in ("second_tick", "ownership", "process", "second_job", "new_pod"):
            smoke, _current, job, pod = self.fixture()
            if failure == "second_tick":
                smoke.exclusion_events.side_effect = [{}, {"event": {"count": 1, "last": LIFECYCLE.timestamp("2026-09-27T12:01:00Z")}}, {}]
            elif failure == "ownership":
                job["metadata"]["ownerReferences"][0]["controller"] = False
            elif failure == "process":
                pod["status"]["containerStatuses"][0]["state"] = {"running": {}}
            elif failure == "second_job":
                other = copy.deepcopy(job)
                other["metadata"]["uid"] = "second"
                smoke.worker_snapshot.side_effect = [([], [], []), ([job, other], [job], [pod])]
            else:
                other = copy.deepcopy(pod)
                other["metadata"]["uid"] = "replacement"
                smoke.worker_snapshot.side_effect = [([], [], []), ([job], [job], [pod]), ([job], [job], [other])]
            with self.subTest(failure=failure), self.assertRaises(LIFECYCLE.LifecycleFailure):
                smoke.exercise()
            self.assertIsNotNone(smoke.worker_restore_spec)

    def test_observed_overlap_is_fatal_and_not_retried_away(self):
        smoke = stub()
        check = mock.Mock(side_effect=[LIFECYCLE.WorkerExclusionFailure("overlap"), True])
        with self.assertRaises(LIFECYCLE.WorkerExclusionFailure):
            LIFECYCLE.Lifecycle.wait(smoke, check, "failed")
        check.assert_called_once()

    def test_snapshot_checks_manual_workers_as_well_as_cron_owned_jobs(self):
        smoke, _current, job, _pod = self.fixture()
        manual = copy.deepcopy(job)
        manual["metadata"] = {"name": "manual", "uid": "manual", "labels": {"app": "worker"}}
        smoke.kubectl.return_value = json.dumps({"items": [job, manual]}).encode()
        with self.assertRaises(LIFECYCLE.WorkerExclusionFailure):
            LIFECYCLE.Lifecycle.worker_snapshot(smoke)


class SpoolTests(unittest.TestCase):
    def test_hashes_preserve_exact_acknowledged_bytes(self):
        first = LIFECYCLE.spool_hashes(archive([("transcripts/project/source.jsonl", b"acknowledged\n", tarfile.REGTYPE)]))
        second = LIFECYCLE.spool_hashes(archive([("transcripts/project/source.jsonl", b"changed\n", tarfile.REGTYPE)]))
        self.assertEqual(first["transcripts/project/source.jsonl"]["bytes"], 13)
        self.assertNotEqual(first, second)

    def test_path_link_duplicate_and_size_attacks_are_refused_without_extraction(self):
        cases = [
            [("transcripts/../outside", b"x", tarfile.REGTYPE)],
            [("/transcripts/file", b"x", tarfile.REGTYPE)],
            [("elsewhere/file", b"x", tarfile.REGTYPE)],
            [("transcripts/link", b"/secret", tarfile.SYMTYPE)],
            [("transcripts/link", b"transcripts/file", tarfile.LNKTYPE)],
            [("transcripts/file", b"a", tarfile.REGTYPE), ("transcripts/file", b"b", tarfile.REGTYPE)],
        ]
        for entries in cases:
            with self.subTest(entries=entries), self.assertRaises(LIFECYCLE.LifecycleFailure):
                LIFECYCLE.spool_hashes(archive(entries))
        with mock.patch.object(LIFECYCLE, "MAX_OUTPUT", 2), self.assertRaises(LIFECYCLE.LifecycleFailure):
            LIFECYCLE.spool_hashes(b"123")


class RollbackTests(unittest.TestCase):
    def test_only_image_and_probe_are_selected(self):
        old, current = deployment("old", path="/healthz"), deployment()
        old["spec"]["template"]["spec"]["containers"][0]["envFrom"] = [{"secretRef": {"name": "stale-secret"}}]
        result = LIFECYCLE.rollback_values(old, current, "https://recall.fleet.test:8443/mcp")
        self.assertEqual(set(result), {"image", "readinessProbe"})
        self.assertEqual(result["image"], "old")
        result["readinessProbe"]["httpGet"]["path"] = "/changed"
        self.assertEqual(old["spec"]["template"]["spec"]["containers"][0]["readinessProbe"]["httpGet"]["path"], "/healthz")

    def test_cross_installation_urls_and_non_singleton_rollbacks_are_rejected(self):
        for change in ("uid", "url", "issuer", "replicas", "strategy", "probe", "port", "same_image"):
            old = deployment("old", path="/healthz")
            container = old["spec"]["template"]["spec"]["containers"][0]
            if change == "uid":
                old["metadata"]["uid"] = "another-cluster"
            elif change == "url":
                container["env"][0]["value"] = "http://old/mcp"
            elif change == "issuer":
                container["env"][1]["value"] = "hydra=http://localhost:4444/"
            elif change == "replicas":
                old["spec"]["replicas"] = 2
            elif change == "strategy":
                old["spec"]["strategy"]["type"] = "RollingUpdate"
            elif change == "probe":
                container["readinessProbe"]["httpGet"]["path"] = "/metrics"
            elif change == "port":
                container["readinessProbe"]["httpGet"]["port"] = 9100
            else:
                container["image"] = "new"
            with self.subTest(change=change), self.assertRaises(LIFECYCLE.LifecycleFailure):
                LIFECYCLE.rollback_values(old, deployment(), "https://recall.fleet.test:8443/mcp")

    def test_patch_does_not_restore_any_database_or_authority_configuration(self):
        smoke = stub()
        smoke.obj.return_value = deployment()
        smoke.patch_image_probe({"image": "old", "readinessProbe": {"httpGet": {"path": "/healthz", "port": "mcp"}}})
        patch = json.loads(smoke.kubectl.call_args_list[0].args[-1])
        self.assertEqual([step["path"] for step in patch], ["/metadata/resourceVersion",
                         "/spec/template/spec/containers/0/image", "/spec/template/spec/containers/0/readinessProbe"])
        smoke.command.assert_not_called()


class DeploymentTests(unittest.TestCase):
    def test_checked_manifest_has_fail_closed_probe_contract(self):
        self.assertEqual(LIFECYCLE.deployment_probe(), {"httpGet": {"path": "/readyz", "port": "mcp"},
                         "periodSeconds": 5, "timeoutSeconds": 1, "failureThreshold": 1})

    def test_preparation_requires_image_on_every_schedulable_node_and_retains_old_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            for installed in (False, True):
                smoke = stub("deploy")
                smoke.args.image = "ostk-fleet-recall:m4-fixture"
                smoke.directory = Path(temporary)
                names = ["docker.io/library/ostk-fleet-recall:m4-fixture"] if installed else ["unrelated:image"]
                smoke.kubectl.return_value = json.dumps({"items": [{"status": {"images": [{"names": names}]}}]}).encode()
                if installed:
                    smoke.prepare_deploy(deployment("previous", path="/healthz"))
                    self.assertEqual(smoke.ready_path, "/healthz")
                    self.assertEqual(smoke.deploy_values["readinessProbe"]["httpGet"]["path"], "/readyz")
                    saved = json.loads((smoke.directory / "deployment-before.json").read_text())
                    self.assertEqual(saved["spec"]["template"]["spec"]["containers"][0]["image"], "previous")
                else:
                    with self.assertRaisesRegex(LIFECYCLE.LifecycleFailure, "import"):
                        smoke.prepare_deploy(deployment("previous", path="/healthz"))
                    self.assertFalse((smoke.directory / "deployment-before.json").exists())

    def test_success_keeps_new_image_but_failed_rollout_or_acceptance_restores_previous(self):
        for failure in (None, "rollout", "health", "preservation"):
            smoke = stub("deploy")
            old = deployment("previous", path="/healthz")
            smoke.deployment_before = copy.deepcopy(old)
            smoke.obj.return_value = old
            smoke.deploy_values = {"image": "ostk-fleet-recall:m4-fixture", "readinessProbe": LIFECYCLE.deployment_probe()}
            smoke.patch_image_probe = mock.Mock()
            if failure == "rollout":
                smoke.patch_image_probe.side_effect = LIFECYCLE.LifecycleFailure("rollout failed")
            elif failure == "health":
                smoke.healthy.side_effect = LIFECYCLE.LifecycleFailure("not ready")
            elif failure == "preservation":
                smoke.fingerprint.side_effect = None
                smoke.fingerprint.return_value = {"changed": True}
            with self.subTest(failure=failure):
                if failure:
                    with self.assertRaises(LIFECYCLE.LifecycleFailure):
                        smoke.exercise()
                    self.assertEqual(smoke.rollback_restore["image"], "previous")
                    smoke.patch_image_probe.side_effect = None
                    smoke.restore_dependencies()
                    self.assertEqual(smoke.patch_image_probe.call_args.args[0]["image"], "previous")
                    self.assertEqual(smoke.ready_path, "/healthz")
                else:
                    smoke.exercise()
                    self.assertIsNone(smoke.rollback_restore)
                    self.assertEqual(smoke.ready_path, "/readyz")
                    smoke.restore_dependencies()
                    smoke.patch_image_probe.assert_called_once_with(smoke.deploy_values)

    def test_configuration_drift_before_mutation_is_rejected(self):
        smoke = stub("deploy")
        smoke.deployment_before = deployment("previous", path="/healthz")
        smoke.obj.return_value = deployment("someone-else-deployed", path="/healthz")
        smoke.deploy_values = {"image": "ostk-fleet-recall:m4-fixture", "readinessProbe": LIFECYCLE.deployment_probe()}
        smoke.patch_image_probe = mock.Mock()
        with self.assertRaisesRegex(LIFECYCLE.LifecycleFailure, "changed"):
            smoke.exercise()
        smoke.patch_image_probe.assert_not_called()

    def test_image_argument_is_limited_to_deploy_and_local_tags(self):
        with tempfile.TemporaryDirectory() as temporary:
            common = ["--state", temporary, "--backup", "backup", "--ca-path", "ca", "--token-file", "token",
                      "--claim-id", "13", "--query", "known"]
            for image in ("remote.example/fleet:v1", "ostk-fleet-recall:bad tag", "ostk-fleet-recall:", "other:v1"):
                with self.subTest(image=image), self.assertRaises(LIFECYCLE.LifecycleFailure):
                    LIFECYCLE.arguments(common + ["--mode", "deploy", "--image", image])
            with self.assertRaises(LIFECYCLE.LifecycleFailure):
                LIFECYCLE.arguments(common + ["--mode", "restart", "--image", "ostk-fleet-recall:m4"])
            self.assertEqual(LIFECYCLE.arguments(common + ["--mode", "deploy", "--image", "ostk-fleet-recall:m4"]).image,
                             "ostk-fleet-recall:m4")


class RecoveryTests(unittest.TestCase):
    def test_unauthenticated_or_drifted_backup_prevents_all_mutations(self):
        for backup_failure in (True, False):
            smoke = stub()
            smoke.suspended = False
            smoke.obj.return_value = {"metadata": {"uid": "cluster"}}
            smoke.secret_fingerprints = mock.Mock(return_value={"key": "changed"})
            smoke.no_sandboxes = mock.Mock()
            with mock.patch.object(LIFECYCLE.CUTOVER, "verify_backup", side_effect=
                                   RuntimeError("invalid backup") if backup_failure else None,
                                   return_value={"key": "old"}):
                with self.assertRaises((RuntimeError, LIFECYCLE.LifecycleFailure)):
                    smoke.preflight()
            smoke.kubectl.assert_not_called()
            smoke.command.assert_not_called()
            self.assertFalse(smoke.suspended)

    def test_pending_scale_is_retained_even_after_ambiguous_command_failure(self):
        smoke = stub()
        smoke.obj.return_value = {"spec": {"replicas": 1, "selector": {"matchLabels": {"app": "embed"}}}}
        smoke.kubectl.side_effect = LIFECYCLE.LifecycleFailure("scale timeout")
        with self.assertRaises(LIFECYCLE.LifecycleFailure):
            smoke.scale_down("fleet-recall", "deployment", "embed")
        self.assertEqual(smoke.scaled, [("fleet-recall", "deployment", "embed")])
        smoke.kubectl.side_effect = None
        smoke.restore_dependencies()
        self.assertIn("--replicas=1", smoke.kubectl.call_args_list[-2].args)
        self.assertEqual(smoke.scaled, [])

    def test_recovery_restores_dependencies_before_health_and_original_worker_state(self):
        for suspended in (False, True):
            smoke = stub()
            smoke.cron["spec"]["suspend"] = suspended
            order = []
            smoke.restore_dependencies = lambda: order.append("dependencies")
            smoke.healthy = lambda: order.append("healthy") or True
            smoke.recover()
            self.assertEqual(order, ["dependencies", "healthy"])
            patch = json.loads(smoke.kubectl.call_args.args[-1])
            self.assertEqual(patch[-1], {"op": "add", "path": "/spec/suspend", "value": suspended})
            self.assertFalse(smoke.suspended)

    def test_drift_failed_health_and_missing_baseline_never_resume_worker(self):
        for failure in ("health", "keys", "baseline", "worker_uid"):
            smoke = stub()
            smoke.restore_dependencies = mock.Mock()
            if failure == "health":
                smoke.healthy.side_effect = LIFECYCLE.LifecycleFailure("unhealthy")
            elif failure == "keys":
                smoke.fingerprint.return_value = {"changed": True}
                smoke.fingerprint.side_effect = None
            elif failure == "baseline":
                smoke.baseline = None
            else:
                smoke.obj.return_value = {"metadata": {"uid": "replaced", "resourceVersion": "2"}}
            with self.subTest(failure=failure), self.assertRaises(LIFECYCLE.LifecycleFailure):
                smoke.recover()
            smoke.restore_dependencies.assert_called_once()
            smoke.kubectl.assert_not_called()
            self.assertTrue(smoke.suspended)

    def test_vm_start_is_attempted_after_ambiguous_stop_and_rollback_restores_image(self):
        smoke = stub()
        smoke.vm_restart_pending = True
        smoke.kubectl.return_value = json.dumps({"items": [{"status": {"conditions": [{"type": "Ready", "status": "True"}]}}]}).encode()
        smoke.rollback_restore = {"image": "current", "readinessProbe": {"httpGet": {"path": "/readyz", "port": "mcp"}}}
        smoke.patch_image_probe = mock.Mock()
        smoke.restore_dependencies()
        self.assertEqual(smoke.command.call_args.args[0], ["limactl", "start", "k0s", "--tty=false"])
        self.assertFalse(smoke.vm_restart_pending)
        smoke.patch_image_probe.assert_called_once()
        self.assertIsNone(smoke.rollback_restore)


class FaultTests(unittest.TestCase):
    def test_ory_selection_excludes_maester_and_requires_exact_application_labels(self):
        for release, application in (("hydra", "hydra"), ("kratos", "kratos"), ("kratos-ui", "kratos-selfservice-ui-node")):
            smoke = stub()
            smoke.kubectl.return_value = json.dumps({"items": [
                {"metadata": {"name": "expected", "labels": {"app.kubernetes.io/instance": release,
                                                              "app.kubernetes.io/name": application}}},
                {"metadata": {"name": "maester", "labels": {"app.kubernetes.io/instance": release,
                                                             "app.kubernetes.io/name": "hydra-maester"}}},
                {"metadata": {"name": "another-release", "labels": {"app.kubernetes.io/instance": "foreign",
                                                                     "app.kubernetes.io/name": application}}}
            ]}).encode()
            self.assertEqual(smoke.release_deployment(release), "expected")
            self.assertIn("app.kubernetes.io/instance=" + release + ",app.kubernetes.io/name=" + application,
                          smoke.kubectl.call_args.args)
        with self.assertRaises(LIFECYCLE.LifecycleFailure):
            smoke.release_deployment("unknown")

    def test_database_fault_checks_original_pod_and_refuses_restart_or_routable_endpoint(self):
        for failure in (None, "restart", "endpoint"):
            smoke = stub("db-outage")
            original = {"metadata": {"name": "recall-original", "uid": "same-pod"}, "status": {
                "containerStatuses": [{"name": "recall", "restartCount": 0}],
                "conditions": [{"type": "Ready", "status": "False"}]}}
            current = copy.deepcopy(original)
            if failure == "restart":
                current["status"]["containerStatuses"][0]["restartCount"] = 1
            smoke.pod = mock.Mock(return_value=original)
            smoke.obj.return_value = current
            smoke.forward = lambda _: contextlib.nullcontext(12345)
            smoke.probe = lambda _port, path: (503 if path == "/readyz" else 200, {})
            smoke.scale_down = mock.Mock()
            smoke.kubectl.return_value = json.dumps({"items": [{"endpoints": [{
                "targetRef": {"uid": "same-pod"}, "conditions": {"ready": failure == "endpoint"}}]}]}).encode()
            with self.subTest(failure=failure):
                if failure:
                    with self.assertRaises(LIFECYCLE.LifecycleFailure):
                        smoke.exercise()
                else:
                    smoke.exercise()
                    self.assertEqual(smoke.events[0]["db_outage"], "ready503_live200_no_restart")
            smoke.scale_down.assert_called_once_with("fleet-recall", "statefulset", "cockroach")

    def test_issuer_probe_distinguishes_warm_and_cold_key_caches(self):
        smoke = stub("issuer-outage")
        events = []
        smoke.restart = lambda *_: events.append("restart")
        smoke.claim = lambda: events.append("claim") or True
        smoke.ready = lambda: events.append("ready")
        smoke.release_deployment = lambda _: "hydra"
        smoke.scale_down = lambda *_: events.append("issuer_down")
        smoke.tool = mock.Mock(return_value={"error": "identity_provider_unavailable"})
        smoke.exercise()
        self.assertEqual(events, ["restart", "claim", "issuer_down", "claim", "ready", "restart", "ready"])
        self.assertEqual(smoke.tool.call_args.kwargs, {"expected": 503})
        smoke.tool.return_value = {"error": "invalid_token"}
        with self.assertRaises(LIFECYCLE.LifecycleFailure):
            smoke.exercise()

    def test_embedding_probe_requires_lexical_hits_before_and_after_recall_restart(self):
        smoke = stub("embed-outage")
        events = []
        smoke.scale_down = lambda *_: events.append("embed_down")
        smoke.lexical_only = lambda: events.append("lexical") or True
        smoke.restart = lambda *_: events.append("restart")
        smoke.exercise()
        self.assertEqual(events, ["embed_down", "lexical", "restart", "lexical"])

    def test_lexical_assertion_rejects_dense_results_empty_hits_or_missing_warning(self):
        for failure in (None, "dense", "empty", "warning"):
            smoke = stub("embed-outage")
            smoke.ready = mock.Mock()
            smoke.claim = mock.Mock()
            result = {"data": {"hits": [{"chunk_id": "fixture"}]}, "diagnostics": {"retrieval": {"lanes": ["lexical"]}},
                      "warnings": [{"code": "query_not_embedded"}]}
            if failure == "dense":
                result["diagnostics"]["retrieval"]["lanes"].append("dense")
            elif failure == "empty":
                result["data"]["hits"] = []
            elif failure == "warning":
                result["warnings"] = []
            smoke.tool = mock.Mock(side_effect=[{"data": {"embedding_tier": {"status": "degraded"}}}, result])
            with self.subTest(failure=failure):
                if failure:
                    with self.assertRaises(LIFECYCLE.LifecycleFailure):
                        smoke.lexical_only()
                else:
                    smoke.lexical_only()

    def test_claim_get_hash_detects_changed_content(self):
        smoke = stub()
        smoke.tool = mock.Mock(return_value={"data": {"claim": {"id": 13, "text": "original"}}})
        smoke.claim()
        smoke.tool.return_value["data"]["claim"]["text"] = "changed"
        with self.assertRaises(LIFECYCLE.LifecycleFailure):
            smoke.claim()

    def test_transient_gateway_non_json_is_a_retryable_sanitized_failure(self):
        smoke = stub()
        smoke.token = "private-fixture-token"
        smoke.count = 1
        smoke.client = mock.Mock()
        smoke.client.request.return_value = (503, {}, b"private gateway diagnostic")
        with self.assertRaisesRegex(LIFECYCLE.LifecycleFailure, "non-JSON"):
            smoke.tool({"action": "status"})
        self.assertNotIn("private gateway diagnostic", json.dumps(smoke.save.call_args.args))
        headers = smoke.client.request.call_args.args[2]
        self.assertEqual(headers["Authorization"], "Bearer private-fixture-token")


class MainTests(unittest.TestCase):
    def test_cleanup_runs_after_failed_exercise_without_echoing_sensitive_exception(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = SimpleNamespace(state=root, mode="db-outage")
            smoke = mock.Mock()
            smoke.exercise.side_effect = RuntimeError("private-fixture-credential")
            smoke.events = []
            smoke.suspended = False
            with mock.patch.object(LIFECYCLE, "arguments", return_value=args), \
                    mock.patch.object(LIFECYCLE, "Lifecycle", return_value=smoke), \
                    mock.patch.object(LIFECYCLE.signal, "signal"), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                previous = LIFECYCLE.os.umask(0o077)
                try:
                    result = LIFECYCLE.main()
                finally:
                    LIFECYCLE.os.umask(previous)
            self.assertEqual(result, 1)
            smoke.recover.assert_called_once()
            self.assertNotIn("private-fixture-credential", output.getvalue())
            proof = next(root.glob("lifecycle-*/result.json"))
            self.assertNotIn("private-fixture-credential", proof.read_text())
            self.assertEqual(proof.stat().st_mode & 0o077, 0)


class CredentialTests(unittest.TestCase):
    def test_token_lifetime_issuer_and_private_permissions_gate_before_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            token_file = root / "token.json"
            args = SimpleNamespace(state=root, token_file=token_file, ca_path=None)
            for issuer, expires, mode in (("https://auth.fleet.test:8443/", time.time() + 3600, 0o600),
                                           ("https://foreign/", time.time() + 3600, 0o600),
                                           ("https://auth.fleet.test:8443/", time.time() + 100, 0o600),
                                           ("https://auth.fleet.test:8443/", time.time() + 3600, 0o644)):
                payload = base64.urlsafe_b64encode(json.dumps({"iss": issuer, "exp": expires}).encode()).decode().rstrip("=")
                token_file.write_text(json.dumps({"access_token": "header." + payload + ".signature"}))
                token_file.chmod(mode)
                accepted = issuer == "https://auth.fleet.test:8443/" and expires - time.time() >= 900 and mode == 0o600
                with self.subTest(issuer=issuer, mode=mode), mock.patch.object(LIFECYCLE.subprocess, "run") as command:
                    if accepted:
                        LIFECYCLE.Lifecycle(args, root)
                    else:
                        with self.assertRaises((LIFECYCLE.LifecycleFailure, LIFECYCLE.SMOKE.SmokeFailure)):
                            LIFECYCLE.Lifecycle(args, root)
                    command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
