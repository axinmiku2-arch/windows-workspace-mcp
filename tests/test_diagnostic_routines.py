"""Offline tests for bounded owner grants; never run PowerShell, DNS, or network."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import io
import os
from pathlib import Path
import subprocess  # import before the Windows compatibility shim
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import Mock, patch

FIXTURE = tempfile.TemporaryDirectory(prefix="dot-routines-fixture-")
os.environ["WINDOWS_WORKSPACE_MCP_STATE"] = FIXTURE.name
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
if os.name != "nt" and "msvcrt" not in sys.modules:
    sys.modules["msvcrt"] = types.SimpleNamespace()

import core
import diagnostic_routines as routines
import project_tasks as project
import windows_toolbox as box


class RoutinesTest(unittest.TestCase):
    SOURCE = {"transport": "https_mcp", "connection_id": "a" * 24}
    WRONG = {"transport": "https_mcp", "connection_id": "b" * 24}

    def setUp(self):
        temp = tempfile.TemporaryDirectory(dir=FIXTURE.name)
        self.addCleanup(temp.cleanup)
        self.data = Path(temp.name)
        self.root = self.data / "workspace"
        self.root.mkdir()
        self.cfg = {
            **core.DEFAULT, "workspace_unified": True, "workspace_enabled": True, "task_enabled": True,
            "approval_mode": "rules", "workspace_root": str(self.root), "workspace_revision": "revision-a",
            "active_workspace_profile": "profile-a", "origin": "https://example.test",
            box.HOSTS_FIELD: ["192.0.2.25", "probe.example.test"],
        }
        for mocked in (
            patch.object(routines, "DB", self.data / "routines.sqlite3"),
            patch.object(routines, "workspace_root", side_effect=Path),
            patch.object(project, "QUEUE", self.data / "jobs"),
            patch.object(project, "_base", side_effect=lambda cfg: self.root),
            patch.object(core, "uses_funnel", return_value=True),
            patch.object(core, "load_config", side_effect=lambda: self.cfg),
        ):
            mocked.start()
            self.addCleanup(mocked.stop)

    def grant(self, preset="windows_ping", **settings):
        return routines.register(preset, self.SOURCE["connection_id"], self.cfg,
                                 host=settings.pop("host", "192.0.2.25" if preset == "windows_ping" else None),
                                 **settings)

    def submit(self, grant, key="run-1", **kwargs):
        source = kwargs.pop("submission", self.SOURCE)
        return project.start(grant["request_preset"], self.cfg, key, submission=source, **kwargs)

    def test_local_grant_validation_strict_and_rules_mode_only(self):
        for kwargs in ({"host": "probe.example.test"}, {"host": "192.0.2.26"},
                       {"minutes": 4}, {"minutes": 61}, {"runs": 0}, {"runs": 6}, {"runs": True},
                       {"preset": "npm_build", "host": None}, {"preset": "windows_ipconfig", "host": "192.0.2.25"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.grant(**kwargs)
        self.cfg["approval_mode"] = "ask"
        with self.assertRaisesRegex(ValueError, "rules or full"):
            self.grant()
        self.cfg["approval_mode"] = "full"
        with self.assertRaises(ValueError):
            routines.register("windows_ipconfig", "token-not-fingerprint", self.cfg)
        first = self.grant()
        self.assertEqual(first["remaining"], 3)
        self.assertTrue(first["active"])
        with self.assertRaisesRegex(ValueError, "before adding another"):
            self.grant("windows_ipconfig")

    def test_routes_for_remote_toolbox_routine_and_direct_diagnostic(self):
        grant = self.grant()
        for settings in ({"key": ""}, {"relative_path": "text.txt"}, {"relative_dir": "src"},
                         {"parameters": {"host": "192.0.2.25"}}, {"submission": None},
                         {"submission": self.WRONG}, {"parameters": []}):
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                self.submit(grant, **settings)
        routine = self.submit(grant)
        self.assertEqual(routine["state"], "queued")
        self.assertNotIn("toolbox_host", routine)
        self.assertEqual(self.submit(grant)["job_id"], routine["job_id"])
        with self.assertRaisesRegex(ValueError, "already queued"):
            self.submit(grant, key="other")
        self.assertEqual(routines.listing(self.cfg)[0]["remaining"], 3)
        with self.assertRaises(ValueError):
            project.status(routine["job_id"], self.cfg, remote=True)
        with self.assertRaises(ValueError):
            project.status(routine["job_id"], self.cfg, remote=True, submission=self.WRONG)
        with self.assertRaises(ValueError):
            project.cancel(routine["job_id"], self.cfg, remote=True, submission=self.WRONG)
        self.assertEqual(project.status(routine["job_id"], self.cfg, remote=True, submission=self.SOURCE)["state"], "queued")
        self.assertFalse(project.listing(self.cfg, remote=True)["jobs"])
        self.assertFalse(any(p["id"].startswith(routines.PREFIX) for p in project.listing(self.cfg, remote=True)["presets"]))
        direct = project.start("windows_ping", self.cfg, parameters={"host": "192.0.2.25"})
        self.assertEqual(direct["state"], "awaiting_approval")

    def test_scope_fingerprint_revision_mode_folder_identity_and_allowlist(self):
        grant = self.grant()
        for delta in ({"active_workspace_profile": "other"}, {"workspace_revision": "revision-b"},
                      {"approval_mode": "full"}, {"origin": "https://other.test"},
                      {box.HOSTS_FIELD: []}, {"workspace_enabled": False}):
            other = {**self.cfg, **delta}
            with self.subTest(delta=delta), self.assertRaises(ValueError):
                routines.plan(grant["routine_id"], self.SOURCE, other)
            self.assertFalse(routines.listing(other)[0]["active"])
        self.root.rename(self.data / "old-scope")
        self.root.mkdir()
        with self.assertRaises(ValueError):
            self.submit(grant)

    def test_atomic_claim_is_used_only_once_even_across_concurrent_connections(self):
        grant = self.grant(runs=1)
        job = self.submit(grant)
        saved = project._read(job["job_id"], self.cfg)

        def attempt(record):
            try:
                routines.consume(record, self.cfg)
            except ValueError:
                return False
            return True

        fixtures = [saved, saved, {**saved, "job_id": "f" * 32}]
        with ThreadPoolExecutor(3) as pool:
            results = list(pool.map(attempt, fixtures))
        self.assertEqual(results.count(True), 1)
        self.assertEqual(routines.listing(self.cfg)[0]["remaining"], 0)
        with self.assertRaises(ValueError):
            routines.plan(grant["routine_id"], self.SOURCE, self.cfg)
        self.assertEqual(self.submit(grant)["job_id"], job["job_id"])

    def test_expire_revoke_and_clock_rate_limit(self):
        now = float(int(time.time()))
        with patch.object(routines.time, "time", return_value=now):
            grant = self.grant(minutes=5)
            job = self.submit(grant)
            item = project._read(job["job_id"], self.cfg)
            routines.consume(item, self.cfg)
            routines.check(item, self.cfg, consumed=True)
            with self.assertRaises(ValueError):
                routines.check(item, self.cfg)
            with self.assertRaisesRegex(ValueError, "10 seconds"):
                routines.consume({**item, "job_id": "e" * 32}, self.cfg)
        with patch.object(routines.time, "time", return_value=now + 10):
            routines.consume({**item, "job_id": "e" * 32}, self.cfg)
        with patch.object(routines.time, "time", return_value=now + 300):
            with self.assertRaises(ValueError):
                routines.check(item, self.cfg, consumed=True)
        routines.revoke(grant["routine_id"])
        with self.assertRaises(ValueError):
            routines.plan(grant["routine_id"], self.SOURCE, self.cfg)

    def test_revoked_or_cancelled_job_does_not_launch_or_spend(self):
        grant = self.grant("windows_ipconfig")
        job = self.submit(grant)
        ident = job["job_id"]
        item = project._read(ident, self.cfg)
        self.assertEqual(project.cancel(ident, self.cfg, remote=True, submission=self.SOURCE)["state"], "cancelling")
        with patch.object(project.subprocess, "Popen", side_effect=AssertionError("no launch")) as popen:
            self.assertEqual(project._run(item, None)[0], "cancelled")
            routines.revoke(grant["routine_id"])
            self.assertEqual(project._run(item, None)[0], "revoked")
            popen.assert_not_called()
        self.assertEqual(routines.listing(self.cfg)[0]["remaining"], 3)

    def test_quota_spent_before_mock_command_handshake(self):
        grant = self.grant("windows_listening_ports", runs=1)
        job = self.submit(grant)
        ident = job["job_id"]
        item = project._read(ident, self.cfg)

        class Handshake(io.BytesIO):
            def write(stream, value):
                self.assertEqual(value, b"1")
                self.assertEqual(routines.listing(self.cfg)[0]["remaining"], 0)
                routines.check(item, self.cfg, consumed=True)
                return super().write(value)

        proc = Mock(returncode=0, stdout=io.BytesIO(b"DOT_PORTS_V1|1|443|0|"), stderr=io.BytesIO(),
                    stdin=Handshake())
        proc.poll.return_value = 0
        with patch.object(project.subprocess, "Popen", return_value=proc) as popen, \
                patch.object(project, "_windows_job"), \
                patch.object(box, "launch_spec", return_value=(["powershell.exe"], self.root, {})):
            state, output = project._run(item, None)
            self.assertEqual(state, "succeeded")
            self.assertEqual(output["result"]["tcp_listening_ports"], [443])
            self.assertEqual(project._run(item, None)[0], "revoked")
            self.assertEqual(popen.call_count, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
