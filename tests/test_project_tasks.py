"""Isolated Windows worker tests for the locally approved project queue."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest


@unittest.skipUnless(os.name == "nt", "Windows Job Objects are needed")
class ProjectTasksTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        stage = Path(__file__).resolve().parents[1]
        fixture = tempfile.TemporaryDirectory(prefix="dot-project-task-test-", dir=stage.parent)
        cls.addClassCleanup(fixture.cleanup)
        cls.root = Path(fixture.name)
        state = cls.root / "state"
        os.environ["WINDOWS_WORKSPACE_MCP_STATE"] = str(state)
        sys.path.insert(0, str(stage / "runtime"))
        import core
        import project_tasks
        if core.STATE != state:
            raise RuntimeError("Run this suite in a fresh process so it cannot access another state directory")
        cls.core, cls.tasks = core, project_tasks
        cls.origin = "https://synthetic-project.invalid"
        core.configure_local_relay(cls.origin, ["https://client.example.invalid/oauth/callback"])
        cls.counter = 0

    def setUp(self):
        type(self).counter += 1
        subroot = self.root / f"workspace-{self.counter}"
        self.folder = subroot / "project"
        self.folder.mkdir(parents=True)
        self.cfg = {**self.core.DEFAULT,
                    "origin": self.origin, "workspace_enabled": True, "workspace_unified": True,
                    "workspace_root": str(self.folder), "workspace_revision": f"ws-{self.counter}",
                    "approval_mode": "ask"}
        self.core.save_json(self.core.CONFIG, self.cfg)
        self.cfg = self.core.load_config()
        self.runner = self.tasks.Runner()
        self.active = []
        self.addCleanup(self.finish_active)

    def finish_active(self):
        cfg = self.core.load_config()
        for job_id in self.active:
            try:
                self.tasks.cancel(job_id, cfg)
            except (ValueError, OSError):
                pass
        if self.runner.thread:
            self.runner.thread.join(6)

    def start(self, preset, request_key=""):
        job = self.tasks.start(preset, self.cfg, request_key)
        self.active.append(job["job_id"])
        return job

    def wait_for(self, read, predicate, timeout=12):
        end = time.monotonic() + timeout
        found = None
        while time.monotonic() < end:
            self.runner.pump(self.core.load_config())
            found = read()
            if predicate(found):
                return found
            time.sleep(0.1)
        self.fail(f"Condition did not complete: {found!r}")

    def terminal(self, job_id):
        return self.wait_for(lambda: self.tasks.status(job_id, self.cfg),
                             lambda item: item["state"] not in self.tasks.ACTIVE)

    def test_rejects_unauthorized_invalid_presets_and_wrong_scope(self):
        with self.assertRaisesRegex(ValueError, "disabled"):
            self.tasks.start("python_build_check", {**self.cfg, "task_enabled": False})
        with self.assertRaisesRegex(ValueError, "presets"):
            self.tasks.start("arbitrary_shell", self.cfg)
        with self.assertRaisesRegex(ValueError, "within the workspace"):
            self.tasks.validate_scope(str(self.root), self.cfg)
        with self.assertRaisesRegex(ValueError, "workspace"):
            self.tasks.start("python_build_check", {**self.cfg, "workspace_enabled": False})
        self.assertEqual(self.tasks.listing(self.cfg)["jobs"], [])

    def test_real_approval_and_exit_codes(self):
        script = self.folder / "source.py"
        script.write_text("raise AssertionError('must compile without executing')\n", encoding="utf-8")
        job = self.start("python_build_check", "valid")
        key = job["job_id"]
        self.assertEqual(self.start("python_build_check", "valid")["job_id"], key)
        with self.assertRaisesRegex(ValueError, "another preset"):
            self.start("git_status", "valid")
        self.runner.pump(self.cfg)
        self.assertEqual(self.tasks.status(key, self.cfg)["state"], "awaiting_approval")
        self.assertIsNone(self.runner.thread)

        self.tasks.decide(key, self.cfg, True)
        result = self.terminal(key)
        self.assertEqual(result.get("state"), "succeeded", result)
        self.assertEqual(result["exit_code"], 0)
        self.assertIn("Python syntax OK: 1 files", result["stdout"])
        self.assertFalse((self.folder / "__pycache__").exists())

        script.write_text("def malformed(\n", encoding="utf-8")
        key = self.start("python_build_check")["job_id"]
        self.tasks.decide(key, self.cfg, True)
        result = self.terminal(key)
        self.assertEqual(result.get("state"), "failed", result)
        self.assertNotEqual(result.get("exit_code"), 0)
        self.assertIn("SyntaxError", result["stderr"])

    def test_denied_and_changed_policy_stay_unstarted(self):
        denied = self.start("python_build_check")["job_id"]
        self.tasks.decide(denied, self.cfg, False)
        self.assertEqual(self.terminal(denied)["state"], "rejected")
        self.assertIsNone(self.runner.thread)

        revoked = self.start("python_build_check")["job_id"]
        self.tasks.decide(revoked, self.cfg, True)
        current = {**self.cfg, "workspace_revision": "revoked"}
        self.core.save_json(self.core.CONFIG, current)
        current = self.core.load_config()
        with self.assertRaisesRegex(ValueError, "current authorization"):
            self.tasks.status(revoked, current)
        last = self.wait_for(lambda: self.core.read_json(self.tasks.QUEUE / (revoked + ".json")),
                             lambda item: item.get("state") == "revoked")
        self.assertEqual(last["state"], "revoked")
        self.assertIsNone(self.runner.thread)

    def test_git_status_and_both_diff_presets(self):
        git = self.tasks._git_binary()
        if not git:
            self.skipTest("Git CLI is not installed")
        tracked = self.folder / "value.py"
        tracked.write_text("VALUE = 1\n", encoding="utf-8")

        def setup_git(*args):
            subprocess.run([str(git), "-c", "core.hooksPath=NUL", "-c", "user.name=Test",
                            "-c", "user.email=test@example.invalid", "-c", "commit.gpgSign=false",
                            *args], check=True, cwd=self.folder, capture_output=True, timeout=10,
                           env=self.tasks._env(git))

        setup_git("init", "-q")
        setup_git("add", "value.py")
        setup_git("commit", "-qm", "test baseline")
        tracked.write_text("VALUE = 2\n", encoding="utf-8")
        setup_git("add", "value.py")
        tracked.write_text("VALUE = 3\n", encoding="utf-8")
        for preset, strings in (
            ("git_status", ("MM value.py",)),
            ("git_diff", ("-VALUE = 2", "+VALUE = 3")),
            ("git_diff_staged", ("-VALUE = 1", "+VALUE = 2")),
        ):
            with self.subTest(preset=preset):
                key = self.start(preset)["job_id"]
                self.tasks.decide(key, self.cfg, True)
                result = self.terminal(key)
                self.assertEqual(result.get("state"), "succeeded", result)
                self.assertEqual(result["exit_code"], 0)
                for expected in strings:
                    self.assertIn(expected, result["stdout"])

    def test_real_npm_test_and_build_in_project_scope(self):
        package = {"name": "test-dot-project-runner", "version": "1.0.0", "private": True,
                   "scripts": {"test": "node fixture.js test", "build": "node fixture.js build"}}
        (self.folder / "package.json").write_text(json.dumps(package), encoding="utf-8")
        (self.folder / "fixture.js").write_text(
            "const fs = require('node:fs');\n"
            "const operation = process.argv[2];\n"
            "if (operation === 'build') fs.writeFileSync('build-result.txt', 'local package output');\n"
            "console.log('local npm fixture: ' + operation);\n",
            encoding="utf-8",
        )
        try:
            self.tasks._command(self.folder, "npm_test")
        except ValueError as exc:
            if "not available" in str(exc):
                self.skipTest(str(exc))
            raise
        for operation in ("test", "build"):
            with self.subTest(operation=operation):
                key = self.start("npm_" + operation)["job_id"]
                self.tasks.decide(key, self.cfg, True)
                result = self.terminal(key)
                self.assertEqual(result.get("state"), "succeeded", result)
                self.assertEqual(result["exit_code"], 0)
                self.assertIn("local npm fixture: " + operation, result["stdout"])
        self.assertEqual((self.folder / "build-result.txt").read_text(encoding="utf-8"),
                         "local package output")

    def test_cancel_stops_a_real_grandchild(self):
        fixture = """import pathlib
import subprocess
import sys
import time
import unittest

class ProjectFixture(unittest.TestCase):
    def test_launch_sleeping_child(self):
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(18)'])
        pathlib.Path('child.pid').write_text(str(child.pid), encoding='ascii')
        time.sleep(18)
"""
        (self.folder / "test_fixture.py").write_text(fixture, encoding="utf-8")
        key = self.start("python_unittest")["job_id"]
        self.tasks.decide(key, self.cfg, True)
        marker = self.folder / "child.pid"

        def read_pid():
            if marker.is_file():
                raw = marker.read_text("ascii")
                return int(raw) if raw.isdecimal() else 0
            state = self.tasks.status(key, self.cfg)
            if state["state"] not in self.tasks.ACTIVE:
                self.fail(f"The fixture did not start a child: {state}")
            return 0

        pid = self.wait_for(read_pid, bool)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        child = None
        try:
            child = kernel.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
            self.assertTrue(child, f"Could not observe test child pid {pid}")
            self.assertEqual(kernel.WaitForSingleObject(child, 0), 258)  # WAIT_TIMEOUT, still running
            self.assertEqual(self.tasks.cancel(key, self.cfg)["state"], "cancelling")
            result = self.terminal(key)
            self.assertEqual(result["state"], "cancelled", result)
            self.assertEqual(kernel.WaitForSingleObject(child, 4000), 0)  # WAIT_OBJECT_0, child terminated
        finally:
            if child:
                kernel.CloseHandle(child)


if __name__ == "__main__":
    unittest.main()
