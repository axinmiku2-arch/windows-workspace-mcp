"""Offline checks for the fixed launcher; no process or network action is executed."""

from pathlib import Path, PureWindowsPath
import hashlib
import io
import os
import subprocess  # preload before the narrow Windows-module compatibility stub
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch
import time

root = tempfile.TemporaryDirectory(prefix="portable-task-safety-")
os.environ["WINDOWS_WORKSPACE_MCP_STATE"] = root.name
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
if os.name != "nt" and "msvcrt" not in sys.modules:
    sys.modules["msvcrt"] = types.SimpleNamespace()

import core
import project_tasks as tasks
import workspace


class PortableSafety(unittest.TestCase):
    def test_unknown_command_never_falls_into_a_known_executable(self):
        for unknown in ("cmd", "powershell", "npm_install", "git_other", "python_eval", "windows_ping"):
            with self.subTest(unknown=unknown), self.assertRaisesRegex(ValueError, "fixed Windows project command"):
                tasks._command(Path("."), unknown)

    def test_hard_approval_rechecked_at_worker_launch(self):
        full = {**core.DEFAULT, "workspace_enabled": True, "task_enabled": True,
                "workspace_unified": True, "approval_mode": "full"}
        for name, spec in tasks.PROJECT_PRESETS.items():
            if not spec["approval"]:
                continue
            with self.subTest(name=name), patch.object(core, "load_config", return_value=full), \
                    patch.object(tasks, "_signal_exists", return_value=False), \
                    patch.object(tasks.subprocess, "Popen", side_effect=AssertionError("must not launch")) as popen:
                state, _ = tasks._run({"preset": name, "job_id": "e" * 32, "policy": tasks._policy(full)}, Path("."))
                self.assertEqual(state, "rejected")
                self.assertFalse(tasks._automatic(name, full))
                popen.assert_not_called()

    def test_git_fixed_environment_does_not_inherit_or_enable_remote_fetch(self):
        with patch.dict(os.environ, {"GIT_ALLOW_PROTOCOL": "https", "EXAMPLE_TOKEN": "synthetic"}), \
                patch.object(tasks, "_git_binary", return_value=None):
            env = tasks._env(Path("git.exe"))
        self.assertEqual(env["GIT_NO_LAZY_FETCH"], "1")
        self.assertEqual(env["GIT_ALLOW_PROTOCOL"], "")
        self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")
        self.assertNotIn("EXAMPLE_TOKEN", env)

    def test_manifest_pinned_for_direct_npm_and_named_recipe(self):
        folder = Path(root.name)
        manifest = folder / "package.json"
        body = b'{" scripts " : {}}\n'
        manifest.write_bytes(body)
        cfg = {**core.DEFAULT, "workspace_enabled": True, "task_enabled": True,
               "workspace_unified": True, "approval_mode": "full"}
        with patch.object(tasks, "_base", return_value=folder), patch.object(tasks, "_scope", return_value=folder):
            direct = tasks._arguments("npm_test", cfg, ".", None, {})
            recipe = tasks._recipe_arguments(tasks.task_recipes.TEMPLATES["npm 测试后构建"]
                    | {"steps": [{"preset": "npm_test", "parameters": {}}, {"preset": "npm_build", "parameters": {}}]},
                    cfg, ".", None, {})
        expected = hashlib.sha256(body).hexdigest()
        self.assertEqual(direct["npm_manifest_sha256"], expected)
        self.assertEqual(recipe["npm_manifest_sha256"], expected)
        self.assertTrue(direct["runs_project_code"])
        self.assertTrue(recipe["runs_project_code"])

    def test_npm_manifest_change_never_releases_actual_process_handshake(self):
        cfg = {**core.DEFAULT, "workspace_enabled": True, "task_enabled": True, "workspace_unified": True}
        item = {"preset": "npm_test", "job_id": "a" * 32, "policy": tasks._policy(cfg),
                "npm_manifest_sha256": "b" * 64}
        fake = Mock(stdout=io.BytesIO(), stderr=io.BytesIO(), stdin=Mock(closed=False))
        fake.poll.return_value = 0
        with patch.object(core, "load_config", return_value=cfg), \
                patch.object(tasks, "_signal_exists", side_effect=lambda _, signal: signal == "approve"), \
                patch.object(tasks, "_command", return_value=["fake-node.exe"]), \
                patch.object(tasks, "_env", return_value={}), \
                patch.object(tasks, "_windows_job"), \
                patch.object(tasks, "_npm_manifest_digest", return_value="c" * 64), \
                patch.object(tasks.subprocess, "Popen", return_value=fake):
            with self.assertRaisesRegex(ValueError, "request again for approval"):
                tasks._run(item, Path(root.name))
        fake.stdin.write.assert_not_called()

    def test_mapped_drive_is_rejected_even_if_scope_names_a_subfolder(self):
        # The drive guard precedes host filesystem access.
        if os.name == "nt":
            parser = Path
        else:
            class EmulatedPath(PureWindowsPath):
                @classmethod
                def home(cls):
                    return cls(r"C:\Users\Example")
            parser = EmulatedPath
        with patch.object(workspace, "Path", parser), patch.object(workspace, "protected_path", return_value=False), \
                patch.object(workspace, "local_drives", return_value=[r"C:" + "\\"]), \
                patch.object(workspace, "no_link", side_effect=AssertionError("there must be no mapped-drive access")):
            with self.assertRaisesRegex(ValueError, "不支持映射的网络盘"):
                workspace.workspace_root(r"Z:\Examples\nested")


if __name__ == "__main__":
    unittest.main(verbosity=2)
