"""Focused recipe registry, approval and revocation checks."""
from __future__ import annotations

from contextlib import ExitStack
import os
from pathlib import Path
import subprocess  # preload before the non-Windows fixture shim
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import zipfile

PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE / "runtime"))
if os.name != "nt" and "msvcrt" not in sys.modules:
    sys.modules["msvcrt"] = types.SimpleNamespace()


class RecipeTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="DotRecipeCheck-", dir=PACKAGE.parent)
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        if "core" not in sys.modules:
            os.environ["WINDOWS_WORKSPACE_MCP_STATE"] = str(self.base / "state")
        import task_recipes
        self.recipes = task_recipes
        mock = patch.object(task_recipes, "REGISTRY", self.base / "recipes.json")
        mock.start()
        self.addCleanup(mock.stop)

    def test_register_reload_and_remove(self):
        r = self.recipes
        self.assertEqual(["inspect-zip", "python-check-test", "npm-test-build"], [item["id"] for item in r.listing()])
        recipe = r.register(r.TEMPLATES["校验 ZIP 后解包"])
        self.assertEqual(recipe, r.get(recipe["id"]))
        self.assertTrue(r.writes(recipe))
        self.assertEqual(r.arguments(recipe, {"destination_path": "result"}), {"destination_path": "result"})
        self.assertEqual(r.revision(recipe), r.revision(r.get(recipe["id"])))
        r.remove(recipe["id"])
        self.assertIsNone(r.get(recipe["id"]))

    def test_rejects_unknown_actions_and_puts_writes_last(self):
        r = self.recipes
        for steps in ([{"preset": "powershell"}], [{"preset": "zip_extract"}, {"preset": "file_sha256"}],
                      [{"preset": "directory_inventory"}], [{"preset": "copy_file", "parameters": {"destination_path": "../elsewhere"}}]):
            with self.assertRaises(ValueError):
                r.normalize({**r.EXAMPLE, "steps": steps})

    def test_workspace_policy_for_recipes(self):
        import project_tasks as tasks
        r = self.recipes
        write = r.normalize(r.TEMPLATES["校验 ZIP 后解包"])
        for mode, read_ok, write_ok in [("ask", False, False), ("rules", True, False), ("full", True, True)]:
            cfg = {"workspace_unified": True, "approval_mode": mode}
            self.assertEqual(tasks._automatic(None, cfg, r.EXAMPLE), read_ok)
            self.assertEqual(tasks._automatic(None, cfg, write), write_ok)

    def test_project_recipes_preserve_step_approval_and_disallow_command_arguments(self):
        import project_tasks as tasks
        r = self.recipes
        cfg = {"workspace_unified": True, "approval_mode": "full"}
        for name in ("npm 测试后构建", "Python 语法检查后测试"):
            recipe = r.normalize(r.TEMPLATES[name])
            self.assertTrue(r.writes(recipe))
            self.assertFalse(tasks._automatic(None, cfg, recipe))
            self.assertFalse(r.can_choose_destination(recipe))
            with self.assertRaises(ValueError):
                r.arguments(recipe, {"command": "user supplied"})
        with self.assertRaises(ValueError):
            r.normalize({**r.TEMPLATES["npm 测试后构建"],
                         "steps": [{"preset": "npm_test", "parameters": {"arguments": ["not-accepted"]}}]})
        syntax = r.normalize({"id": "syntax-only", "label": "Syntax", "target": "directory",
                              "steps": [{"preset": "python_build_check"}]})
        self.assertTrue(tasks._automatic(None, cfg, syntax))

    def test_changed_recipe_revokes_queued_write(self):
        import core, project_tasks as tasks, unified_workspace
        r = self.recipes
        root = self.base / "workspace"
        root.mkdir()
        with zipfile.ZipFile(root / "example.zip", "w") as bundle:
            bundle.writestr("note.txt", "fixture")
        queue = self.base / "jobs"
        config = self.base / "config.json"
        state = self.base / "state"
        funnel = state / "funnel"
        endpoint = funnel / "endpoint.json"
        with ExitStack() as scope:
            for change in (patch.multiple(core, STATE=state, CONFIG=config, FUNNEL=funnel, FUNNEL_SETTINGS=endpoint),
                           patch.object(tasks, "QUEUE", queue)):
                scope.enter_context(change)
            if os.name != "nt":
                # Revocation is exercised against a synthetic directory; no
                # actual Win32 drive or file execution claims in this test.
                scope.enter_context(patch.object(tasks, "workspace_root", side_effect=Path))
                scope.enter_context(patch.object(unified_workspace, "workspace_root", side_effect=Path))
            origin = "https://synthetic-recipe.invalid"
            core.configure_local_relay(origin, ["https://client.example.invalid/oauth/callback"])
            core.update_config(origin=origin)
            cfg = unified_workspace.grant(str(root), "full")
            item = r.register(r.TEMPLATES["校验 ZIP 后解包"])
            created = tasks.start("recipe:" + item["id"], cfg, relative_dir="example.zip")
            self.assertEqual(created["state"], "queued")
            r.register({**item, "label": "An edited recipe"})
            tasks.Runner().pump(cfg)
            self.assertEqual(tasks.status(created["job_id"], cfg)["state"], "revoked")
        self.assertFalse((root / "example-extracted").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
