import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest


@unittest.skipUnless(os.name == "nt", "requires Windows workspaces and file publication")
class WorkspaceExtras(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        stage = Path(__file__).resolve().parents[1]
        cls.area = tempfile.TemporaryDirectory(prefix="dot-p2-test-", dir=stage.parent)
        cls.addClassCleanup(cls.area.cleanup)
        cls.path = Path(cls.area.name)
        # No test may read the production configuration or approval registry.
        os.environ["WINDOWS_WORKSPACE_MCP_STATE"] = str(cls.path / "state")
        sys.path.insert(0, str(stage / "runtime"))
        import core
        import workspace
        import workspace_extra
        cls.core, cls.workspace, cls.extra = core, workspace, workspace_extra
        cls.origin = "https://workspace.test.invalid"
        core.update_config(origin=cls.origin)
        core.configure_local_relay(cls.origin, ["https://client.example.invalid/oauth/redirect"])
        cls.sequence = 0

    def setUp(self):
        type(self).sequence += 1
        self.root = self.path / f"workspace-{self.sequence}"
        self.root.mkdir()
        self.config("full")
        self.gate = self.workspace.WorkspaceGate()

    def config(self, mode, revision="test-revision"):
        self.core.save_json(self.core.CONFIG, {
            **self.core.load_config(),
            "origin": self.origin, "workspace_root": str(self.root), "workspace_enabled": True,
            "approval_mode": mode, "workspace_revision": revision,
        })

    def call(self, op, **payload):
        return self.gate.handle({"operation": "workspace_" + op, "payload": payload})

    def approve(self, request):
        self.assertEqual(request.get("state"), "approval_required", request)
        key = request["request_id"]
        self.core.save_json(self.workspace.DECISIONS / (key + ".json"), {"decision": "allow"})
        return self.call("approval", request_id=key)

    def test_window_search_and_patch_after_legacy_limit(self):
        doc = self.root / "源代码.py"
        raw = b"\xef\xbb\xbf" + (b"# padding\r\n" * 1000) + b"old line\r\nanchor\r\n"
        doc.write_bytes(raw)
        page = self.call("read_lines", relative_path=doc.name, start_line=1001, line_count=1)
        self.assertEqual(page["lines"], [
            {"line": 1001, "column": 1, "text": "old line", "text_truncated": False, "line_ending": "\r\n"}
        ])
        self.assertEqual(page["next_start_line"], 1002)
        match = self.call("search_content", query="OLD LINE", extension=".py", max_depth=0)
        self.assertEqual([(x["name"], x["line"], x["column"]) for x in match["matches"]],
                         [(doc.name, 1001, 1)])
        self.assertEqual(self.call("search_content", query="OLD LINE", case_sensitive=True)["matches"], [])
        listing = self.call("list")
        self.assertIn("read_workspace_lines", listing["files"][0]["content_tools"])
        self.assertNotIn("read_workspace_file", listing["files"][0]["content_tools"])
        patch = self.call("patch", relative_path=doc.name, expected_sha256=page["sha256"],
                          replacements=[{"find": "old line\nanchor", "replace": "new line\nanchor"},
                                        {"find": "anchor", "replace": "замена"}])
        self.assertTrue(patch.get("backup_created"), patch)
        self.assertTrue(doc.read_bytes().startswith(b"\xef\xbb\xbf"))
        self.assertTrue(doc.read_bytes().endswith("new line\r\nзамена\r\n".encode()))
        self.assertTrue(any(item.read_bytes() == raw for item in self.workspace.BACKUPS.glob("*")))
        conflict = self.call("patch", relative_path=doc.name, expected_sha256=page["sha256"],
                             replacements=[{"find": "new line", "replace": "unexpected"}])
        self.assertIn("changed", conflict["error"])

    def test_patch_is_all_or_nothing_and_finds_overlaps(self):
        doc = self.root / "sample.txt"
        source = b"first\r\naaa\nthird\r"
        doc.write_bytes(source)
        result = self.call("patch", relative_path=doc.name,
                           expected_sha256=hashlib.sha256(source).hexdigest(),
                           replacements=[{"find": "first", "replace": "changed"},
                                         {"find": "aa", "replace": "no"}])
        self.assertIn("must match exactly once", result["error"])
        self.assertEqual(doc.read_bytes(), source)

    def test_approval_safe_folder_move_trash_restore_and_no_overwrite(self):
        self.assertTrue(self.call("create_folder", relative_path="source")["created"])
        self.assertTrue(self.call("create_folder", relative_path="target")["created"])
        source = self.root / "source"
        (source / "entry.bin").write_bytes(b"package")
        collision = self.call("move", relative_path="source", destination_path="target")
        self.assertIn("cannot overwrite", collision["error"])
        moved = self.approve(self.call("move", relative_path="source",
                                       destination_path="target/folder"))
        self.assertEqual(moved.get("state"), "executed", moved)
        self.assertFalse(source.exists())
        moved_path = self.root / "target" / "folder"
        self.assertEqual((moved_path / "entry.bin").read_bytes(), b"package")
        deleted = self.approve(self.call("trash", relative_path="target/folder"))
        self.assertEqual(deleted.get("state"), "executed", deleted)
        key = deleted["result"]["trash_id"]
        self.assertFalse(moved_path.exists())
        self.assertEqual(self.call("list_trash")["entries"][0]["trash_id"], key)
        moved_path.mkdir()
        self.assertIn("cannot overwrite", self.call("restore", trash_id=key)["error"])
        moved_path.rmdir()
        restored = self.approve(self.call("restore", trash_id=key))
        self.assertEqual(restored.get("state"), "executed", restored)
        self.assertEqual((moved_path / "entry.bin").read_bytes(), b"package")
        self.assertEqual(self.call("list_trash")["total"], 0)

    def test_reject_traversal_changed_target_and_revoked_approval(self):
        self.assertIn("allowed relative path", self.call("create_folder", relative_path="../escape")["error"])
        source = self.root / "source.txt"
        source.write_text("before", encoding="utf-8")
        request = self.call("trash", relative_path=source.name)
        source.write_text("after changing size", encoding="utf-8")
        result = self.approve(request)
        self.assertEqual(result.get("state"), "failed", result)
        self.assertIn("changed", result["error"])
        self.assertTrue(source.exists())
        request = self.call("move", relative_path=source.name, destination_path="dest.txt")
        self.config("full", revision="revoked")
        self.assertEqual(self.approve(request)["state"], "unknown_or_expired")
        self.assertTrue(source.exists())

    def test_pending_workflow_and_output_budget(self):
        self.config("rules")
        self.assertEqual(self.call("create_folder", relative_path="later")["state"], "approval_required")
        data = self.root / "large.txt"
        data.write_text(("ж" * 3000 + "\n") * 200, encoding="utf-8")
        result = self.call("read_lines", relative_path=data.name, line_count=200)
        self.assertEqual((result["next_start_line"], result["next_start_column"]), (1, 2401))
        self.assertTrue(result["lines"][0]["text_truncated"])
        more = self.call("read_lines", relative_path=data.name, line_count=1,
                         start_line=result["next_start_line"], start_column=result["next_start_column"])
        self.assertEqual(result["lines"][0]["text"] + more["lines"][0]["text"], "ж" * 3000)
        self.assertEqual((more["next_start_line"], more["next_start_column"]), (2, 1))
        self.config("ask")
        self.assertEqual(self.call("search_content", query="ж")["state"], "approval_required")

    def test_no_hardlink_access_via_file_management(self):
        outside = self.path / "outside.txt"
        outside.write_text("private value", encoding="utf-8")
        inside = self.root / "linked.txt"
        os.link(outside, inside)
        self.assertIn("hard links", self.call("trash", relative_path=inside.name)["error"])
        self.assertIn("hard links", self.call("read_lines", relative_path=inside.name)["error"])
        self.assertEqual(self.call("search_content", query="private value")["matches"], [])
        self.assertTrue(outside.is_file())


if __name__ == "__main__":
    unittest.main()
