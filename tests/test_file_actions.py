"""Windows file actions: publication, collision, cancellation, and recovery."""
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid
import zipfile

PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE / "runtime"))


@unittest.skipUnless(os.name == "nt", "requires Windows file publication")
class FileActionTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix="DotFileActions-", dir=PACKAGE.parent)
        self.addCleanup(scratch.cleanup)
        self.base = Path(scratch.name).resolve()
        self.root = self.base / "workspace"
        self.root.mkdir()
        if "core" not in sys.modules:
            os.environ["WINDOWS_WORKSPACE_MCP_STATE"] = str(self.base / "state")
        import task_files
        import task_verification
        self.actions, self.verify = task_files, task_verification

    def job(self, preset, source, destination):
        item = {"preset": preset, "job_id": uuid.uuid4().hex,
                "destination_path": destination.relative_to(self.root).as_posix()}
        if source.is_file():
            item["file_stamp"] = self.verify.stamp(source.stat())
        return item

    def execute(self, preset, source, destination, checkpoint=lambda *_args, **_kw: None):
        item = self.job(preset, source, destination)
        return self.actions.execute(self.root, source, item, checkpoint, lambda _: None)

    def assert_clean(self):
        self.assertFalse(list(self.root.rglob(".dot-action-*")))

    def test_copy_file_keeps_content_and_refuses_collision(self):
        source = self.root / "input.bin"
        source.write_bytes(b"data\x00test")
        target = self.root / "new.bin"
        result = self.execute("copy_file", source, target)
        self.assertEqual(result["size_bytes"], len(source.read_bytes()))
        self.assertEqual(source.read_bytes(), target.read_bytes())
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.execute("copy_file", source, target)
        self.assert_clean()

    def test_directory_copy_keeps_tree_and_counts_exclusions(self):
        source = self.root / "release"
        (source / "nested" / "empty").mkdir(parents=True)
        (source / "nested" / "file.bin").write_bytes(b"contents")
        (source / "private.key").write_bytes(b"protected fixture")
        target = self.root / "release-copy"
        result = self.execute("copy_directory", source, target)
        self.assertEqual((result["files"], result["directories"], result["excluded_entries"]), (1, 2, 1))
        self.assertTrue((target / "nested" / "empty").is_dir())
        self.assertEqual((target / "nested" / "file.bin").read_bytes(), b"contents")
        self.assertFalse((target / "private.key").exists())
        self.assert_clean()

    def test_extract_zip_and_reject_protected_or_conflicting_names(self):
        source = self.root / "payload.zip"
        target = self.root / "new-folder"
        with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_DEFLATED) as z:
            z.mkdir("empty")
            z.writestr("nested/payload.exe", b"opaque data")
        result = self.execute("zip_extract", source, target)
        self.assertEqual((result["files"], result["directories"], result["crc_verified"]), (1, 2, True))
        self.assertTrue((target / "empty").is_dir())
        self.assertEqual((target / "nested" / "payload.exe").read_bytes(), b"opaque data")
        for number, names in enumerate((("a.txt", "private.pfx"), ("a.txt", "A.txt"), ("a.txt", "../outside.invalid"))):
            with zipfile.ZipFile(source, "w") as z:
                for name in names:
                    z.writestr(name, b"fixture")
            rejected = self.root / f"reject-{number}"
            with self.assertRaises(ValueError):
                self.execute("zip_extract", source, rejected)
            self.assertFalse(rejected.exists())
            self.assertFalse((self.root / "outside.invalid").exists())
        self.assert_clean()

    def test_cancel_and_late_collision_do_not_publish_partial_output(self):
        source = self.root / "blob.bin"
        source.write_bytes(b"test" * 100)
        target = self.root / "target.bin"

        def cancel(*args, force=False):
            if force:
                raise InterruptedError("cancelled by fixture")
        with self.assertRaises(InterruptedError):
            self.execute("copy_file", source, target, cancel)
        self.assertFalse(target.exists())

        def collide(*args, force=False):
            if force:
                target.write_bytes(b"existing")
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.execute("copy_file", source, target, collide)
        self.assertEqual(target.read_bytes(), b"existing")
        self.assert_clean()

    def test_recovery_distinguishes_staged_from_published(self):
        source = self.root / "file.txt"
        source.write_text("data", encoding="utf-8")
        for committed in (False, True):
            target = self.root / f"out-{committed}.txt"
            job = self.job("copy_file", source, target)
            stage = self.actions._stage_path(target, job["job_id"])
            stage.mkdir()
            content = stage / "content"
            content.write_text("data", encoding="utf-8")
            job["publication"] = {"stage_id": self.actions._identifier(stage, True), "phase": "publishing",
                                  "output_id": self.actions._identifier(content, False), "directory": False,
                                  "result": {"destination_path": target.name, "size_bytes": 4}}
            if committed:
                os.rename(content, target)
            self.assertEqual(self.actions.recover(self.root, job),
                             job["publication"]["result"] if committed else None)
            self.assertEqual(target.exists(), committed)
            self.assert_clean()

    def test_destination_policy_and_atomic_state_retry(self):
        import project_tasks
        folder = self.root / "source"
        folder.mkdir()
        with self.assertRaises(ValueError):
            self.actions.destination(self.root, folder, "copy_directory", {"destination_path": "source/nested"})
        with self.assertRaises(ValueError):
            self.actions.destination(self.root, folder, "copy_directory", {"destination_path": "../elsewhere"})
        cfg = {"workspace_unified": True, "approval_mode": "rules"}
        self.assertFalse(project_tasks._automatic("zip_extract", cfg))
        self.assertTrue(project_tasks._automatic("zip_extract", {**cfg, "approval_mode": "full"}))
        queue = self.base / "jobs"
        queue.mkdir()
        item = self.job("copy_directory", folder, self.root / "result")
        saved = project_tasks.core.save_json
        attempts = 0

        def bounce_then_save(path, contents):
            nonlocal attempts
            attempts += 1
            if attempts <= 2:
                raise PermissionError("simulated short Windows sharing violation")
            return saved(path, contents)

        with patch.object(project_tasks, "QUEUE", queue), patch.object(project_tasks.core, "save_json", bounce_then_save):
            project_tasks._write(item)
            self.assertEqual(project_tasks._load_job(project_tasks._path(item["job_id"])), item)
        self.assertEqual(attempts, 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
