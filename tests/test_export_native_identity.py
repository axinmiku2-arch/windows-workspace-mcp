"""Synthetic tests for the actual export handle and its queued identity."""

import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
import file_bridge as bridge


class SourceIdentityTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name) / "fixtures"
        self.root.mkdir()
        self.source = self.root / "source.zip"
        self.output = self.root / "exported.bin"
        self.payload = b"local synthetic content" * 2048
        self.source.write_bytes(self.payload)

    def copy(self, stamp):
        return bridge._snapshot_copy(self.source, self.output, stamp, len(self.payload), lambda _size: None)

    def test_unchanged_original_matches_across_native_handles(self):
        queued = bridge._source_stamp(self.source)
        with bridge._open_original(self.source) as (_original, opened):
            self.assertEqual(opened, queued)
            self.assertEqual(queued[2], len(self.payload))
            if os.name == "nt":
                self.assertRegex(queued[1], r"^[0-9a-f]{32}$")
        self.assertEqual(self.copy(queued), hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(self.output.read_bytes(), self.payload)

    def test_replaced_file_is_not_accepted_even_with_same_size_and_mtime(self):
        queued = bridge._source_stamp(self.source)
        meta = self.source.stat()
        self.source.rename(self.root / "still-held-original.zip")
        self.source.write_bytes(b"!" * len(self.payload))
        os.utime(self.source, ns=(meta.st_atime_ns, meta.st_mtime_ns))
        with self.assertRaisesRegex(ValueError, "since submission"):
            self.copy(queued)
        self.assertFalse(self.output.exists())

    def test_reopened_path_check_detects_post_read_swap(self):
        queued = bridge._source_stamp(self.source)
        native_stamp = bridge._source_stamp_guarded

        def replace_after_copy(path):
            self.source.rename(self.root / "moved-after-read.zip")
            self.source.write_bytes(b"?" * len(self.payload))
            return native_stamp(path)

        with patch("file_bridge._source_stamp_guarded", side_effect=replace_after_copy):
            with self.assertRaisesRegex(ValueError, "was replaced during copy"):
                self.copy(queued)

    def test_archive_member_uses_same_checked_metadata(self):
        directory = self.root / "one-directory"
        directory.mkdir()
        self.source.rename(directory / self.source.name)
        info = directory.lstat()
        record = {"bytes": 1_000_000, "directory_id": [info.st_dev, info.st_ino]}
        size, digest, included, excluded = bridge._archive_copy(directory, self.output, record, lambda _size: None)
        self.assertEqual((size, digest, included, excluded),
                         (self.output.stat().st_size, hashlib.sha256(self.output.read_bytes()).hexdigest(), 1, 0))
        with zipfile.ZipFile(self.output) as archive:
            self.assertEqual(archive.read(f"{directory.name}/{self.source.name}"), self.payload)

    def test_hardlinks_rejected(self):
        try:
            os.link(self.source, self.root / "another-link.zip")
        except OSError as exc:
            self.skipTest(f"Hard links not supported by the test volume ({exc.__class__.__name__})")
        with self.assertRaisesRegex(ValueError, "without links"):
            bridge._source_stamp(self.source)

    @unittest.skipUnless(os.name == "nt", "Win32 file sharing semantics")
    def test_source_handle_denies_concurrent_writes_and_rename(self):
        with bridge._open_original(self.source):
            with self.assertRaises(OSError):
                with self.source.open("r+b"):
                    pass
            with self.assertRaises(OSError):
                self.source.rename(self.root / "cannot-rename-while-pinned.zip")


if __name__ == "__main__":
    unittest.main(verbosity=2)
