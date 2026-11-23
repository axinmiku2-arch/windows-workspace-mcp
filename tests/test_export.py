"""Optional Windows integration tests for the original-download storage layer."""
from pathlib import Path
import hashlib
import logging
import json
import os
import runpy
import sys
import tempfile
import time
import unittest
from urllib.parse import urlsplit

PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE / "runtime"))
_fixture = tempfile.TemporaryDirectory(prefix="DotExportTesting-", dir=PACKAGE.parent)
FIXTURE = Path(_fixture.name)
os.environ["WINDOWS_WORKSPACE_MCP_STATE"] = str(FIXTURE / "state")

import core
if os.name == "nt":
    import file_bridge as bridge

CALLBACK = "https://client.example.invalid/oauth/redirect"


@unittest.skipUnless(os.name == "nt", "requires Windows snapshot locking")
class ExportTest(unittest.TestCase):
    def _relay_client(self, origin):
        from starlette.testclient import TestClient
        relay = FIXTURE / "relay"
        relay.mkdir()
        (relay / "probe_key").write_text("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", encoding="ascii")
        (relay / "worker_key").write_text("0" * 64, encoding="ascii")
        os.environ.pop("STATE_DIRECTORY", None)
        os.environ.update(PROBE_ORIGIN=origin, CREDENTIALS_DIRECTORY=str(relay),
                          RUNTIME_DIRECTORY=str(relay), PROBE_WORKSPACE="1", PROBE_PORT="18773",
                          PROBE_PRIVATE_WORKER_PORT="18774", PROBE_OAUTH_CALLBACKS_JSON=json.dumps([CALLBACK]))
        module = runpy.run_path(str(PACKAGE / "vps" / "probe.py"))
        logging.getLogger("httpx").setLevel(logging.WARNING)
        return TestClient(module["app_with_trace"], base_url=origin, client=("127.0.0.1", 12345))

    def _range(self, client, path, start, end, etag, size):
        response = client.get(path, headers={"Range": f"bytes={start}-{end}", "If-Range": etag})
        self.assertEqual(response.status_code, 206, response.headers)
        self.assertEqual(response.headers["Content-Range"], f"bytes {start}-{end}/{size}")
        self.assertEqual(response.headers["ETag"], etag)
        self.assertEqual(len(response.content), end - start + 1)
        return response.content

    def test_background_resume_revocation_and_legacy(self):
        self.assertEqual(core.STATE, FIXTURE / "state", "Run this suite in a fresh Python process")
        workspace = FIXTURE / "workspace"
        docs = workspace / "documents"
        docs.mkdir(parents=True)
        origin = "https://example-export.test:18773"
        core.update_config(origin=origin)
        core.configure_local_relay(origin, [CALLBACK])
        cfg = dict(core.load_config(), origin=origin, workspace_root=str(workspace), workspace_enabled=True,
                   workspace_revision="workspace-1", approval_mode="full", documents_enabled=True,
                   document_scope=str(docs), document_revision="documents-1", transfer_max_mb=100)
        core.save_json(core.CONFIG, cfg)

        other = workspace / "not-authorized.zip"
        other.write_bytes(b"scope")
        with self.assertRaisesRegex(ValueError, "outside the authorized document folder"):
            bridge.begin_export(other, cfg)

        too_large = docs / "over-limit.zip"
        with too_large.open("wb") as handle:
            handle.truncate(100_000_001)
        with self.assertRaisesRegex(ValueError, "100,000,000-byte"):
            bridge.begin_export(too_large, cfg)
        too_large.unlink()

        item = docs / "boundary.zip"
        expected = hashlib.sha256()
        block = bytes(range(256)) * 3906
        with item.open("wb") as handle:
            left = 100_000_000
            while left:
                chunk = block[:left]
                handle.write(chunk)
                expected.update(chunk)
                left -= len(chunk)
        expected = expected.hexdigest()
        queued = bridge.begin_export(item, cfg)
        self.assertEqual(queued["state"], "queued")
        job_id = queued["job_id"]
        meta_path, interrupted, _ = bridge._job_paths(job_id)
        # Simulate worker shutdown between writes: next pump starts that job again.
        saved = core.read_json(meta_path)
        core.save_json(meta_path, dict(saved, state="copying", prepared_bytes=123))
        interrupted.write_bytes(b"partial")
        self.assertEqual(bridge.export_status(job_id, cfg)["prepared_bytes"], 123)
        bridge.pump_exports(cfg)
        if bridge._runner is not None:
            bridge._runner.join(timeout=15)
            self.assertFalse(bridge._runner.is_alive())
        result = bridge.export_status(job_id, cfg)
        self.assertEqual(result["state"], "ready", result)
        self.assertEqual(result["progress_percent"], 100)
        self.assertEqual(result["sha256"], expected)
        self.assertFalse(interrupted.exists())

        old_token = urlsplit(result["download_url"]).path.rsplit("/", 1)[1]
        original, response = bridge.ready_download(old_token)
        with original.open("rb") as handle:
            handle.seek(90_000_000)
            self.assertEqual(len(handle.read()), 10_000_000)
        self.assertEqual(response["sha256"], expected)
        self.assertEqual(bridge.export_status(job_id, cfg, renew=True)["download_url"], result["download_url"])

        relay = resumed = None
        if os.environ.get("WINDOWS_WORKSPACE_MCP_EXPORT_TEST_HTTP") == "1":
            relay = self._relay_client(origin)
            self.addCleanup(relay.close)
            path = urlsplit(result["download_url"]).path
            etag = '"' + expected + '"'
            head = relay.head(path)
            self.assertEqual(head.status_code, 200)
            self.assertEqual(head.headers["Content-Length"], "100000000")
            self.assertEqual(head.headers["ETag"], etag)
            self.assertEqual(head.headers["Accept-Ranges"], "bytes")
            self.assertEqual(relay.get(path, headers={"Range": "bytes=0-3,8-12"}).status_code, 416)
            resumed = hashlib.sha256(self._range(relay, path, 0, 9_999_999, etag, 100_000_000))

        record = core.read_json(meta_path)
        core.save_json(meta_path, dict(record, link_expires_at=time.time() - 1))
        link_path, _ = bridge.files(old_token)
        core.save_json(link_path, dict(core.read_json(link_path), expires=time.time() - 1))
        self.assertIsNone(bridge.ready_download(old_token))
        self.assertTrue(bridge.export_status(job_id, cfg)["renew_available"])
        renewed = bridge.export_status(job_id, cfg, renew=True)
        rotated_token = urlsplit(renewed["download_url"]).path.rsplit("/", 1)[1]
        self.assertNotEqual(old_token, rotated_token)
        self.assertEqual(bridge.ready_download(rotated_token)[0], original)
        self.assertEqual(renewed["sha256"], expected)

        if relay is not None:
            self.assertEqual(relay.get(path).status_code, 404)
            new_path = urlsplit(renewed["download_url"]).path
            for start in range(10_000_000, 100_000_000, 10_000_000):
                resumed.update(self._range(relay, new_path, start, start + 9_999_999, etag, 100_000_000))
            self.assertEqual(resumed.hexdigest(), expected)

        small = docs / "small.txt"
        small.write_bytes(b"tiny")
        legacy = bridge.snapshot(small, cfg)
        legacy_token = urlsplit(legacy["download_url"]).path.rsplit("/", 1)[1]
        self.assertEqual(bridge.ready_download(legacy_token)[0].read_bytes(), b"tiny")
        cancelled = bridge.begin_export(small, cfg)
        self.assertEqual(bridge.cancel_export(cancelled["job_id"], cfg)["state"], "cancelled")

        small_job = bridge.begin_export(small, cfg)["job_id"]
        bridge.pump_exports(cfg)
        bridge._runner.join(timeout=15)
        small_result = bridge.export_status(small_job, cfg)
        small_token = urlsplit(small_result["download_url"]).path.rsplit("/", 1)[1]
        with self.assertRaisesRegex(ValueError, "does not match"):
            bridge.complete_export(small_job, cfg, "0" * 64)
        self.assertEqual(bridge.complete_export(small_job, cfg, small_result["sha256"])["state"], "delivered")
        self.assertEqual(bridge.complete_export(small_job, cfg, small_result["sha256"])["progress_percent"], 100)
        self.assertIsNone(bridge.ready_download(small_token))

        cfg["document_revision"] = "documents-2"
        core.save_json(core.CONFIG, cfg)
        self.assertIsNone(bridge.ready_download(legacy_token))
        self.assertIsNone(bridge.ready_download(rotated_token))
        self.assertEqual(bridge.export_status(job_id, cfg)["state"], "revoked")


if __name__ == "__main__":
    unittest.main(verbosity=2)
