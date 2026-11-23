"""Offline tests for the cloud export receiver; all HTTP responses are synthetic."""
from email.message import Message
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import urllib.error
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cloud"))
from resume_export import ExportError, Metrics, Snapshot, receive  # noqa: E402

DATA = b"12345678901234567890"
HASH = sha256(DATA).hexdigest()
JOB = "a" * 32
CAP1 = "https://helper.example.test/dot-files/" + "X" * 43
CAP2 = "https://helper.example.test/dot-files/" + "Y" * 43


def status(url=CAP1, digest=HASH, job=JOB, payload=DATA):
    return {"state": "ready", "job_id": job, "bytes": len(payload), "sha256": digest, "download_url": url}


class Reply(io.BytesIO):
    def __init__(self, data, headers, code=206):
        super().__init__(data)
        self.headers = Message()
        for key, value in headers.items():
            self.headers[key] = value
        self.code = code

    def getcode(self):
        return self.code


class Synthetic:
    def __init__(self, faults=None, data=DATA, digest=HASH):
        self.calls = []
        self.faults = faults or {}
        self.data = data
        self.digest = digest

    def open(self, request, timeout):
        assert request.method == "GET" and timeout > 0
        match = re.fullmatch(r"bytes=(\d+)-(\d+)", request.get_header("Range"))
        assert match is not None and request.get_header("If-range") == f'"{self.digest}"'
        start, end = map(int, match.groups())
        self.calls.append((request.full_url, start, end))
        bad = self.faults.get(len(self.calls))
        if isinstance(bad, int) and bad != 200:
            raise urllib.error.HTTPError(request.full_url, bad, request.full_url, Message(), None)
        data = self.data[start:end + 1]
        headers = {"Content-Range": f"bytes {start}-{end}/{len(self.data)}", "Content-Length": str(len(data)),
                   "ETag": f'"{self.digest}"', "X-File-SHA256": self.digest}
        if bad == "short":
            data = data[:-1]
        elif bad == "wrong_range":
            headers["Content-Range"] = f"bytes 0-{end}/{len(self.data)}"
        elif bad == "wrong_etag":
            headers["ETag"] = '"' + "9" * 64 + '"'
        elif bad == "wrong_header_hash":
            headers["X-File-SHA256"] = "9" * 64
        elif bad == "corrupt":
            data = b"X" + data[1:]
        return Reply(data, headers, 200 if bad == 200 else 206)


class UpgradeTransport(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.dest = self.folder / "sample.bin"
        self.partial = self.folder / "sample.bin.part"
        self.record = self.folder / "sample.bin.resume.json"
        self.addCleanup(self.temp.cleanup)

    def recv(self, synthetic, data=None, **kwargs):
        return receive(data or status(), self.dest, segment_bytes=8, retries_per_segment=0,
                       opener=synthetic.open, **kwargs)

    def test_exact_segments_and_final_digest(self):
        mock = Synthetic()
        progress = []
        rec = self.recv(mock, progress=progress.append)
        self.assertEqual(rec["state"], "verified")
        self.assertEqual(rec["sha256"], HASH)
        self.assertEqual(self.dest.read_bytes(), DATA)
        self.assertFalse(self.record.exists())
        self.assertFalse(self.partial.exists())
        self.assertEqual([c[1:] for c in mock.calls], [(0, 7), (8, 15), (16, 19)])
        self.assertEqual([p["verified_range_end"] for p in progress], [8, 16, 20])
        self.assertEqual(rec["metrics"]["downloaded_bytes"], 20)

    def test_interruption_does_not_commit_partial_segment_and_restarts(self):
        with self.assertRaisesRegex(ExportError, "complete range"):
            self.recv(Synthetic({2: "short"}))
        self.assertEqual(self.partial.read_bytes(), DATA[:8])
        self.assertNotIn(CAP1, self.record.read_text())
        mock = Synthetic()
        rec = self.recv(mock, status(CAP2))
        self.assertEqual([c[1] for c in mock.calls], [8, 16])
        self.assertEqual(rec["metrics"]["resumed_bytes"], 8)
        self.assertEqual(self.dest.read_bytes(), DATA)

    def test_retry_transient_without_duplication(self):
        mock = Synthetic({2: 503})
        with patch("resume_export.time.sleep"):
            rec = receive(status(), self.dest, segment_bytes=8, retries_per_segment=1, opener=mock.open)
        self.assertEqual([c[1] for c in mock.calls], [0, 8, 8, 16])
        self.assertEqual(rec["metrics"]["retries"], 1)
        self.assertEqual(self.dest.read_bytes(), DATA)

    def test_renew_keeps_same_snapshot(self):
        mock = Synthetic({2: 404})
        called = []
        def renew(job):
            called.append(job)
            return status(CAP2)
        rec = self.recv(mock, renew=renew)
        self.assertEqual(called, [JOB])
        self.assertEqual([c[:2] for c in mock.calls], [(CAP1, 0), (CAP1, 8), (CAP2, 8), (CAP2, 16)])
        self.assertEqual(rec["metrics"]["renewals"], 1)
        self.assertEqual(self.dest.read_bytes(), DATA)

    def test_expired_link_without_callback_is_safe(self):
        with self.assertRaises(ExportError) as err:
            self.recv(Synthetic({2: 404}))
        self.assertEqual(err.exception.code, "link_unavailable")
        self.assertNotIn(CAP1, str(err.exception))
        self.assertEqual(self.partial.read_bytes(), DATA[:8])

    def test_revoked_snapshot_does_not_retry(self):
        mock = Synthetic({2: 410})
        with self.assertRaises(ExportError) as err:
            self.recv(mock, renew=lambda _job: {"state": "revoked"})
        self.assertEqual(err.exception.code, "snapshot_not_available")
        self.assertEqual(len(mock.calls), 2)
        self.assertEqual(self.partial.read_bytes(), DATA[:8])

    def test_renewal_cannot_change_sha_job_or_origin(self):
        for i, new in enumerate((
            status(CAP2, digest="b" * 64), status(CAP2, job="d" * 32),
            status(CAP2.replace("helper.example.test", "other.example.test"))
        )):
            with self.subTest(case=i):
                self.dest = self.folder / f"sample-{i}.bin"
                mock = Synthetic({2: 404})
                with self.assertRaises(ExportError) as err:
                    self.recv(mock, renew=lambda _job: new)
                self.assertEqual(err.exception.code, "snapshot_changed")
                self.assertEqual(len(mock.calls), 2)

    def test_range_and_identity_errors_do_not_append(self):
        for i, failure in enumerate(("wrong_range", 200, "wrong_etag", "wrong_header_hash")):
            with self.subTest(failure=failure):
                self.dest = self.folder / f"neg-{i}.bin"
                mock = Synthetic({2: failure})
                with self.assertRaises(ExportError) as err:
                    self.recv(mock)
                self.assertIn(err.exception.code, {"range_mismatch", "snapshot_changed"})
                self.assertEqual(self.dest.with_name(self.dest.name + ".part").read_bytes(), DATA[:8])
                self.assertFalse(self.dest.exists())

    def test_wrong_final_digest_never_publishes(self):
        mock = Synthetic({2: "corrupt"})
        with self.assertRaises(ExportError) as err:
            self.recv(mock)
        self.assertEqual(err.exception.code, "integrity")
        self.assertFalse(self.dest.exists())

    def test_preserve_existing_destination_and_reject_untracked_partial(self):
        self.dest.write_bytes(b"keep me")
        mock = Synthetic()
        with self.assertRaises(ExportError) as err:
            self.recv(mock)
        self.assertEqual(err.exception.code, "destination_exists")
        self.assertEqual(self.dest.read_bytes(), b"keep me")
        self.dest.unlink()
        self.partial.write_bytes(b"untracked")
        with self.assertRaises(ExportError) as err:
            self.recv(mock)
        self.assertEqual(err.exception.code, "local_state")
        self.assertEqual(self.partial.read_bytes(), b"untracked")
        self.assertEqual(mock.calls, [])

    def test_invalid_capability_and_over_limit_metadata(self):
        for value in (
            status(CAP1.replace("https", "http")), status(CAP1.replace("helper.example.test", "user@helper.example.test")),
            status(CAP1 + "?private=value"), {**status(), "bytes": 1_000_000_001},
            status(CAP1.replace("helper.example.test", "127.0.0.1")),
            status(CAP1.replace("helper.example.test", "helper.example.test:0")),
        ):
            with self.assertRaises(ExportError):
                Snapshot.from_status(value)
        self.assertNotIn(CAP1, repr(Snapshot.from_status(status())))

    def test_redirect_and_denial_are_never_retried(self):
        for i, code in enumerate((302, 401, 403)):
            with self.subTest(code=code):
                self.dest = self.folder / f"http-{i}.bin"
                mock = Synthetic({1: code})
                with self.assertRaises(ExportError) as err:
                    self.recv(mock, renew=lambda _job: self.fail("unexpected renewal"))
                self.assertEqual(err.exception.code, "http")
                self.assertNotIn(CAP1, str(err.exception))
                self.assertEqual(len(mock.calls), 1)

    def test_zero_bytes_checked_without_nonexistent_range(self):
        digest = sha256(b"").hexdigest()
        mock = Synthetic(data=b"", digest=digest)
        rec = self.recv(mock, status(digest=digest, payload=b""), metrics=Metrics())
        self.assertEqual(rec["bytes"], 0)
        self.assertEqual(mock.calls, [])
        self.assertEqual(self.dest.read_bytes(), b"")

    def test_restart_after_publication_can_return_verified_receipt(self):
        self.partial.write_bytes(DATA)
        self.record.write_text(json.dumps(Snapshot.from_status(status()).identity()), encoding="utf-8")
        os.link(self.partial, self.dest)
        mock = Synthetic()
        rec = self.recv(mock)
        self.assertEqual(rec["state"], "verified")
        self.assertEqual(rec["metrics"]["resumed_bytes"], len(DATA))
        self.assertEqual(self.dest.read_bytes(), DATA)
        self.assertFalse(self.partial.exists())
        self.assertFalse(self.record.exists())
        self.assertEqual(mock.calls, [])


if __name__ == "__main__":
    unittest.main()
