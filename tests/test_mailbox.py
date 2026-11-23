"""Isolated incoming/outgoing mailbox tests on Windows."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

STAGE = Path(__file__).resolve().parents[1]
SANDBOX = tempfile.TemporaryDirectory(prefix="dot-mailbox-test-", dir=STAGE.parent)
ROOT = Path(SANDBOX.name)
os.environ["WINDOWS_WORKSPACE_MCP_STATE"] = str(ROOT / "state")
sys.path.insert(0, str(STAGE / "runtime"))

import core
if os.name == "nt":
    import file_bridge
    import transfer_mailbox as mailbox
    from starlette.requests import Request

ORIGIN = "https://test.sample.invalid"


def tearDownModule():
    SANDBOX.cleanup()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def put(link, data, *, length=None, disconnect=False):
    async def exchange():
        messages = iter([
            {"type": "http.request", "body": data[:7], "more_body": True},
            ({"type": "http.disconnect"} if disconnect else
             {"type": "http.request", "body": data[7:], "more_body": False}),
        ])

        async def receive():
            return next(messages)

        request = Request({"type": "http", "method": "PUT", "path": link.split(ORIGIN)[1],
                           "headers": [(b"content-length", str(len(data) if length is None else length).encode())],
                           "path_params": {"token": link.rsplit("/", 1)[-1]}}, receive=receive)
        result = await mailbox.upload_http(request)
        return result.status_code, json.loads(result.body)

    return asyncio.run(exchange())


@unittest.skipUnless(os.name == "nt", "requires Windows mailbox and file locks")
class MailboxTests(unittest.TestCase):
    def setUp(self):
        core.update_config(origin=ORIGIN)
        core.configure_local_relay(ORIGIN, ["https://client.example.invalid/oauth/redirect"])
        self.work = ROOT / self._testMethodName
        self.inbox = self.work / "inbox"
        self.inbox.mkdir(parents=True)
        self.cfg = {**core.load_config(), "origin": ORIGIN, "workspace_enabled": True,
                    "workspace_root": str(self.work), "workspace_revision": self._testMethodName,
                    "documents_enabled": True, "document_scope": str(self.work),
                    "document_revision": self._testMethodName, "approval_mode": "full",
                    "receive_enabled": True, "receive_scope": str(self.inbox),
                    "receive_revision": self._testMethodName, "transfer_max_mb": 100}
        core.save_json(core.CONFIG, self.cfg)
        mailbox.cleanup(self.cfg, force=True)
        self.data = "PK Windows 测试".encode()

    def new(self, name="包.zip", key="retry_key", data=None):
        if data is None:
            data = self.data
        return mailbox.create_upload(name, len(data), sha(data), self.cfg, key)

    def test_transfer_verifies_before_local_approval(self):
        request = self.new()
        tid = request["transfer_id"]
        self.assertNotIn("upload_url", mailbox.upload_status(tid, self.cfg))
        with self.assertRaises(ValueError):
            mailbox.approve_upload(tid, self.cfg)
        rc, content = put(request["upload_url"], self.data)
        self.assertEqual((rc, content["state"]), (201, "awaiting_approval"))
        self.assertNotIn("upload_url", content)
        self.assertFalse((self.inbox / "包.zip").exists())
        duplicate = self.new()
        self.assertEqual(duplicate["transfer_id"], tid)
        self.assertNotIn("upload_url", duplicate)
        rc, content = put(request["upload_url"], self.data)
        self.assertEqual((rc, content["state"]), (200, "awaiting_approval"))
        receipt = mailbox.approve_upload(tid, self.cfg)
        self.assertEqual((receipt["state"], receipt["sha256"]), ("delivered", sha(self.data)))
        self.assertEqual((self.inbox / "包.zip").read_bytes(), self.data)
        self.assertFalse(mailbox.payload_path(tid).exists())
        self.assertEqual(mailbox.approve_upload(tid, self.cfg)["state"], "delivered")
        self.assertEqual(mailbox.list_mailbox(self.cfg)["incoming"][0]["state"], "delivered")

    def test_failed_digest_interrupted_stream_and_retry(self):
        request = self.new()
        tid = request["transfer_id"]
        self.assertEqual(put(request["upload_url"], b"0" * len(self.data))[0], 422)
        self.assertEqual(mailbox.upload_status(tid, self.cfg)["state"], "awaiting_upload")
        self.assertEqual(put(request["upload_url"], self.data, disconnect=True)[0], 408)
        self.assertEqual(mailbox.upload_status(tid, self.cfg)["state"], "awaiting_upload")
        renewal = mailbox.upload_status(tid, self.cfg, renew=True)
        self.assertEqual(put(request["upload_url"], self.data)[0], 404)
        self.assertEqual(put(renewal["upload_url"], self.data)[0], 201)
        self.assertEqual(mailbox.reject_upload(tid, self.cfg)["state"], "rejected")
        self.assertFalse(mailbox.payload_path(tid).exists())
        self.assertFalse((self.inbox / "包.zip").exists())

    def test_non_overwrite_scope_and_policy_revocation(self):
        request = self.new()
        tid = request["transfer_id"]
        self.assertEqual(put(request["upload_url"], self.data)[0], 201)
        file = self.inbox / "包.zip"
        file.write_bytes(b"existing")
        with self.assertRaisesRegex(ValueError, "already exists"):
            mailbox.approve_upload(tid, self.cfg)
        self.assertEqual(file.read_bytes(), b"existing")
        self.assertEqual(mailbox.upload_status(tid, self.cfg)["state"], "awaiting_approval")
        second = self.new("second.zip", "second")
        self.cfg["receive_revision"] = "revoked"
        core.save_json(core.CONFIG, self.cfg)
        mailbox.cleanup(self.cfg, force=True)
        self.assertEqual(put(second["upload_url"], self.data)[0], 404)
        self.assertFalse(mailbox.payload_path(tid).exists())
        self.assertEqual(mailbox.list_mailbox(self.cfg)["incoming"], [])
        for value in ("..\\no.zip", "name:alternate.zip", "CON.zip", "LPT1", "name.", "sub/file.zip"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.new(value, "bad")
        with self.assertRaises(ValueError):
            mailbox.validate_receive_scope(self.work, self.cfg)

    def test_large_reservation_and_cancel(self):
        request = mailbox.create_upload("large.zip", 20_000_001, "a" * 64, self.cfg)
        tid = request["transfer_id"]
        self.assertEqual(request["size_bytes"], 20_000_001)
        self.assertEqual(mailbox.cancel_upload(tid, self.cfg)["state"], "cancelled")
        with self.assertRaises(ValueError):
            mailbox.create_upload("excess.zip", 100_000_001, "a" * 64, self.cfg)

    def test_outgoing_receipt_is_hash_bound_and_durable(self):
        source = self.work / "origin.zip"
        source.write_bytes(self.data)
        item = mailbox.queue_outgoing(source, self.cfg)
        tid = item["transfer_id"]
        self.assertNotIn("download_url", item)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            file_bridge.pump_exports(self.cfg)
            status = mailbox.get_outgoing(tid, self.cfg)
            if status["state"] == "ready":
                break
            time.sleep(0.05)
        self.assertEqual(status["state"], "ready")
        self.assertIn("download_url", status)
        self.assertNotIn("download_url", mailbox.list_mailbox(self.cfg)["outgoing"][0])
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            mailbox.acknowledge_outgoing(tid, "0" * 64, self.cfg)
        receipt = mailbox.acknowledge_outgoing(tid, sha(self.data), self.cfg)
        self.assertEqual(receipt["state"], "received")
        self.assertEqual(mailbox.get_outgoing(tid, self.cfg), receipt)
        self.assertEqual(mailbox.acknowledge_outgoing(tid, sha(self.data), self.cfg), receipt)


if __name__ == "__main__":
    unittest.main(verbosity=2)
