"""Standalone tests for the durable Windows/Dot notes API."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

STAGE = Path(__file__).resolve().parents[1]
SANDBOX = tempfile.TemporaryDirectory(prefix="dot-notes-test-", dir=STAGE.parent)
ROOT = Path(SANDBOX.name)
os.environ["WINDOWS_WORKSPACE_MCP_STATE"] = str(ROOT / "state")
sys.path.insert(0, str(STAGE / "runtime"))

import core
import operator_messages as notes


def tearDownModule():
    SANDBOX.cleanup()


class OperatorMessagesTests(unittest.TestCase):
    def setUp(self):
        root = ROOT / self._testMethodName
        root.mkdir(exist_ok=True)
        origin = "https://test.sample.invalid"
        core.update_config(origin=origin)
        core.configure_local_relay(origin, ["https://client.example.invalid/oauth/redirect"])
        self.cfg = {**core.load_config(), "origin": origin, "workspace_root": str(root),
                    "workspace_enabled": True, "workspace_revision": self._testMethodName}
        core.save_json(core.CONFIG, self.cfg)

    def test_send_both_directions_and_recipient_specific_ack(self):
        to_windows = notes.send("incoming", "本机便签\n保留后缀", self.cfg, "in")
        to_dot = notes.send("outgoing", "云端便签 👍", self.cfg, "out")
        self.assertEqual(notes.list_messages("windows", self.cfg)["messages"], [to_windows])
        self.assertEqual(notes.list_messages("dot", self.cfg)["messages"], [to_dot])
        with self.assertRaisesRegex(ValueError, "recipient"):
            notes.acknowledge("windows", to_dot["message_id"], self.cfg)
        result = notes.acknowledge("dot", to_dot["message_id"], self.cfg)
        self.assertEqual(result["status"], "read")
        self.assertEqual(notes.acknowledge("dot", to_dot["message_id"], self.cfg), result)
        self.assertEqual(notes.list_messages("dot", self.cfg, unread_only=True)["unread_count"], 0)
        self.assertEqual(notes.list_messages("windows", self.cfg)["unread_count"], 1)

    def test_idempotence_and_live_grant_revocation(self):
        first = notes.send("incoming", "第一条", self.cfg, "same")
        self.assertEqual(notes.send("incoming", "第一条", self.cfg, "same"), first)
        with self.assertRaisesRegex(ValueError, "different message"):
            notes.send("incoming", "不可替换", self.cfg, "same")
        updated = {**self.cfg, "workspace_revision": self.cfg["workspace_revision"] + "new"}
        core.save_json(core.CONFIG, updated)
        with self.assertRaisesRegex(ValueError, "changed"):
            notes.list_messages("windows", self.cfg)
        self.assertEqual(notes.list_messages("windows", updated)["messages"], [])
        with self.assertRaisesRegex(ValueError, "expired"):
            notes.acknowledge("windows", first["message_id"], updated)

    def test_utf8_response_budget_and_input_validation(self):
        body = "🧪" * 1200
        for i in range(20):
            notes.send("outgoing", body, self.cfg, f"long{i}")
        feed = notes.list_messages("dot", self.cfg, limit=20, unread_only=True)
        self.assertTrue(feed["has_more"])
        self.assertEqual(feed["unread_count"], 20)
        self.assertGreater(len(feed["messages"]), 0)
        self.assertLessEqual(len(json.dumps(feed).encode("utf-8")), 24_000)
        for invalid in ("\x00", " ", "a" * 1201):
            with self.subTest(text=invalid), self.assertRaises(ValueError):
                notes.send("outgoing", invalid, self.cfg)
        with self.assertRaises(ValueError):
            notes.list_messages("dot", self.cfg, limit=True)

    def test_age_limit(self):
        then = notes.time.time()
        with mock.patch.object(notes.time, "time", return_value=then):
            item = notes.send("outgoing", "即将过期", self.cfg)
        with mock.patch.object(notes.time, "time", return_value=then + notes.HISTORY + 5):
            self.assertEqual(notes.list_messages("dot", self.cfg)["messages"], [])
            with self.assertRaisesRegex(ValueError, "expired"):
                notes.acknowledge("dot", item["message_id"], self.cfg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
